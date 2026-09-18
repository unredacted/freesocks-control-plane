/**
 * `fsv1_` service/user bearer tokens (P3 lookup + P6d resolve/mint). Ported from
 * services/api-tokens.ts. Only the SHA-256 hash + a short prefix are stored;
 * minting needs CSPRNG so it lives in an action. Resolution hashes the presented
 * plaintext, matches the unique index, and debounces the last-used write to
 * avoid hot-row updates. Scope enforcement happens at the call site (HTTP layer).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { base64UrlEncode, sha256Hex } from './lib/crypto';
import { writeAuditLog } from './lib/audit';

export const TOKEN_PREFIX = 'fsv1_';
const TOKEN_RANDOM_BYTES = 32;
const LAST_USED_DEBOUNCE_MS = 5 * 60_000;

/**
 * Resolve a plaintext token by its SHA-256 hash. Returns null for unknown,
 * revoked, or expired tokens. Scope enforcement is the caller's job.
 * Internal (pass 2): a public query here was a token-hash → scopes oracle on
 * the raw Convex channel. Explicit return type breaks the same-file
 * internal.* self-reference inference cycle.
 */
export const byTokenHash = internalQuery({
  args: { tokenHash: v.string() },
  handler: async (ctx, { tokenHash }): Promise<Doc<'apiTokens'> | null> => {
    const tok = await ctx.db
      .query('apiTokens')
      .withIndex('by_token_hash', (q) => q.eq('tokenHash', tokenHash))
      .unique();
    if (!tok || tok.revokedAt) return null;
    if (tok.expiresAt && tok.expiresAt < Date.now()) return null;
    return tok;
  },
});

// --- resolve path (P6d) ---

type ResolvedToken = {
  id: Id<'apiTokens'>;
  scopes: string[];
  subjectType: 'service' | 'user';
  subjectUserId: Id<'users'> | null;
};

/** Hash → lookup → debounced touch. The HTTP bearer-auth path calls this. */
export const resolveToken = internalAction({
  args: { plaintext: v.string() },
  handler: async (ctx, { plaintext }): Promise<ResolvedToken | null> => {
    if (!plaintext.startsWith(TOKEN_PREFIX)) return null;
    const tokenHash = await sha256Hex(plaintext);
    const tok = await ctx.runQuery(internal.apiTokens.byTokenHash, { tokenHash });
    if (!tok) return null;
    await ctx.runMutation(internal.apiTokens.touchLastUsed, { tokenId: tok._id });
    return {
      id: tok._id,
      scopes: tok.scopes,
      subjectType: tok.subjectType,
      subjectUserId: tok.subjectUserId ?? null,
    };
  },
});

/** The registration boundary an `admin:edges:register` token carries (null = none set). */
export const registrationBoundary = internalQuery({
  args: { tokenId: v.id('apiTokens') },
  handler: async (ctx, { tokenId }) => {
    const row = await ctx.db.get(tokenId);
    if (!row || row.revokedAt) return null;
    return row.edgeRegistration ?? null;
  },
});

/** Debounced last-used write (≤ once per 5 min) to avoid hot-row updates. */
export const touchLastUsed = internalMutation({
  args: { tokenId: v.id('apiTokens') },
  handler: async (ctx, { tokenId }) => {
    const row = await ctx.db.get(tokenId);
    if (!row) return null;
    const now = Date.now();
    if (!row.lastUsedAt || now - row.lastUsedAt > LAST_USED_DEBOUNCE_MS) {
      await ctx.db.patch(tokenId, { lastUsedAt: now, updatedAt: now });
    }
    return null;
  },
});

// --- mint / revoke (admin) ---

/** Mint a token (CSPRNG → must be an action). Returns the plaintext once. */
const REGISTER_SCOPE = 'admin:edges:register';

/**
 * The boundary a register-scoped token is minted with. A token holding the
 * scope WITHOUT a boundary could register nothing (httpEdges treats it as an
 * empty boundary), so the mint refuses instead of handing out an inert token;
 * a boundary on a token without the scope is refused as a mistake.
 */
async function resolveRegistrationBoundary(
  ctx: MutationCtx,
  scopes: string[],
  requested:
    | { backendServerIds?: string[]; backendSlugs?: string[]; nodeNames?: string[] }
    | undefined,
): Promise<{ backendServerIds: Id<'backendServers'>[]; nodeNames?: string[] } | null> {
  const hasScope = scopes.includes(REGISTER_SCOPE);
  const refuse = (message: string) => new ConvexError({ code: 'validation', message });
  if (!requested) {
    if (hasScope)
      throw refuse(`A ${REGISTER_SCOPE} token needs a registration boundary (backend servers)`);
    return null;
  }
  if (!hasScope) throw refuse(`A registration boundary needs the ${REGISTER_SCOPE} scope`);
  const ids = new Set<Id<'backendServers'>>();
  for (const raw of requested.backendServerIds ?? []) {
    const id = ctx.db.normalizeId('backendServers', raw);
    if (!id || !(await ctx.db.get(id))) throw refuse('Unknown backend server in the boundary');
    ids.add(id);
  }
  for (const slug of requested.backendSlugs ?? []) {
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!server) throw refuse(`Unknown backend server slug in the boundary: ${slug}`);
    ids.add(server._id);
  }
  if (ids.size === 0) throw refuse('The registration boundary names no backend server');
  if (ids.size > 50) throw refuse('The registration boundary holds at most 50 backend servers');
  const nodeNames = [...new Set((requested.nodeNames ?? []).map((n) => n.trim()).filter(Boolean))];
  if (nodeNames.length > 200 || nodeNames.some((n) => n.length > 128))
    throw refuse('The registration boundary holds at most 200 node names of 128 characters');
  return { backendServerIds: [...ids], ...(nodeNames.length > 0 ? { nodeNames } : {}) };
}

export const createToken = internalAction({
  args: {
    name: v.string(),
    scopes: v.array(v.string()),
    subjectType: v.union(v.literal('service'), v.literal('user')),
    subjectUserId: v.optional(v.id('users')),
    expiresInDays: v.optional(v.number()),
    createdByAdminId: v.id('adminUsers'),
    // Registration boundary for an `admin:edges:register` token (docs/edges.md):
    // backend servers by id and/or slug, optionally confined to node names.
    edgeRegistration: v.optional(
      v.object({
        backendServerIds: v.optional(v.array(v.string())),
        backendSlugs: v.optional(v.array(v.string())),
        nodeNames: v.optional(v.array(v.string())),
      }),
    ),
  },
  handler: async (ctx, a): Promise<{ id: Id<'apiTokens'>; plaintext: string; prefix: string }> => {
    // Retry on the (astronomically unlikely) tokenHash collision flagged by the
    // insert's uniqueness read-check.
    for (let attempt = 0; attempt < 3; attempt++) {
      const random = new Uint8Array(TOKEN_RANDOM_BYTES);
      crypto.getRandomValues(random);
      const plaintext = `${TOKEN_PREFIX}${base64UrlEncode(random)}`;
      const tokenHash = await sha256Hex(plaintext);
      const tokenPrefix = plaintext.slice(0, 12); // "fsv1_" + 7 chars
      try {
        const id = await ctx.runMutation(internal.apiTokens.insertToken, {
          name: a.name,
          tokenHash,
          tokenPrefix,
          createdByAdminId: a.createdByAdminId,
          scopes: a.scopes,
          subjectType: a.subjectType,
          subjectUserId: a.subjectUserId,
          expiresAt: a.expiresInDays ? Date.now() + a.expiresInDays * 86_400_000 : undefined,
          edgeRegistration: a.edgeRegistration,
        });
        return { id, plaintext, prefix: tokenPrefix };
      } catch (err) {
        // A refusal (validation) is final; only the hash collision is retried.
        if (err instanceof ConvexError || attempt === 2) throw err;
      }
    }
    throw new Error('unreachable');
  },
});

export const insertToken = internalMutation({
  args: {
    name: v.string(),
    tokenHash: v.string(),
    tokenPrefix: v.string(),
    createdByAdminId: v.id('adminUsers'),
    scopes: v.array(v.string()),
    subjectType: v.union(v.literal('service'), v.literal('user')),
    subjectUserId: v.optional(v.id('users')),
    expiresAt: v.optional(v.number()),
    // Registration boundary for an `admin:edges:register` token (docs/edges.md):
    // backend servers by id and/or slug, optionally confined to node names.
    edgeRegistration: v.optional(
      v.object({
        backendServerIds: v.optional(v.array(v.string())),
        backendSlugs: v.optional(v.array(v.string())),
        nodeNames: v.optional(v.array(v.string())),
      }),
    ),
  },
  handler: async (ctx, a) => {
    const { edgeRegistration: requested, ...row } = a;
    const edgeRegistration = await resolveRegistrationBoundary(ctx, a.scopes, requested);
    // Uniqueness read-check (no UNIQUE constraint in Convex): a tokenHash dup
    // would silently break resolveToken's .unique() lookup. A collision throws
    // so the mint action retries with fresh randomness.
    const clash = await ctx.db
      .query('apiTokens')
      .withIndex('by_token_hash', (q) => q.eq('tokenHash', a.tokenHash))
      .unique();
    if (clash) throw new Error('token hash collision');
    const id = await ctx.db.insert('apiTokens', {
      ...row,
      ...(edgeRegistration ? { edgeRegistration } : {}),
      updatedAt: Date.now(),
    });
    // Credential mints are security-relevant: audit (never the token/hash).
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.createdByAdminId,
      action: 'admin.token.mint',
      targetType: 'api_token',
      targetId: id,
      payload: {
        name: a.name,
        scopeCount: a.scopes.length,
        subjectType: a.subjectType,
        ...(edgeRegistration
          ? {
              boundaryServers: edgeRegistration.backendServerIds.length,
              boundaryNodes: edgeRegistration.nodeNames?.length ?? 0,
            }
          : {}),
      },
    });
    return id;
  },
});

// `list` and `revoke` (public query/mutation) were deleted in pass 2: dead code
// — the admin CMS uses adminApi.tokensList / adminApi.revokeToken — and public
// functions are callable by anyone who can reach the Convex deploy port.
