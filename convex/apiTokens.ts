/**
 * `fsv1_` service/user bearer tokens (P3 lookup + P6d resolve/mint). Ported from
 * services/api-tokens.ts. Only the SHA-256 hash + a short prefix are stored;
 * minting needs CSPRNG so it lives in an action. Resolution hashes the presented
 * plaintext, matches the unique index, and debounces the last-used write to
 * avoid hot-row updates. Scope enforcement happens at the call site (HTTP layer).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { base64UrlEncode, sha256Hex } from './lib/crypto';

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
export const createToken = internalAction({
  args: {
    name: v.string(),
    scopes: v.array(v.string()),
    subjectType: v.union(v.literal('service'), v.literal('user')),
    subjectUserId: v.optional(v.id('users')),
    expiresInDays: v.optional(v.number()),
    createdByAdminId: v.id('adminUsers'),
  },
  handler: async (ctx, a): Promise<{ id: Id<'apiTokens'>; plaintext: string; prefix: string }> => {
    const random = new Uint8Array(TOKEN_RANDOM_BYTES);
    crypto.getRandomValues(random);
    const plaintext = `${TOKEN_PREFIX}${base64UrlEncode(random)}`;
    const tokenHash = await sha256Hex(plaintext);
    const tokenPrefix = plaintext.slice(0, 12); // "fsv1_" + 7 chars
    const id = await ctx.runMutation(internal.apiTokens.insertToken, {
      name: a.name,
      tokenHash,
      tokenPrefix,
      createdByAdminId: a.createdByAdminId,
      scopes: a.scopes,
      subjectType: a.subjectType,
      subjectUserId: a.subjectUserId,
      expiresAt: a.expiresInDays ? Date.now() + a.expiresInDays * 86_400_000 : undefined,
    });
    return { id, plaintext, prefix: tokenPrefix };
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
  },
  handler: (ctx, a) => ctx.db.insert('apiTokens', { ...a, updatedAt: Date.now() }),
});

// `list` and `revoke` (public query/mutation) were deleted in pass 2: dead code
// — the admin CMS uses adminApi.tokensList / adminApi.revokeToken — and public
// functions are callable by anyone who can reach the Convex deploy port.
