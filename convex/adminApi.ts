/**
 * Admin resource API (the `/api/v1/admin/*` surface): the Convex half of the
 * passkey-gated admin CMS. The HTTP routes in convex/http.ts authenticate the
 * admin (cookie OR an `admin:*`-scoped fsv1_ token) via `resolveAdmin`, then
 * call these functions. Row → contract mapping (Convex string `_id`, ISO
 * timestamps from `_creationTime`/`updatedAt`) lives here so the HTTP layer
 * stays thin and the shapes match src/shared/contracts/{admin,tokens}.ts.
 *
 * Security:
 *  - Outline server rows carry a secret `apiUrl` (the Manager URL embeds a
 *    credential path). It is NEVER returned, only `apiUrlMasked` (scheme+host,
 *    path replaced with `/***`). The full URL is stored on create/edit and read
 *    back only by the internal backend actions.
 *  - Uniqueness (tier slug, outline slug) is enforced inside the mutation via a
 *    by-field index read-check (serializable OCC makes it race-free).
 *
 * Some actions reference same-file `internal.adminApi.*`; those handlers carry
 * an explicit return-type annotation to break Convex's self-reference inference
 * cycle (this repo has hit it before).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';

// Admin resource functions are INTERNAL: the only caller is the admin-gated
// HTTP layer (convex/http.ts) via ctx.runQuery/runMutation. Keeping them off
// `api.*` means they can't be reached on the public Convex query/mutation
// channel without first passing the `resolveAdmin` gate.

// --- shared validators (mirror the contract enums) --------------------------

const backendId = v.union(v.literal('remnawave'), v.literal('outline'));
const trafficStrategy = v.union(
  v.literal('NO_RESET'),
  v.literal('DAY'),
  v.literal('WEEK'),
  v.literal('MONTH'),
);

/** Fields shared by tier create + update (the contract's TierUpsert). */
const tierUpsertFields = {
  slug: v.string(),
  name: v.string(),
  description: v.union(v.string(), v.null()),
  backend: backendId,
  monthlyTrafficGb: v.number(),
  deviceLimit: v.number(),
  hwidLimit: v.number(),
  hwidEnabled: v.boolean(),
  trafficStrategy,
  remnawaveSquadUuid: v.union(v.string(), v.null()),
  isDefaultFree: v.boolean(),
  isActive: v.boolean(),
  priority: v.number(),
  expirationDaysAfterMembershipLapse: v.number(),
};

// --- mappers (Doc -> contract shape) ----------------------------------------

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function mapTier(t: Doc<'tiers'>) {
  return {
    id: t._id as string,
    slug: t.slug,
    name: t.name,
    description: t.description ?? null,
    backend: t.backend,
    monthlyTrafficGb: t.monthlyTrafficGb,
    deviceLimit: t.deviceLimit,
    hwidLimit: t.hwidLimit,
    hwidEnabled: t.hwidEnabled,
    trafficStrategy: t.trafficStrategy,
    remnawaveSquadUuid: t.remnawaveSquadUuid ?? null,
    isDefaultFree: t.isDefaultFree,
    isActive: t.isActive,
    priority: t.priority,
    expirationDaysAfterMembershipLapse: t.expirationDaysAfterMembershipLapse,
    createdAt: iso(t._creationTime),
    updatedAt: iso(t.updatedAt),
  };
}

function mapToken(t: Doc<'apiTokens'>) {
  return {
    id: t._id as string,
    name: t.name,
    tokenPrefix: t.tokenPrefix,
    scopes: t.scopes,
    subjectType: t.subjectType,
    subjectUserId: (t.subjectUserId as string | undefined) ?? null,
    expiresAt: t.expiresAt != null ? iso(t.expiresAt) : null,
    lastUsedAt: t.lastUsedAt != null ? iso(t.lastUsedAt) : null,
    revokedAt: t.revokedAt != null ? iso(t.revokedAt) : null,
    createdAt: iso(t._creationTime),
  };
}

function mapAudit(e: Doc<'auditLog'>) {
  return {
    id: e._id as string,
    actorType: e.actorType,
    actorId: e.actorId ?? null,
    action: e.action,
    targetType: e.targetType ?? null,
    targetId: e.targetId ?? null,
    payload: e.payload ?? null,
    requestId: e.requestId ?? null,
    createdAt: iso(e._creationTime),
  };
}

/**
 * Redact the Outline Manager secret: keep scheme + host(+port), replace the
 * whole path (which embeds the credential) with `/***`. Falls back to a bare
 * sentinel if the stored value isn't a parseable URL.
 */
export function maskApiUrl(apiUrl: string): string {
  try {
    const u = new URL(apiUrl);
    return `${u.protocol}//${u.host}/***`;
  } catch {
    return '***';
  }
}

function mapOutlineServer(s: Doc<'outlineServers'>) {
  return {
    id: s._id as string,
    name: s.name,
    slug: s.slug,
    apiUrlMasked: maskApiUrl(s.apiUrl),
    websocketEnabled: s.websocketEnabled,
    websocketDomain: s.websocketDomain ?? null,
    prometheusUrl: s.prometheusUrl ?? null,
    isActive: s.isActive,
    priority: s.priority,
    lastHealthOkAt: s.lastHealthOkAt != null ? iso(s.lastHealthOkAt) : null,
    accessKeyCount: s.accessKeyCount,
    createdAt: iso(s._creationTime),
    updatedAt: iso(s.updatedAt),
  };
}

// === tiers ==================================================================

export const tiersList = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('tiers').collect();
    return { tiers: rows.sort((a, b) => a.priority - b.priority).map(mapTier) };
  },
});

export const createTier = internalMutation({
  args: tierUpsertFields,
  handler: async (ctx, a) => {
    // Slug uniqueness (no UNIQUE constraint in Convex): read-check the index.
    const clash = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (clash) throw new Error(`A tier with slug "${a.slug}" already exists`);
    const id = await ctx.db.insert('tiers', {
      slug: a.slug,
      name: a.name,
      description: a.description ?? undefined,
      backend: a.backend,
      monthlyTrafficGb: a.monthlyTrafficGb,
      deviceLimit: a.deviceLimit,
      hwidLimit: a.hwidLimit,
      hwidEnabled: a.hwidEnabled,
      trafficStrategy: a.trafficStrategy,
      remnawaveSquadUuid: a.remnawaveSquadUuid ?? undefined,
      isDefaultFree: a.isDefaultFree,
      isActive: a.isActive,
      priority: a.priority,
      expirationDaysAfterMembershipLapse: a.expirationDaysAfterMembershipLapse,
      updatedAt: Date.now(),
    });
    const created = await ctx.db.get(id);
    return mapTier(created!);
  },
});

export const updateTier = internalMutation({
  // All fields optional: the SPA sends a partial patch (TierUpsert minus
  // anything unchanged). `description` / `remnawaveSquadUuid` accept null.
  args: {
    id: v.id('tiers'),
    slug: v.optional(v.string()),
    name: v.optional(v.string()),
    description: v.optional(v.union(v.string(), v.null())),
    backend: v.optional(backendId),
    monthlyTrafficGb: v.optional(v.number()),
    deviceLimit: v.optional(v.number()),
    hwidLimit: v.optional(v.number()),
    hwidEnabled: v.optional(v.boolean()),
    trafficStrategy: v.optional(trafficStrategy),
    remnawaveSquadUuid: v.optional(v.union(v.string(), v.null())),
    isDefaultFree: v.optional(v.boolean()),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    expirationDaysAfterMembershipLapse: v.optional(v.number()),
  },
  handler: async (ctx, { id, ...patch }) => {
    const existing = await ctx.db.get(id);
    if (!existing) throw new Error('tier not found');
    if (patch.slug !== undefined && patch.slug !== existing.slug) {
      const clash = await ctx.db
        .query('tiers')
        .withIndex('by_slug', (q) => q.eq('slug', patch.slug!))
        .unique();
      if (clash) throw new Error(`A tier with slug "${patch.slug}" already exists`);
    }
    // Normalize the nullable-optional contract fields to Convex's "absent" form.
    const fields: Partial<Doc<'tiers'>> = { updatedAt: Date.now() };
    for (const [k, val] of Object.entries(patch) as [keyof typeof patch, unknown][]) {
      if (val === undefined) continue;
      if ((k === 'description' || k === 'remnawaveSquadUuid') && val === null) {
        (fields as Record<string, unknown>)[k] = undefined;
      } else {
        (fields as Record<string, unknown>)[k] = val;
      }
    }
    await ctx.db.patch(id, fields);
    const updated = await ctx.db.get(id);
    return mapTier(updated!);
  },
});

export const deleteTier = internalMutation({
  args: { id: v.id('tiers') },
  handler: async (ctx, { id }) => {
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});

// === users ==================================================================

const userStatus = v.union(
  v.literal('active'),
  v.literal('grace'),
  v.literal('disabled'),
  v.literal('deleted'),
);

/**
 * Resolve a user's current/active subscription for the admin list (so the row
 * can show the backend + backend user id). Mirrors subscriptions.resolveCurrentOrActive
 * but inline so this stays a single query (no cross-module action hop per row).
 */
async function currentBackendForUser(
  ctx: { db: import('./_generated/server').QueryCtx['db'] },
  user: Doc<'users'>,
): Promise<{ backend: 'remnawave' | 'outline' | null; backendUserId: string | null }> {
  let sub: Doc<'subscriptions'> | null = null;
  if (user.currentSubscriptionId) {
    const cur = await ctx.db.get(user.currentSubscriptionId);
    if (cur && cur.state === 'active') sub = cur;
  }
  if (!sub) {
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', user._id))
      .collect();
    sub =
      rows
        .filter((s) => s.state === 'active')
        .sort((a, b) => b._creationTime - a._creationTime)[0] ?? null;
  }
  return sub
    ? { backend: sub.backend, backendUserId: sub.backendUserId }
    : { backend: null, backendUserId: null };
}

async function mapUser(
  ctx: { db: import('./_generated/server').QueryCtx['db'] },
  u: Doc<'users'>,
  tierSlugById: Map<string, string>,
) {
  const cur = await currentBackendForUser(ctx, u);
  return {
    id: u._id as string,
    accountIdPrefix: u.accountIdPrefix ?? null,
    status: u.status,
    tierSlug: tierSlugById.get(u.tierId) ?? 'free',
    membershipExpiresAt: u.membershipExpiresAt != null ? iso(u.membershipExpiresAt) : null,
    backendUserId: cur.backendUserId,
    backend: cur.backend,
    createdAt: iso(u._creationTime),
  };
}

/**
 * Admin user search. Filters:
 *  - `q`: a 4-digit account-number prefix, looked up via the prefix index (a
 *    full number is never an admin oracle). The prefix is the only searchable
 *    handle for an anonymous member, so any non-prefix query matches nothing.
 *  - `status` / `tier`: post-filters.
 * Pagination is a keyset over `_creationTime` desc via an opaque cursor.
 */
export const usersSearch = internalQuery({
  args: {
    q: v.optional(v.string()),
    status: v.optional(userStatus),
    tier: v.optional(v.string()),
    cursor: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { q, status, tier, cursor, limit }) => {
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);

    // Tier slug → id map (for the `tier` filter) and id → slug map (for rows).
    const tiers = await ctx.db.query('tiers').collect();
    const tierSlugById = new Map<string, string>(tiers.map((t) => [t._id as string, t.slug]));
    const tierIdBySlug = new Map<string, Id<'tiers'>>(tiers.map((t) => [t.slug, t._id]));

    const trimmed = q?.trim();

    // Targeted lookups when `q` clearly identifies a single user; these short
    // out before the paginated scan and ignore the cursor (small result set).
    if (trimmed) {
      // The 4-digit account-number prefix is the only searchable handle; any
      // other query has nothing to match against (members are anonymous).
      const matches: Doc<'users'>[] = /^\d{4}$/.test(trimmed)
        ? await ctx.db
            .query('users')
            .withIndex('by_account_id_prefix', (idx) => idx.eq('accountIdPrefix', trimmed))
            .take(pageSize)
        : [];
      const filtered = matches
        .filter((u) => (status ? u.status === status : true))
        .filter((u) => (tier ? u.tierId === tierIdBySlug.get(tier) : true))
        .slice(0, pageSize);
      const users = await Promise.all(filtered.map((u) => mapUser(ctx, u, tierSlugById)));
      return { users, nextCursor: null };
    }

    // Unfiltered/paginated browse: keyset over _creationTime desc.
    let qry = ctx.db.query('users').order('desc');
    if (cursor) {
      const before = Number(cursor);
      if (Number.isFinite(before)) qry = qry.filter((f) => f.lt(f.field('_creationTime'), before));
    }
    // Over-fetch to allow post-filtering without breaking the page size.
    const raw = await qry.take(pageSize * 4 + 1);
    const matchFilter = (u: Doc<'users'>) =>
      (status ? u.status === status : true) && (tier ? u.tierId === tierIdBySlug.get(tier) : true);
    const filtered = raw.filter(matchFilter);
    const page = filtered.slice(0, pageSize);
    const last = page[page.length - 1];
    // More pages iff we filled the page AND there were rows beyond it.
    const more =
      page.length === pageSize && raw.length > filtered.indexOf(page[page.length - 1]!) + 1;
    const nextCursor = more && last ? String(last._creationTime) : null;
    const users = await Promise.all(page.map((u) => mapUser(ctx, u, tierSlugById)));
    return { users, nextCursor };
  },
});

/**
 * Admin "disable" op: flip the user to `disabled` locally + record audit. The
 * backend-subscription pause is done by the HTTP action (it needs an action
 * context for the backend HTTP call); this mutation owns the durable state.
 */
export const disableUser = internalMutation({
  args: { userId: v.id('users'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { userId, actorAdminId }) => {
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('user not found');
    await ctx.db.patch(userId, {
      status: 'disabled',
      disabledReason: 'admin_action',
      suspendedAt: Date.now(),
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.user.disable',
      targetType: 'user',
      targetId: userId,
    });
    return { ok: true as const };
  },
});

/** The user's active subscription (backend + backendUserId) for admin ops. */
export const activeSubForUser = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    const sub = rows
      .filter((s) => s.state === 'active')
      .sort((a, b) => b._creationTime - a._creationTime)[0];
    return sub ? { backend: sub.backend, backendUserId: sub.backendUserId } : null;
  },
});

export const recordUserOpAudit = internalMutation({
  args: {
    action: v.string(),
    userId: v.id('users'),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { action, userId, actorAdminId }) => {
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action,
      targetType: 'user',
      targetId: userId,
    });
    return null;
  },
});

/**
 * HTTP entry for the three user ops the admin SPA exposes
 * (`disable` | `reset-traffic` | `resync`). Lives in an action because two of
 * them touch the proxy backend over HTTP. Returns `{ ok: true }` (the SPA
 * parses an empty/loose object).
 */
export const runUserOp = internalAction({
  args: {
    userId: v.id('users'),
    op: v.union(v.literal('disable'), v.literal('reset-traffic'), v.literal('resync')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { userId, op, actorAdminId }): Promise<{ ok: true }> => {
    if (op === 'disable') {
      await ctx.runMutation(internal.adminApi.disableUser, { userId, actorAdminId });
      const sub = await ctx.runQuery(internal.adminApi.activeSubForUser, { userId });
      if (sub) {
        try {
          await ctx.runAction(internal.backends.updateUser, {
            backend: sub.backend,
            backendUserId: sub.backendUserId,
            patch: { status: 'disabled' },
          });
        } catch {
          /* best-effort: local state is authoritative; cron/edit will reconcile */
        }
      }
      return { ok: true };
    }

    // reset-traffic + resync both need the live subscription.
    const sub = await ctx.runQuery(internal.adminApi.activeSubForUser, { userId });
    if (op === 'reset-traffic') {
      if (sub) {
        try {
          await ctx.runAction(internal.backends.resetUserTraffic, {
            backend: sub.backend,
            backendUserId: sub.backendUserId,
          });
        } catch {
          /* best-effort */
        }
      }
      await ctx.runMutation(internal.adminApi.recordUserOpAudit, {
        action: 'admin.user.reset_traffic',
        userId,
        actorAdminId,
      });
      return { ok: true };
    }

    // resync: re-push the user's tier spec to the live backend (idempotent).
    await ctx.runAction(internal.lifecycle.pushTierToBackend, { userId });
    await ctx.runMutation(internal.adminApi.recordUserOpAudit, {
      action: 'admin.user.resync',
      userId,
      actorAdminId,
    });
    return { ok: true };
  },
});

// === tokens =================================================================

export const tokensList = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('apiTokens').collect();
    return { tokens: rows.sort((a, b) => b._creationTime - a._creationTime).map(mapToken) };
  },
});

/** Fetch one token mapped to the contract shape (for the create response). */
export const tokenById = internalQuery({
  args: { id: v.id('apiTokens') },
  handler: async (ctx, { id }) => {
    const t = await ctx.db.get(id);
    return t ? mapToken(t) : null;
  },
});

export const revokeToken = internalMutation({
  args: { id: v.id('apiTokens') },
  handler: async (ctx, { id }) => {
    await ctx.db.patch(id, { revokedAt: Date.now(), updatedAt: Date.now() });
    return { ok: true as const };
  },
});

// === audit ==================================================================

/**
 * Audit log page (newest first) with an opaque keyset cursor over
 * `_creationTime`. The cursor is just the last row's creation time stringified.
 */
export const auditList = internalQuery({
  args: { cursor: v.optional(v.string()), limit: v.optional(v.number()) },
  handler: async (ctx, { cursor, limit }) => {
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);
    let qry = ctx.db.query('auditLog').order('desc');
    if (cursor) {
      const before = Number(cursor);
      if (Number.isFinite(before)) qry = qry.filter((f) => f.lt(f.field('_creationTime'), before));
    }
    const rows = await qry.take(pageSize + 1);
    const hasMore = rows.length > pageSize;
    const page = rows.slice(0, pageSize);
    const last = page[page.length - 1];
    const nextCursor = hasMore && last ? String(last._creationTime) : null;
    return { entries: page.map(mapAudit), nextCursor };
  },
});

// === settings ===============================================================
// Read/patch reuse appSettings.resolved + appSettings.set at the HTTP layer;
// no extra functions needed here.

// === outline servers ========================================================

export const outlineServersList = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('outlineServers').collect();
    return { servers: rows.sort((a, b) => a.priority - b.priority).map(mapOutlineServer) };
  },
});

export const createOutlineServer = internalMutation({
  args: {
    name: v.string(),
    slug: v.string(),
    apiUrl: v.string(),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
    prometheusUrl: v.optional(v.union(v.string(), v.null())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const clash = await ctx.db
      .query('outlineServers')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (clash) throw new Error(`An Outline server with slug "${a.slug}" already exists`);
    const id = await ctx.db.insert('outlineServers', {
      name: a.name,
      slug: a.slug,
      apiUrl: a.apiUrl,
      websocketEnabled: a.websocketEnabled ?? false,
      websocketDomain: a.websocketDomain ?? undefined,
      prometheusUrl: a.prometheusUrl ?? undefined,
      isActive: a.isActive ?? true,
      priority: a.priority ?? 0,
      accessKeyCount: 0,
      updatedAt: Date.now(),
    });
    const created = await ctx.db.get(id);
    return mapOutlineServer(created!);
  },
});

export const updateOutlineServer = internalMutation({
  args: {
    id: v.id('outlineServers'),
    name: v.optional(v.string()),
    slug: v.optional(v.string()),
    // apiUrl only present when the admin retyped it (rotate the secret).
    apiUrl: v.optional(v.string()),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
    prometheusUrl: v.optional(v.union(v.string(), v.null())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
  },
  handler: async (ctx, { id, ...patch }) => {
    const existing = await ctx.db.get(id);
    if (!existing) throw new Error('Outline server not found');
    if (patch.slug !== undefined && patch.slug !== existing.slug) {
      const clash = await ctx.db
        .query('outlineServers')
        .withIndex('by_slug', (q) => q.eq('slug', patch.slug!))
        .unique();
      if (clash) throw new Error(`An Outline server with slug "${patch.slug}" already exists`);
    }
    const fields: Partial<Doc<'outlineServers'>> = { updatedAt: Date.now() };
    if (patch.name !== undefined) fields.name = patch.name;
    if (patch.slug !== undefined) fields.slug = patch.slug;
    if (patch.apiUrl !== undefined && patch.apiUrl !== '') fields.apiUrl = patch.apiUrl;
    if (patch.websocketEnabled !== undefined) fields.websocketEnabled = patch.websocketEnabled;
    if (patch.websocketDomain !== undefined)
      fields.websocketDomain = patch.websocketDomain ?? undefined;
    if (patch.prometheusUrl !== undefined) fields.prometheusUrl = patch.prometheusUrl ?? undefined;
    if (patch.isActive !== undefined) fields.isActive = patch.isActive;
    if (patch.priority !== undefined) fields.priority = patch.priority;
    await ctx.db.patch(id, fields);
    const updated = await ctx.db.get(id);
    return mapOutlineServer(updated!);
  },
});

export const deleteOutlineServer = internalMutation({
  args: { id: v.id('outlineServers') },
  handler: async (ctx, { id }) => {
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});

/**
 * Best-effort connectivity check for the Outline Manager URL the admin pasted
 * (before they save it). Lists access keys; on success returns the current key
 * count. The apiUrl is treated as a credential: never echoed back, never put
 * in the error message (the Outline helpers already scrub it).
 */
export const testOutlineConnection = internalAction({
  args: { apiUrl: v.string() },
  handler: async (
    _ctx: ActionCtx,
    { apiUrl }: { apiUrl: string },
  ): Promise<{ ok: true; keyCount: number } | { ok: false; error: string }> => {
    const base = apiUrl.endsWith('/') ? apiUrl : `${apiUrl}/`;
    let url: string;
    try {
      url = new URL('access-keys', base).toString();
    } catch {
      return { ok: false, error: 'Invalid URL' };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: controller.signal,
      });
      if (!res.ok) {
        // Status only, never the URL (it carries the secret path).
        return { ok: false, error: `Outline returned HTTP ${res.status}` };
      }
      const body = (await res.json().catch(() => null)) as { accessKeys?: unknown[] } | null;
      const keyCount = Array.isArray(body?.accessKeys) ? body!.accessKeys!.length : 0;
      return { ok: true, keyCount };
    } catch (err) {
      const msg =
        err instanceof Error && err.name === 'AbortError'
          ? 'Connection timed out'
          : 'Connection failed';
      return { ok: false, error: msg };
    } finally {
      clearTimeout(timer);
    }
  },
});
