/**
 * Admin resource API (the `/api/v1/admin/*` surface): the Convex half of the
 * passkey-gated admin CMS. The HTTP routes in convex/http.ts authenticate the
 * admin (cookie OR an `admin:*`-scoped fsv1_ token) via `resolveAdmin`, then
 * call these functions. Row → contract mapping (Convex string `_id`, ISO
 * timestamps from `_creationTime`/`updatedAt`) lives here so the HTTP layer
 * stays thin and the shapes match src/shared/contracts/{admin,tokens}.ts.
 *
 * Security:
 *  - Backend instance rows carry a secret `config` (a Remnawave apiToken, an
 *    Outline Manager apiUrl whose path embeds a credential). It is NEVER
 *    returned; admin responses mask it (apiUrlMasked / apiTokenSet). The full
 *    secret is stored on create/edit and read back only by the backend actions.
 *  - Uniqueness (tier slug, backend-server slug) is enforced inside the mutation
 *    via a by-field index read-check (serializable OCC makes it race-free).
 *
 * Some actions reference same-file `internal.adminApi.*`; those handlers carry
 * an explicit return-type annotation to break Convex's self-reference inference
 * cycle (this repo has hit it before).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { ConvexError, v } from 'convex/values';
import { writeAuditLog } from './lib/audit';
import { applyCountsDelta, readUserCounts } from './lib/statusCounters';
// One shared by-key upsert (Review P3): the local upsertSetting + setBillingConfig's
// inline copy both delegate here (also appSettings.set/setMany use it).
import { upsertSettingRow as upsertSetting } from './appSettings';
import { applyMembership } from './lifecycle';
import { THEME_PRESET_IDS, sanitizeHue } from './lib/themeConfig';
import { connectionModeWrites, resolveConnectionModes } from './lib/connectionModes';
import { resolveBoundModeIds } from './lib/remnawavePlacement';
import { sanitizeHttpsUrl, sanitizeOnion } from './lib/verificationConfig';
import { sanitizeBannerText, sanitizeEmail } from './lib/siteConfig';
import { normalizeSupportId } from './lib/supportId';
import { CRON_META, cronStaleAfterMs } from './cronHeartbeat';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import {
  billingConfigWrites,
  billingSecretWrites,
  processorSecretStatus,
  resolveBillingConfig,
  resolveProcessorSecrets,
} from './lib/billingConfig';

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
  // Optional at create (most tiers leave it unset); the SPA's TierUpsert always
  // sends it (null default), but other internal callers / tests may omit it.
  peerTierId: v.optional(v.union(v.id('tiers'), v.null())),
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
    peerTierId: (t.peerTierId as string | undefined) ?? null,
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

function mapBackendServer(s: Doc<'backendServers'>) {
  const config =
    s.config.type === 'remnawave'
      ? {
          type: 'remnawave' as const,
          baseUrl: s.config.baseUrl,
          apiTokenSet: s.config.apiToken.length > 0,
        }
      : {
          type: 'outline' as const,
          apiUrlMasked: maskApiUrl(s.config.apiUrl),
          websocketEnabled: s.config.websocketEnabled,
          websocketDomain: s.config.websocketDomain ?? null,
          prometheusUrl: s.config.prometheusUrl ?? null,
        };
  return {
    id: s._id as string,
    backend: s.backend,
    name: s.name,
    slug: s.slug,
    location: s.location ?? null,
    locationLabel: s.locationLabel ?? null,
    isActive: s.isActive,
    priority: s.priority,
    keyCount: s.keyCount,
    maxKeys: s.maxKeys ?? null,
    lastHealthOkAt: s.lastHealthOkAt != null ? iso(s.lastHealthOkAt) : null,
    lastHealthRttMs: s.lastHealthRttMs ?? null,
    config,
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

/**
 * Invariant: at most ONE default-free tier per backend (tiers.getDefaultFree is
 * otherwise priority/creation-order dependent and free sign-ups could land on
 * the wrong tier after an admin misconfig). AUTO-CLEAR rather than reject:
 * with reject semantics, moving the default from tier A to B needs A cleared
 * first — a window where getDefaultFree returns null and every sign-up fails.
 * One serializable mutation keeps the move atomic. Cleared regardless of
 * isActive so a later re-activation can't resurrect ambiguity; each clear is
 * audited.
 */
async function clearOtherDefaultFree(
  ctx: MutationCtx,
  backend: 'remnawave' | 'outline',
  keepId: Id<'tiers'>,
): Promise<void> {
  const tiers = await ctx.db.query('tiers').collect(); // admin write path; tiny table
  for (const t of tiers) {
    if (t._id !== keepId && t.backend === backend && t.isDefaultFree) {
      await ctx.db.patch(t._id, { isDefaultFree: false, updatedAt: Date.now() });
      await writeAuditLog(ctx, {
        actorType: 'admin',
        action: 'admin.tier.default_free_cleared',
        targetType: 'tier',
        targetId: t._id,
      });
    }
  }
}

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
      peerTierId: a.peerTierId ?? undefined,
      isDefaultFree: a.isDefaultFree,
      isActive: a.isActive,
      priority: a.priority,
      expirationDaysAfterMembershipLapse: a.expirationDaysAfterMembershipLapse,
      updatedAt: Date.now(),
    });
    if (a.isDefaultFree) await clearOtherDefaultFree(ctx, a.backend, id);
    const created = await ctx.db.get(id);
    return mapTier(created!);
  },
});

/** Nullable-optional tier fields whose explicit `null` maps to Convex "absent". */
const TIER_NULLABLE_KEYS = new Set(['description', 'peerTierId']);

/**
 * Build a tier patch `fields` object from provided args: skip undefined, map an
 * explicit null on a nullable field to undefined (Convex "absent"), pass the rest
 * through. Shared by updateTier + upsertTierBySlug's update path. (Review P3.)
 * Callers pass only tier fields (upsert strips slug/actorAdminId first).
 */
function buildTierPatchFields(patch: Record<string, unknown>): Partial<Doc<'tiers'>> {
  const fields: Partial<Doc<'tiers'>> = { updatedAt: Date.now() };
  for (const [k, val] of Object.entries(patch)) {
    if (val === undefined) continue;
    (fields as Record<string, unknown>)[k] =
      TIER_NULLABLE_KEYS.has(k) && val === null ? undefined : val;
  }
  return fields;
}

export const updateTier = internalMutation({
  // All fields optional: the SPA sends a partial patch (TierUpsert minus
  // anything unchanged). `description` accepts null.
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
    peerTierId: v.optional(v.union(v.id('tiers'), v.null())),
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
    const fields = buildTierPatchFields(patch);
    await ctx.db.patch(id, fields);
    // Compute the post-patch effective row: a patch may flip isDefaultFree on,
    // OR move an already-default tier to another backend — both must clear the
    // peer default on the resulting backend.
    const effectiveDefaultFree = patch.isDefaultFree ?? existing.isDefaultFree;
    const effectiveBackend = patch.backend ?? existing.backend;
    if (effectiveDefaultFree) await clearOtherDefaultFree(ctx, effectiveBackend, id);
    const updated = await ctx.db.get(id);
    return mapTier(updated!);
  },
});

export const deleteTier = internalMutation({
  args: { id: v.id('tiers') },
  handler: async (ctx, { id }) => {
    // P2: refuse to delete a tier that would orphan accounts or break sign-up.
    // Convex has no FK enforcement, so check by hand.
    const tier = await ctx.db.get(id);
    if (!tier) throw new ConvexError({ code: 'not_found', message: 'tier not found' });
    if (tier.isDefaultFree) {
      throw new ConvexError({
        code: 'tier.in_use',
        message: 'Cannot delete the default-free tier (new sign-ups need it).',
      });
    }
    const referencing = await ctx.db
      .query('users')
      .withIndex('by_tier', (q) => q.eq('tierId', id))
      .first();
    if (referencing) {
      throw new ConvexError({
        code: 'tier.in_use',
        message: 'Cannot delete a tier that still has users. Move them off it first.',
      });
    }
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});

/**
 * Idempotent tier upsert addressed by slug — the IaC converge primitive for
 * tiers + the mechanism behind declarative squad↔tier binding (the squad UUID
 * is just a tier field). Mirrors `upsertBackendServerBySlug`: all fields are
 * optional and the slug is authoritative (from the path).
 *  - MISSING tier → CREATE, defaulting the mechanical entitlement fields so a
 *    minimal `{slug}` yields a sane template. `isDefaultFree` defaults FALSE so
 *    a converge can NEVER silently steal the sign-up default tier.
 *  - EXISTING tier → PATCH only the provided fields (reuses updateTier's
 *    nullable-normalize + the one-default-free-per-backend invariant), so a
 *    converge can adjust an already-seeded tier without disturbing its other
 *    entitlements.
 * Audited as `admin.tier.upsert`. (Node placement is bound separately, per
 * connection mode, via /api/v1/admin/remnawave/mode-placements — never here.)
 */
export const upsertTierBySlug = internalMutation({
  args: {
    slug: v.string(),
    name: v.optional(v.string()),
    description: v.optional(v.union(v.string(), v.null())),
    backend: v.optional(backendId),
    monthlyTrafficGb: v.optional(v.number()),
    deviceLimit: v.optional(v.number()),
    hwidLimit: v.optional(v.number()),
    hwidEnabled: v.optional(v.boolean()),
    trafficStrategy: v.optional(trafficStrategy),
    isDefaultFree: v.optional(v.boolean()),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    expirationDaysAfterMembershipLapse: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const existing = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();

    if (!existing) {
      // CREATE — default the mechanical fields; never default isDefaultFree on.
      const backend = a.backend ?? 'remnawave';
      const id = await ctx.db.insert('tiers', {
        slug: a.slug,
        name: a.name ?? a.slug,
        description: a.description ?? undefined,
        backend,
        monthlyTrafficGb: a.monthlyTrafficGb ?? 0,
        deviceLimit: a.deviceLimit ?? 0,
        hwidLimit: a.hwidLimit ?? 0,
        hwidEnabled: a.hwidEnabled ?? false,
        trafficStrategy: a.trafficStrategy ?? 'MONTH',
        isDefaultFree: a.isDefaultFree ?? false,
        isActive: a.isActive ?? true,
        priority: a.priority ?? 0,
        expirationDaysAfterMembershipLapse: a.expirationDaysAfterMembershipLapse ?? 0,
        updatedAt: Date.now(),
      });
      if (a.isDefaultFree) await clearOtherDefaultFree(ctx, backend, id);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: a.actorAdminId ?? undefined,
        action: 'admin.tier.upsert',
        targetType: 'tier',
        targetId: id,
        payload: { slug: a.slug, backend, created: true },
      });
      return { ...mapTier((await ctx.db.get(id))!), created: true };
    }

    // UPDATE — patch only the provided fields (shares buildTierPatchFields with
    // updateTier). The slug is the address + actorAdminId isn't a tier field, so
    // strip both before normalizing.
    const { slug: _slug, actorAdminId: _actor, ...tierPatch } = a;
    const fields = buildTierPatchFields(tierPatch);
    await ctx.db.patch(existing._id, fields);
    const effectiveDefaultFree = a.isDefaultFree ?? existing.isDefaultFree;
    const effectiveBackend = a.backend ?? existing.backend;
    if (effectiveDefaultFree) await clearOtherDefaultFree(ctx, effectiveBackend, existing._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.tier.upsert',
      targetType: 'tier',
      targetId: existing._id,
      payload: { slug: a.slug, backend: effectiveBackend, created: false },
    });
    return { ...mapTier((await ctx.db.get(existing._id))!), created: false };
  },
});

// === users ==================================================================

const userStatus = v.union(
  v.literal('active'),
  v.literal('grace'),
  v.literal('disabled'),
  v.literal('deleted'),
  v.literal('inactive'),
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
    sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', user._id).eq('state', 'active'))
      .order('desc')
      .first();
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
    supportId: u.supportId ?? null,
    status: u.status,
    tierSlug: tierSlugById.get(u.tierId) ?? 'free',
    membershipExpiresAt: u.membershipExpiresAt != null ? iso(u.membershipExpiresAt) : null,
    backendUserId: cur.backendUserId,
    backend: cur.backend,
    backendPushFailedAt: u.backendPushFailedAt != null ? iso(u.backendPushFailedAt) : null,
    createdAt: iso(u._creationTime),
  };
}

/**
 * Admin user search. Filters:
 *  - `q`: a member's W3 support ID (`FS-XXXX-XXXX`, the preferred handle), OR a
 *    4-digit account-number prefix, looked up via the respective index (a full
 *    account number is never an admin oracle). Any other query matches nothing
 *    (members are anonymous).
 *  - `status` / `tier`: post-filters.
 * Pagination is a keyset over `_creationTime` desc via an opaque cursor.
 */
export const usersSearch = internalQuery({
  args: {
    q: v.optional(v.string()),
    status: v.optional(userStatus),
    tier: v.optional(v.string()),
    drift: v.optional(v.boolean()),
    cursor: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { q, status, tier, drift, cursor, limit }) => {
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);

    // Tier slug → id map (for the `tier` filter) and id → slug map (for rows).
    const tiers = await ctx.db.query('tiers').collect();
    const tierSlugById = new Map<string, string>(tiers.map((t) => [t._id as string, t.slug]));
    const tierIdBySlug = new Map<string, Id<'tiers'>>(tiers.map((t) => [t.slug, t._id]));

    const trimmed = q?.trim();

    // Targeted lookups when `q` clearly identifies a single user; these short
    // out before the paginated scan and ignore the cursor (small result set).
    if (trimmed) {
      // Searchable handles: the W3 support ID (FS-…, exact) or the 4-digit
      // account-number prefix. Anything else matches nothing (members are
      // anonymous).
      let matches: Doc<'users'>[] = [];
      if (/^fs[\s-]?/i.test(trimmed)) {
        const supportId = normalizeSupportId(trimmed);
        const bySupport = await ctx.db
          .query('users')
          .withIndex('by_support_id', (idx) => idx.eq('supportId', supportId))
          .unique();
        matches = bySupport ? [bySupport] : [];
      } else if (/^\d{4}$/.test(trimmed)) {
        matches = await ctx.db
          .query('users')
          .withIndex('by_account_id_prefix', (idx) => idx.eq('accountIdPrefix', trimmed))
          .take(pageSize);
      }
      const filtered = matches
        .filter((u) => (status ? u.status === status : true))
        .filter((u) => (tier ? u.tierId === tierIdBySlug.get(tier) : true))
        .filter((u) => (drift ? u.backendPushFailedAt != null : true))
        .slice(0, pageSize);
      const users = await Promise.all(filtered.map((u) => mapUser(ctx, u, tierSlugById)));
      return { users, nextCursor: null };
    }

    // Unfiltered/paginated browse: keyset over _creationTime desc. The
    // status/tier/drift post-filters have no supporting index, so we scan windows
    // and filter in JS — but keep ADVANCING the keyset until the page fills or the
    // table is exhausted. The old single over-fetch (pageSize*4+1) returned a short
    // page with nextCursor:null once a sparse filter (e.g. `drift` over many users)
    // had few matches in that one window, hiding thousands of unscanned rows. (Review #4.)
    const matchFilter = (u: Doc<'users'>) =>
      (status ? u.status === status : true) &&
      (tier ? u.tierId === tierIdBySlug.get(tier) : true) &&
      (drift ? u.backendPushFailedAt != null : true);

    const WINDOW = pageSize * 4;
    const MAX_ITERS = 50; // backstop: bounded windows/request (each a by_creation_time seek)
    const page: Doc<'users'>[] = [];
    let before = cursor && Number.isFinite(Number(cursor)) ? Number(cursor) : null;
    let exhausted = false;
    let iters = 0;
    while (page.length < pageSize && !exhausted && iters < MAX_ITERS) {
      iters++;
      // Seek via the by_creation_time index range, NOT a .filter() over the full
      // desc scan — a filter re-reads from the newest row every window (discarded
      // rows still count against the read limit), making the loop quadratic. The
      // index bound makes each window O(WINDOW). (Re-review follow-up.)
      const b = before;
      const window = await ctx.db
        .query('users')
        .withIndex('by_creation_time', (q) => (b != null ? q.lt('_creationTime', b) : q))
        .order('desc')
        .take(WINDOW);
      exhausted = window.length < WINDOW;
      for (const u of window) {
        if (matchFilter(u)) {
          page.push(u);
          if (page.length >= pageSize) break;
        }
      }
      // Resume from the last RETURNED row when the page filled (so no match is
      // skipped), else from the last RAW row scanned.
      if (page.length >= pageSize) {
        before = page[page.length - 1]!._creationTime;
      } else if (window.length > 0) {
        before = window[window.length - 1]!._creationTime;
      }
    }
    if (iters >= MAX_ITERS && page.length < pageSize && !exhausted) {
      console.warn('[usersSearch] filtered browse hit the per-request scan cap; more rows remain');
    }
    // Emit a cursor whenever we returned a full page (keyset continues from the
    // last returned row); the client pages until it gets a short/empty page. Never
    // a short page with a null cursor while matches remain. Over-emitting at most
    // costs one trailing empty request.
    const last = page[page.length - 1];
    const nextCursor = page.length === pageSize && last ? String(last._creationTime) : null;
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
    await applyCountsDelta(ctx, { statusFrom: user.status, statusTo: 'disabled' });
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

/**
 * Inverse of disableUser: lift a disabled account back to active and clear the
 * suspension fields. Idempotent — only acts on a `disabled` user. NOTE: this
 * clears the suspension only; a user disabled because a PAID membership lapsed
 * will be re-swept (active→grace→disabled) unless their membership is also
 * extended (admin grant / redemption / billing — W2). Free users have no
 * expiry, so they simply stay active.
 */
export const reEnableUser = internalMutation({
  args: { userId: v.id('users'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { userId, actorAdminId }) => {
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('user not found');
    if (user.status !== 'disabled') return { ok: true as const };
    await ctx.db.patch(userId, {
      status: 'active',
      disabledReason: undefined,
      suspendedAt: undefined,
      updatedAt: Date.now(),
    });
    await applyCountsDelta(ctx, { statusFrom: 'disabled', statusTo: 'active' });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.user.reenable',
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
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .order('desc')
      .first();
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
 * Live backend state for ONE user (the admin per-user detail expander): status,
 * used/limit, reset cadence, devices. Its own action because the users LIST is a
 * pure DB query that can't call the backend. Returns null when there's no
 * subscription or the backend is unreachable — a convenience read, never blocking.
 */
export const userBackendState = internalAction({
  args: { userId: v.id('users') },
  handler: async (
    ctx,
    { userId },
  ): Promise<{
    status: 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';
    trafficLimitBytes: number | null;
    usedTrafficBytes: number;
    trafficLimitStrategy: 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH' | null;
    lastTrafficResetAt: string | null;
    devices: {
      hwid: string;
      platform: string | null;
      deviceModel: string | null;
      firstSeenAt: string | null;
      lastSeenAt: string | null;
    }[];
  } | null> => {
    const sub = await ctx.runQuery(internal.adminApi.activeSubForUser, { userId });
    if (!sub) return null;
    try {
      const state = await ctx.runAction(internal.backends.getUser, {
        backend: sub.backend,
        backendUserId: sub.backendUserId,
      });
      return {
        status: state.status,
        trafficLimitBytes: state.trafficLimitBytes,
        usedTrafficBytes: state.usedTrafficBytes,
        trafficLimitStrategy: state.trafficLimitStrategy ?? null,
        lastTrafficResetAt: state.lastTrafficResetAt ?? null,
        devices: state.devices.map((d) => ({
          hwid: d.hwid,
          platform: d.platform ?? null,
          deviceModel: d.deviceModel ?? null,
          firstSeenAt: d.firstSeenAt ?? null,
          lastSeenAt: d.lastSeenAt ?? null,
        })),
      };
    } catch {
      return null;
    }
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
    op: v.union(
      v.literal('disable'),
      v.literal('re-enable'),
      v.literal('reset-traffic'),
      v.literal('resync'),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { userId, op, actorAdminId }): Promise<{ ok: true }> => {
    if (op === 'disable') {
      await ctx.runMutation(internal.adminApi.disableUser, { userId, actorAdminId });
      const sub = await ctx.runQuery(internal.adminApi.activeSubForUser, { userId });
      if (sub) {
        try {
          await ctx.runAction(internal.backends.setUserStatus, {
            backend: sub.backend,
            backendUserId: sub.backendUserId,
            active: false,
          });
          await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
        } catch {
          // Local state is authoritative, but the key may still route on the
          // backend — flag the drift so the admin sees the push didn't land.
          await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: true });
        }
      }
      return { ok: true };
    }

    if (op === 're-enable') {
      await ctx.runMutation(internal.adminApi.reEnableUser, { userId, actorAdminId });
      const sub = await ctx.runQuery(internal.adminApi.activeSubForUser, { userId });
      if (sub) {
        try {
          await ctx.runAction(internal.backends.setUserStatus, {
            backend: sub.backend,
            backendUserId: sub.backendUserId,
            active: true,
          });
          await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
        } catch {
          // Local state is authoritative, but the key may still be disabled on
          // the backend — flag the drift so the admin sees the push didn't land.
          await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: true });
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

/**
 * Admin grant/extend of a membership from the Users page. Reuses the shared
 * `applyMembership` seam (same path as billing + code redemption): extends from
 * max(now, current expiry) by `durationDays`, re-activating a lapsed
 * (grace/disabled) user, and scheduling the backend tier push. ALWAYS writes an
 * admin-attributed audit entry — `applyMembership`'s own audit fires only on a
 * tier CHANGE, not a same-tier extension, so the admin action would otherwise be
 * invisible.
 */
export const grantMembership = internalMutation({
  args: {
    userId: v.id('users'),
    tierId: v.id('tiers'),
    durationDays: v.number(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { userId, tierId, durationDays, actorAdminId }) => {
    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650) {
      throw new Error('durationDays must be an integer between 1 and 3650');
    }
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('user not found');
    const tier = await ctx.db.get(tierId);
    if (!tier) throw new Error('tier not found');

    const base = Math.max(Date.now(), user.membershipExpiresAt ?? 0);
    const expiresAtMs = base + durationDays * 86_400_000;

    await applyMembership(ctx, {
      userId,
      tierId,
      expiresAtMs,
      reason: 'admin_grant',
      triggeredBy: 'admin',
      // An explicit admin grant IS the un-ban path: it may lift an admin
      // disable (a payment/code redemption never does).
      liftAdminBan: true,
    });

    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.user.grant_membership',
      targetType: 'user',
      targetId: userId,
      payload: { tierId, durationDays },
    });

    return { ok: true as const, membershipExpiresAt: expiresAtMs };
  },
});

// === tokens =================================================================

// The admin scopes an automation token may be minted with. Kept in sync with the
// `admin` group in src/shared/contracts/scopes.ts (convex doesn't import the
// client-side zod enum). Member scopes (account:*, subscription:*) are
// intentionally NOT mintable here — an automation/service identity has no member.
const AUTOMATION_ALLOWED_SCOPES = [
  'admin:tiers:read',
  'admin:tiers:write',
  'admin:users:read',
  'admin:users:write',
  'admin:admins:read',
  'admin:admins:write',
  'admin:audit:read',
  'admin:tokens:read',
  'admin:tokens:write',
  'admin:settings:read',
  'admin:settings:write',
  'admin:servers:read',
  'admin:servers:write',
  'admin:status:read',
] as const;

/**
 * Mint an `fsv1_` automation token from the trusted control plane, e.g.
 *   bunx convex run adminApi:mintAutomationToken '{"scopes":["admin:servers:read","admin:servers:write"]}'
 *
 * This is the zero-touch bootstrap path for the Ansible role: the operator
 * already holds the self-hosted admin key (it runs seed:seedCutover), so minting
 * a SCOPED token with it is a de-escalation, not new attack surface. The token is
 * attributed to a synthetic, credential-less `automation` admin row — a valid
 * audit actor that can NEVER establish a cookie session (it has no passkey).
 *
 * We deliberately do NOT relax the HTTP cookie gate on `/api/v1/admin/tokens`:
 * letting any `admin:tokens:write` token mint fresh tokens over the public edge
 * would be token self-escalation + audit anonymization. Capability boundary ==
 * network boundary. Only `admin:*` scopes are mintable here.
 */
export const mintAutomationToken = internalAction({
  args: {
    scopes: v.array(v.string()),
    name: v.optional(v.string()),
    expiresInDays: v.optional(v.number()),
  },
  handler: async (
    ctx,
    { scopes, name, expiresInDays },
  ): Promise<{
    id: Id<'apiTokens'>;
    plaintext: string;
    prefix: string;
    adminUserId: Id<'adminUsers'>;
    scopes: string[];
  }> => {
    if (scopes.length === 0) throw new Error('at least one scope is required');
    const allowed = new Set<string>(AUTOMATION_ALLOWED_SCOPES);
    const bad = scopes.filter((s) => !allowed.has(s));
    if (bad.length > 0) {
      throw new Error(
        `invalid or non-admin scope(s): ${bad.join(', ')}. Automation tokens may only hold ` +
          `admin:* scopes (see src/shared/contracts/scopes.ts).`,
      );
    }
    const uniqueScopes = [...new Set(scopes)];

    // Idempotent synthetic admin (no passkey ⇒ can't log in, only an audit anchor).
    const adminUserId = await ctx.runMutation(internal.admins.upsertByUsername, {
      username: 'automation',
      displayName: 'Automation (service)',
    });

    const tokenName = name && name.trim().length > 0 ? name.trim() : 'automation';
    const result = await ctx.runAction(internal.apiTokens.createToken, {
      name: tokenName,
      scopes: uniqueScopes,
      subjectType: 'service',
      expiresInDays,
      createdByAdminId: adminUserId,
    });

    await ctx.runMutation(internal.audit.record, {
      actorType: 'admin',
      actorId: adminUserId,
      action: 'admin.automation_token.mint',
      targetType: 'apiToken',
      targetId: result.id,
      payload: { name: tokenName, scopeCount: uniqueScopes.length },
    });

    return { ...result, adminUserId, scopes: uniqueScopes };
  },
});

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
const AUDIT_ACTOR_TYPES = ['system', 'admin', 'member', 'anonymous', 'webhook'] as const;
type AuditActorType = (typeof AUDIT_ACTOR_TYPES)[number];

export const auditList = internalQuery({
  args: {
    cursor: v.optional(v.string()),
    limit: v.optional(v.number()),
    // Optional forensic filters. `action` and `actorType` each have an index;
    // the most selective is chosen below. `since` is an epoch-ms lower bound.
    action: v.optional(v.string()),
    actorType: v.optional(v.string()),
    since: v.optional(v.number()),
  },
  handler: async (ctx, { cursor, limit, action, actorType, since }) => {
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);

    // Pick the most selective index for the primary filter (action > actorType).
    // Every Convex index appends _creationTime, so newest-first ordering + the
    // `since` lower bound + paginate's keyset compose on whichever index we choose.
    const ordered = action
      ? ctx.db
          .query('auditLog')
          .withIndex('by_action', (ix) => ix.eq('action', action))
          .order('desc')
      : actorType && (AUDIT_ACTOR_TYPES as readonly string[]).includes(actorType)
        ? ctx.db
            .query('auditLog')
            .withIndex('by_actor', (ix) => ix.eq('actorType', actorType as AuditActorType))
            .order('desc')
        : ctx.db.query('auditLog').order('desc');

    // paginate()'s compound (_creationTime,_id) cursor replaces the hand-rolled
    // keyset — bulk-written audit rows share a creation-ms, exactly the collision
    // the old strict-lt cursor could skip at a page boundary. `since` stays a
    // lower-bound filter (unset ⇒ an always-true sentinel). (Review P2.)
    const res = await ordered
      .filter((f) =>
        since != null ? f.gte(f.field('_creationTime'), since) : f.gt(f.field('_creationTime'), 0),
      )
      .paginate({ cursor: cursor ?? null, numItems: pageSize });
    return {
      entries: res.page.map(mapAudit),
      nextCursor: res.isDone ? null : res.continueCursor,
    };
  },
});

// === settings ===============================================================
// Read/patch reuse appSettings.resolved + appSettings.set at the HTTP layer;
// no extra functions needed here.

// === backend servers (instances) ===========================================

export const backendServersList = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('backendServers').collect();
    return { servers: rows.sort((a, b) => a.priority - b.priority).map(mapBackendServer) };
  },
});

type BackendServerConfig = Doc<'backendServers'>['config'];

interface BackendServerConfigArgs {
  backend: 'remnawave' | 'outline';
  baseUrl?: string;
  apiToken?: string;
  apiUrl?: string;
  websocketEnabled?: boolean;
  websocketDomain?: string | null;
  prometheusUrl?: string | null;
}

/** maxKeys is a hard capacity cap consumed by pickCandidatesForIssue; only a
 *  positive integer makes sense (null clears the cap, absent keeps it). */
function checkMaxKeys(n: number | null | undefined): void {
  if (typeof n === 'number' && (!Number.isInteger(n) || n < 1)) {
    throw new Error('maxKeys must be a positive integer (or null to clear the cap)');
  }
}

/**
 * Normalize the instance's member-facing location fields: a short code
 * (e.g. "MCI") + a display label ("Kansas City, MO"). Null/blank clears; the
 * code is what issuance filters on, so it's kept short and space-free.
 */
function checkLocation(a: { location?: string | null; locationLabel?: string | null }): {
  location?: string;
  locationLabel?: string;
} {
  const out: { location?: string; locationLabel?: string } = {};
  if (a.location != null) {
    const code = a.location.trim();
    if (code && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$/.test(code)) {
      throw new Error('location must be a short code (letters/digits/dashes, max 16 chars)');
    }
    if (code) out.location = code;
  }
  if (a.locationLabel != null) {
    const label = a.locationLabel.trim();
    if (label.length > 64) throw new Error('locationLabel must be at most 64 characters');
    if (label) out.locationLabel = label;
  }
  return out;
}

/**
 * Build a fresh backend-server config from create/upsert args (validates the
 * required fields per backend). Shared by createBackendServer +
 * upsertBackendServerBySlug's create path. (Review P3: was inlined twice.)
 */
function buildBackendServerConfig(a: BackendServerConfigArgs): BackendServerConfig {
  if (a.backend === 'remnawave') {
    if (!a.baseUrl || !a.apiToken)
      throw new Error('A Remnawave instance needs a base URL and an API token');
    return { type: 'remnawave', baseUrl: a.baseUrl, apiToken: a.apiToken };
  }
  if (!a.apiUrl) throw new Error('An Outline instance needs an apiUrl');
  return {
    type: 'outline',
    apiUrl: a.apiUrl,
    websocketEnabled: a.websocketEnabled ?? false,
    websocketDomain: a.websocketDomain ?? undefined,
    prometheusUrl: a.prometheusUrl ?? undefined,
  };
}

/**
 * Merge a config patch into an existing backend-server config, KEEPING the stored
 * secret when the incoming one is blank/absent (edits never wipe the credential).
 * The backend TYPE is immutable. Shared by updateBackendServer +
 * upsertBackendServerBySlug's update path. (Review P3: was inlined twice.)
 */
function mergeBackendServerConfig(
  existing: BackendServerConfig,
  patch: Omit<BackendServerConfigArgs, 'backend'>,
): BackendServerConfig {
  if (existing.type === 'remnawave') {
    const cfg = { ...existing };
    if (patch.baseUrl !== undefined && patch.baseUrl !== '') cfg.baseUrl = patch.baseUrl;
    if (patch.apiToken !== undefined && patch.apiToken !== '') cfg.apiToken = patch.apiToken;
    return cfg;
  }
  const cfg = { ...existing };
  if (patch.apiUrl !== undefined && patch.apiUrl !== '') cfg.apiUrl = patch.apiUrl;
  if (patch.websocketEnabled !== undefined) cfg.websocketEnabled = patch.websocketEnabled;
  if (patch.websocketDomain !== undefined) cfg.websocketDomain = patch.websocketDomain ?? undefined;
  if (patch.prometheusUrl !== undefined) cfg.prometheusUrl = patch.prometheusUrl ?? undefined;
  return cfg;
}

export const createBackendServer = internalMutation({
  args: {
    backend: backendId,
    name: v.string(),
    slug: v.string(),
    location: v.optional(v.union(v.string(), v.null())),
    locationLabel: v.optional(v.union(v.string(), v.null())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    maxKeys: v.optional(v.union(v.number(), v.null())),
    // Remnawave:
    baseUrl: v.optional(v.string()),
    apiToken: v.optional(v.string()),
    // Outline:
    apiUrl: v.optional(v.string()),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
    prometheusUrl: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const clash = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (clash) throw new Error(`A backend server with slug "${a.slug}" already exists`);
    checkMaxKeys(a.maxKeys);
    const loc = checkLocation(a);

    const config = buildBackendServerConfig(a);
    const id = await ctx.db.insert('backendServers', {
      backend: a.backend,
      name: a.name,
      slug: a.slug,
      location: loc.location,
      locationLabel: loc.locationLabel,
      config,
      isActive: a.isActive ?? true,
      priority: a.priority ?? 0,
      keyCount: 0,
      maxKeys: a.maxKeys ?? undefined,
      updatedAt: Date.now(),
    });
    return mapBackendServer((await ctx.db.get(id))!);
  },
});

export const updateBackendServer = internalMutation({
  args: {
    id: v.id('backendServers'),
    name: v.optional(v.string()),
    slug: v.optional(v.string()),
    location: v.optional(v.union(v.string(), v.null())),
    locationLabel: v.optional(v.union(v.string(), v.null())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    maxKeys: v.optional(v.union(v.number(), v.null())),
    // Secret-bearing fields are present only when the admin retyped them (rotate).
    baseUrl: v.optional(v.string()),
    apiToken: v.optional(v.string()),
    apiUrl: v.optional(v.string()),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
    prometheusUrl: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, { id, ...patch }) => {
    const existing = await ctx.db.get(id);
    if (!existing) throw new Error('Backend server not found');
    if (patch.slug !== undefined && patch.slug !== existing.slug) {
      const clash = await ctx.db
        .query('backendServers')
        .withIndex('by_slug', (q) => q.eq('slug', patch.slug!))
        .unique();
      if (clash) throw new Error(`A backend server with slug "${patch.slug}" already exists`);
    }
    checkMaxKeys(patch.maxKeys);
    const loc = checkLocation(patch);
    const fields: Partial<Doc<'backendServers'>> = { updatedAt: Date.now() };
    if (patch.name !== undefined) fields.name = patch.name;
    if (patch.slug !== undefined) fields.slug = patch.slug;
    if (patch.isActive !== undefined) fields.isActive = patch.isActive;
    if (patch.priority !== undefined) fields.priority = patch.priority;
    // null clears the cap (patch-to-undefined unsets the optional field).
    if (patch.maxKeys !== undefined) fields.maxKeys = patch.maxKeys ?? undefined;
    // null/blank clears the location fields the same way.
    if (patch.location !== undefined) fields.location = loc.location;
    if (patch.locationLabel !== undefined) fields.locationLabel = loc.locationLabel;

    // The backend TYPE is immutable; a blank/absent secret keeps the stored one.
    fields.config = mergeBackendServerConfig(existing.config, patch);
    await ctx.db.patch(id, fields);
    return mapBackendServer((await ctx.db.get(id))!);
  },
});

export const deleteBackendServer = internalMutation({
  args: { id: v.id('backendServers') },
  handler: async (ctx, { id }) => {
    await ctx.db.delete(id);
    return { ok: true as const };
  },
});

/**
 * Idempotent upsert of a backend-server instance keyed by `slug` (the operator's
 * stable identifier — for the Ansible role + IaC). Collapses the role's old
 * GET-list → client-side match → POST/PATCH dance into a single PUT, dissolving
 * the response-envelope bug class, the O(n) list, and the duplicate-slug failure
 * on re-run.
 *
 * Reuses the exact reshape from createBackendServer and the keep-secret-on-blank
 * merge from updateBackendServer (inlined — Convex forbids a mutation calling
 * another mutation). The backend TYPE is immutable: an existing slug of a
 * different type is rejected. Returns the masked row + `created` so the caller
 * can report create-vs-update without a second request.
 */
export const upsertBackendServerBySlug = internalMutation({
  args: {
    slug: v.string(),
    backend: backendId,
    name: v.optional(v.string()),
    location: v.optional(v.union(v.string(), v.null())),
    locationLabel: v.optional(v.union(v.string(), v.null())),
    isActive: v.optional(v.boolean()),
    priority: v.optional(v.number()),
    maxKeys: v.optional(v.union(v.number(), v.null())),
    baseUrl: v.optional(v.string()),
    apiToken: v.optional(v.string()),
    apiUrl: v.optional(v.string()),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
    prometheusUrl: v.optional(v.union(v.string(), v.null())),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const existing = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();

    checkMaxKeys(a.maxKeys);
    const loc = checkLocation(a);
    if (!existing) {
      // CREATE path — shares the reshape with createBackendServer.
      const config = buildBackendServerConfig(a);
      const id = await ctx.db.insert('backendServers', {
        backend: a.backend,
        name: a.name ?? a.slug,
        slug: a.slug,
        location: loc.location,
        locationLabel: loc.locationLabel,
        config,
        isActive: a.isActive ?? true,
        priority: a.priority ?? 0,
        keyCount: 0,
        maxKeys: a.maxKeys ?? undefined,
        updatedAt: Date.now(),
      });
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: a.actorAdminId ?? undefined,
        action: 'admin.backend_server.upsert',
        targetType: 'backendServer',
        targetId: id,
        payload: { slug: a.slug, backend: a.backend, created: true },
      });
      return { ...mapBackendServer((await ctx.db.get(id))!), created: true };
    }

    // UPDATE path (mirrors updateBackendServer's keep-secret-on-blank merge).
    if (existing.backend !== a.backend) {
      throw new Error(
        `Backend server "${a.slug}" exists as type "${existing.backend}"; cannot change it to "${a.backend}"`,
      );
    }
    const fields: Partial<Doc<'backendServers'>> = { updatedAt: Date.now() };
    if (a.name !== undefined) fields.name = a.name;
    if (a.isActive !== undefined) fields.isActive = a.isActive;
    if (a.priority !== undefined) fields.priority = a.priority;
    if (a.maxKeys !== undefined) fields.maxKeys = a.maxKeys ?? undefined;
    if (a.location !== undefined) fields.location = loc.location;
    if (a.locationLabel !== undefined) fields.locationLabel = loc.locationLabel;
    fields.config = mergeBackendServerConfig(existing.config, a);
    await ctx.db.patch(existing._id, fields);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.backend_server.upsert',
      targetType: 'backendServer',
      targetId: existing._id,
      payload: { slug: a.slug, backend: a.backend, created: false },
    });
    return { ...mapBackendServer((await ctx.db.get(existing._id))!), created: false };
  },
});

/**
 * Idempotent slug-addressed delete (for migrate / IaC): a no-op (`deleted:false`)
 * when the slug is absent, so a re-run never errors. Audited — unlike the by-id
 * deleteBackendServer above, since this is the operator-automation path.
 */
export const deleteBackendServerBySlug = internalMutation({
  args: { slug: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { slug, actorAdminId }) => {
    const row = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!row) return { ok: true as const, deleted: false };
    await ctx.db.delete(row._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.backend_server.delete',
      targetType: 'backendServer',
      targetId: row._id,
      payload: { slug },
    });
    return { ok: true as const, deleted: true };
  },
});

/**
 * Best-effort connectivity check for the connection details the admin pasted
 * (before they save). Routes to the backend type's provider; the secret is a
 * credential (never echoed back, never put in the error: the providers scrub it).
 *
 * With `id` set (editing an EXISTING instance), blank fields fall back to the
 * STORED config so an admin can verify a live instance without retyping its
 * secret — the secret never round-trips to the client either way. Typed fields
 * still override the stored ones.
 */
export const testBackendConnection = internalAction({
  args: {
    backend: backendId,
    id: v.optional(v.id('backendServers')),
    baseUrl: v.optional(v.string()),
    apiToken: v.optional(v.string()),
    apiUrl: v.optional(v.string()),
    websocketEnabled: v.optional(v.boolean()),
    websocketDomain: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (
    ctx,
    a,
  ): Promise<{ ok: true; keyCount: number } | { ok: false; error: string }> => {
    let stored: BackendConfig | null = null;
    if (a.id) {
      const row = await ctx.runQuery(internal.backendServers.getById, { id: a.id });
      if (!row) return { ok: false, error: 'Instance not found' };
      if (row.backend !== a.backend) {
        return { ok: false, error: 'Backend type does not match the stored instance' };
      }
      stored = row.config as BackendConfig;
    }
    let config: BackendConfig;
    if (a.backend === 'remnawave') {
      const rw = stored?.type === 'remnawave' ? stored : null;
      const baseUrl = a.baseUrl?.trim() || rw?.baseUrl;
      const apiToken = a.apiToken?.trim() || rw?.apiToken;
      if (!baseUrl || !apiToken)
        return { ok: false, error: 'A base URL and an API token are required' };
      config = { type: 'remnawave', baseUrl, apiToken };
    } else {
      const ol = stored?.type === 'outline' ? stored : null;
      const apiUrl = a.apiUrl?.trim() || ol?.apiUrl;
      if (!apiUrl) return { ok: false, error: 'An apiUrl is required' };
      config = {
        type: 'outline',
        apiUrl,
        websocketEnabled: a.websocketEnabled ?? ol?.websocketEnabled ?? false,
        websocketDomain: a.websocketDomain ?? ol?.websocketDomain ?? undefined,
      };
    }
    return PROVIDERS[a.backend].testConnection(config);
  },
});

// === billing (self-service membership) ======================================
// Config edits reuse the appSettings `billing.*` namespace (validated by
// billingConfigWrites); the orders list redacts the opaque ref to a prefix
// (the full ref is the member's poll token) and carries no payer PII.

function mapBillingOrder(o: Doc<'billingOrders'>) {
  return {
    id: o._id as string,
    processor: o.processor,
    refPrefix: o.opaqueRef.slice(0, 8),
    userId: o.userId as string,
    status: o.status,
    amountCents: o.amountCents,
    donationCents: o.donationCents ?? 0,
    currency: o.currency,
    durationDays: o.durationDays,
    processorRef: o.processorRef ?? null,
    createdAt: iso(o._creationTime),
    paidAt: o.paidAt != null ? iso(o.paidAt) : null,
  };
}

const BILLING_ORDER_STATUSES = new Set(['pending', 'confirming', 'paid', 'failed', 'expired']);

/** Admin billing overview: the resolved config + a keyset page of recent orders. */
export const billingOverview = internalQuery({
  args: {
    cursor: v.optional(v.string()),
    limit: v.optional(v.number()),
    status: v.optional(v.string()),
  },
  handler: async (ctx, { cursor, limit, status }) => {
    const config = await resolveBillingConfig(ctx.db);
    // Credential status as booleans + the non-secret URLs — never the values.
    const secretStatus = processorSecretStatus(await resolveProcessorSecrets(ctx.db));
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);
    const useStatus = status && BILLING_ORDER_STATUSES.has(status);
    const qry = useStatus
      ? ctx.db
          .query('billingOrders')
          .withIndex('by_status', (q) =>
            q.eq('status', status as 'pending' | 'confirming' | 'paid' | 'failed' | 'expired'),
          )
          .order('desc')
      : ctx.db.query('billingOrders').order('desc');
    // paginate()'s compound (_creationTime,_id) cursor avoids the ms-collision skip
    // the hand-rolled _creationTime keyset had at a page boundary. (Review P2.)
    const res = await qry.paginate({ cursor: cursor ?? null, numItems: pageSize });
    // Enrich each row with the buyer's non-secret support id ("who donated"),
    // resolved per page (≤200 rows) — never the account number.
    const orders = await Promise.all(
      res.page.map(async (o) => {
        const u = await ctx.db.get(o.userId);
        return { ...mapBillingOrder(o), userHandle: u?.supportId ?? null };
      }),
    );
    // Failed webhook claims = a paid-but-ungranted order once the sender's
    // retries run out. Bounded (retention sweeps the table at 90d); newest 10
    // listed, plus the total so ">10" is visible.
    const failedRows = await ctx.db
      .query('webhookEvents')
      .withIndex('by_status', (q) => q.eq('status', 'failed'))
      .order('desc')
      .collect();
    const failedWebhooks = {
      count: failedRows.length,
      recent: failedRows.slice(0, 10).map((w) => ({
        eventId: w.eventId,
        source: w.source,
        at: iso(w._creationTime),
      })),
    };
    return {
      config,
      secretStatus,
      orders,
      failedWebhooks,
      nextCursor: res.isDone ? null : res.continueCursor,
    };
  },
});

/**
 * Admin: patch the billing config + processor credentials (partial). Config
 * fields are validated/sanitized; secret fields are write-only (a blank box is
 * left unchanged). Audited per key (the key NAME, never the secret value).
 */
export const setBillingConfig = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    let writes: Array<{ key: string; value: string }>;
    try {
      writes = [...billingConfigWrites(patch), ...billingSecretWrites(patch)];
    } catch (e) {
      throw new ConvexError({
        code: 'validation',
        message: e instanceof Error ? e.message : 'invalid billing config',
      });
    }
    if (writes.length === 0) {
      throw new ConvexError({ code: 'validation', message: 'no recognized billing fields' });
    }
    for (const { key, value } of writes) {
      await upsertSetting(ctx, key, value, actorAdminId);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId,
        action: 'billing.config.update',
        targetType: 'billing_config',
        targetId: key,
        payload: { key },
      });
    }
    const config = await resolveBillingConfig(ctx.db);
    const secretStatus = processorSecretStatus(await resolveProcessorSecrets(ctx.db));
    return { config, secretStatus };
  },
});

// === status / dashboard =====================================================

/**
 * Shared operator status snapshot — feeds BOTH the admin landing dashboard and
 * an Ansible post-deploy health-gate (scope `admin:status:read`). Read-only and
 * non-secret: counts + health booleans only, never a backend `config`.
 */
export const statusSummary = internalQuery({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    const FRESH_MS = 30 * 60_000; // mirrors the backendServers pool freshness window

    // Users tallied by status via the maintained counter (statusCounters.ts) —
    // bumped on every status transition + reconciled daily — so this is O(1)
    // instead of the former O(users) collect() that 500-ed the /status health-gate
    // once the user base passed Convex's per-query read limit (M2 / WS3).
    const counts = await readUserCounts(ctx.db);
    const usersByStatus = {
      active: counts.active,
      grace: counts.grace,
      disabled: counts.disabled,
      deleted: counts.deleted,
      inactive: counts.inactive,
    };
    const backendDrift = counts.backendDrift;

    // Backends are small + admin-managed. Health + key counts only; never config.
    const serverRows = await ctx.db.query('backendServers').collect();
    const backends = serverRows
      .sort((a, b) => a.priority - b.priority)
      .map((s) => ({
        slug: s.slug,
        backend: s.backend,
        isActive: s.isActive,
        keyCount: s.keyCount,
        healthy: s.lastHealthOkAt != null && now - s.lastHealthOkAt < FRESH_MS,
        lastHealthOkAt: s.lastHealthOkAt != null ? iso(s.lastHealthOkAt) : null,
        lastHealthRttMs: s.lastHealthRttMs ?? null,
        // Read-only fleet observability, cached by the healthcheck cron (null until
        // the first successful fetch / for backends without a fleet, e.g. Outline).
        fleetStats: s.fleetStats ?? null,
      }));
    const activeBackends = backends.filter((b) => b.isActive);

    // Cron freshness: the newest successful healthcheck across ACTIVE backends vs
    // the 10-min cron cadence. Stale ⇒ the backend-healthcheck cron (or the
    // backends themselves) may be wedged. lastHealthOkAt is the only cron-stamped
    // signal we have, so it doubles as a liveness proxy for that cron.
    const lastOkMs = serverRows
      .filter((s) => s.isActive && s.lastHealthOkAt != null)
      .reduce<
        number | null
      >((max, s) => (max == null || s.lastHealthOkAt! > max ? s.lastHealthOkAt! : max), null);

    // Per-cron liveness (W4-B4): join the heartbeat rows against the known cron
    // cadences (CRON_META). `pending` = never observed since heartbeats shipped;
    // `stale` = overdue past ~1.5 cadences. Stamped at each job's run START, so
    // this is a pure "is the scheduler firing it?" signal — independent of the
    // job's own success (which surfaces via drift / healthcheck freshness).
    const hbByName = new Map(
      (await ctx.db.query('cronHeartbeats').collect()).map((h) => [h.name, h]),
    );
    const crons = CRON_META.map((c) => {
      const hb = hbByName.get(c.name);
      const lastRunAt = hb?.lastRunAt ?? null;
      const ageMs = lastRunAt != null ? now - lastRunAt : null;
      const state: 'ok' | 'stale' | 'pending' =
        lastRunAt == null ? 'pending' : ageMs! > cronStaleAfterMs(c.everyMs) ? 'stale' : 'ok';
      return {
        name: c.name,
        description: c.description,
        everyMs: c.everyMs,
        state,
        lastRunAt: lastRunAt != null ? iso(lastRunAt) : null,
        ageSeconds: ageMs != null ? Math.max(0, Math.round(ageMs / 1000)) : null,
        runCount: hb?.runCount ?? 0,
      };
    });
    const cronsStale = crons.filter((c) => c.state === 'stale').length;

    // PoP enrollment readiness (the POP_REQUIRED enforcement flip). Enforcement
    // rejects ONLY cookie-only (unbound) sessions — a bound session is always
    // verified regardless of the flag. So enabling POP_REQUIRED is safe exactly
    // once no active session is unbound (nothing gets logged out). This makes the
    // flip an observed decision instead of a timed guess, and it also surfaces
    // clients that log in but cannot enroll a key (they show as persistent
    // unbound sessions and would be locked out by the flip).
    // NOTE: O(active sessions) — bounded by live logins; fine at beta scale.
    const liveSessions = await ctx.db
      .query('sessions')
      .withIndex('by_expires', (q) => q.gt('expiresAt', now))
      .collect();
    let popBound = 0;
    let unboundMember = 0;
    let unboundAdmin = 0;
    for (const row of liveSessions) {
      if (row.popPublicKey != null) popBound += 1;
      else if (row.kind === 'admin') unboundAdmin += 1;
      else unboundMember += 1;
    }
    const pop = {
      required: process.env.POP_REQUIRED === 'true',
      activeSessions: liveSessions.length,
      bound: popBound,
      unbound: unboundMember + unboundAdmin,
      unboundMember,
      unboundAdmin,
      // Nothing relies on cookie-only auth → enabling POP_REQUIRED logs no one out.
      readyToEnable: unboundMember + unboundAdmin === 0,
    };

    return {
      users: usersByStatus,
      backendDrift,
      totals: {
        backends: backends.length,
        activeBackends: activeBackends.length,
        healthyBackends: activeBackends.filter((b) => b.healthy).length,
        keys: serverRows.reduce((n, s) => n + (s.keyCount ?? 0), 0),
      },
      backends,
      healthcheck: {
        ok: lastOkMs != null && now - lastOkMs < FRESH_MS,
        lastOkAt: lastOkMs != null ? iso(lastOkMs) : null,
        staleSeconds: lastOkMs != null ? Math.max(0, Math.round((now - lastOkMs) / 1000)) : null,
      },
      crons,
      cronsStale,
      pop,
      generatedAt: iso(now),
    };
  },
});

// === theme ==================================================================

/** Admin sets the brand theme (preset + optional hue override). Writes the
 *  appSettings `theme.*` namespace + audits; resolveTheme/publicConfig read it
 *  back. Invalid preset → reject; out-of-range hue → null (no override). */
export const setTheme = internalMutation({
  args: {
    preset: v.string(),
    hue: v.union(v.number(), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { preset, hue, actorAdminId }) => {
    if (!(THEME_PRESET_IDS as readonly string[]).includes(preset)) {
      throw new Error(`unknown theme preset "${preset}"`);
    }
    const cleanHue = sanitizeHue(hue);
    await upsertSetting(ctx, 'theme.preset', JSON.stringify(preset), actorAdminId);
    await upsertSetting(ctx, 'theme.hue', JSON.stringify(cleanHue), actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.theme.change',
      targetType: 'theme',
      payload: { preset, hue: cleanHue },
    });
    return { preset, hue: cleanHue };
  },
});

/**
 * Set the E2EE verification config (V-config): the off-CDN channels shown in the
 * "Verify connection" panel + the master show/hide toggle. Sanitizes each URL
 * (https-only for release/source; .onion for the mirror) so a bad value stores as
 * '' rather than a broken/unsafe link. Audited (URLs are non-secret).
 */
export const setVerification = internalMutation({
  args: {
    showPanel: v.boolean(),
    releaseUrl: v.string(),
    onionAddress: v.string(),
    sourceUrl: v.string(),
    extensionUrl: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (
    ctx,
    { showPanel, releaseUrl, onionAddress, sourceUrl, extensionUrl, actorAdminId },
  ) => {
    const clean = {
      showPanel,
      releaseUrl: sanitizeHttpsUrl(releaseUrl),
      onionAddress: sanitizeOnion(onionAddress),
      sourceUrl: sanitizeHttpsUrl(sourceUrl),
      extensionUrl: sanitizeHttpsUrl(extensionUrl),
    };
    await upsertSetting(
      ctx,
      'verification.showPanel',
      JSON.stringify(clean.showPanel),
      actorAdminId,
    );
    await upsertSetting(
      ctx,
      'verification.releaseUrl',
      JSON.stringify(clean.releaseUrl),
      actorAdminId,
    );
    await upsertSetting(
      ctx,
      'verification.onionAddress',
      JSON.stringify(clean.onionAddress),
      actorAdminId,
    );
    await upsertSetting(
      ctx,
      'verification.sourceUrl',
      JSON.stringify(clean.sourceUrl),
      actorAdminId,
    );
    await upsertSetting(
      ctx,
      'verification.extensionUrl',
      JSON.stringify(clean.extensionUrl),
      actorAdminId,
    );
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.verification.change',
      targetType: 'verification',
      payload: clean,
    });
    return clean;
  },
});

/**
 * Set the site-chrome config: the announcement banner (on/off + text), the
 * footer "View source" repo link (on/off + https URL), and the footer ToS /
 * Privacy / transparency-report / social-profile URLs. Sanitizes the text (trim +
 * cap) and each URL (https-only, else '') so a bad value stores harmlessly rather
 * than as a broken/unsafe link. Audited (everything here is non-secret).
 */
export const setSiteConfig = internalMutation({
  args: {
    bannerEnabled: v.boolean(),
    bannerText: v.string(),
    repoEnabled: v.boolean(),
    repoUrl: v.string(),
    tosUrl: v.string(),
    privacyUrl: v.string(),
    transparencyUrl: v.string(),
    socialXUrl: v.string(),
    socialMastodonUrl: v.string(),
    socialBlueskyUrl: v.string(),
    supportEmail: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (
    ctx,
    {
      bannerEnabled,
      bannerText,
      repoEnabled,
      repoUrl,
      tosUrl,
      privacyUrl,
      transparencyUrl,
      socialXUrl,
      socialMastodonUrl,
      socialBlueskyUrl,
      supportEmail,
      actorAdminId,
    },
  ) => {
    const clean = {
      bannerEnabled,
      bannerText: sanitizeBannerText(bannerText),
      repoEnabled,
      repoUrl: sanitizeHttpsUrl(repoUrl),
      tosUrl: sanitizeHttpsUrl(tosUrl),
      privacyUrl: sanitizeHttpsUrl(privacyUrl),
      transparencyUrl: sanitizeHttpsUrl(transparencyUrl),
      socialXUrl: sanitizeHttpsUrl(socialXUrl),
      socialMastodonUrl: sanitizeHttpsUrl(socialMastodonUrl),
      socialBlueskyUrl: sanitizeHttpsUrl(socialBlueskyUrl),
      supportEmail: sanitizeEmail(supportEmail),
    };
    await upsertSetting(
      ctx,
      'site.bannerEnabled',
      JSON.stringify(clean.bannerEnabled),
      actorAdminId,
    );
    await upsertSetting(ctx, 'site.bannerText', JSON.stringify(clean.bannerText), actorAdminId);
    await upsertSetting(ctx, 'site.repoEnabled', JSON.stringify(clean.repoEnabled), actorAdminId);
    await upsertSetting(ctx, 'site.repoUrl', JSON.stringify(clean.repoUrl), actorAdminId);
    await upsertSetting(ctx, 'site.tosUrl', JSON.stringify(clean.tosUrl), actorAdminId);
    await upsertSetting(ctx, 'site.privacyUrl', JSON.stringify(clean.privacyUrl), actorAdminId);
    await upsertSetting(
      ctx,
      'site.transparencyUrl',
      JSON.stringify(clean.transparencyUrl),
      actorAdminId,
    );
    await upsertSetting(ctx, 'site.socialXUrl', JSON.stringify(clean.socialXUrl), actorAdminId);
    await upsertSetting(
      ctx,
      'site.socialMastodonUrl',
      JSON.stringify(clean.socialMastodonUrl),
      actorAdminId,
    );
    await upsertSetting(
      ctx,
      'site.socialBlueskyUrl',
      JSON.stringify(clean.socialBlueskyUrl),
      actorAdminId,
    );
    await upsertSetting(ctx, 'site.supportEmail', JSON.stringify(clean.supportEmail), actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.site.change',
      targetType: 'site',
      payload: clean,
    });
    return clean;
  },
});

// === connection modes ========================================================

/**
 * Admin sets the GENERIC connection-mode catalog: per-mode label/description +
 * the default. Writes the appSettings `connectionMode.*` namespace. The
 * Remnawave placement pool (which squads a mode issues into) is backend-specific
 * and set separately via remnawaveNodes.setModePlacements. Returns the catalog
 * view (label null unless admin-set, so it doesn't round-trip the compiled
 * default into the form + pin English over i18n).
 */
export const setConnectionModes = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    let writes: Array<{ key: string; value: string }>;
    try {
      writes = connectionModeWrites(patch);
    } catch (e) {
      throw new ConvexError({
        code: 'validation',
        message: e instanceof Error ? e.message : 'invalid connection-mode config',
      });
    }
    if (writes.length === 0) {
      throw new ConvexError({
        code: 'validation',
        message: 'no recognized connection-mode fields',
      });
    }
    for (const { key, value } of writes) {
      await upsertSetting(ctx, key, value, actorAdminId);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'admin.connection_mode.update',
        targetType: 'connection_mode',
        targetId: key,
        payload: { key },
      });
    }
    const [modes, bound] = await Promise.all([
      resolveConnectionModes(ctx.db),
      resolveBoundModeIds(ctx.db),
    ]);
    return {
      modes: modes.map((m) => ({
        id: m.id,
        label: m.label,
        description: m.description,
        deliveryStyle: m.deliveryStyle,
        isDefault: m.isDefault,
        bound: bound.has(m.id),
      })),
    };
  },
});
