// Pass 2: every function here is internal — a subscription row carries the
// live proxy key (subscriptionUrl), so nothing in this module may be callable
// on the raw Convex channel. The old public `get` / `activeForUser` queries
// were dead code and were deleted outright.
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { randomHex } from './lib/crypto';

const mirror = v.object({
  provider: v.string(),
  publicUrl: v.string(),
  objectPath: v.optional(v.string()),
  status: v.optional(v.union(v.literal('ok'), v.literal('failed'))),
});

/** Unique-index lookup by the backend's primary user id. */
export const byBackendUserId = internalQuery({
  args: { backendUserId: v.string() },
  handler: (ctx, { backendUserId }) =>
    ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique(),
});

/**
 * Resolve a subscription by its opaque FCP-fronted token (the capability in
 * GET /api/v1/sub/<subToken>). Returns the full row (incl. the `subCache` blob)
 * or null. Internal — the row carries the live proxy key.
 *
 * A `deleted` row resolves as NOT FOUND (Review D-#12): its backend user is
 * gone, so the route would otherwise fetch → panel 404 → answer a misleading
 * "device limit reached" body that also confirms the token exists. Tombstoned
 * rows (24h grace) still resolve — the grace URL must keep working.
 */
export const bySubToken = internalQuery({
  args: { subToken: v.string() },
  handler: async (ctx, { subToken }) => {
    const row = await ctx.db
      .query('subscriptions')
      .withIndex('by_sub_token', (q) => q.eq('subToken', subToken))
      .unique();
    return row && row.state !== 'deleted' ? row : null;
  },
});

/**
 * Core current-or-active resolution (replaces lib/current-subscription): prefer the
 * user's `currentSubscriptionId` (so a freshly regenerated key shows immediately),
 * but only if it's still active — never a tombstoned row during the 24h grace
 * window — else the newest active row. Plain fn so both resolveCurrentOrActive and
 * mirrorContextForUser share ONE copy of the rule.
 */
async function currentOrActiveSub(
  db: DatabaseReader,
  user: Doc<'users'>,
): Promise<Doc<'subscriptions'> | null> {
  if (user.currentSubscriptionId) {
    const cur = await db.get(user.currentSubscriptionId);
    if (cur && cur.state === 'active') return cur;
  }
  // Newest active row via the (userId, state) index — within the equal prefix the
  // index orders by _creationTime, so desc->first is newest.
  return (
    (await db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', user._id).eq('state', 'active'))
      .order('desc')
      .first()) ?? null
  );
}

/** The resolver shared by /account + /subscription. */
export const resolveCurrentOrActive = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    return currentOrActiveSub(ctx.db, user);
  },
});

// --- write mutations (issuance saga, P5c) ---

/** Persist a freshly-issued subscription. Returns its id. */
export const insertSubscription = internalMutation({
  args: {
    userId: v.id('users'),
    backend: v.union(v.literal('remnawave'), v.literal('outline')),
    backendUserId: v.string(),
    backendShortId: v.string(),
    backendServerId: v.optional(v.id('backendServers')),
    subscriptionUrl: v.string(),
    subscriptionMirrors: v.array(mirror),
    rawContentHash: v.optional(v.string()),
    // The opaque backend placement handle this key was issued into (Remnawave:
    // the chosen squad) — read back by lifecycle.activeSubAndTier so tier pushes
    // never re-home a live key.
    placement: v.optional(v.string()),
    // The node the PREVIOUS key was pinned to (regenerate) — avoided on the
    // next fetch's pin pick so the new key lands on a different node.
    excludeNode: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    // Mint the opaque per-subscription token for the FCP-fronted URL. 128-bit;
    // uniqueness enforced by an index read-check inside this mutation (Convex has
    // no UNIQUE constraint), matching the slug/tokenHash/accountIdHash convention.
    let subToken = randomHex(16);
    while (
      await ctx.db
        .query('subscriptions')
        .withIndex('by_sub_token', (q) => q.eq('subToken', subToken))
        .first()
    ) {
      subToken = randomHex(16);
    }
    const { placement, ...rest } = a;
    return ctx.db.insert('subscriptions', {
      ...rest,
      // Map the generic arg onto the schema field name.
      backendPlacement: placement,
      subToken,
      state: 'active',
      updatedAt: Date.now(),
    });
  },
});

// Bounded per-UA content cache (Review #11): keep the N most-recently-written UA
// formats so multiple clients on one subscription (phone + desktop, distinct UAs)
// don't evict each other into a refetch-on-every-request thrash. Small cap — a
// short-TTL edge cache, not durable storage.
const SUB_CACHE_MAX = 4;
interface SubCacheEntry {
  content: string;
  contentType: string;
  headers?: Record<string, string>;
  ua: string;
  at: number;
}

/**
 * Merge one freshly-fetched UA entry into the subscription's bounded per-UA
 * content cache for the fronted route (a serialized list of
 * {content, contentType, headers?, ua, at} — see convex/http.ts). Serializable
 * read-merge-write so concurrent distinct-UA writes don't clobber each other;
 * replaces this UA's slot and keeps the most-recent SUB_CACHE_MAX (bounded — no
 * row growth). Migrates a legacy single-entry blob transparently.
 */
export const writeContentCache = internalMutation({
  args: { subscriptionId: v.id('subscriptions'), entry: v.string() },
  handler: async (ctx, { subscriptionId, entry }) => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub) return;
    let incoming: SubCacheEntry;
    try {
      incoming = JSON.parse(entry) as SubCacheEntry;
    } catch {
      return;
    }
    let existing: SubCacheEntry[] = [];
    if (sub.subCache) {
      try {
        const parsed = JSON.parse(sub.subCache) as unknown;
        existing = Array.isArray(parsed)
          ? (parsed as SubCacheEntry[])
          : parsed && typeof parsed === 'object'
            ? [parsed as SubCacheEntry] // migrate a legacy single-entry blob
            : [];
      } catch {
        existing = [];
      }
    }
    const merged = [incoming, ...existing.filter((e) => e.ua !== incoming.ua)]
      .sort((a, b) => b.at - a.at)
      .slice(0, SUB_CACHE_MAX);
    await ctx.db.patch(subscriptionId, { subCache: JSON.stringify(merged) });
  },
});

// Record the node a subscription's content is currently pinned to (Remnawave
// node pinning) so a future issuance (regenerate) can exclude it. Written by
// the serve paths when the pin changes — never rewrites the content cache.
export const recordPinnedNode = internalMutation({
  args: { subscriptionId: v.id('subscriptions'), node: v.string() },
  handler: async (ctx, { subscriptionId, node }) => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub || sub.pinnedNode === node) return;
    await ctx.db.patch(subscriptionId, { pinnedNode: node });
  },
});

/**
 * Page active subscriptions for the S3 mirror-refresh cron. Mirrors are OPT-IN +
 * LAZY now, so the refresh only keeps EXISTING mirrors fresh — it pages only subs
 * that already have ≥1 mirror and reports each sub's OWN providers + the shared
 * object path (re-uploaded in place → a stable mirror URL). It never creates one.
 */
/** One page of mirrored active subs for the refresh cron (storage.refreshActiveMirrors). */
export interface ActiveMirrorPage {
  isDone: boolean;
  continueCursor: string;
  items: {
    id: Id<'subscriptions'>;
    backend: 'remnawave' | 'outline';
    backendServerId: Id<'backendServers'> | null;
    backendShortId: string;
    subscriptionUrl: string;
    rawContentHash: string | null;
    objectPath: string | null;
    /** The providers THIS sub was mirrored to (names) — refresh re-uploads to these only. */
    providers: string[];
  }[];
}

export const pageActiveForMirror = internalQuery({
  args: { cursor: v.union(v.string(), v.null()), numItems: v.number() },
  // Explicit return type breaks Convex's cross-module inference cycle (storage.ts
  // calls this), same convention as billing.ts/lifecycle.ts.
  handler: async (ctx, { cursor, numItems }): Promise<ActiveMirrorPage> => {
    const res = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'active'))
      .paginate({ cursor, numItems });
    return {
      isDone: res.isDone,
      continueCursor: res.continueCursor,
      items: res.page
        // Opt-in only: refresh ONLY subs that already have a mirror; never create.
        .filter((s) => s.subscriptionMirrors.length > 0)
        .map((s) => ({
          id: s._id,
          backend: s.backend,
          backendServerId: s.backendServerId ?? null,
          backendShortId: s.backendShortId,
          subscriptionUrl: s.subscriptionUrl,
          rawContentHash: s.rawContentHash ?? null,
          objectPath: s.subscriptionMirrors[0]?.objectPath ?? null,
          providers: s.subscriptionMirrors.map((m) => m.provider),
        })),
    };
  },
});

/**
 * Per-member context for the opt-in "try a mirror" flow: the active sub + which
 * providers it has already been mirrored to (the "tried" set) + the shared
 * capability object path (null until the first mirror). Same current-or-active
 * resolution as resolveCurrentOrActive.
 */
export interface MirrorContext {
  subscriptionId: Id<'subscriptions'>;
  backend: 'remnawave' | 'outline';
  backendServerId: Id<'backendServers'> | null;
  backendShortId: string;
  /** The panel-provided public subscription URL — where the raw content actually lives. */
  subscriptionUrl: string;
  /** The node the previous key was pinned to (regenerate exclusion hint). */
  excludeNode: string | null;
  triedProviders: string[];
  objectPath: string | null;
}

export const mirrorContextForUser = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<MirrorContext | null> => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    const sub = await currentOrActiveSub(ctx.db, user);
    if (!sub) return null;
    return {
      subscriptionId: sub._id,
      backend: sub.backend,
      backendServerId: sub.backendServerId ?? null,
      backendShortId: sub.backendShortId,
      subscriptionUrl: sub.subscriptionUrl,
      excludeNode: sub.excludeNode ?? null,
      triedProviders: sub.subscriptionMirrors.map((m) => m.provider),
      objectPath: sub.subscriptionMirrors[0]?.objectPath ?? null,
    };
  },
});

/** Append one freshly-provisioned mirror (opt-in flow), idempotent per provider.
 *  The cap is RE-CHECKED inside this serializable mutation (Review D-#8): the
 *  action's earlier read-then-act check raced two concurrent provisions, both
 *  passing `used < cap` before either appended. */
export const appendMirror = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    mirror,
    rawContentHash: v.string(),
    cap: v.number(),
  },
  handler: async (ctx, { subscriptionId, mirror: entry, rawContentHash, cap }) => {
    const row = await ctx.db.get(subscriptionId);
    if (!row || row.state !== 'active') return { appended: false as const };
    const existing = row.subscriptionMirrors.some((m) => m.provider === entry.provider);
    if (!existing && row.subscriptionMirrors.length >= cap) return { appended: false as const };
    const others = row.subscriptionMirrors.filter((m) => m.provider !== entry.provider);
    await ctx.db.patch(subscriptionId, {
      subscriptionMirrors: [...others, entry],
      rawContentHash,
      updatedAt: Date.now(),
    });
    return { appended: true as const };
  },
});

/** Clear all of a sub's mirrors (member "remove" / reset). Returns the removed
 *  objects so the action can best-effort delete them from the buckets. */
export const clearMirrors = internalMutation({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (
    ctx,
    { subscriptionId },
  ): Promise<{ items: { provider: string; objectPath: string }[] }> => {
    const row = await ctx.db.get(subscriptionId);
    if (!row) return { items: [] };
    const items = row.subscriptionMirrors
      .filter((m): m is typeof m & { objectPath: string } => typeof m.objectPath === 'string')
      .map((m) => ({ provider: m.provider, objectPath: m.objectPath }));
    await ctx.db.patch(subscriptionId, { subscriptionMirrors: [], updatedAt: Date.now() });
    return { items };
  },
});

/**
 * Merge a refresh round's results into a subscription's S3 mirrors + content hash
 * (the refresh cron). No-op if the row is gone or no longer active (tombstoned
 * mid-refresh). MERGE by provider (Review #2) rather than replace: a refreshed
 * provider → its fresh entry; a provider that FAILED this round → keep its existing
 * entry marked `status:'failed'` (so it isn't dropped — the member's account view
 * and the per-user cap both still count it, and the next refresh retries it);
 * others untouched. Wholesale-replacing with only the successes silently dropped a
 * failed provider's entry, shrinking `triedProviders` (re-provision past the cap).
 */
export const updateMirrors = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    successes: v.array(mirror),
    failedProviders: v.array(v.string()),
    rawContentHash: v.string(),
  },
  handler: async (ctx, { subscriptionId, successes, failedProviders, rawContentHash }) => {
    const row = await ctx.db.get(subscriptionId);
    if (!row || row.state !== 'active') return null;
    const fresh = new Map(successes.map((m) => [m.provider, m]));
    const failed = new Set(failedProviders);
    const merged = row.subscriptionMirrors.map((m) => {
      const hit = fresh.get(m.provider);
      if (hit) {
        fresh.delete(m.provider);
        return hit;
      }
      return failed.has(m.provider) ? { ...m, status: 'failed' as const } : m;
    });
    // Defensive: a success for a provider not previously mirrored (refresh targets
    // are always already-mirrored, so normally none).
    for (const m of fresh.values()) merged.push(m);
    await ctx.db.patch(subscriptionId, {
      subscriptionMirrors: merged,
      rawContentHash,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Hard-delete marker: state→deleted (used by cleanup + tombstone sweep). */
export const markSubscriptionDeleted = internalMutation({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { subscriptionId }) => {
    await ctx.db.patch(subscriptionId, {
      state: 'deleted',
      deletedAt: Date.now(),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Point a user at their current subscription. */
export const setCurrentSubscription = internalMutation({
  args: { userId: v.id('users'), subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { userId, subscriptionId }) => {
    await ctx.db.patch(userId, { currentSubscriptionId: subscriptionId, updatedAt: Date.now() });
    return null;
  },
});

/**
 * Re-point an EXISTING key to a new backend placement IN PLACE (a connection-mode
 * switch that PATCHes the Remnawave user's squad rather than re-issuing). Updates
 * `backendPlacement` and DROPS the per-UA content cache: the fronted
 * `/api/v1/sub/<token>` keeps the SAME `subToken`, so a stale `subCache` would keep
 * serving the OLD node's config for up to the cache TTL after the switch. Clearing
 * it forces the next fetch to reflect the new placement. `null` clears the
 * placement (mirrors insertSubscription's optional-field mapping). No state/token
 * change, so the member's saved URL keeps working.
 */
export const setPlacementAndClearCache = internalMutation({
  args: { subscriptionId: v.id('subscriptions'), placement: v.union(v.string(), v.null()) },
  handler: async (ctx, { subscriptionId, placement }) => {
    await ctx.db.patch(subscriptionId, {
      backendPlacement: placement ?? undefined,
      subCache: undefined,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * Soft-delete a subscription with a grace window: state→disabled,
 * deletedAt = now + graceMs; the backend user is left alive so the URL keeps
 * working until the tombstone sweep (P5d) hard-deletes it. Re-tombstoning a
 * non-active row is a no-op (returns its existing deletedAt) so a double
 * regenerate can't reset the grace clock.
 */
export const tombstoneWithGrace = internalMutation({
  args: { backendUserId: v.string(), graceMs: v.number() },
  handler: async (ctx, { backendUserId, graceMs }) => {
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique();
    if (!sub) return null;
    if (sub.state !== 'active') return sub.deletedAt != null ? { deletedAt: sub.deletedAt } : null;
    const deletedAt = Date.now() + graceMs;
    await ctx.db.patch(sub._id, { state: 'disabled', deletedAt, updatedAt: Date.now() });
    return { deletedAt };
  },
});

// Post-issuance tombstone retry (L1): regenerate/switch mint a NEW key, then
// tombstone the old one — if that mutation fails transiently the old key would
// stay live FOREVER alongside the new one (no sweep re-tombstones an active
// row). The saga schedules this action on failure; it retries with bounded
// backoff and audits loudly at the end so two-live-keys never goes silent.
const TOMBSTONE_RETRY_BACKOFF_MS = [30_000, 120_000, 480_000, 1_800_000];

export const tombstoneWithGraceAction = internalAction({
  args: { backendUserId: v.string(), graceMs: v.number(), attempt: v.optional(v.number()) },
  handler: async (ctx, { backendUserId, graceMs, attempt }): Promise<null> => {
    const n = attempt ?? 0;
    try {
      await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, { backendUserId, graceMs });
      return null;
    } catch (err) {
      if (n >= TOMBSTONE_RETRY_BACKOFF_MS.length) {
        console.warn(
          `[subscription] tombstone retry exhausted for ${backendUserId.slice(0, 8)}…: ` +
            `${err instanceof Error ? err.message : String(err)}`,
        );
        await ctx.runMutation(internal.audit.record, {
          actorType: 'system',
          action: 'subscription.tombstone_failed',
          targetType: 'subscription',
          payload: { backendUserId },
        });
        return null;
      }
      await ctx.scheduler.runAfter(
        TOMBSTONE_RETRY_BACKOFF_MS[n]!,
        internal.subscriptions.tombstoneWithGraceAction,
        { backendUserId, graceMs, attempt: n + 1 },
      );
      return null;
    }
  },
});
