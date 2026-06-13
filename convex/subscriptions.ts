// Pass 2: every function here is internal — a subscription row carries the
// live proxy key (subscriptionUrl), so nothing in this module may be callable
// on the raw Convex channel. The old public `get` / `activeForUser` queries
// were dead code and were deleted outright.
import { internalMutation, internalQuery } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';

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
 * The resolver shared by /account + /subscription (replaces
 * lib/current-subscription.resolveActiveSubscription): prefer the user's
 * `currentSubscriptionId` (so a freshly regenerated key shows immediately), but
 * only if it's still active, never a tombstoned row during the 24h grace
 * window. Falls back to the newest active row.
 */
export const resolveCurrentOrActive = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    if (user.currentSubscriptionId) {
      const cur = await ctx.db.get(user.currentSubscriptionId);
      if (cur && cur.state === 'active') return cur;
    }
    // Newest active row via the (userId, state) index — within the equal
    // prefix the index orders by _creationTime, so desc->first is newest.
    return (
      (await ctx.db
        .query('subscriptions')
        .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
        .order('desc')
        .first()) ?? null
    );
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
  },
  handler: (ctx, a) =>
    ctx.db.insert('subscriptions', { ...a, state: 'active', updatedAt: Date.now() }),
});

/**
 * Page active subscriptions for the S3 mirror-refresh cron. Returns just the
 * fields the refresh needs (incl. the existing mirror objectPath, which it
 * reuses to overwrite in place → a stable mirror URL) + the cursor.
 */
/** One page of active subs for the mirror-refresh cron (storage.refreshActiveMirrors). */
export interface ActiveMirrorPage {
  isDone: boolean;
  continueCursor: string;
  items: {
    id: Id<'subscriptions'>;
    backend: 'remnawave' | 'outline';
    backendServerId: Id<'backendServers'> | null;
    backendShortId: string;
    rawContentHash: string | null;
    objectPath: string | null;
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
      items: res.page.map((s) => ({
        id: s._id,
        backend: s.backend,
        backendServerId: s.backendServerId ?? null,
        backendShortId: s.backendShortId,
        rawContentHash: s.rawContentHash ?? null,
        objectPath: s.subscriptionMirrors[0]?.objectPath ?? null,
      })),
    };
  },
});

/** Replace a subscription's S3 mirrors + content hash (the refresh cron). No-op
 *  if the row is gone or no longer active (tombstoned mid-refresh). */
export const updateMirrors = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    mirrors: v.array(mirror),
    rawContentHash: v.string(),
  },
  handler: async (ctx, { subscriptionId, mirrors, rawContentHash }) => {
    const row = await ctx.db.get(subscriptionId);
    if (!row || row.state !== 'active') return null;
    await ctx.db.patch(subscriptionId, {
      subscriptionMirrors: mirrors,
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
