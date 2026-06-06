import { internalMutation, query } from './_generated/server';
import { v } from 'convex/values';

const mirror = v.object({
  provider: v.string(),
  publicUrl: v.string(),
  objectPath: v.optional(v.string()),
  status: v.optional(v.union(v.literal('ok'), v.literal('failed'))),
});

export const get = query({
  args: { id: v.id('subscriptions') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Unique-index lookup by the backend's primary user id. */
export const byBackendUserId = query({
  args: { backendUserId: v.string() },
  handler: (ctx, { backendUserId }) =>
    ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique(),
});

/**
 * Newest active subscription for a user — the resolver shared by /account and
 * /subscription (replaces lib/current-subscription.ts). Tombstoned rows are
 * excluded; ties broken by creation time (newest wins).
 */
export const activeForUser = query({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    return (
      rows
        .filter((s) => s.state === 'active')
        .sort((a, b) => b._creationTime - a._creationTime)[0] ?? null
    );
  },
});

/**
 * The resolver shared by /account + /subscription (replaces
 * lib/current-subscription.resolveActiveSubscription): prefer the user's
 * `currentSubscriptionId` (so a freshly regenerated key shows immediately), but
 * only if it's still active — never a tombstoned row during the 24h grace
 * window. Falls back to the newest active row.
 */
export const resolveCurrentOrActive = query({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    if (user.currentSubscriptionId) {
      const cur = await ctx.db.get(user.currentSubscriptionId);
      if (cur && cur.state === 'active') return cur;
    }
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    return (
      rows
        .filter((s) => s.state === 'active')
        .sort((a, b) => b._creationTime - a._creationTime)[0] ?? null
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
    outlineServerId: v.optional(v.id('outlineServers')),
    subscriptionUrl: v.string(),
    subscriptionMirrors: v.array(mirror),
    rawContentHash: v.optional(v.string()),
  },
  handler: (ctx, a) =>
    ctx.db.insert('subscriptions', { ...a, state: 'active', updatedAt: Date.now() }),
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
