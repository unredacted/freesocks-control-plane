import { query } from './_generated/server';
import { v } from 'convex/values';

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
