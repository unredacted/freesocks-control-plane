// Pass 2: every function here is internal — user rows (account-id hashes,
// status, tier) must never be readable on the raw Convex channel.
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

export const get = internalQuery({
  args: { id: v.id('users') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Set a user's tier (peer backend switch, no membership-state change). */
export const setTier = internalMutation({
  args: { userId: v.id('users'), tierId: v.id('tiers') },
  handler: async (ctx, { userId, tierId }) => {
    await ctx.db.patch(userId, { tierId, updatedAt: Date.now() });
    return null;
  },
});

/** Set a member's chosen connection profile (transport/squad), orthogonal to
 *  their tier. Re-issuing the key into the new squad is the caller's job
 *  (account.switchProfile). */
export const setConnectionProfile = internalMutation({
  args: { userId: v.id('users'), profileId: v.union(v.literal('evade'), v.literal('privacy')) },
  handler: async (ctx, { userId, profileId }) => {
    await ctx.db.patch(userId, { connectionProfileId: profileId, updatedAt: Date.now() });
    return null;
  },
});

/**
 * Account-number login lookup. The caller (a Node action) hashes the submitted
 * number and passes the hash; we match it against the unique index. Returns
 * null when unknown OR the owner is disabled/deleted; the caller treats both
 * identically (no existence oracle). Rate-limiting + constant-time padding are
 * the caller's responsibility (see the account-login HTTP action, P6/P7).
 */
export const byAccountIdHash = internalQuery({
  args: { accountIdHash: v.string() },
  handler: async (ctx, { accountIdHash }) => {
    const user = await ctx.db
      .query('users')
      .withIndex('by_account_id_hash', (q) => q.eq('accountIdHash', accountIdHash))
      .unique();
    if (!user || user.status === 'disabled' || user.status === 'deleted') return null;
    return user;
  },
});

/**
 * Status-blind hash lookup for the billing-webhook seam: unlike the login
 * lookup it returns disabled/deleted owners too, so a renewed payment can
 * re-target a lapsed account. Internal-only (never an enumeration surface).
 */
export const byAccountIdHashInternal = internalQuery({
  args: { accountIdHash: v.string() },
  handler: (ctx, { accountIdHash }) =>
    ctx.db
      .query('users')
      .withIndex('by_account_id_hash', (q) => q.eq('accountIdHash', accountIdHash))
      .unique(),
});

// `searchByAccountIdPrefix` (public query) was deleted in pass 2: dead code —
// adminApi.usersSearch implements the prefix search inline behind admin auth.
