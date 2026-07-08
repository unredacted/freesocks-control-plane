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

/** Set a member's chosen connection mode (transport), orthogonal to their tier.
 *  The id is validated against the catalog at the HTTP boundary. Re-issuing the
 *  key into the new placement is the caller's job (account.switchMode). */
export const setConnectionMode = internalMutation({
  args: { userId: v.id('users'), modeId: v.string() },
  handler: async (ctx, { userId, modeId }) => {
    await ctx.db.patch(userId, { connectionModeId: modeId, updatedAt: Date.now() });
    return null;
  },
});

/**
 * Account-number login lookup. The caller (a Node action) hashes the submitted
 * number and passes the hash; we match it against the unique index. Returns null
 * when unknown, `deleted`, or admin-disabled — the caller treats all of these
 * identically (no existence oracle). A LAPSED member (status=disabled, reason
 * 'membership_lapsed') IS returned so they can log back in to renew; the caller
 * auto-downgrades them to the free tier (Review #1). A successful login for a real
 * member is not an oracle — only *failures* must stay indistinguishable.
 * Rate-limiting + constant-time padding are the caller's responsibility (see the
 * account-login HTTP action, P6/P7).
 */
export const byAccountIdHash = internalQuery({
  args: { accountIdHash: v.string() },
  handler: async (ctx, { accountIdHash }) => {
    const user = await ctx.db
      .query('users')
      .withIndex('by_account_id_hash', (q) => q.eq('accountIdHash', accountIdHash))
      .unique();
    if (!user || user.status === 'deleted') return null;
    // Admit lapsed members (auto-downgraded to free on login); keep admin-disabled
    // (reason 'admin_action' or any non-lapse reason) locked out. (Review #1.)
    if (user.status === 'disabled' && user.disabledReason !== 'membership_lapsed') return null;
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
