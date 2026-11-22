/**
 * Account-number minting (P5a). The plaintext is generated in an action
 * (CSPRNG) and revealed exactly once; only the hash + 4-digit prefix are
 * persisted. Uniqueness of the hash is enforced inside the mutation via the
 * by_account_id_hash read-check (serializable OCC, race-free, replacing the
 * old UNIQUE index). The login lookup is users.byAccountIdHash (P3).
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import { accountIdPrefix, generateAccountId, hashAccountId } from './lib/accountId';

/**
 * Mint (or rotate) an account number for a user. Returns the one-time
 * plaintext. Retries once on the astronomically rare hash collision.
 */
export const mintForUser = internalAction({
  args: {
    userId: v.id('users'),
    rotate: v.optional(v.boolean()),
    keepSid: v.optional(v.string()),
  },
  handler: async (ctx, { userId, rotate, keepSid }): Promise<{ accountId: string }> => {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      const plaintext = generateAccountId();
      const hash = await hashAccountId(plaintext);
      try {
        await ctx.runMutation(internal.accountId.setAccountId, {
          userId,
          hash,
          prefix: accountIdPrefix(plaintext),
          rotate: rotate ?? false,
          keepSid,
        });
        return { accountId: plaintext };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('account-id mint failed after retry');
  },
});

/** Replace the credential and revoke prior sessions in the same transaction. */
export const setAccountId = internalMutation({
  args: {
    userId: v.id('users'),
    hash: v.string(),
    prefix: v.string(),
    rotate: v.boolean(),
    keepSid: v.optional(v.string()),
  },
  handler: async (ctx, { userId, hash, prefix, rotate, keepSid }): Promise<null> => {
    if (rotate) {
      const session = keepSid
        ? await ctx.runQuery(internal.sessions.bySid, { sid: keepSid, recentMember: true })
        : null;
      const user = session?.userId === userId ? await ctx.db.get(userId) : null;
      if (
        !user ||
        user.status === 'deleted' ||
        (user.status === 'disabled' && user.disabledReason !== 'membership_lapsed')
      ) {
        throw new ConvexError({
          code: 'auth.reauthentication_required',
          message: 'Sign in again to manage account credentials.',
        });
      }
    }
    const existing = await ctx.db
      .query('users')
      .withIndex('by_account_id_hash', (q) => q.eq('accountIdHash', hash))
      .unique();
    if (existing && (rotate || existing._id !== userId))
      throw new Error('account-id hash collision');
    await ctx.db.patch(userId, {
      accountIdHash: hash,
      accountIdPrefix: prefix,
      updatedAt: Date.now(),
    });
    if (rotate) {
      await ctx.runMutation(internal.sessions.deleteAllForUserExcept, { userId, keepSid });
    }
    return null;
  },
});
