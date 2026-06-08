/**
 * Account-number minting (P5a). The plaintext is generated in an action
 * (CSPRNG) and revealed exactly once; only the hash + 4-digit prefix are
 * persisted. Uniqueness of the hash is enforced inside the mutation via the
 * by_account_id_hash read-check (serializable OCC, race-free, replacing the
 * old UNIQUE index). The login lookup is users.byAccountIdHash (P3).
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { accountIdPrefix, generateAccountId, hashAccountId } from './lib/accountId';

/**
 * Mint (or rotate) an account number for a user. Returns the one-time
 * plaintext. Retries once on the astronomically rare hash collision.
 */
export const mintForUser = internalAction({
  args: { userId: v.id('users'), rotate: v.optional(v.boolean()) },
  handler: async (ctx, { userId, rotate }): Promise<{ accountId: string }> => {
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
        });
        return { accountId: plaintext };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('account-id mint failed after retry');
  },
});

/** Persist hash+prefix on the user, enforcing hash uniqueness. Throws on collision. */
export const setAccountId = internalMutation({
  args: { userId: v.id('users'), hash: v.string(), prefix: v.string(), rotate: v.boolean() },
  handler: async (ctx, { userId, hash, prefix, rotate }) => {
    const existing = await ctx.db
      .query('users')
      .withIndex('by_account_id_hash', (q) => q.eq('accountIdHash', hash))
      .unique();
    if (existing && existing._id !== userId) throw new Error('account-id hash collision');
    const now = Date.now();
    await ctx.db.patch(userId, {
      accountIdHash: hash,
      accountIdPrefix: prefix,
      ...(rotate ? { accountIdRotatedAt: now } : { accountIdCreatedAt: now }),
      updatedAt: now,
    });
    return null;
  },
});
