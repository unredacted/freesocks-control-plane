/**
 * Support-ID minting (W3). A non-secret `FS-XXXX-XXXX` handle assigned once per
 * user, plaintext, with uniqueness enforced inside the mutation via a
 * by_support_id read-check (serializable OCC, race-free — mirrors accountId.ts).
 * Minted at account creation and lazily backfilled for pre-W3 users on their
 * next account view. NOT a credential; see lib/supportId.ts.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import type { Id } from './_generated/dataModel';
import { generateSupportId, normalizeSupportId } from './lib/supportId';

/** Mint a support ID for a user if it lacks one; returns the (existing or new) value. */
export const ensureForUser = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ supportId: string }> => {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      const candidate = generateSupportId();
      try {
        const result = await ctx.runMutation(internal.supportId.setSupportId, {
          userId,
          supportId: candidate,
        });
        return { supportId: result.supportId };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('support-id mint failed after retries');
  },
});

/**
 * Assign a support ID, enforcing uniqueness. Idempotent: if the user already has
 * one, returns it without overwriting (so a lazy backfill races safely and the
 * handle is stable). Throws on collision with a DIFFERENT user so the action retries.
 */
export const setSupportId = internalMutation({
  args: { userId: v.id('users'), supportId: v.string() },
  handler: async (ctx, { userId, supportId }) => {
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('user not found');
    if (user.supportId) return { supportId: user.supportId };
    const clash = await ctx.db
      .query('users')
      .withIndex('by_support_id', (q) => q.eq('supportId', supportId))
      .unique();
    if (clash && clash._id !== userId) throw new Error('support-id collision');
    await ctx.db.patch(userId, { supportId, updatedAt: Date.now() });
    return { supportId };
  },
});

/** Admin exact lookup by support ID (normalized). Returns the user id or null. */
export const findBySupportId = internalQuery({
  args: { input: v.string() },
  handler: async (ctx, { input }): Promise<Id<'users'> | null> => {
    const normalized = normalizeSupportId(input);
    const user = await ctx.db
      .query('users')
      .withIndex('by_support_id', (q) => q.eq('supportId', normalized))
      .unique();
    return user?._id ?? null;
  },
});
