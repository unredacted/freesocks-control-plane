/**
 * Rate-limit counters (P6) — replaces the KV `rateLimit` namespace. Unlike the
 * old best-effort KV limiter (which could be raced past its cap because KV is
 * eventually-consistent and non-transactional), this is a STRICT counter:
 * `checkAndIncrement` runs as a serializable mutation, so concurrent callers
 * conflict on the bucket row and the cap holds exactly. A fixed window anchored
 * at the first hit; the row resets once it expires (and a daily cron sweeps
 * stragglers). The bucket key encodes the subject + window granularity, e.g.
 * `account-login:ip:<ipHash>` or `account-login:prefix:<1234>`.
 */
import { internalMutation } from './_generated/server';
import { v } from 'convex/values';

export const checkAndIncrement = internalMutation({
  args: { bucket: v.string(), max: v.number(), windowMs: v.number() },
  handler: async (ctx, { bucket, max, windowMs }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('rateLimits')
      .withIndex('by_bucket', (q) => q.eq('bucket', bucket))
      .unique();

    // No row, or the window has elapsed → start a fresh window.
    if (!row || row.expiresAt <= now) {
      if (row) await ctx.db.patch(row._id, { count: 1, expiresAt: now + windowMs });
      else await ctx.db.insert('rateLimits', { bucket, count: 1, expiresAt: now + windowMs });
      return { allowed: true, remaining: Math.max(0, max - 1), retryAfterMs: 0 };
    }

    if (row.count >= max) {
      return { allowed: false, remaining: 0, retryAfterMs: row.expiresAt - now };
    }
    await ctx.db.patch(row._id, { count: row.count + 1 });
    return { allowed: true, remaining: Math.max(0, max - row.count - 1), retryAfterMs: 0 };
  },
});

/** Cron: delete a page of elapsed rate-limit windows. */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const now = Date.now();
    const expired = await ctx.db
      .query('rateLimits')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(limit ?? 500);
    for (const row of expired) await ctx.db.delete(row._id);
    return { removed: expired.length };
  },
});
