/**
 * Single-use PoP request-nonce guard (CDN-blinding Phase 2). Each authenticated,
 * proof-of-possession-signed request carries a 16-byte nonce that the signature
 * covers; `consumeNonce` records (sid, nonceHash) exactly once. A second request
 * with the same (sid, nonce) inside the freshness window is rejected, so a
 * passive CDN that captured a signed request cannot replay it.
 *
 * Like the free-tier cap (the freetier.create rate limit) and the rate limiter
 * (rateLimits.checkAndIncrement), the insert-if-absent runs as a SERIALIZABLE
 * mutation: concurrent callers racing the same (sid, nonceHash) conflict on the
 * read-check + insert under Convex OCC, so exactly one wins set semantics hold.
 *
 * The raw nonce is never stored: the caller passes its SHA-256 hash (hex). TTL
 * is the PoP freshness window plus a margin; a daily cron sweeps `expiresAt`.
 */
import { internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { recordHeartbeat } from './cronHeartbeat';
import { v } from 'convex/values';

/** Matches retention.ts: bound the immediate re-run chain so a pathological
 *  table can't chain forever; the next daily tick picks up the remainder. */
const MAX_DRAIN_ROUNDS = 50;

export const consumeNonce = internalMutation({
  args: { sid: v.string(), nonceHash: v.string(), ttlMs: v.number() },
  handler: async (ctx, { sid, nonceHash, ttlMs }): Promise<{ ok: boolean }> => {
    const existing = await ctx.db
      .query('replayGuard')
      .withIndex('by_sid_nonce', (q) => q.eq('sid', sid).eq('nonceHash', nonceHash))
      .unique();
    // A previously-seen nonce is a replay, even if its row has technically
    // expired but not yet been swept (defence-in-depth: the freshness ts check
    // in the verifier already bounds how old a still-valid signature can be).
    if (existing) return { ok: false };
    await ctx.db.insert('replayGuard', { sid, nonceHash, expiresAt: Date.now() + ttlMs });
    return { ok: true };
  },
});

/**
 * Cron: delete a page of elapsed nonce rows. A FULL page means more to drain:
 * re-run immediately (each run is its own transaction) — one 500-row page/day
 * can never keep up with a table that accrues a row per PoP-signed request
 * (same drain-chain pattern as retention.ts, bounded by MAX_DRAIN_ROUNDS).
 */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'replay-guard-sweep');
    const now = Date.now();
    const page = limit ?? 500;
    const expired = await ctx.db
      .query('replayGuard')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(page);
    for (const row of expired) await ctx.db.delete(row._id);
    if (expired.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[replay-guard-sweep] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.replayGuard.sweepExpired, { rounds: n + 1 });
    }
    return { removed: expired.length };
  },
});
