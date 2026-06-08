/**
 * Single-use PoP request-nonce guard (CDN-blinding Phase 2). Each authenticated,
 * proof-of-possession-signed request carries a 16-byte nonce that the signature
 * covers; `consumeNonce` records (sid, nonceHash) exactly once. A second request
 * with the same (sid, nonce) inside the freshness window is rejected, so a
 * passive CDN that captured a signed request cannot replay it.
 *
 * Like the free-tier cap (freeTier.claimFreeSlot) and the rate limiter
 * (rateLimits.checkAndIncrement), the insert-if-absent runs as a SERIALIZABLE
 * mutation: concurrent callers racing the same (sid, nonceHash) conflict on the
 * read-check + insert under Convex OCC, so exactly one wins set semantics hold.
 *
 * The raw nonce is never stored: the caller passes its SHA-256 hash (hex). TTL
 * is the PoP freshness window plus a margin; a daily cron sweeps `expiresAt`.
 */
import { internalMutation } from './_generated/server';
import { v } from 'convex/values';

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

/** Cron: delete a page of elapsed nonce rows. */
export const sweepExpired = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const now = Date.now();
    const expired = await ctx.db
      .query('replayGuard')
      .withIndex('by_expires', (q) => q.lt('expiresAt', now))
      .take(limit ?? 500);
    for (const row of expired) await ctx.db.delete(row._id);
    return { removed: expired.length };
  },
});
