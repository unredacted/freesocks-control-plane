/**
 * Free-tier issuance primitives (P5b). The headline win: the per-(ipHash,
 * dayBucket) daily cap is now a SERIALIZABLE mutation instead of the old
 * `slot = COUNT()%cap` + composite-UNIQUE-index hack.
 *
 * Why this is race-free (closes deferred bug H1): Convex mutations run under
 * serializable OCC. `claimFreeSlot` reads the grants for (ipHash, dayBucket)
 * over the by_ip_day index, then inserts only if under cap. The read set is the
 * grant range, so two concurrent claims have a read/write conflict — the loser
 * is aborted and retried, re-reads the now-larger count, and sees the cap. Two
 * racers therefore can NEVER both observe `< cap`. No slot column, no modulo,
 * no UNIQUE trick.
 *
 * The backend issuance (HTTP) can't happen in this mutation — it's the action
 * leg of the saga (P5c). The slot is held durably before any side effect, so
 * the cap is enforced up front; `releaseFreeSlot` compensates if issuance fails.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

export const claimFreeSlot = internalMutation({
  args: {
    ipHash: v.string(),
    dayBucket: v.number(),
    cap: v.number(),
    tierId: v.id('tiers'),
    ipCountry: v.optional(v.string()),
    asn: v.optional(v.number()),
    tlsFingerprint: v.optional(v.string()),
    turnstileAction: v.optional(v.string()),
    turnstileCdata: v.optional(v.string()),
    userAgentHash: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query('freeGrants')
      .withIndex('by_ip_day', (q) =>
        q.eq('ipHash', args.ipHash).eq('grantedDayBucket', args.dayBucket),
      )
      .collect();
    if (existing.length >= args.cap) return { claimed: false as const };

    const now = Date.now();
    // free_grants.userId is required, so the bare user must precede the grant.
    const userId = await ctx.db.insert('users', {
      tierId: args.tierId,
      status: 'active',
      updatedAt: now,
    });
    const grantId = await ctx.db.insert('freeGrants', {
      userId,
      ipHash: args.ipHash,
      ipCountry: args.ipCountry,
      asn: args.asn,
      tlsFingerprint: args.tlsFingerprint,
      turnstileAction: args.turnstileAction,
      turnstileCdata: args.turnstileCdata,
      userAgentHash: args.userAgentHash,
      grantedAt: now,
      grantedDayBucket: args.dayBucket,
    });
    return { claimed: true as const, userId, grantId };
  },
});

/** Compensating leg: release a claimed slot + its bare user when issuance fails. */
export const releaseFreeSlot = internalMutation({
  args: { userId: v.id('users'), grantId: v.id('freeGrants') },
  handler: async (ctx, { userId, grantId }) => {
    await ctx.db.delete(grantId);
    await ctx.db.delete(userId);
    return null;
  },
});

/** Grants for an (ipHash, dayBucket) — used by reissue logic and the cap test. */
export const grantsForIpDay = internalQuery({
  args: { ipHash: v.string(), dayBucket: v.number() },
  handler: (ctx, { ipHash, dayBucket }) =>
    ctx.db
      .query('freeGrants')
      .withIndex('by_ip_day', (q) => q.eq('ipHash', ipHash).eq('grantedDayBucket', dayBucket))
      .collect(),
});
