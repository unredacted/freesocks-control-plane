/**
 * Free-tier issuance primitives (P5b). The headline win: the per-(ipHash,
 * dayBucket) daily cap is now a SERIALIZABLE mutation instead of the old
 * `slot = COUNT()%cap` + composite-UNIQUE-index hack.
 *
 * Why this is race-free (closes deferred bug H1): Convex mutations run under
 * serializable OCC. `claimFreeSlot` reads the grants for (ipHash, dayBucket)
 * over the by_ip_day index, then inserts only if under cap. The read set is the
 * grant range, so two concurrent claims have a read/write conflict; the loser
 * is aborted and retried, re-reads the now-larger count, and sees the cap. Two
 * racers therefore can NEVER both observe `< cap`. No slot column, no modulo,
 * no UNIQUE trick.
 *
 * The backend issuance (HTTP) can't happen in this mutation; it's the action
 * leg of the saga (P5c). The slot is held durably before any side effect, so
 * the cap is enforced up front; `releaseFreeSlot` compensates if issuance fails.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { hmacSha256Hex, randomHex, sha256Hex } from './lib/crypto';
import { issueNewSubscription } from './lib/issuance';

type FreeIssueOutcome = {
  user: { id: Id<'users'>; tierSlug: string };
  subscription: {
    id: Id<'subscriptions'>;
    url: string;
    shortUuid: string;
    backend: 'remnawave' | 'outline';
    mirrors: {
      provider: string;
      publicUrl: string;
      objectPath?: string;
      status?: 'ok' | 'failed';
    }[];
    expireAt: string;
    trafficLimitBytes: number | null;
  };
};
// Explicit return type breaks the same-file internal-reference inference cycle.
type IssueOrReissueResult =
  | ({ reissued: true; accountIdAvailable: boolean } & FreeIssueOutcome)
  | ({ reissued: false; accountId: string } & FreeIssueOutcome);

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

/** Grants for an (ipHash, dayBucket), used by reissue logic and the cap test. */
export const grantsForIpDay = internalQuery({
  args: { ipHash: v.string(), dayBucket: v.number() },
  handler: (ctx, { ipHash, dayBucket }) =>
    ctx.db
      .query('freeGrants')
      .withIndex('by_ip_day', (q) => q.eq('ipHash', ipHash).eq('grantedDayBucket', dayBucket))
      .collect(),
});

/**
 * Anonymous free-tier issuance: the top-level saga (replaces
 * FreeTierService.issueOrReissue). Turnstile is verified upstream (the HTTP
 * action, P7). Cap is the serializable claimFreeSlot; on a lost claim we serve
 * the existing key (reissue) or reject. On a win we issue, mint a one-time
 * account number, and finalize (tier history + audit).
 */
export const issueOrReissue = internalAction({
  args: {
    ip: v.string(),
    ipCountry: v.optional(v.string()),
    asn: v.optional(v.number()),
    tlsFingerprint: v.optional(v.string()),
    userAgent: v.optional(v.string()),
    turnstileAction: v.optional(v.string()),
    turnstileCdata: v.optional(v.string()),
    requestId: v.string(),
    backend: v.optional(v.union(v.literal('remnawave'), v.literal('outline'))),
  },
  handler: async (ctx, a): Promise<IssueOrReissueResult> => {
    const salt = process.env.IP_HASH_SALT;
    if (!salt) throw new Error('IP_HASH_SALT must be set (bunx convex env set ...)');
    const ipHash = await hmacSha256Hex(salt, a.ip);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const cap = Number(process.env.FREE_TIER_DAILY_CAP ?? '1');
    const expiryDays = Number(process.env.FREE_TIER_EXPIRY_DAYS ?? '90');

    const tier = await ctx.runQuery(api.tiers.getDefaultFree, { backend: a.backend });
    if (!tier) throw new Error('No default-free tier configured');

    const claim = await ctx.runMutation(internal.freeTier.claimFreeSlot, {
      ipHash,
      dayBucket,
      cap,
      tierId: tier._id,
      ipCountry: a.ipCountry,
      asn: a.asn,
      tlsFingerprint: a.tlsFingerprint,
      turnstileAction: a.turnstileAction,
      turnstileCdata: a.turnstileCdata,
      userAgentHash: a.userAgent ? await sha256Hex(a.userAgent) : undefined,
    });

    if (!claim.claimed) {
      const reissue = await ctx.runQuery(internal.freeTier.tryReissue, {
        ipHash,
        dayBucket,
        expiryDays,
      });
      if (reissue) return { reissued: true as const, ...reissue };
      throw new Error('rate_limit: daily free-tier cap reached on this network');
    }

    const trafficLimitBytes =
      tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;
    const expireAt = new Date(Date.now() + expiryDays * 86_400_000).toISOString();

    let issued;
    try {
      issued = await issueNewSubscription(ctx, {
        userId: claim.userId,
        backend: tier.backend,
        spec: {
          username: `freesocks-anon-${randomHex(8)}`,
          trafficLimitBytes,
          trafficLimitStrategy: tier.trafficStrategy,
          expireAt,
          hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
          tag: 'free',
          description: `freesocks:free:${ipHash.slice(0, 12)}`,
          remnawaveSquadUuid: tier.remnawaveSquadUuid ?? null,
        },
      });
    } catch (err) {
      // Backend issuance failed: release the slot + bare user so a transient
      // error doesn't burn this IP's daily allowance.
      await ctx.runMutation(internal.freeTier.releaseFreeSlot, {
        userId: claim.userId,
        grantId: claim.grantId,
      });
      throw err;
    }

    const acct = await ctx.runAction(internal.accountId.mintForUser, { userId: claim.userId });
    await ctx.runMutation(internal.freeTier.finalizeFreeIssuance, {
      userId: claim.userId,
      tierId: tier._id,
      requestId: a.requestId,
      ipHash,
      ipCountry: a.ipCountry,
      asn: a.asn,
    });

    return {
      reissued: false as const,
      accountId: acct.accountId,
      user: { id: claim.userId, tierSlug: tier.slug },
      subscription: {
        id: issued.subscriptionId,
        url: issued.subscriptionUrl,
        shortUuid: issued.backendShortId,
        backend: issued.backend,
        mirrors: issued.mirrors,
        expireAt,
        trafficLimitBytes,
      },
    };
  },
});

/**
 * Reissue path: when the cap is hit and this (ipHash, dayBucket) has exactly
 * one prior grant with a live subscription, hand the existing key back rather
 * than reject. Read-only.
 */
export const tryReissue = internalQuery({
  args: { ipHash: v.string(), dayBucket: v.number(), expiryDays: v.number() },
  handler: async (ctx, { ipHash, dayBucket, expiryDays }) => {
    const grants = await ctx.db
      .query('freeGrants')
      .withIndex('by_ip_day', (q) => q.eq('ipHash', ipHash).eq('grantedDayBucket', dayBucket))
      .collect();
    if (grants.length !== 1) return null;
    const grant = grants[0]!;
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', grant.userId))
      .collect();
    const sub = subs
      .filter((s) => s.state === 'active')
      .sort((a, b) => b._creationTime - a._creationTime)[0];
    if (!sub) return null;
    const user = await ctx.db.get(grant.userId);
    if (!user) return null;
    const tier = await ctx.db.get(user.tierId);
    if (!tier) return null;
    const trafficLimitBytes =
      tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;
    const expireAt = new Date(user._creationTime + expiryDays * 86_400_000).toISOString();
    return {
      accountIdAvailable: false,
      user: { id: user._id, tierSlug: tier.slug },
      subscription: {
        id: sub._id,
        url: sub.subscriptionUrl,
        shortUuid: sub.backendShortId,
        backend: sub.backend,
        mirrors: sub.subscriptionMirrors,
        expireAt,
        trafficLimitBytes,
      },
    };
  },
});

/** Tier history + audit for a fresh free-tier issuance (currentSubscriptionId is set by the saga). */
export const finalizeFreeIssuance = internalMutation({
  args: {
    userId: v.id('users'),
    tierId: v.id('tiers'),
    requestId: v.string(),
    ipHash: v.string(),
    ipCountry: v.optional(v.string()),
    asn: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    await ctx.db.insert('tierHistory', {
      userId: a.userId,
      toTierId: a.tierId,
      reason: 'initial',
      triggeredBy: 'anonymous',
    });
    await ctx.db.insert('auditLog', {
      actorType: 'anonymous',
      action: 'user.create.free',
      targetType: 'user',
      targetId: a.userId,
      payload: { ipCountry: a.ipCountry ?? null, asn: a.asn ?? null },
      requestId: a.requestId,
      ipHash: a.ipHash,
    });
    return null;
  },
});
