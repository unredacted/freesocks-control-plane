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
 * The cap gates ACCOUNT creation (createFreeAccount): the slot is held durably
 * before any side effect, so the cap is enforced up front, and `releaseFreeSlot`
 * compensates if the mint/session step fails. Proxy-key issuance is no longer
 * part of this flow; it's a separate authenticated member action
 * (account.regenerate), so a missing/empty backend can never block sign-up.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { hmacSha256Hex, randomHex, sha256Hex } from './lib/crypto';
import { signValue } from './lib/cookies';
import { MEMBER_TTL_MS } from './auth';
import { writeAuditLog } from './lib/audit';

// Explicit return type breaks the same-file internal-reference inference cycle.
type CreateAccountResult =
  | {
      ok: true;
      accountId: string;
      signedCookieValue: string;
      maxAgeSec: number;
      userId: Id<'users'>;
      /** Public per-session token, returned in the response body (only when PoP-bound). */
      popSessionToken?: string;
      tier: {
        slug: string;
        name: string;
        monthlyTrafficGb: number;
        deviceLimit: number;
        backend: 'remnawave' | 'outline';
      };
    }
  | { ok: false; reason: 'cap_reached' };

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
 * Anonymous free-account creation. Turnstile + client IP are verified upstream
 * (convex/http.ts). The per-(IP,day) cap is the serializable claimFreeSlot; a
 * lost claim returns `cap_reached` (there is no key to hand back now that
 * issuance is a separate flow, so the visitor signs in with their existing
 * number instead). On a win we mint the one-time account number, finalize (tier
 * history + audit), and mint a member session so the caller is signed in. NO
 * backend is touched, so account creation succeeds even with no proxy server
 * available; the proxy key is created later via account.regenerate.
 */
export const createFreeAccount = internalAction({
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
    // PoP (CDN-blinding Phase 2): account creation establishes a member session,
    // so the client folds its session public key in to bind it (like login).
    popPublicKey: v.optional(v.string()),
    /** The PoP algorithm ('EdDSA' | 'ES256') for popPublicKey; stored on the session. */
    popAlg: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<CreateAccountResult> => {
    const salt = process.env.IP_HASH_SALT;
    if (!salt) throw new Error('IP_HASH_SALT must be set (bunx convex env set ...)');
    const signingKey = process.env.SESSION_SIGNING_KEY;
    if (!signingKey) throw new Error('SESSION_SIGNING_KEY must be set');
    const ipHash = await hmacSha256Hex(salt, a.ip);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    // Daily per-(IP,day) cap is the admin-tunable `freetier.create` policy (W2);
    // a disabled policy means no cap. The hard enforcement is the serializable
    // claimFreeSlot mutation below — this just supplies its `cap` number.
    const policy = await ctx.runQuery(internal.rateLimits.getPolicy, {
      policyKey: 'freetier.create',
    });
    const cap = policy && policy.enabled ? policy.max : Number.MAX_SAFE_INTEGER;

    const tier = await ctx.runQuery(internal.tiers.getDefaultFree, { backend: a.backend });
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
    if (!claim.claimed) return { ok: false as const, reason: 'cap_reached' as const };

    try {
      const acct = await ctx.runAction(internal.accountId.mintForUser, { userId: claim.userId });
      // W3: assign the non-secret support handle at creation (lazy backfill in
      // getAccountView covers pre-W3 accounts).
      await ctx.runAction(internal.supportId.ensureForUser, { userId: claim.userId });
      await ctx.runMutation(internal.freeTier.finalizeFreeIssuance, {
        userId: claim.userId,
        tierId: tier._id,
        requestId: a.requestId,
        ipHash,
        ipCountry: a.ipCountry,
        asn: a.asn,
      });

      // Mint a member session + signed cookie so the caller is signed in (same
      // shape as auth.accountLogin; the HTTP layer wraps it in a Set-Cookie).
      const sid = randomHex(32);
      const popSessionToken = a.popPublicKey ? randomHex(16) : undefined;
      await ctx.runMutation(internal.sessions.create, {
        sid,
        kind: 'member',
        userId: claim.userId,
        ttlMs: MEMBER_TTL_MS,
        ...(a.popPublicKey
          ? { popPublicKey: a.popPublicKey, popAlg: a.popAlg, popSessionToken }
          : {}),
      });
      const signedCookieValue = await signValue(sid, signingKey);

      return {
        ok: true as const,
        accountId: acct.accountId,
        signedCookieValue,
        maxAgeSec: MEMBER_TTL_MS / 1000,
        userId: claim.userId,
        popSessionToken,
        tier: {
          slug: tier.slug,
          name: tier.name,
          monthlyTrafficGb: tier.monthlyTrafficGb,
          deviceLimit: tier.deviceLimit,
          backend: tier.backend,
        },
      };
    } catch (err) {
      // The mint/session step failed: release the slot + bare user so a transient
      // error doesn't burn this IP's daily allowance.
      await ctx.runMutation(internal.freeTier.releaseFreeSlot, {
        userId: claim.userId,
        grantId: claim.grantId,
      });
      throw err;
    }
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
    await writeAuditLog(ctx, {
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
