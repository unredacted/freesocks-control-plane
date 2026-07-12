/**
 * Free-tier issuance primitives.
 *
 * PRIVACY: FCP stores NO user IP, even hashed. The per-(IP,day) free-account cap
 * is enforced by the EPHEMERAL, serializable `freetier.create` rate-limit counter
 * (`convex/rateLimits.ts`) — a bucket keyed by a one-way HMAC of the IP that
 * auto-expires (24h window) and is cron-swept. Nothing durable ever records the
 * IP: the hash exists only for the life of that rate-limit window, and no
 * durable ledger/audit row carries it.
 *
 * Why the cap stays race-free (closes deferred bug H1): the rate-limit `enforce`
 * runs as a serializable mutation that conflicts on the bucket row, so two
 * concurrent creates can never both observe `< max` — the same OCC guarantee the
 * old durable slot-claim ledger had, minus any stored IP. The slot is reserved
 * (increment) BEFORE any side effect and RELEASED (decrement) if the mint/session
 * step fails, so a transient error never burns the IP's daily allowance.
 *
 * Account creation touches NO backend, so it succeeds even with no proxy server
 * available; the proxy key is created later via `account.regenerate`.
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { hmacSha256Hex, randomHex } from './lib/crypto';
import { signValue } from './lib/cookies';
import { MEMBER_TTL_MS } from './auth';
import { freeWindowExpiryMs } from './lifecycle';
import { applyCountsDelta } from './lib/statusCounters';
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

/**
 * Insert the bare free-tier user. The per-(IP,day) cap is enforced UPSTREAM by
 * the `freetier.create` rate limit in `createFreeAccount`; this mutation records
 * NO IP — issuance is captured by `tierHistory` + the audit log instead.
 */
export const createFreeUser = internalMutation({
  args: { tierId: v.id('tiers') },
  handler: async (ctx, { tierId }): Promise<{ userId: Id<'users'> }> => {
    const now = Date.now();
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      // Start the idle clock so the deactivate-idle-free sweep can find this user
      // once their free key ages out (never before).
      freeKeyExpiresAt: await freeWindowExpiryMs(ctx.db),
      updatedAt: now,
    });
    await applyCountsDelta(ctx, { statusTo: 'active' });
    return { userId };
  },
});

/** Compensating leg: delete the bare user when issuance fails. The reserved
 *  rate-limit slot is released separately (see `createFreeAccount`'s catch). */
export const deleteFreeUser = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const u = await ctx.db.get(userId);
    if (!u) return null;
    await ctx.db.delete(userId);
    await applyCountsDelta(ctx, {
      statusFrom: u.status,
      driftDelta: u.backendPushFailedAt != null ? -1 : 0,
    });
    return null;
  },
});

/**
 * Anonymous free-account creation. Captcha + client IP are verified upstream
 * (`convex/http.ts`). The per-(IP,day) cap is the serializable `freetier.create`
 * rate-limit counter — the IP is hashed ONLY to key that ephemeral bucket and is
 * never stored durably. A lost claim returns `cap_reached`. On a win we mint the
 * one-time account number, finalize (tier history + audit), and mint a member
 * session so the caller is signed in. NO backend is touched.
 */
export const createFreeAccount = internalAction({
  args: {
    ip: v.string(),
    ipCountry: v.optional(v.string()),
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

    // The ONLY use of the IP: a transient, one-way HMAC that keys the per-(IP,day)
    // cap. The `freetier.create` policy (default 3/day) is the hard cap, enforced
    // by the serializable rate-limit counter; the hash lives only in that
    // auto-expiring bucket, never in a durable row. A disabled policy => no cap
    // (enforce allows through). This is the account-creation slot RESERVATION.
    const ipHash = await hmacSha256Hex(salt, a.ip);
    const gate = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'freetier.create',
      subject: ipHash,
    });
    if (!gate.allowed) return { ok: false as const, reason: 'cap_reached' as const };

    const releaseSlot = () =>
      ctx.runMutation(internal.rateLimits.release, {
        policyKey: 'freetier.create',
        subject: ipHash,
      });

    const tier = await ctx.runQuery(internal.tiers.getDefaultFree, { backend: a.backend });
    if (!tier) {
      await releaseSlot(); // couldn't issue → don't burn the IP's allowance
      throw new Error('No default-free tier configured');
    }

    const { userId } = await ctx.runMutation(internal.freeTier.createFreeUser, {
      tierId: tier._id,
    });

    try {
      const acct = await ctx.runAction(internal.accountId.mintForUser, { userId });
      // W3: assign the non-secret support handle at creation (lazy backfill in
      // getAccountView covers pre-W3 accounts).
      await ctx.runAction(internal.supportId.ensureForUser, { userId });
      await ctx.runMutation(internal.freeTier.finalizeFreeIssuance, {
        userId,
        tierId: tier._id,
        requestId: a.requestId,
        ipCountry: a.ipCountry,
      });

      // Mint a member session + signed cookie so the caller is signed in (same
      // shape as auth.accountLogin; the HTTP layer wraps it in a Set-Cookie).
      // Create the session LAST — after the (pure) cookie signing — so a throw
      // can't leave a session row pointing at a user the catch below deletes.
      const sid = randomHex(32);
      const popSessionToken = a.popPublicKey ? randomHex(16) : undefined;
      const signedCookieValue = await signValue(sid, signingKey);
      await ctx.runMutation(internal.sessions.create, {
        sid,
        kind: 'member',
        userId,
        ttlMs: MEMBER_TTL_MS,
        ...(a.popPublicKey
          ? { popPublicKey: a.popPublicKey, popAlg: a.popAlg, popSessionToken }
          : {}),
      });

      return {
        ok: true as const,
        accountId: acct.accountId,
        signedCookieValue,
        maxAgeSec: MEMBER_TTL_MS / 1000,
        userId,
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
      // The mint/session step failed: delete the bare user AND give the reserved
      // rate-limit slot back, so a transient error doesn't burn this IP's daily
      // allowance.
      await ctx.runMutation(internal.freeTier.deleteFreeUser, { userId });
      await releaseSlot();
      throw err;
    }
  },
});

/** Tier history + audit for a fresh free-tier issuance (currentSubscriptionId is
 *  set by the saga). No IP (not even hashed) is recorded — only the coarse,
 *  non-identifying `ipCountry` (never the IP). */
export const finalizeFreeIssuance = internalMutation({
  args: {
    userId: v.id('users'),
    tierId: v.id('tiers'),
    requestId: v.string(),
    ipCountry: v.optional(v.string()),
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
      payload: { ipCountry: a.ipCountry ?? null },
      requestId: a.requestId,
    });
    return null;
  },
});
