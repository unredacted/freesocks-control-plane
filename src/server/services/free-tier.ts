import { and, eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { freeGrants, subscriptions, tierHistory, users } from '../db/schema';
import { randomHex } from '../lib/crypto';
import { RateLimitError } from '../lib/errors';
import type { Logger } from '../lib/logger';
import { parseMirrors } from '../lib/mirrors';
import type { PlatformConfig } from '../platform/interface';
import type { AuditService } from './audit';
import type { RateLimitService } from './rate-limit';
import type { SubscriptionDeliveryService } from './subscription-delivery';
import type { TierPolicyService, Tier } from './tier-policy';

interface Deps {
  db: Db;
  rateLimit: RateLimitService;
  tierPolicy: TierPolicyService;
  subscription: SubscriptionDeliveryService;
  audit: AuditService;
  logger: Logger;
  config: PlatformConfig;
}

export interface FreeGrantContext {
  ip: string;
  ipCountry?: string;
  asn?: number;
  tlsFingerprint?: string;
  userAgent?: string;
  turnstileAction?: string;
  turnstileCdata?: string;
  requestId: string;
  /**
   * Preferred backend. Set by the route handler when the caller explicitly
   * picked one in the request body AND user-choice is enabled AND the chosen
   * backend itself is enabled. Otherwise undefined → the resolver falls back
   * to whatever `subscription.default_backend` says.
   *
   * Whatever lands here is treated as a hard requirement — the resolver
   * either finds a default-free tier on that backend or throws.
   */
  backend?: 'remnawave' | 'outline';
}

export interface FreeGrantOutcome {
  reissued: boolean;
  banner?: string;
  user: {
    id: number;
    tier: Tier;
  };
  subscription: {
    id: number;
    url: string;
    shortUuid: string;
    // `objectPath` is optional on read because `parseMirrors` makes it
    // optional for forward compatibility. Writers (subscription-delivery.ts
    // issueNew) always populate it; consumers that need to delete from
    // storage filter to entries that have it. Consumers that only render
    // publicUrl (SPA) don't care.
    mirrors: { provider: string; publicUrl: string; objectPath?: string }[];
    expireAt: string | null;
    trafficLimitBytes: number | null;
  };
}

export class FreeTierService {
  constructor(private readonly deps: Deps) {}

  async issueOrReissue(ctx: FreeGrantContext): Promise<FreeGrantOutcome> {
    const ipHash = await this.deps.rateLimit.hashIp(ctx.ip);
    const dayBucket = this.deps.rateLimit.dayBucket();
    const dailyKey = `rl:free:ip:${ipHash}:${dayBucket}`;
    const cap = this.deps.config.FREE_TIER_DAILY_CAP;

    const decision = await this.deps.rateLimit.checkAndIncrement(dailyKey, cap, 90_000);
    if (!decision.allowed) {
      const reissued = await this.tryReissue(ipHash, dayBucket, ctx);
      if (reissued) return reissued;
      throw new RateLimitError(
        decision.retryAfterSeconds,
        'Daily free tier cap reached on this network',
      );
    }

    // Cheap, non-authoritative fast path: reject an obvious over-cap before
    // doing any work, and serve the "here's your existing key" reissue. KV is
    // eventually consistent and this COUNT is a plain read, so neither is the
    // real guard — the atomic slot claim below is. This just avoids creating a
    // throwaway user row in the common, already-capped case.
    const priorGrants = await this.deps.db
      .select()
      .from(freeGrants)
      .where(and(eq(freeGrants.ipHash, ipHash), eq(freeGrants.grantedDayBucket, dayBucket)))
      .all();
    if (priorGrants.length >= cap) {
      const reissued = await this.tryReissue(ipHash, dayBucket, ctx);
      if (reissued) return reissued;
      throw new RateLimitError(90_000, 'Daily free tier cap reached on this network');
    }

    const tier = await this.deps.tierPolicy.getDefaultFreeTier(ctx.backend);
    const expireAt = new Date(
      Date.now() + this.deps.config.FREE_TIER_EXPIRY_DAYS * 86_400_000,
    ).toISOString();
    const trafficLimitBytes =
      tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;

    // Create the bare user row first: free_grants.user_id is NOT NULL + FK, so
    // the grant can't precede the user. No backend side effects yet, so this
    // row is cheap to roll back if we lose the slot race below.
    const userInsertResult = await this.deps.db
      .insert(users)
      .values({
        tierId: tier.id,
        status: 'active',
      })
      .returning();
    const newUser = userInsertResult[0];
    if (!newUser) throw new Error('user insert returned no row');

    // ATOMIC CAP (closes H1). Claim a slot for this (ipHash, dayBucket): the
    // new row's `slot` is `COUNT(existing grants) % cap`, and the UNIQUE index
    // on (ip_hash, granted_day_bucket, slot) bounds the group to `cap` distinct
    // slots. D1/SQLite serialize writes, so the (cap+1)-th insert recomputes a
    // slot that's already taken (mod wraps it back into [0, cap)) and hits the
    // unique constraint — `onConflictDoNothing` turns that into a no-op and
    // `.returning()` comes back empty. Empty-array detection is the portable
    // cross-driver signal; affected-rows counts are NOT uniform across
    // D1/better-sqlite3/libSQL. (cap <= 0 can't reach here — checkAndIncrement
    // and the priorGrants check both reject first — so the `% cap` is safe.)
    const grantInsert = await this.deps.db
      .insert(freeGrants)
      .values({
        userId: newUser.id,
        ipHash,
        ipCountry: ctx.ipCountry ?? null,
        asn: ctx.asn ?? null,
        tlsFingerprint: ctx.tlsFingerprint ?? null,
        turnstileAction: ctx.turnstileAction ?? null,
        turnstileCdata: ctx.turnstileCdata ?? null,
        grantedDayBucket: dayBucket,
        slot: sql`((SELECT COUNT(*) FROM free_grants WHERE ip_hash = ${ipHash} AND granted_day_bucket = ${dayBucket}) % ${cap})`,
      })
      .onConflictDoNothing({
        target: [freeGrants.ipHash, freeGrants.grantedDayBucket, freeGrants.slot],
      })
      .returning();

    if (grantInsert.length === 0) {
      // Lost the race to a concurrent issuance. Roll back the throwaway user
      // (no backend user/subscription/mirror exists yet) and fall back to the
      // reissue/reject path, exactly like the priorGrants branch above.
      await this.rollbackUser(newUser.id);
      const reissued = await this.tryReissue(ipHash, dayBucket, ctx);
      if (reissued) return reissued;
      throw new RateLimitError(90_000, 'Daily free tier cap reached on this network');
    }
    const grant = grantInsert[0];

    // Won the slot — do the (expensive, side-effectful) backend issuance. If it
    // throws, release the slot + user so a transient backend error doesn't burn
    // this IP's daily allowance for the rest of the day.
    let subscription: Awaited<ReturnType<SubscriptionDeliveryService['issueNew']>>;
    try {
      subscription = await this.deps.subscription.issueNew({
        userId: newUser.id,
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
      if (grant) await this.releaseGrant(grant.id);
      await this.rollbackUser(newUser.id);
      throw err;
    }

    await this.deps.db
      .update(users)
      .set({ currentSubscriptionId: subscription.id, updatedAt: Date.now() })
      .where(eq(users.id, newUser.id));

    await this.deps.db.insert(tierHistory).values({
      userId: newUser.id,
      fromTierId: null,
      toTierId: tier.id,
      reason: 'initial',
      triggeredBy: 'anonymous',
    });

    await this.deps.audit.record({
      actorType: 'anonymous',
      action: 'user.create.free',
      targetType: 'user',
      targetId: String(newUser.id),
      payload: { ipCountry: ctx.ipCountry, asn: ctx.asn },
      requestId: ctx.requestId,
      ipHash,
    });

    return {
      reissued: false,
      user: { id: newUser.id, tier },
      subscription: {
        id: subscription.id,
        url: subscription.subscriptionUrl,
        shortUuid: subscription.backendShortId,
        mirrors: subscription.mirrors,
        expireAt,
        trafficLimitBytes,
      },
    };
  }

  /** Best-effort delete of a throwaway user row created during issuance. */
  private async rollbackUser(userId: number): Promise<void> {
    try {
      await this.deps.db.delete(users).where(eq(users.id, userId));
    } catch (err) {
      this.deps.logger.warn('free_rollback_user_failed', { userId, error: String(err) });
    }
  }

  /** Best-effort delete of a free_grants row to release a claimed slot. */
  private async releaseGrant(grantId: number): Promise<void> {
    try {
      await this.deps.db.delete(freeGrants).where(eq(freeGrants.id, grantId));
    } catch (err) {
      this.deps.logger.warn('free_release_grant_failed', { grantId, error: String(err) });
    }
  }

  private async tryReissue(
    ipHash: string,
    dayBucket: number,
    ctx: FreeGrantContext,
  ): Promise<FreeGrantOutcome | null> {
    const grants = await this.deps.db
      .select()
      .from(freeGrants)
      .where(and(eq(freeGrants.ipHash, ipHash), eq(freeGrants.grantedDayBucket, dayBucket)))
      .all();
    if (grants.length !== 1) return null;
    const grant = grants[0];
    if (!grant) return null;
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(and(eq(subscriptions.userId, grant.userId), eq(subscriptions.state, 'active')))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub) return null;
    const userRow = await this.deps.db
      .select()
      .from(users)
      .where(eq(users.id, grant.userId))
      .limit(1)
      .all();
    const user = userRow[0];
    if (!user) return null;
    const tier = await this.deps.tierPolicy.getById(user.tierId);
    if (!tier) return null;
    await this.deps.audit.record({
      actorType: 'anonymous',
      action: 'user.reissue.free',
      targetType: 'user',
      targetId: String(user.id),
      requestId: ctx.requestId,
      ipHash,
    });
    // Populate the actual tier + expiry values so the SPA renders the right
    // traffic cap and expiry on the reissue path. Previously this returned
    // `null` for both, so a user who hit the per-IP cap got their existing
    // key back labeled "no limit, no expiry" — contradicting the real
    // limits enforced on the backend.
    //
    // `trafficLimitBytes` mirrors the issue path: 0 GB tier means unlimited
    // (-> null), otherwise convert GB → bytes.
    // `expireAt` is computed from when the free-tier user was created plus
    // the configured expiry days. This matches what the cleanup-expired-free
    // cron uses to decide who to delete, so the value the SPA shows is
    // consistent with when the user will actually lose access.
    const trafficLimitBytes =
      tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;
    const expireAt = new Date(
      user.createdAt + this.deps.config.FREE_TIER_EXPIRY_DAYS * 86_400_000,
    ).toISOString();

    return {
      reissued: true,
      banner: 'You already requested a key today on this network. Here it is again.',
      user: { id: user.id, tier },
      subscription: {
        id: sub.id,
        url: sub.subscriptionUrl,
        shortUuid: sub.backendShortId,
        mirrors: parseMirrors(sub.subscriptionMirrors, this.deps.logger, {
          subscriptionId: sub.id,
          userId: user.id,
        }),
        expireAt,
        trafficLimitBytes,
      },
    };
  }

  async cleanupExpired(now = Date.now()): Promise<number> {
    const cutoff = now;
    const expired = await this.deps.db
      .select()
      .from(users)
      .innerJoin(
        subscriptions,
        and(eq(subscriptions.userId, users.id), eq(subscriptions.state, 'active')),
      )
      .where(
        and(
          eq(users.status, 'active'),
          sql`${users.tierId} IN (SELECT id FROM tiers WHERE is_default_free = 1)`,
          sql`${users.createdAt} < ${cutoff - this.deps.config.FREE_TIER_EXPIRY_DAYS * 86_400_000}`,
        ),
      )
      .limit(100)
      .all();
    let removed = 0;
    for (const row of expired) {
      try {
        await this.deps.subscription.deleteSubscription(
          row.subscriptions.backend,
          row.subscriptions.backendUserId,
        );
        await this.deps.db
          .update(users)
          .set({ status: 'deleted', updatedAt: Date.now() })
          .where(eq(users.id, row.users.id));
        removed++;
      } catch (err) {
        this.deps.logger.warn('free_cleanup_failed', {
          userId: row.users.id,
          error: String(err),
        });
      }
    }
    return removed;
  }
}
