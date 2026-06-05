import { and, eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { subscriptions, tierHistory, users } from '../db/schema';
import type { Logger } from '../lib/logger';
import type { PlatformConfig } from '../platform/interface';
import type { AuditService } from './audit';
import type { BackendRegistry } from './backend-registry';
import type { EmailDeliveryService } from './email-delivery';
import { renderDisabled, renderGraceWarning, renderWelcome } from './email-templates';
import type { TierPolicyService, Tier } from './tier-policy';

interface Deps {
  db: Db;
  backends: BackendRegistry;
  tierPolicy: TierPolicyService;
  audit: AuditService;
  email: EmailDeliveryService;
  logger: Logger;
  config: PlatformConfig;
}

/**
 * Membership lifecycle: the entitlement-write seam (`setMembership`) plus the
 * generic `active → grace → disabled` state machine driven off
 * `users.membershipExpiresAt`.
 *
 * The former CiviCRM reconcile/poll (runReconcile/applyMembership/reconcileOne,
 * the high-water-mark cursor and the KV poll lock) has been removed. Entitlements
 * now arrive through `setMembership`, which the admin tier-change flow calls today
 * and the future billing portal will call in place of the CiviCRM ingestion.
 */
export class MembershipSyncService {
  constructor(private readonly deps: Deps) {}

  /**
   * Entitlement-write seam. Sets a user's tier + membership expiry from an
   * external source of truth. When the tier actually changes it records tier
   * history, audits, pushes the new spec to the live backend subscription, and
   * fires a welcome email on a free→paid upgrade. When only the expiry moved it
   * just updates that. Idempotent: re-applying the same tier+expiry is a no-op.
   */
  async setMembership(input: {
    userId: number;
    tierId: number;
    expiresAtMs: number | null;
    reason: string;
    triggeredBy?: string;
  }): Promise<void> {
    const userRow = await this.deps.db
      .select()
      .from(users)
      .where(eq(users.id, input.userId))
      .limit(1)
      .all();
    const user = userRow[0];
    if (!user) {
      this.deps.logger.debug('set_membership_user_not_present', { userId: input.userId });
      return;
    }
    const toTier = await this.deps.tierPolicy.getById(input.tierId);
    if (!toTier) {
      this.deps.logger.error('set_membership_tier_missing', {
        userId: input.userId,
        tierId: input.tierId,
      });
      throw new Error(`tier ${input.tierId} not found`);
    }

    if (user.tierId === toTier.id) {
      // Tier unchanged — only refresh expiry if it moved.
      if (input.expiresAtMs !== user.membershipExpiresAt) {
        await this.deps.db
          .update(users)
          .set({ membershipExpiresAt: input.expiresAtMs, updatedAt: Date.now() })
          .where(eq(users.id, user.id));
      }
      return;
    }

    const fromTier = await this.deps.tierPolicy.getById(user.tierId);
    const wasFree = fromTier?.isDefaultFree ?? false;
    const isUpgrade = wasFree && !toTier.isDefaultFree;

    // Authoritative state FIRST, history trails it — if the users update failed
    // after a history insert, tier_history would record a change that never
    // happened (and a retry would duplicate it).
    await this.deps.db
      .update(users)
      .set({
        tierId: toTier.id,
        membershipExpiresAt: input.expiresAtMs,
        updatedAt: Date.now(),
      })
      .where(eq(users.id, user.id));

    await this.deps.db.insert(tierHistory).values({
      userId: user.id,
      fromTierId: user.tierId,
      toTierId: toTier.id,
      reason: input.reason,
      triggeredBy: input.triggeredBy ?? 'system',
    });

    await this.deps.audit.record({
      actorType: 'system',
      action: 'membership.tier_change',
      targetType: 'user',
      targetId: String(user.id),
      payload: { fromTierId: user.tierId, toTierId: toTier.id, reason: input.reason },
    });

    // Push the new tier's spec to the user's live backend subscription so the
    // change actually takes effect on traffic limits / HWID / squad.
    await this.pushTierToBackend(user.id, toTier);

    // Fire a welcome email on free → paid upgrade. Dedupe key prevents a
    // double-send if the same change is applied twice.
    if (isUpgrade && user.email) {
      await this.deps.email.send({
        to: user.email,
        templateKey: 'member.welcome',
        params: { tierSlug: toTier.slug, userId: user.id },
        dedupeKey: `welcome:user:${user.id}:tier:${toTier.id}`,
        ...renderWelcome({
          tierName: toTier.name,
          accountUrl: `${this.deps.config.WEBAUTHN_ORIGIN}/account`,
        }),
      });
    }
  }

  /**
   * Push a tier's spec to the user's live backend subscription so the backend
   * user's traffic cap / HWID / squad reflects the tier they're on. No-ops
   * gracefully when the user has no active subscription.
   */
  private async pushTierToBackend(userId: number, tier: Tier): Promise<void> {
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(and(eq(subscriptions.userId, userId), eq(subscriptions.state, 'active')))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub) return;
    try {
      await this.deps.backends.fromSubscription(sub).updateUser(sub.backendUserId, {
        trafficLimitBytes: tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null,
        trafficLimitStrategy: tier.trafficStrategy,
        hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
        remnawaveSquadUuid: tier.remnawaveSquadUuid,
      });
    } catch (err) {
      this.deps.logger.warn('membership_sync_backend_push_failed', {
        userId,
        backend: sub.backend,
        backendUserId: sub.backendUserId,
        error: String(err),
      });
    }
  }

  /**
   * Disable the user's live backend subscription. Used by `runGraceSweep`'s
   * disabled branch so a lapsed member's proxy key actually stops routing.
   */
  private async disableBackendForUser(userId: number): Promise<void> {
    const subRow = await this.deps.db
      .select()
      .from(subscriptions)
      .where(and(eq(subscriptions.userId, userId), eq(subscriptions.state, 'active')))
      .limit(1)
      .all();
    const sub = subRow[0];
    if (!sub) return;
    try {
      await this.deps.backends.fromSubscription(sub).updateUser(sub.backendUserId, {
        status: 'disabled',
      });
    } catch (err) {
      this.deps.logger.warn('membership_sync_backend_disable_failed', {
        userId,
        backend: sub.backend,
        backendUserId: sub.backendUserId,
        error: String(err),
      });
    }
  }

  private async transitionToGrace(userId: number): Promise<void> {
    await this.deps.db
      .update(users)
      .set({ status: 'grace', updatedAt: Date.now() })
      .where(eq(users.id, userId));
    await this.deps.audit.record({
      actorType: 'system',
      action: 'membership.transition.grace',
      targetType: 'user',
      targetId: String(userId),
    });

    // Fire grace-warning email — deduped per (user, grace cycle) so a user who
    // flips back to active and then lapses again gets a fresh warning.
    const userRow = await this.deps.db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1)
      .all();
    const user = userRow[0];
    if (user?.email && user.membershipExpiresAt) {
      const tier = await this.deps.tierPolicy.getById(user.tierId);
      const graceEndsAt = new Date(
        user.membershipExpiresAt + (tier?.expirationDaysAfterMembershipLapse ?? 7) * 86_400_000,
      ).toISOString();
      await this.deps.email.send({
        to: user.email,
        templateKey: 'member.grace_warning',
        params: { userId: user.id, graceEndsAt },
        dedupeKey: `grace_warning:user:${user.id}:expires:${user.membershipExpiresAt}`,
        ...renderGraceWarning({
          graceEndsAt,
          renewUrl: `${this.deps.config.WEBAUTHN_ORIGIN}/account`,
        }),
      });
    }
  }

  async runGraceSweep(): Promise<{ toGrace: number; toDisabled: number }> {
    const now = Date.now();
    const toGraceRows = await this.deps.db
      .select()
      .from(users)
      .where(
        sql`${users.status} = 'active' AND ${users.membershipExpiresAt} IS NOT NULL AND ${users.membershipExpiresAt} < ${now}`,
      )
      .limit(500)
      .all();
    for (const row of toGraceRows) {
      await this.transitionToGrace(row.id);
    }
    const toDisabledRows = await this.deps.db
      .select()
      .from(users)
      .where(
        // Disable once the user is past THEIR tier's grace window, not a flat
        // 7 days — matches the graceEndsAt the warning email promises. The
        // per-tier value is read via a correlated subquery (column default is 7).
        sql`${users.status} = 'grace' AND ${users.membershipExpiresAt} IS NOT NULL AND ${users.membershipExpiresAt} + (SELECT expiration_days_after_membership_lapse FROM tiers WHERE tiers.id = ${users.tierId}) * 86400000 < ${now}`,
      )
      .limit(500)
      .all();
    for (const row of toDisabledRows) {
      await this.deps.db
        .update(users)
        .set({
          status: 'disabled',
          disabledReason: 'membership_lapsed',
          suspendedAt: now,
          updatedAt: now,
        })
        .where(eq(users.id, row.id));
      // Disable the backend subscription too, otherwise the user's proxy key
      // keeps routing traffic indefinitely after their membership lapses.
      await this.disableBackendForUser(row.id);
      // Fire disabled email — deduped per (user, expiry cycle).
      if (row.email && row.membershipExpiresAt) {
        await this.deps.email.send({
          to: row.email,
          templateKey: 'member.disabled',
          params: { userId: row.id },
          dedupeKey: `disabled:user:${row.id}:expires:${row.membershipExpiresAt}`,
          ...renderDisabled({
            renewUrl: `${this.deps.config.WEBAUTHN_ORIGIN}/account`,
            freeTierKeyUrl: `${this.deps.config.WEBAUTHN_ORIGIN}/get-key`,
          }),
        });
      }
      await this.deps.audit.record({
        actorType: 'system',
        action: 'membership.transition.disabled',
        targetType: 'user',
        targetId: String(row.id),
      });
    }
    return { toGrace: toGraceRows.length, toDisabled: toDisabledRows.length };
  }
}
