import { and, eq, gt, sql } from 'drizzle-orm';
import { subscriptions, users } from '../db/schema';
import type { ServiceContainer } from '../services/container';

const BATCH_SIZE = 50;
const MAX_PER_RUN = 500;
const PROPAGATION_LOCK_KEY = 'lock:tier-propagation';

/**
 * Bulk-applies the current tier definition to all users on that tier.
 *
 * Queued automatically by `TierPolicyService.upsert` whenever a propagation-
 * relevant field changes (traffic limit, device limit, HWID config, squad).
 *
 * Designed to run from cron with cursor-based resumption — if we hit the
 * MAX_PER_RUN cap (e.g. a tier with 50k users), the next cron tick continues
 * from where we left off without re-applying earlier batches.
 *
 * Importantly: tier-definition changes do NOT reset traffic counters. A user
 * mid-billing-cycle keeps their existing usage; only the cap moves. This is
 * deliberate — see plan doc tier semantics.
 */
export async function propagateTierChanges(services: ServiceContainer): Promise<{
  tiersProcessed: number;
  usersUpdated: number;
}> {
  // Best-effort cross-instance lock so two overlapping cron ticks don't both
  // walk the propagation queue and double-PATCH users / race the per-tier
  // cursor. Self-host already has the in-process runGuarded; this covers the
  // Workers/KV path. Not an atomic CAS — a rare overlap remains possible but
  // the backend updates are idempotent, so it's harmless.
  const kv = services.platform.kv.cache;
  if (await kv.get(PROPAGATION_LOCK_KEY)) {
    services.platform.logger.info('tier_propagation_locked', { reason: 'another run in progress' });
    return { tiersProcessed: 0, usersUpdated: 0 };
  }
  await kv.put(PROPAGATION_LOCK_KEY, String(Date.now()), { expirationTtl: 300 });
  try {
    return await runPropagation(services);
  } finally {
    await kv.delete(PROPAGATION_LOCK_KEY);
  }
}

async function runPropagation(services: ServiceContainer): Promise<{
  tiersProcessed: number;
  usersUpdated: number;
}> {
  const platform = services.platform;
  const pending = await services.tierPolicy.listPendingPropagations();
  if (pending.length === 0) {
    return { tiersProcessed: 0, usersUpdated: 0 };
  }

  let totalUpdated = 0;
  let tiersProcessed = 0;

  for (const job of pending) {
    if (totalUpdated >= MAX_PER_RUN) break;
    const tier = await services.tierPolicy.getById(job.tierId);
    if (!tier) {
      // Tier deleted — drop the propagation job.
      await services.tierPolicy.clearPropagation(job.tierId);
      continue;
    }

    let cursor = job.lastUserId;
    let processedForThisTier = 0;
    let exhausted = false;

    while (totalUpdated < MAX_PER_RUN) {
      // Pull a batch of users on this tier whose id > cursor, oldest first.
      const batch = await platform.db
        .select()
        .from(users)
        .where(
          and(
            eq(users.tierId, tier.id),
            sql`${users.status} IN ('active', 'grace')`,
            gt(users.id, cursor),
          ),
        )
        .orderBy(users.id)
        .limit(BATCH_SIZE)
        .all();

      if (batch.length === 0) {
        exhausted = true;
        break;
      }

      for (const user of batch) {
        if (totalUpdated >= MAX_PER_RUN) break;
        // Look up the user's subscription to get the Remnawave UUID.
        const subRow = (
          await platform.db
            .select()
            .from(subscriptions)
            .where(and(eq(subscriptions.userId, user.id), eq(subscriptions.state, 'active')))
            .limit(1)
            .all()
        )[0];

        if (!subRow) {
          // No active subscription to PATCH; skip but advance cursor.
          cursor = user.id;
          continue;
        }

        const trafficLimitBytes =
          tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;

        try {
          // Dispatch via the SUBSCRIPTION's backend, not the tier's.
          // Backend changes on a tier deliberately don't propagate to existing
          // users (see TierPolicyService.affectsExistingUsers) — so if an
          // admin flipped a tier from Remnawave to Outline, existing users
          // still have Remnawave-backed subscriptions and we need to PATCH
          // those, not pretend they're Outline. The OutlineBackend silently
          // ignores fields it doesn't support, so passing the full patch
          // is safe for either path.
          await services.backends.fromSubscription(subRow).updateUser(subRow.backendUserId, {
            trafficLimitBytes,
            trafficLimitStrategy: tier.trafficStrategy,
            hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
            // Squad-uuid changes are a propagation trigger
            // (`affectsExistingUsers` checks it). If we don't pass it
            // through here, every queued squad change is a no-op — admin
            // sees "propagation complete" but the backend users still
            // sit in the old squad. Outline silently ignores this field;
            // Remnawave applies it.
            remnawaveSquadUuid: tier.remnawaveSquadUuid,
            // We deliberately do NOT reset traffic; admin-driven tier edits
            // shouldn't grant unearned bandwidth mid-cycle.
          });
          totalUpdated++;
          processedForThisTier++;
          cursor = user.id;
          await services.tierPolicy.setPropagationCursor(tier.id, cursor);
        } catch (err) {
          platform.logger.error('tier_propagation_user_failed', {
            tierId: tier.id,
            userId: user.id,
            backend: subRow.backend,
            backendUserId: subRow.backendUserId,
            error: String(err),
          });
          // Move past this user; we'll retry on the next propagation pass
          // for failed users only if you re-trigger the tier upsert.
          cursor = user.id;
          await services.tierPolicy.setPropagationCursor(tier.id, cursor);
        }
      }

      if (batch.length < BATCH_SIZE) {
        exhausted = true;
        break;
      }
    }

    if (exhausted) {
      await services.tierPolicy.clearPropagation(tier.id);
      tiersProcessed++;
      await services.audit.record({
        actorType: 'system',
        action: 'tier.propagation.complete',
        targetType: 'tier',
        targetId: String(tier.id),
        payload: { usersUpdated: processedForThisTier },
      });
    }
  }

  return { tiersProcessed, usersUpdated: totalUpdated };
}
