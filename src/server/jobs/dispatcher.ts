import type { PlatformAdapter } from '../platform/interface';
import { buildServices } from '../services/container';
import { propagateTierChanges } from './propagate-tier-change';
import { runOutlineHealthcheck } from './outline-healthcheck';

export type CronTask =
  | 'grace-sweep'
  | 'cleanup-expired-free'
  | 'propagate-tier-changes'
  | 'outline-healthcheck';

export async function runCronTask(task: CronTask, platform: PlatformAdapter): Promise<void> {
  // Intentionally per-run: cron is infrequent, short-lived, and never verifies
  // JWTs, so it gains nothing from the request-path service singleton — and on
  // Workers a scheduled invocation runs in its own isolate that couldn't share
  // the fetch handler's closure anyway.
  const services = buildServices(platform);
  const start = Date.now();
  platform.logger.info('cron_start', { task });
  try {
    switch (task) {
      case 'grace-sweep': {
        const result = await services.membershipSync.runGraceSweep();
        platform.logger.info('cron_grace_sweep_complete', result);
        // Outline healthcheck shares the 10-min cadence — running it here
        // saves a separate cron trigger and keeps the trigger count bounded
        // under Workers' free-tier cron limit.
        const health = await runOutlineHealthcheck(services);
        platform.logger.info('cron_outline_healthcheck_complete', { ...health });
        // Sweep subscription tombstones whose 24h overlap window has
        // elapsed — set by regenerate and switch-backend flows.
        const subsSwept = await services.subscription.sweepGracePeriodTombstones();
        if (subsSwept.swept > 0 || subsSwept.failed > 0) {
          platform.logger.info('cron_subscription_tombstones_complete', subsSwept);
        }
        break;
      }
      case 'cleanup-expired-free': {
        const removed = await services.freeTier.cleanupExpired();
        platform.logger.info('cron_free_cleanup_complete', { removed });
        break;
      }
      case 'propagate-tier-changes': {
        // Manually-runnable variant for ops or testing — normal flow runs it
        // alongside reconcile-memberships above.
        const propagated = await propagateTierChanges(services);
        platform.logger.info('cron_tier_propagation_complete', propagated);
        break;
      }
      case 'outline-healthcheck': {
        // Probes every active Outline server's /access-keys endpoint, updates
        // `lastHealthOkAt` + `accessKeyCount`. Drives the pool's scoring and
        // the admin UI's health badge. Runs every 10 min, sharing the slot
        // with `grace-sweep` — they're both cheap and independent.
        const health = await runOutlineHealthcheck(services);
        platform.logger.info('cron_outline_healthcheck_complete', { ...health });
        break;
      }
    }
  } catch (err) {
    platform.logger.error('cron_failed', { task, error: String(err) });
    throw err;
  } finally {
    platform.logger.info('cron_end', { task, durationMs: Date.now() - start });
  }
}

export function scheduledHandlerToTask(cron: string): CronTask | null {
  // Map our wrangler cron triggers to tasks. Keep ordering aligned with wrangler.toml.
  // The */5 slot formerly drove CiviCRM reconcile; it now runs tier propagation
  // (membership entitlements arrive via setMembership, not a poll).
  if (cron.startsWith('*/5 ')) return 'propagate-tier-changes';
  if (cron.startsWith('*/10 ')) return 'grace-sweep';
  if (cron.startsWith('0 3 ')) return 'cleanup-expired-free';
  return null;
}
