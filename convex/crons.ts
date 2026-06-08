/**
 * Scheduled jobs (P8): replaces jobs/dispatcher.ts + the per-platform cron
 * triad (Workers triggers / node-cron / external scheduler). Convex runs these
 * natively; each target is an internalAction/internalMutation already built and
 * live-tested in P5/P6. Bulk sweeps take a bounded page per run (the functions
 * cap at 100 to 500 rows) and simply catch up on the next tick.
 *
 * Tier propagation is NOT a cron: it's event-driven. lifecycle.setMembership
 * schedules pushTierToBackend via ctx.scheduler.runAfter on each tier change.
 */
import { cronJobs } from 'convex/server';
import { internal } from './_generated/api';

const crons = cronJobs();

// active→grace→disabled for lapsed memberships (per-tier grace window).
crons.interval('grace-sweep', { minutes: 10 }, internal.lifecycle.runGraceSweep, {});

// Hard-delete subscriptions whose 24h regenerate/switch-backend grace elapsed.
crons.interval('tombstone-sweep', { minutes: 10 }, internal.lifecycle.sweepTombstones, {});

// Ping active Outline servers; stamp lastHealthOkAt (feeds pool selection).
crons.interval('outline-healthcheck', { minutes: 10 }, internal.outlineServers.healthcheck, {});

// Delete free-tier users (+ backend/S3) past the expiry window.
crons.daily(
  'cleanup-expired-free',
  { hourUTC: 3, minuteUTC: 0 },
  internal.lifecycle.cleanupExpiredFree,
  {},
);

// Drop expired session + rate-limit rows (the tables that replaced KV TTLs).
crons.daily('session-sweep', { hourUTC: 3, minuteUTC: 15 }, internal.sessions.sweepExpired, {});
crons.daily(
  'rate-limit-sweep',
  { hourUTC: 3, minuteUTC: 30 },
  internal.rateLimits.sweepExpired,
  {},
);

// Drop consumed PoP request nonces past their freshness window (Phase 2).
crons.daily(
  'replay-guard-sweep',
  { hourUTC: 3, minuteUTC: 45 },
  internal.replayGuard.sweepExpired,
  {},
);

// Mint a fresh manifest-signed HPKE epoch key (CDN-blinding Phase 3); the login
// request seals to the current epoch key, not the multi-day static key. Each run
// also destroys long-expired epoch seeds (forward secrecy). No-op when the
// manifest key is unset. A daily backstop sweep runs even if rotation stalls.
crons.interval('epoch-key-rotate', { minutes: 10 }, internal.lib.e2eeCrypto.rotateEpochKey, {});
crons.daily('epoch-key-sweep', { hourUTC: 3, minuteUTC: 50 }, internal.keyEpochs.sweepExpired, {});

export default crons;
