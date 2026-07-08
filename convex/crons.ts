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

// Ping active backend instances of every type; stamp lastHealthOkAt + rtt
// (feeds pool selection). Per-type health lives in the provider registry.
crons.interval('backend-healthcheck', { minutes: 10 }, internal.backendServers.healthcheck, {});

// Deactivate + RETAIN idle free users (reclaim the key, keep the row on the free
// tier, reactivatable on return); never deletes — manual purgeInactiveFree removes.
crons.daily(
  'deactivate-idle-free',
  { hourUTC: 3, minuteUTC: 0 },
  internal.lifecycle.deactivateIdleFree,
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

// Drop expired admin invite rows (multi-admin onboarding tokens).
crons.daily(
  'admin-invite-sweep',
  { hourUTC: 3, minuteUTC: 55 },
  internal.admins.sweepExpiredInvites,
  {},
);

// Mint a fresh manifest-signed HPKE epoch key (CDN-blinding Phase 3); the login
// request seals to the current epoch key, not the multi-day static key. Each run
// also destroys long-expired epoch seeds (forward secrecy). Gated in the isolate
// (keyEpochs.maybeRotate) so a dark deployment doesn't cold-start a Node action
// every 10 min just to no-op. A daily backstop sweep runs even if rotation stalls.
crons.interval('epoch-key-rotate', { minutes: 10 }, internal.keyEpochs.maybeRotate, {});
crons.daily('epoch-key-sweep', { hourUTC: 3, minuteUTC: 50 }, internal.keyEpochs.sweepExpired, {});

// P2: retention sweeps for the append-only tables (bounded daily deletes past a
// per-table window) so storage doesn't grow without bound.
crons.daily('retention-audit', { hourUTC: 4, minuteUTC: 0 }, internal.retention.sweepAuditLog, {});
crons.daily(
  'retention-webhooks',
  { hourUTC: 4, minuteUTC: 5 },
  internal.retention.sweepWebhookEvents,
  {},
);
crons.daily(
  'retention-tier-history',
  { hourUTC: 4, minuteUTC: 10 },
  internal.retention.sweepTierHistory,
  {},
);
crons.daily(
  'retention-free-grants',
  { hourUTC: 4, minuteUTC: 15 },
  internal.retention.sweepFreeGrants,
  {},
);
crons.daily(
  'retention-subscriptions',
  { hourUTC: 4, minuteUTC: 20 },
  internal.retention.sweepDeletedSubscriptions,
  {},
);
crons.daily(
  'retention-billing-orders',
  { hourUTC: 4, minuteUTC: 25 },
  internal.retention.sweepBillingOrders,
  {},
);
crons.daily(
  'retention-webauthn-auth',
  { hourUTC: 4, minuteUTC: 30 },
  internal.retention.sweepWebauthnAuthChallenges,
  {},
);
crons.daily(
  'retention-webauthn-reg',
  { hourUTC: 4, minuteUTC: 35 },
  internal.retention.sweepWebauthnRegistrationChallenges,
  {},
);

// Expire abandoned membership checkouts (pending/confirming with no terminal
// webhook past the TTL). Frequent: abandoned checkouts are common, and an
// expired order should stop the SPA's poll promptly. Never grants.
crons.interval(
  'billing-pending-sweep',
  { minutes: 15 },
  internal.retention.expireStalePendingOrders,
  {},
);

// Backstop: clear the transient plaintext gift-code reveal from paid gift orders
// the buyer never acknowledged (an explicit ack clears it sooner), so plaintext
// gift codes never linger at rest. The codes stay hash-only in redemptionCodes.
crons.interval(
  'billing-gift-reveal-sweep',
  { hours: 1 },
  internal.retention.clearStaleGiftReveals,
  {},
);

// Keep the S3 subscription mirrors fresh: re-fetch each active sub's current
// content and re-upload it (skip-if-unchanged). No-op unless S3 mirroring is
// configured. The censorship-fallback URL is only useful if it isn't stale.
crons.interval('mirror-refresh', { hours: 6 }, internal.storage.refreshActiveMirrors, {});

// Self-heal the maintained user-status counter (statusCounters.ts) that feeds the
// /status health-gate — recomputes it exactly, correcting any missed transition bump.
crons.daily(
  'user-counts-reconcile',
  { hourUTC: 4, minuteUTC: 0 },
  internal.userStats.reconcileUserCounts,
  {},
);

export default crons;
