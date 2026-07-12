/**
 * Per-cron liveness heartbeats (W4-B4). Every scheduled job in convex/crons.ts
 * stamps `cronHeartbeats` at the START of its run via one of the two entry
 * points here; `adminApi.statusSummary` joins the rows against CRON_META to
 * flag any job the scheduler has stopped firing (surfaced on the admin
 * dashboard + the shared /api/v1/admin/status snapshot).
 *
 * Why stamp at the START (not the end): the heartbeat answers "is the cron
 * SYSTEM delivering ticks to this job?", which must stay INDEPENDENT of whether
 * the job's work succeeds. A job whose body throws every run is a different
 * alarm (surfaced via logs / backend-drift / healthcheck freshness); an
 * end-stamp would conflate the two, so a wedged backend would make an otherwise
 * healthy cron look dead. Action targets stamp via `heartbeatFromAction`
 * (committed independently of the action's later work, and never allowed to
 * throw into the job); mutation targets call `recordHeartbeat` inline.
 */
import { v } from 'convex/values';
import { internal } from './_generated/api';
import { internalMutation, type ActionCtx, type MutationCtx } from './_generated/server';

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

/**
 * Canonical registry of every job in convex/crons.ts: the heartbeat key (== the
 * cron name), its nominal cadence, and a one-line description for the dashboard.
 * A drift test (cronHeartbeat.test.ts) asserts these names match crons.ts
 * exactly, so a newly-added cron cannot silently escape heartbeat surfacing.
 * Order mirrors crons.ts (frequent intervals first, then the daily sweeps).
 */
export const CRON_META: { name: string; everyMs: number; description: string }[] = [
  {
    name: 'grace-sweep',
    everyMs: 10 * MIN,
    description: 'Lapsed memberships: active → grace → disabled',
  },
  {
    name: 'tombstone-sweep',
    everyMs: 10 * MIN,
    description: 'Hard-delete subscriptions past their 24h grace',
  },
  {
    name: 'backend-healthcheck',
    everyMs: 10 * MIN,
    description: 'Ping active backends; stamp health + fleet stats',
  },
  {
    name: 'donation-bonus-reconcile',
    everyMs: HOUR,
    description: 'Re-cap free keys to the current donation bandwidth bonus',
  },
  {
    name: 'epoch-key-rotate',
    everyMs: 10 * MIN,
    description: 'Rotate the HPKE epoch key (CDN-blinding)',
  },
  {
    name: 'billing-pending-sweep',
    everyMs: 15 * MIN,
    description: 'Expire abandoned membership checkouts',
  },
  {
    name: 'billing-gift-reveal-sweep',
    everyMs: HOUR,
    description: 'Clear stale plaintext gift-code reveals',
  },
  { name: 'mirror-refresh', everyMs: 6 * HOUR, description: 'Refresh the S3 subscription mirrors' },
  {
    name: 'deactivate-idle-free',
    everyMs: DAY,
    description: 'Deactivate + retain idle free users (reclaim key, keep row)',
  },
  {
    name: 'user-counts-reconcile',
    everyMs: DAY,
    description: 'Recompute the user-status counter (self-heal)',
  },
  { name: 'session-sweep', everyMs: DAY, description: 'Drop expired session rows' },
  { name: 'rate-limit-sweep', everyMs: DAY, description: 'Drop expired rate-limit rows' },
  {
    name: 'replay-guard-sweep',
    everyMs: DAY,
    description: 'Drop consumed PoP nonces past their window',
  },
  { name: 'admin-invite-sweep', everyMs: DAY, description: 'Drop expired admin invite tokens' },
  { name: 'epoch-key-sweep', everyMs: DAY, description: 'Destroy long-expired HPKE epoch seeds' },
  { name: 'retention-audit', everyMs: DAY, description: 'Prune the audit log past its window' },
  { name: 'retention-webhooks', everyMs: DAY, description: 'Prune webhook dedupe records' },
  { name: 'retention-tier-history', everyMs: DAY, description: 'Prune tier-change history' },
  {
    name: 'retention-subscriptions',
    everyMs: DAY,
    description: 'Prune long-deleted subscription rows',
  },
  { name: 'retention-billing-orders', everyMs: DAY, description: 'Prune terminal billing orders' },
  {
    name: 'retention-webauthn-auth',
    everyMs: DAY,
    description: 'Prune passkey assertion challenges',
  },
  {
    name: 'retention-webauthn-reg',
    everyMs: DAY,
    description: 'Prune passkey registration challenges',
  },
  {
    name: 'retention-member-webauthn-auth',
    everyMs: DAY,
    description: 'Prune member passkey assertion challenges',
  },
  {
    name: 'retention-member-webauthn-reg',
    everyMs: DAY,
    description: 'Prune member passkey registration challenges',
  },
];

/**
 * A job is stale once it is overdue by ~1.5 cadences plus 10 min of slack —
 * enough to absorb one missed tick and scheduler jitter without false-alarming
 * (a 10-min cron flags at ~25 min; a daily at ~1.5 days).
 */
export function cronStaleAfterMs(everyMs: number): number {
  return Math.round(everyMs * 1.5) + 10 * MIN;
}

/** Core upsert. Used directly by mutation-context cron targets. Tolerant of any
 *  stray duplicate row (`.first()`, never `.unique()`), so it can never throw. */
export async function recordHeartbeat(ctx: MutationCtx, name: string): Promise<void> {
  const existing = await ctx.db
    .query('cronHeartbeats')
    .withIndex('by_name', (q) => q.eq('name', name))
    .first();
  const now = Date.now();
  if (existing) {
    await ctx.db.patch(existing._id, { lastRunAt: now, runCount: existing.runCount + 1 });
  } else {
    await ctx.db.insert('cronHeartbeats', { name, lastRunAt: now, runCount: 1 });
  }
}

/** Heartbeat entry point for action-context cron targets. Commits independently
 *  of the action's later work, and swallows any error: a heartbeat write must
 *  NEVER break the actual scheduled job. */
export async function heartbeatFromAction(ctx: ActionCtx, name: string): Promise<void> {
  try {
    await ctx.runMutation(internal.cronHeartbeat.stamp, { name });
  } catch {
    // Intentionally ignored — observability must not affect the job it observes.
  }
}

/** The mutation `heartbeatFromAction` calls; also stampable on its own. */
export const stamp = internalMutation({
  args: { name: v.string() },
  handler: async (ctx, { name }) => {
    await recordHeartbeat(ctx, name);
  },
});
