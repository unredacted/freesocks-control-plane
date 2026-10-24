/**
 * P2: retention sweeps for the append-only tables that otherwise grow without
 * bound (auditLog, webhookEvents, tierHistory, …). Each is a daily,
 * paginated delete of rows older than a per-table window. Conservative windows;
 * tune via env if needed. Uses the system `by_creation_time` index (or the
 * table's own time index) so deletes are a bounded range scan, not a full table.
 */
import { internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { recordHeartbeat } from './cronHeartbeat';

const DAY = 86_400_000;
const HOUR = 3_600_000;
const PAGE = 1000;
// Rows with per-row child cleanup (destroyed edges → probe rollups) page smaller.
const EDGE_PAGE = 50;

/**
 * A sweep that deletes a FULL page has more to drain: re-run immediately (each
 * run is its own transaction) instead of waiting a day for the next cron tick —
 * one page/day can never catch up once a table accrues faster than that (L4).
 * Bounded so a pathological table can't chain forever; a warn names the straggler.
 */
const MAX_DRAIN_ROUNDS = 50;

const num = (envKey: string, fallbackDays: number): number => {
  const raw = Number(process.env[envKey]);
  return Number.isFinite(raw) && raw > 0 ? raw : fallbackDays;
};

/** Audit log: keep ~180 days by default (AUDIT_RETENTION_DAYS). */
export const sweepAuditLog = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-audit');
    const cutoff = Date.now() - num('AUDIT_RETENTION_DAYS', 180) * DAY;
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('auditLog')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-audit] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.retention.sweepAuditLog, { rounds: n + 1 });
    }
    return { removed: rows.length };
  },
});

/** Webhook dedupe records: keep ~90 days of TERMINAL (`processed`) rows (far
 *  beyond any replay window). `pending`/`failed` claims are exempt from the
 *  sweep — they're documented as retryable, and deleting one would let a
 *  processor redelivery past the window re-ingest (double-grant). A wedged
 *  pending claim therefore stays until it resolves, which is intentional. */
export const sweepWebhookEvents = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-webhooks');
    const cutoff = Date.now() - num('WEBHOOK_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? PAGE;
    // by_status = ['status', _creationTime]: an exact range over terminal rows.
    const rows = await ctx.db
      .query('webhookEvents')
      .withIndex('by_status', (q) => q.eq('status', 'processed').lt('_creationTime', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-webhooks] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepWebhookEvents, { rounds: n + 1 });
    }
    return { removed: rows.length };
  },
});

/**
 * Passkey assertion challenges: minutes-long TTLs, but the rows were insert-only
 * (consumption is a patch) and grew without bound. Delete anything expired at
 * least a day ago — consumed or not — via the by_expires index.
 */
export const sweepWebauthnAuthChallenges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-webauthn-auth');
    const cutoff = Date.now() - num('WEBAUTHN_CHALLENGE_RETENTION_DAYS', 1) * DAY;
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('webauthnAuthChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-webauthn-auth] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepWebauthnAuthChallenges, {
          rounds: n + 1,
        });
    }
    return { removed: rows.length };
  },
});

/** Passkey registration challenges: same shape as the assertion sweep above. */
export const sweepWebauthnRegistrationChallenges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-webauthn-reg');
    const cutoff = Date.now() - num('WEBAUTHN_CHALLENGE_RETENTION_DAYS', 1) * DAY;
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('webauthnRegistrationChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-webauthn-reg] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepWebauthnRegistrationChallenges, {
          rounds: n + 1,
        });
    }
    return { removed: rows.length };
  },
});

/** Tier-change history: keep ~365 days. */
export const sweepTierHistory = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-tier-history');
    const cutoff = Date.now() - num('TIER_HISTORY_RETENTION_DAYS', 365) * DAY;
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('tierHistory')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-tier-history] drain cap hit; remainder next run');
      else await ctx.scheduler.runAfter(0, internal.retention.sweepTierHistory, { rounds: n + 1 });
    }
    return { removed: rows.length };
  },
});

/**
 * Long-deleted subscription rows: keep ~90 days. A row reaches state:'deleted'
 * only AFTER its backend user is gone (deleteSubscriptionEverywhere marks it
 * last), so these are pure history — but they used to accumulate forever for
 * paid users (each regenerate/switch leaves one), bloating the per-user
 * resolvers. Range-scans the (state, deletedAt) index. Tombstoned (disabled)
 * rows are NOT touched: the tombstone sweep owns those.
 */
export const sweepDeletedSubscriptions = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-subscriptions');
    const cutoff = Date.now() - num('SUBSCRIPTION_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'deleted').lt('deletedAt', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-subscriptions] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepDeletedSubscriptions, {
          rounds: n + 1,
        });
    }
    return { removed: rows.length };
  },
});

/**
 * Expire abandoned checkouts: a pending/confirming billing order with no
 * terminal webhook past BILLING_PENDING_TTL_HOURS (default 48) flips to
 * `expired`. NEVER grants — only a `paid` webhook does. Range-scans the by_status
 * index per non-terminal status (Convex appends `_creationTime`). Runs often
 * (abandoned checkouts are common); kept as PATCH (not delete) so the order
 * lifecycle stays auditable until the retention sweep below deletes it.
 */
export const expireStalePendingOrders = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'billing-pending-sweep');
    const cutoff = Date.now() - num('BILLING_PENDING_TTL_HOURS', 48) * HOUR;
    const page = limit ?? PAGE;
    let expired = 0;
    for (const status of ['pending', 'confirming'] as const) {
      const rows = await ctx.db
        .query('billingOrders')
        .withIndex('by_status', (q) => q.eq('status', status).lt('_creationTime', cutoff))
        .take(page);
      for (const r of rows) {
        await ctx.db.patch(r._id, { status: 'expired', updatedAt: Date.now() });
        expired++;
      }
    }
    return { expired };
  },
});

/**
 * Gift-reveal backstop: clear the transient plaintext code buffer from gift
 * orders PAID more than BILLING_GIFT_REVEAL_TTL_HOURS (default 24) ago that the
 * buyer never acknowledged, so plaintext gift codes never linger at rest. (An
 * explicit ack clears it sooner; the codes themselves remain hash-only in
 * redemptionCodes.) The window runs from paidAt, not order creation: a slow
 * crypto confirmation or an operator grant days after checkout used to lose its
 * codes to the next hourly sweep before the buyer could see them.
 */
export const clearStaleGiftReveals = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'billing-gift-reveal-sweep');
    const cutoff = Date.now() - num('BILLING_GIFT_REVEAL_TTL_HOURS', 24) * HOUR;
    // Scan ONLY unacked gift reveals (giftRevealPending=true) paid before the
    // cutoff, via a dedicated index (oldest paidAt first). The old by_status='paid'
    // scan cleared nothing once >PAGE paid self-orders predated the window; here
    // cleared rows drop giftRevealPending and leave the eq(true) index by
    // construction, so the sweep always makes progress. (Review #5.)
    const rows = await ctx.db
      .query('billingOrders')
      .withIndex('by_gift_reveal_pending_paid', (q) =>
        q.eq('giftRevealPending', true).lt('paidAt', cutoff),
      )
      .take(limit ?? PAGE);
    for (const r of rows) {
      await ctx.db.patch(r._id, {
        giftReveal: undefined,
        giftRevealAck: true,
        giftRevealPending: undefined,
        updatedAt: Date.now(),
      });
    }
    return { cleared: rows.length };
  },
});

/**
 * One-off backfill (Review #5): gift orders paid BEFORE `giftRevealPending` existed
 * carry a plaintext `giftReveal` but no flag, so clearStaleGiftReveals (which scans
 * only the by_gift_reveal_pending_paid index) never clears them. Flag any unacked paid
 * gift order so the normal sweep clears it on its next run. Paged by the by_status
 * index + a _creationTime cursor, idempotent (a flagged row no longer matches).
 * Run `bunx convex run retention:backfillGiftRevealPending '{}'`; if it returns a
 * nextCursor, re-run with `{"cursor": <n>}` until null. Likely a no-op (gifting is new).
 */
export const backfillGiftRevealPending = internalMutation({
  args: { limit: v.optional(v.number()), cursor: v.optional(v.number()) },
  handler: async (ctx, { limit, cursor }) => {
    const page = limit ?? PAGE;
    const rows = await ctx.db
      .query('billingOrders')
      .withIndex('by_status', (q) =>
        cursor != null
          ? q.eq('status', 'paid').gt('_creationTime', cursor)
          : q.eq('status', 'paid'),
      )
      .take(page);
    let flagged = 0;
    for (const r of rows) {
      if (
        r.kind === 'gift' &&
        (r.giftReveal?.length ?? 0) > 0 &&
        r.giftRevealPending === undefined &&
        r.giftRevealAck !== true
      ) {
        await ctx.db.patch(r._id, { giftRevealPending: true, updatedAt: Date.now() });
        flagged++;
      }
    }
    const nextCursor = rows.length === page ? (rows[rows.length - 1]?._creationTime ?? null) : null;
    return { scanned: rows.length, flagged, nextCursor };
  },
});

/** Terminal billing orders (paid/failed/expired): keep ~365 days for accounting. */
export const sweepBillingOrders = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-billing-orders');
    const cutoff = Date.now() - num('BILLING_ORDER_RETENTION_DAYS', 365) * DAY;
    const page = limit ?? PAGE;
    let removed = 0;
    let full = false;
    for (const status of ['paid', 'failed', 'expired'] as const) {
      const rows = await ctx.db
        .query('billingOrders')
        .withIndex('by_status', (q) => q.eq('status', status).lt('_creationTime', cutoff))
        .take(page);
      for (const r of rows) await ctx.db.delete(r._id);
      removed += rows.length;
      if (rows.length === page) full = true;
    }
    if (full) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-billing-orders] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepBillingOrders, { rounds: n + 1 });
    }
    return { removed };
  },
});

// --- origin edges ------------------------------------------------------------------------------

/**
 * Destroyed edges: the row is a ledger of what existed; keep ~30 days
 * (EDGE_RETENTION_DAYS), then delete in bounded pages via the `by_status`
 * index (status + statusChangedAt = an exact range). Rotations keep referring
 * to the id; every reader treats a missing edge as null.
 */
export const sweepDestroyedEdges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-edges');
    const cutoff = Date.now() - num('EDGE_RETENTION_DAYS', 30) * DAY;
    // Each edge drags its probe rollups (countries × sources × families ×
    // ports) into the same transaction, so the page is small; the drain rounds
    // still clear a backlog instead of retrying one oversized page.
    const page = limit ?? EDGE_PAGE;
    const rows = await ctx.db
      .query('edges')
      .withIndex('by_status', (q) => q.eq('status', 'destroyed').lt('statusChangedAt', cutoff))
      .take(page);
    for (const r of rows) {
      // Nothing cascades in Convex: the edge's probe rollups (keyed by its id
      // as a string, bounded per target: countries × sources × families ×
      // ports) would otherwise outlive it forever, unreachable through any
      // live edge.
      const rollups = await ctx.db
        .query('probeReachability')
        .withIndex('by_target_country', (q) => q.eq('targetKind', 'edge').eq('targetRef', r._id))
        .collect();
      for (const x of rollups) await ctx.db.delete(x._id);
      await ctx.db.delete(r._id);
    }
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-edges] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepDestroyedEdges, { rounds: n + 1 });
    }
    return { removed: rows.length };
  },
});

const TERMINAL_ROTATION_PHASES = [
  'done',
  'failed',
  'rolled_back',
  'quarantined',
  'cancelled',
] as const;

/**
 * Terminal rotations: keep ~90 days (EDGE_ROTATION_RETENTION_DAYS) via the
 * `by_phase_finished` index (phase + finishedAt). A `quarantined` row that a
 * origin's live quarantine still points at is kept whatever its age (it is the
 * operator's evidence until resolved).
 */
export const sweepEdgeRotations = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-edge-rotations');
    const cutoff = Date.now() - num('EDGE_ROTATION_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? PAGE;
    let removed = 0;
    let full = false;
    for (const phase of TERMINAL_ROTATION_PHASES) {
      const rows = await ctx.db
        .query('edgeRotations')
        .withIndex('by_phase_finished', (q) =>
          q.eq('phase', phase).gt('finishedAt', 0).lt('finishedAt', cutoff),
        )
        .take(page);
      for (const r of rows) {
        if (phase === 'quarantined') {
          const relay = await ctx.db.get(r.relayId);
          if (relay?.quarantine?.rotationId === r._id) continue;
        }
        await ctx.db.delete(r._id);
        removed++;
      }
      if (rows.length === page) full = true;
    }
    if (full) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-edge-rotations] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepEdgeRotations, { rounds: n + 1 });
    }
    return { removed };
  },
});

// --- the servers and edges workflow tables ---------------------------------------------------------
//
// Ledger ops, name rollouts, setup runs, activation runs, Host hides, port
// changes, maintenance holds and obligations all accrue a row per action and are
// read by index, never swept by their own modules. Each sweep deletes TERMINAL
// rows past a window (90 days by default) and keeps every row something still
// reads: the cursor steps past a kept row, so a run of them never stalls the
// drain (a row left at a page boundary is seen again the next day). Not swept,
// by design: node renames and their aliases (a former name stays reserved and
// keeps resolving), a node's retirement (its intent points at it and keeps the
// name reserved; one row per node ever retired), the ownership rows (a
// tombstone is what refuses re-creating an object removed on purpose; one row
// per backend object), mirror upload records (one open row per object, deleted
// when settled) and the vantage tables (`sniVantage.sweep` keeps its own window).

const WORKFLOW_PAGE = 100;
const cursorArg = v.optional(v.object({ i: v.number(), after: v.number() }));
type SweepCursor = { i: number; after: number };

/** Next round: the same state past the last row seen, else the next state, else done. */
function nextCursor(
  c: SweepCursor,
  states: number,
  full: boolean,
  lastAt: number,
): SweepCursor | null {
  if (full) return { i: c.i, after: lastAt };
  return c.i + 1 < states ? { i: c.i + 1, after: 0 } : null;
}

async function chain(
  label: string,
  rounds: number | undefined,
  next: SweepCursor | null,
  schedule: (args: { rounds: number; cursor: SweepCursor }) => Promise<unknown>,
): Promise<void> {
  if (!next) return;
  const n = rounds ?? 0;
  if (n >= MAX_DRAIN_ROUNDS) console.warn(`[${label}] drain cap hit; remainder next run`);
  else await schedule({ rounds: n + 1, cursor: next });
}

/**
 * Settled ledger ops (`panelOps`, closed) past PANEL_OP_RETENTION_DAYS (90).
 * Kept while a claim, a name rollout, a port change or a node rename names the
 * op: a port change and a rollout read their outcome from it.
 */
export const sweepPanelOps = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-panel-ops');
    const cutoff = Date.now() - num('PANEL_OP_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('panelOps')
      .withIndex('by_open_updated', (q) =>
        q.eq('open', false).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const op of rows) {
      const named = await Promise.all([
        ctx.db
          .query('panelClaims')
          .withIndex('by_op', (q) => q.eq('opId', op._id))
          .first(),
        ctx.db
          .query('sniRollouts')
          .withIndex('by_op', (q) => q.eq('opId', op._id))
          .first(),
        ctx.db
          .query('panelPortChanges')
          .withIndex('by_op', (q) => q.eq('opId', op._id))
          .first(),
        ctx.db
          .query('panelNodeRenames')
          .withIndex('by_op', (q) => q.eq('opId', op._id))
          .first(),
      ]);
      if (named.some((x) => x !== null)) continue;
      await ctx.db.delete(op._id);
      removed++;
    }
    const next = nextCursor(c, 1, rows.length === page, rows.at(-1)?.updatedAt ?? 0);
    await chain('retention-panel-ops', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepPanelOps, args),
    );
    return { removed };
  },
});

const ROLLOUT_DONE = ['panel_confirmed', 'failed', 'superseded'] as const;

/**
 * Finished server-name rollouts past SNI_ROLLOUT_RETENTION_DAYS (90), with
 * their acceptance receipts (long expired by then). The newest rollout of each
 * binding stays: it is what the binding last did.
 */
export const sweepSniRollouts = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-sni-rollouts');
    const cutoff = Date.now() - num('SNI_ROLLOUT_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('sniRollouts')
      .withIndex('by_phase_updated', (q) =>
        q.eq('phase', ROLLOUT_DONE[c.i]).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const r of rows) {
      const newest = await ctx.db
        .query('sniRollouts')
        .withIndex('by_binding', (q) => q.eq('bindingId', r.bindingId))
        .order('desc')
        .first();
      if (newest?._id === r._id) continue;
      for (const receipt of await ctx.db
        .query('sniAcceptanceReceipts')
        .withIndex('by_rollout', (q) => q.eq('rolloutId', r._id))
        .collect())
        await ctx.db.delete(receipt._id);
      await ctx.db.delete(r._id);
      removed++;
    }
    const next = nextCursor(
      c,
      ROLLOUT_DONE.length,
      rows.length === page,
      rows.at(-1)?.updatedAt ?? 0,
    );
    await chain('retention-sni-rollouts', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepSniRollouts, args),
    );
    return { removed };
  },
});

const SETUP_RUN_DONE = ['done', 'done_unbound', 'failed', 'cancelled'] as const;
const ACTIVATION_OPEN = new Set(['review', 'running', 'blocked']);

/**
 * Finished guided setup runs past EDGE_SETUP_RUN_RETENTION_DAYS (90). Kept: the
 * newest run of each node (what its pages show last) and a run an open
 * activation still points at.
 */
export const sweepEdgeSetupRuns = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-edge-setup-runs');
    const cutoff = Date.now() - num('EDGE_SETUP_RUN_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('edgeSetupRuns')
      .withIndex('by_state', (q) =>
        q.eq('state', SETUP_RUN_DONE[c.i]).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const r of rows) {
      const newest = await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_origin', (q) =>
          q.eq('backendServerId', r.backendServerId).eq('nodeName', r.nodeName),
        )
        .order('desc')
        .first();
      if (newest?._id === r._id) continue;
      const act = r.activationRunId ? await ctx.db.get(r.activationRunId) : null;
      if (act && ACTIVATION_OPEN.has(act.state)) continue;
      await ctx.db.delete(r._id);
      removed++;
    }
    const next = nextCursor(
      c,
      SETUP_RUN_DONE.length,
      rows.length === page,
      rows.at(-1)?.updatedAt ?? 0,
    );
    await chain('retention-edge-setup-runs', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepEdgeSetupRuns, args),
    );
    return { removed };
  },
});

const ACTIVATION_DONE = ['committed', 'superseded', 'failed'] as const;

/**
 * Finished activation runs past ACTIVATION_RUN_RETENTION_DAYS (90). Every
 * render reads a node's runs (the delivery gate), so they must not pile up;
 * but an uncommitted run's resources stay ISOLATED from members only while the
 * row exists. Kept: the node's current run, a committed run of the node's
 * current approval (admission reads its review), and an uncommitted run while
 * any of its candidates (an edge not destroyed, a Host still on the backend)
 * outside the committed set remains.
 */
export const sweepActivationRuns = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-activation-runs');
    const cutoff = Date.now() - num('ACTIVATION_RUN_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('panelActivationRuns')
      .withIndex('by_state_updated', (q) =>
        q.eq('state', ACTIVATION_DONE[c.i]).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const r of rows) {
      const intent = await ctx.db.get(r.intentId);
      if (intent) {
        if (intent.activation.currentRunId === r._id) continue;
        if (r.state === 'committed') {
          if (r.candidate.reviewHash === intent.approved?.reviewHash) continue;
        } else {
          const committed = intent.approved?.committed ?? { hostUuids: [], edgeIds: [] };
          let live = false;
          for (const e of r.resources.edgeIds) {
            if (committed.edgeIds.includes(e)) continue;
            const id = ctx.db.normalizeId('edges', e);
            const edge = id ? await ctx.db.get(id) : null;
            if (edge && edge.status !== 'destroyed') live = true;
          }
          for (const h of r.resources.hostUuids) {
            if (committed.hostUuids.includes(h)) continue;
            const host = await ctx.db
              .query('panelHosts')
              .withIndex('by_server_uuid', (q) =>
                q.eq('backendServerId', r.backendServerId).eq('hostUuid', h),
              )
              .first();
            if (host) live = true;
          }
          if (live) continue;
        }
      }
      await ctx.db.delete(r._id);
      removed++;
    }
    const next = nextCursor(
      c,
      ACTIVATION_DONE.length,
      rows.length === page,
      rows.at(-1)?.updatedAt ?? 0,
    );
    await chain('retention-activation-runs', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepActivationRuns, args),
    );
    return { removed };
  },
});

/**
 * Released direct-Host hide rows past EDGE_HOST_HIDE_RETENTION_DAYS (90). An
 * origin that ever hid a Host keeps the newest row of that Host (whether a
 * restore workflow is needed is decided from those rows), and nothing is
 * deleted while its restore runs. Rows of a deleted origin all go.
 */
export const sweepHostHides = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-edge-host-hides');
    const cutoff = Date.now() - num('EDGE_HOST_HIDE_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('edgeHostHides')
      .withIndex('by_state_updated', (q) =>
        q.eq('state', 'released').gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const r of rows) {
      const relay = await ctx.db.get(r.relayId);
      if (relay) {
        if (relay.restore) continue;
        const newest = (
          await ctx.db
            .query('edgeHostHides')
            .withIndex('by_host', (q) => q.eq('hostUuid', r.hostUuid))
            .order('desc')
            .take(50)
        ).find((x) => x.relayId === r.relayId);
        if (!newest || newest._id === r._id) continue;
      }
      await ctx.db.delete(r._id);
      removed++;
    }
    const next = nextCursor(c, 1, rows.length === page, rows.at(-1)?.updatedAt ?? 0);
    await chain('retention-edge-host-hides', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepHostHides, args),
    );
    return { removed };
  },
});

const PORT_CHANGE_DONE = ['refused', 'cancelled', 'applying'] as const;

/**
 * Finished port changes past PORT_CHANGE_RETENTION_DAYS (90), with their
 * per-node requirements. A claimed (`applying`) change is finished once its op
 * closed; its op becomes sweepable after the change is gone.
 */
export const sweepPortChanges = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-port-changes');
    const cutoff = Date.now() - num('PORT_CHANGE_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('panelPortChanges')
      .withIndex('by_state_updated', (q) =>
        q.eq('state', PORT_CHANGE_DONE[c.i]).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const r of rows) {
      if (r.state === 'applying') {
        const op = r.opId ? await ctx.db.get(r.opId) : null;
        if (op?.open) continue;
      }
      for (const req of await ctx.db
        .query('panelPortRequirements')
        .withIndex('by_change', (q) => q.eq('changeId', r._id))
        .collect())
        await ctx.db.delete(req._id);
      await ctx.db.delete(r._id);
      removed++;
    }
    const next = nextCursor(
      c,
      PORT_CHANGE_DONE.length,
      rows.length === page,
      rows.at(-1)?.updatedAt ?? 0,
    );
    await chain('retention-port-changes', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepPortChanges, args),
    );
    return { removed };
  },
});

/**
 * Released maintenance holds past MAINTENANCE_HOLD_RETENTION_DAYS (90). The gate
 * reads only open holds and an open hold is never swept, whatever its age; the
 * audit log keeps the transition and its release.
 */
export const sweepMaintenanceHolds = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()) },
  handler: async (ctx, { limit, rounds }) => {
    await recordHeartbeat(ctx, 'retention-maintenance-holds');
    const cutoff = Date.now() - num('MAINTENANCE_HOLD_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const rows = await ctx.db
      .query('panelMaintenanceHolds')
      .withIndex('by_released_updated', (q) => q.eq('released', true).lt('updatedAt', cutoff))
      .take(page);
    for (const r of rows) await ctx.db.delete(r._id);
    if (rows.length === page) {
      const n = rounds ?? 0;
      if (n >= MAX_DRAIN_ROUNDS)
        console.warn('[retention-maintenance-holds] drain cap hit; remainder next run');
      else
        await ctx.scheduler.runAfter(0, internal.retention.sweepMaintenanceHolds, {
          rounds: n + 1,
        });
    }
    return { removed: rows.length };
  },
});

const OBLIGATION_SETTLED = ['confirmed', 'failed'] as const;

/**
 * Settled obligations past OBLIGATION_RETENTION_DAYS (90). An outstanding one
 * (pending, sent, unresolved) blocks its identity and is never swept. Kept: a
 * confirmed create of an origin name's DNS record, which is how FCP knows the
 * record is its own (the node's retirement withdraws it by that row; a
 * withdrawn record's row is settled `failed` and goes).
 */
export const sweepObligations = internalMutation({
  args: { limit: v.optional(v.number()), rounds: v.optional(v.number()), cursor: cursorArg },
  handler: async (ctx, { limit, rounds, cursor }) => {
    await recordHeartbeat(ctx, 'retention-obligations');
    const cutoff = Date.now() - num('OBLIGATION_RETENTION_DAYS', 90) * DAY;
    const page = limit ?? WORKFLOW_PAGE;
    const c = cursor ?? { i: 0, after: 0 };
    const rows = await ctx.db
      .query('backendObligations')
      .withIndex('by_state_updated', (q) =>
        q.eq('state', OBLIGATION_SETTLED[c.i]).gt('updatedAt', c.after).lt('updatedAt', cutoff),
      )
      .take(page);
    let removed = 0;
    for (const o of rows) {
      if (o.kind === 'dns.record' && o.verb === 'create' && o.state === 'confirmed') continue;
      await ctx.db.delete(o._id);
      removed++;
    }
    const next = nextCursor(
      c,
      OBLIGATION_SETTLED.length,
      rows.length === page,
      rows.at(-1)?.updatedAt ?? 0,
    );
    await chain('retention-obligations', rounds, next, (args) =>
      ctx.scheduler.runAfter(0, internal.retention.sweepObligations, args),
    );
    return { removed };
  },
});
