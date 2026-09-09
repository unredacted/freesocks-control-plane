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
 * Gift-reveal backstop: clear the transient plaintext code buffer from paid gift
 * orders older than BILLING_GIFT_REVEAL_TTL_HOURS (default 24) that the buyer
 * never acknowledged, so plaintext gift codes never linger at rest. (An explicit
 * ack clears it sooner; the codes themselves remain hash-only in redemptionCodes.)
 */
export const clearStaleGiftReveals = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'billing-gift-reveal-sweep');
    const cutoff = Date.now() - num('BILLING_GIFT_REVEAL_TTL_HOURS', 24) * HOUR;
    // Scan ONLY unacked gift reveals (giftRevealPending=true) older than the TTL,
    // via a dedicated index (Convex appends _creationTime → oldest first). The old
    // by_status='paid' scan cleared nothing once >PAGE paid self-orders predated
    // the window; here cleared rows drop giftRevealPending and leave the eq(true)
    // index by construction, so the sweep always makes progress. (Review #5.)
    const rows = await ctx.db
      .query('billingOrders')
      .withIndex('by_gift_reveal_pending', (q) =>
        q.eq('giftRevealPending', true).lt('_creationTime', cutoff),
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
 * only the by_gift_reveal_pending index) never clears them. Flag any unacked paid
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

// --- relay edges ------------------------------------------------------------------------------

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
 * relay's live quarantine still points at is kept whatever its age (it is the
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
