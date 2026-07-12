/**
 * P2: retention sweeps for the append-only tables that otherwise grow without
 * bound (auditLog, webhookEvents, tierHistory, …). Each is a daily,
 * paginated delete of rows older than a per-table window. Conservative windows;
 * tune via env if needed. Uses the system `by_creation_time` index (or the
 * table's own time index) so deletes are a bounded range scan, not a full table.
 */
import { internalMutation } from './_generated/server';
import { v } from 'convex/values';
import { recordHeartbeat } from './cronHeartbeat';

const DAY = 86_400_000;
const HOUR = 3_600_000;
const PAGE = 1000;

const num = (envKey: string, fallbackDays: number): number => {
  const raw = Number(process.env[envKey]);
  return Number.isFinite(raw) && raw > 0 ? raw : fallbackDays;
};

/** Audit log: keep ~180 days by default (AUDIT_RETENTION_DAYS). */
export const sweepAuditLog = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-audit');
    const cutoff = Date.now() - num('AUDIT_RETENTION_DAYS', 180) * DAY;
    const rows = await ctx.db
      .query('auditLog')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/** Webhook dedupe records: keep ~90 days (far beyond any replay window). */
export const sweepWebhookEvents = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-webhooks');
    const cutoff = Date.now() - num('WEBHOOK_RETENTION_DAYS', 90) * DAY;
    const rows = await ctx.db
      .query('webhookEvents')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/**
 * Passkey assertion challenges: minutes-long TTLs, but the rows were insert-only
 * (consumption is a patch) and grew without bound. Delete anything expired at
 * least a day ago — consumed or not — via the by_expires index.
 */
export const sweepWebauthnAuthChallenges = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-webauthn-auth');
    const cutoff = Date.now() - num('WEBAUTHN_CHALLENGE_RETENTION_DAYS', 1) * DAY;
    const rows = await ctx.db
      .query('webauthnAuthChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/** Passkey registration challenges: same shape as the assertion sweep above. */
export const sweepWebauthnRegistrationChallenges = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-webauthn-reg');
    const cutoff = Date.now() - num('WEBAUTHN_CHALLENGE_RETENTION_DAYS', 1) * DAY;
    const rows = await ctx.db
      .query('webauthnRegistrationChallenges')
      .withIndex('by_expires', (q) => q.lt('expiresAt', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/** Tier-change history: keep ~365 days. */
export const sweepTierHistory = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-tier-history');
    const cutoff = Date.now() - num('TIER_HISTORY_RETENTION_DAYS', 365) * DAY;
    const rows = await ctx.db
      .query('tierHistory')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
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
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-subscriptions');
    const cutoff = Date.now() - num('SUBSCRIPTION_RETENTION_DAYS', 90) * DAY;
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'deleted').lt('deletedAt', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
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
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    await recordHeartbeat(ctx, 'retention-billing-orders');
    const cutoff = Date.now() - num('BILLING_ORDER_RETENTION_DAYS', 365) * DAY;
    const page = limit ?? PAGE;
    let removed = 0;
    for (const status of ['paid', 'failed', 'expired'] as const) {
      const rows = await ctx.db
        .query('billingOrders')
        .withIndex('by_status', (q) => q.eq('status', status).lt('_creationTime', cutoff))
        .take(page);
      for (const r of rows) await ctx.db.delete(r._id);
      removed += rows.length;
    }
    return { removed };
  },
});
