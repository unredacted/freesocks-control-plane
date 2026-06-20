/**
 * P2: retention sweeps for the append-only tables that otherwise grow without
 * bound (auditLog, webhookEvents, tierHistory, freeGrants). Each is a daily,
 * paginated delete of rows older than a per-table window. Conservative windows;
 * tune via env if needed. Uses the system `by_creation_time` index (or the
 * table's own time index) so deletes are a bounded range scan, not a full table.
 */
import { internalMutation } from './_generated/server';
import { v } from 'convex/values';

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
    const cutoff = Date.now() - num('WEBHOOK_RETENTION_DAYS', 90) * DAY;
    const rows = await ctx.db
      .query('webhookEvents')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/** Tier-change history: keep ~365 days. */
export const sweepTierHistory = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
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
    const cutoff = Date.now() - num('SUBSCRIPTION_RETENTION_DAYS', 90) * DAY;
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'deleted').lt('deletedAt', cutoff))
      .take(limit ?? PAGE);
    for (const r of rows) await ctx.db.delete(r._id);
    return { removed: rows.length };
  },
});

/** Free-grant issuance ledger: keep ~30 days (the per-(IP,day) cap window + buffer). */
export const sweepFreeGrants = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
    const cutoff = Date.now() - num('FREE_GRANT_RETENTION_DAYS', 30) * DAY;
    const rows = await ctx.db
      .query('freeGrants')
      .withIndex('by_granted_at', (q) => q.lt('grantedAt', cutoff))
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
    const cutoff = Date.now() - num('BILLING_GIFT_REVEAL_TTL_HOURS', 24) * HOUR;
    const rows = await ctx.db
      .query('billingOrders')
      .withIndex('by_status', (q) => q.eq('status', 'paid').lt('_creationTime', cutoff))
      .take(limit ?? PAGE);
    let cleared = 0;
    for (const r of rows) {
      if (r.kind === 'gift' && r.giftReveal && r.giftReveal.length > 0) {
        await ctx.db.patch(r._id, {
          giftReveal: undefined,
          giftRevealAck: true,
          updatedAt: Date.now(),
        });
        cleared++;
      }
    }
    return { cleared };
  },
});

/** Terminal billing orders (paid/failed/expired): keep ~365 days for accounting. */
export const sweepBillingOrders = internalMutation({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }) => {
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
