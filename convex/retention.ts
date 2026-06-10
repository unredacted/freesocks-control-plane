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
