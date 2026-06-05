/**
 * Outline server pool — the DB-touching half of the Outline backend (ported
 * from services/outline-pool.ts). These are INTERNAL functions: the server
 * rows carry the secret `apiUrl`, so they must never be exposed via a public
 * query. The dispatch action (convex/backends.ts) calls them, does the HTTP
 * (convex/lib/backends/outline.ts), and — for issuance — the random pick.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';
import type { QueryCtx } from './_generated/server';

const DEFAULT_LATENCY_WEIGHT = 1;
const DEFAULT_KEY_COUNT_WEIGHT = 100;

async function scoringWeights(ctx: QueryCtx): Promise<{ latency: number; keyCount: number }> {
  const read = async (key: string, def: number): Promise<number> => {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    const n = row ? Number(row.value) : NaN;
    return Number.isFinite(n) ? n : def;
  };
  return {
    latency: await read('outline.scoring.latency_weight', DEFAULT_LATENCY_WEIGHT),
    keyCount: await read('outline.scoring.key_count_weight', DEFAULT_KEY_COUNT_WEIGHT),
  };
}

/**
 * Top-N scored active servers for new-key issuance (lower score wins). The
 * action picks one at random among them — randomness can't live in a query.
 * `latency` is a placeholder (0) until the healthcheck cron captures real RTT,
 * so order is effectively by access-key count then admin `priority`.
 */
export const pickCandidatesForIssue = internalQuery({
  args: { poolIds: v.optional(v.array(v.id('outlineServers'))), limit: v.optional(v.number()) },
  handler: async (ctx, { poolIds, limit }) => {
    let candidates = await ctx.db
      .query('outlineServers')
      .withIndex('by_active_priority', (q) => q.eq('isActive', true))
      .collect();
    if (poolIds && poolIds.length > 0) {
      const allow = new Set<string>(poolIds);
      candidates = candidates.filter((s) => allow.has(s._id));
    }
    if (candidates.length === 0) return [];
    // Prefer servers healthy within ~30 min; fall back to all if none qualify.
    const now = Date.now();
    const fresh = candidates.filter(
      (s) => s.lastHealthOkAt != null && now - s.lastHealthOkAt < 30 * 60_000,
    );
    const usable = fresh.length > 0 ? fresh : candidates;
    const w = await scoringWeights(ctx);
    return usable
      .map((s) => ({ s, score: w.latency * 0 + w.keyCount * s.accessKeyCount }))
      .sort((a, b) => a.score - b.score || a.s.priority - b.s.priority)
      .slice(0, limit ?? 3)
      .map((x) => x.s);
  },
});

export const getById = internalQuery({
  args: { id: v.id('outlineServers') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Resolve which server hosts a given access key, via its subscription row. */
export const resolveKeyServer = internalQuery({
  args: { backendUserId: v.string() },
  handler: async (ctx, { backendUserId }) => {
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique();
    if (!sub || !sub.outlineServerId) return null;
    return ctx.db.get(sub.outlineServerId);
  },
});

/** Keep the per-server key count fresh between healthchecks (pool load-scoring). */
export const bumpAccessKeyCount = internalMutation({
  args: { id: v.id('outlineServers'), delta: v.optional(v.number()) },
  handler: async (ctx, { id, delta }) => {
    const s = await ctx.db.get(id);
    if (!s) return null;
    await ctx.db.patch(id, {
      accessKeyCount: Math.max(0, s.accessKeyCount + (delta ?? 1)),
      updatedAt: Date.now(),
    });
    return null;
  },
});
