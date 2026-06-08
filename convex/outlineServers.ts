/**
 * Outline server pool: the DB-touching half of the Outline backend (ported
 * from services/outline-pool.ts). These are INTERNAL functions: the server
 * rows carry the secret `apiUrl`, so they must never be exposed via a public
 * query. The dispatch action (convex/backends.ts) calls them, does the HTTP
 * (convex/lib/backends/outline.ts), and, for issuance, the random pick.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import type { QueryCtx } from './_generated/server';
import { outlineHealth } from './lib/backends/outline';

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
 * action picks one at random among them; randomness can't live in a query.
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

// --- healthcheck (cron, P11 follow-up) -------------------------------------

/** All active servers WITH their secret apiUrl; internal-only (the cron pings them). */
export const listActiveWithSecret = internalQuery({
  args: {},
  handler: (ctx) =>
    ctx.db
      .query('outlineServers')
      .withIndex('by_active_priority', (q) => q.eq('isActive', true))
      .collect(),
});

/** Stamp a server healthy: refresh lastHealthOkAt + the live access-key count. */
export const markHealthy = internalMutation({
  args: { id: v.id('outlineServers'), keyCount: v.number() },
  handler: async (ctx, { id, keyCount }) => {
    await ctx.db.patch(id, {
      lastHealthOkAt: Date.now(),
      accessKeyCount: keyCount,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * Cron: ping each active Outline server. On success, stamp lastHealthOkAt (which
 * keeps it in `pickCandidatesForIssue`'s 30-min "fresh" set) + refresh its key
 * count. A failing server is NOT deactivated; it simply ages out of the fresh
 * window and is deprioritized, with all-servers fallback preserved, so a
 * transient blip can't take the whole pool offline.
 */
export const healthcheck = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; healthy: number }> => {
    const servers = await ctx.runQuery(internal.outlineServers.listActiveWithSecret, {});
    let healthy = 0;
    for (const s of servers) {
      try {
        const { keyCount } = await outlineHealth({
          apiUrl: s.apiUrl,
          websocketEnabled: s.websocketEnabled,
          websocketDomain: s.websocketDomain ?? null,
        });
        await ctx.runMutation(internal.outlineServers.markHealthy, { id: s._id, keyCount });
        healthy++;
      } catch {
        /* unhealthy: ages out of the fresh window; never logs the secret apiUrl */
      }
    }
    return { checked: servers.length, healthy };
  },
});
