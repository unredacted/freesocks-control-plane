/**
 * Backend instance pool: the DB-touching half of the backend system, generalized
 * from the former outlineServers.ts so EVERY backend type (Remnawave, Outline,
 * ...) is selected from the same registry. These are INTERNAL functions: the
 * rows carry the secret `config`, so they must never be exposed via a public
 * query. The dispatch action (convex/backends.ts) calls them, does the HTTP via
 * the provider registry (convex/lib/backends/registry.ts), and (issuance) the
 * random pick (CSPRNG can't live in a query).
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { heartbeatFromAction } from './cronHeartbeat';
import { v } from 'convex/values';
import type { QueryCtx } from './_generated/server';
import type { BackendConfig } from './lib/backends/registry';
import { PROVIDERS } from './lib/backends/registry';

// Keep in sync with BACKEND_IDS (src/shared/contracts/backends.ts).
const backendId = v.union(v.literal('remnawave'), v.literal('outline'));

const DEFAULT_LATENCY_WEIGHT = 1;
const DEFAULT_KEY_COUNT_WEIGHT = 100;

/** Scoring weights (admin-tunable via appSettings; JSON-encoded numbers). */
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
    latency: await read('backend.scoring.latency_weight', DEFAULT_LATENCY_WEIGHT),
    keyCount: await read('backend.scoring.key_count_weight', DEFAULT_KEY_COUNT_WEIGHT),
  };
}

/**
 * Top-N scored active instances of a given backend type for new-key issuance
 * (lower score wins). The action picks one at random among them. Score =
 * latency_weight * lastHealthRttMs + key_count_weight * keyCount, then admin
 * `priority` as a tiebreak. An instance we have NEVER successfully probed sorts
 * after every probed one (we have no evidence it works), so it can't win the pool
 * on a phantom rtt of 0 — only relevant in the no-fresh-instances fallback below,
 * since the `fresh` set is already probed-by-definition.
 */
export const pickCandidatesForIssue = internalQuery({
  args: {
    backend: backendId,
    poolIds: v.optional(v.array(v.id('backendServers'))),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { backend, poolIds, limit }) => {
    let candidates = await ctx.db
      .query('backendServers')
      .withIndex('by_backend_active', (q) => q.eq('backend', backend).eq('isActive', true))
      .collect();
    if (poolIds && poolIds.length > 0) {
      const allow = new Set<string>(poolIds);
      candidates = candidates.filter((s) => allow.has(s._id));
    }
    if (candidates.length === 0) return [];
    // Prefer instances healthy within ~30 min; fall back to all if none qualify.
    const now = Date.now();
    const fresh = candidates.filter(
      (s) => s.lastHealthOkAt != null && now - s.lastHealthOkAt < 30 * 60_000,
    );
    const usable = fresh.length > 0 ? fresh : candidates;
    const w = await scoringWeights(ctx);
    return usable
      .map((s) => ({
        s,
        // Probed-ness is the PRIMARY sort key: an instance with no successful
        // healthcheck yet (lastHealthRttMs == null) is less trustworthy than any
        // probed one and must sort last, not score as rtt=0 ("fastest"). In the
        // common `fresh` path every instance is probed, so this is a no-op there.
        probed: s.lastHealthRttMs != null,
        score: w.latency * (s.lastHealthRttMs ?? 0) + w.keyCount * s.keyCount,
      }))
      .sort(
        (a, b) =>
          Number(b.probed) - Number(a.probed) || a.score - b.score || a.s.priority - b.s.priority,
      )
      .slice(0, limit ?? 3)
      .map((x) => x.s);
  },
});

export const getById = internalQuery({
  args: { id: v.id('backendServers') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Resolve which instance hosts a given key, via its subscription row. */
export const resolveKeyServer = internalQuery({
  args: { backendUserId: v.string() },
  handler: async (ctx, { backendUserId }) => {
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
      .unique();
    if (!sub || !sub.backendServerId) return null;
    return ctx.db.get(sub.backendServerId);
  },
});

/** Keep the per-instance key count fresh between healthchecks (pool load-scoring). */
export const bumpKeyCount = internalMutation({
  args: { id: v.id('backendServers'), delta: v.optional(v.number()) },
  handler: async (ctx, { id, delta }) => {
    const s = await ctx.db.get(id);
    if (!s) return null;
    await ctx.db.patch(id, {
      keyCount: Math.max(0, s.keyCount + (delta ?? 1)),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** All active instances WITH their secret config; internal-only (the cron pings them). */
export const listActiveWithSecret = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await ctx.db.query('backendServers').collect()).filter((s) => s.isActive),
});

/**
 * Stamp an instance healthy: refresh lastHealthOkAt + rtt, and (when the backend
 * reports an authoritative count, i.e. Outline) the key count. A null keyCount
 * (Remnawave) leaves the bumped estimate alone.
 */
export const markHealthy = internalMutation({
  args: {
    id: v.id('backendServers'),
    keyCount: v.union(v.number(), v.null()),
    rttMs: v.number(),
  },
  handler: async (ctx, { id, keyCount, rttMs }) => {
    const fields: {
      lastHealthOkAt: number;
      lastHealthRttMs: number;
      updatedAt: number;
      keyCount?: number;
    } = {
      lastHealthOkAt: Date.now(),
      lastHealthRttMs: rttMs,
      updatedAt: Date.now(),
    };
    if (keyCount != null) fields.keyCount = keyCount;
    await ctx.db.patch(id, fields);
    return null;
  },
});

/** Cache the latest read-only fleet stats on the instance row (for the admin
 *  dashboard). Stamped by the healthcheck cron; best-effort, so it's only called
 *  when a fetch succeeded — a failed fetch leaves the last values in place. */
export const markFleetStats = internalMutation({
  args: {
    id: v.id('backendServers'),
    fleetStats: v.object({
      onlineNow: v.number(),
      nodesOnline: v.number(),
      nodesTotal: v.number(),
      distinctCountries: v.number(),
      monthTrafficBytes: v.number(),
      lifetimeTrafficBytes: v.number(),
      panelVersion: v.string(),
    }),
  },
  handler: async (ctx, { id, fleetStats }) => {
    await ctx.db.patch(id, { fleetStats, fleetStatsAt: Date.now(), updatedAt: Date.now() });
    return null;
  },
});

/**
 * Cron: ping each active instance through its provider's health probe. On
 * success, stamp lastHealthOkAt (which keeps it in pickCandidatesForIssue's
 * 30-min "fresh" set) + rtt (+ key count for backends that report one). A failing
 * instance is NOT deactivated; it ages out of the fresh window and is
 * deprioritized, with all-instances fallback preserved, so a transient blip
 * can't take a backend's whole pool offline. Never logs the secret config.
 */
export const healthcheck = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; healthy: number }> => {
    await heartbeatFromAction(ctx, 'backend-healthcheck');
    const servers = await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
    let healthy = 0;
    for (const s of servers) {
      try {
        const provider = PROVIDERS[s.backend];
        const { keyCount, rttMs } = await provider.health(s.config as BackendConfig);
        await ctx.runMutation(internal.backendServers.markHealthy, { id: s._id, keyCount, rttMs });
        healthy++;
        // Best-effort fleet observability (read-only) — a failure here must NOT
        // mark the instance unhealthy, so it's caught on its own and just skips.
        if (provider.getFleetStats) {
          try {
            const fleetStats = await provider.getFleetStats(s.config as BackendConfig);
            await ctx.runMutation(internal.backendServers.markFleetStats, {
              id: s._id,
              fleetStats,
            });
          } catch {
            /* fleet stats unavailable this cycle; last stamped values are kept */
          }
        }
      } catch {
        /* unhealthy: ages out of the fresh window; secret config never logged */
      }
    }
    return { checked: servers.length, healthy };
  },
});
