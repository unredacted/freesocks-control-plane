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
import { resolveLocations } from './lib/locations';

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
    // Hard capacity cap: an at-capacity instance is out of the running entirely
    // (before the fresh/fallback split, so being "the only fresh one" can't
    // resurrect it). All-at-capacity → [] → the caller's backend.unavailable.
    candidates = candidates.filter((s) => s.maxKeys == null || s.keyCount < s.maxKeys);
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
 * The member-facing node-location catalog (see lib/locations.ts). Non-secret
 * (code + display label + online bit only) — projected via publicConfig and
 * used to validate a member's location pick at the HTTP boundary.
 */
export const listLocations = internalQuery({
  args: {},
  handler: (ctx) => resolveLocations(ctx.db),
});

/**
 * On-demand node-stats pull for ONE instance (the member node-status endpoint's
 * freshness refresh — the same pull the healthcheck cron does every 10 min).
 * Best-effort: false on any failure, keeping the last snapshot. Callers gate it
 * behind `remnawaveNodes.claimStatsRefresh` so a burst of members polling can't
 * stampede the panel.
 */
export const refreshNodeStats = internalAction({
  args: { id: v.id('backendServers') },
  handler: async (ctx, { id }): Promise<boolean> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id });
    if (!server || !server.isActive) return false;
    const provider = PROVIDERS[server.backend];
    if (!provider.getNodeStats) return false;
    try {
      const nodes = await provider.getNodeStats(server.config as BackendConfig);
      if (nodes.length > 0) {
        await ctx.runMutation(internal.remnawaveNodes.markNodeStats, {
          backendServerId: id,
          nodes,
        });
      }
      return true;
    } catch {
      return false; // panel unreachable: the cached snapshot stays authoritative
    }
  },
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

// Node-load telemetry (feeds issuance-time node placement) lives in the
// Remnawave-namespaced module convex/remnawaveNodes.ts (markNodeStats /
// listNodeStats). The healthcheck cron below stamps it via provider.getNodeStats.

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
        // Best-effort per-node load for issuance-time node placement — same
        // isolation as fleet stats: a failure keeps the last snapshot and
        // must NOT mark the instance unhealthy.
        if (provider.getNodeStats) {
          try {
            const nodes = await provider.getNodeStats(s.config as BackendConfig);
            if (nodes.length > 0) {
              await ctx.runMutation(internal.remnawaveNodes.markNodeStats, {
                backendServerId: s._id,
                nodes,
              });
            }
          } catch {
            /* node stats unavailable this cycle; picker falls back gracefully */
          }
        }
      } catch {
        /* unhealthy: ages out of the fresh window; secret config never logged */
      }
    }
    return { checked: servers.length, healthy };
  },
});

/**
 * Enforce the no-client-IP-logging posture on every active Remnawave instance's
 * config profiles (docs/privacy.md §5), via each provider's `hardenLogging` — a
 * SAFE read-modify-write that touches only the Xray `log`/`policy`, preserving
 * inbounds/Reality/routing. `dryRun` reports what WOULD change without writing.
 * Backends with no config-profile concept (Outline) are skipped. A per-instance
 * failure is isolated + reported, never thrown, so one unreachable panel can't
 * block the rest. Writing restarts the affected nodes (Remnawave auto-push).
 */
export const hardenRemnawaveLogging = internalAction({
  args: { dryRun: v.boolean() },
  handler: async (
    ctx,
    { dryRun },
  ): Promise<{
    instances: Array<{
      serverId: string;
      name: string;
      ok: boolean;
      error?: string;
      profiles: Array<{
        uuid: string;
        name: string;
        hardened: boolean;
        changed: boolean;
        error?: string;
      }>;
    }>;
  }> => {
    const servers = await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
    const instances = [];
    for (const s of servers) {
      const provider = PROVIDERS[s.backend];
      if (!provider.hardenLogging) continue; // no config-profile concept (Outline)
      try {
        const report = await provider.hardenLogging(s.config as BackendConfig, { dryRun });
        instances.push({
          serverId: s._id as string,
          name: s.name,
          ok: true as const,
          profiles: report.profiles,
        });
      } catch (err) {
        instances.push({
          serverId: s._id as string,
          name: s.name,
          ok: false as const,
          error: err instanceof Error ? err.message : String(err),
          profiles: [],
        });
      }
    }
    return { instances };
  },
});
