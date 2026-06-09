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
 * `priority` as a tiebreak. Instances never health-checked contribute rtt 0.
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
      .map((s) => ({ s, score: w.latency * (s.lastHealthRttMs ?? 0) + w.keyCount * s.keyCount }))
      .sort((a, b) => a.score - b.score || a.s.priority - b.s.priority)
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
  handler: async (ctx) => (await ctx.db.query('backendServers').collect()).filter((s) => s.isActive),
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
    const fields: { lastHealthOkAt: number; lastHealthRttMs: number; updatedAt: number; keyCount?: number } = {
      lastHealthOkAt: Date.now(),
      lastHealthRttMs: rttMs,
      updatedAt: Date.now(),
    };
    if (keyCount != null) fields.keyCount = keyCount;
    await ctx.db.patch(id, fields);
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
    const servers = await ctx.runQuery(internal.backendServers.listActiveWithSecret, {});
    let healthy = 0;
    for (const s of servers) {
      try {
        const { keyCount, rttMs } = await PROVIDERS[s.backend].health(s.config as BackendConfig);
        await ctx.runMutation(internal.backendServers.markHealthy, { id: s._id, keyCount, rttMs });
        healthy++;
      } catch {
        /* unhealthy: ages out of the fresh window; secret config never logged */
      }
    }
    return { checked: servers.length, healthy };
  },
});
