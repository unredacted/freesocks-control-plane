/**
 * The Remnawave node-load CACHE — the `remnawaveNodeStats` upserts the
 * healthcheck cron feeds plus its admin/member reads. Placement RESOLUTION and
 * BINDING moved to the generic seam (convex/connectionModes.ts dispatching over
 * lib/placement.ts); the Remnawave-specific logic itself lives in
 * lib/remnawavePlacement.ts.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';
import { resolveBoundModeCounts } from './lib/remnawavePlacement';

/** Cache the latest per-placement node-load snapshots (upsert by placement).
 *  Fed by the backend-healthcheck cron via provider.getNodeStats → the picker
 *  reads these to home a new key to the least-loaded node. */
export const markNodeStats = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodes: v.array(
      v.object({
        placement: v.string(),
        label: v.string(),
        usersOnline: v.number(),
        trafficBytesRealtime: v.optional(v.number()),
        online: v.boolean(),
        nodeCount: v.number(),
      }),
    ),
  },
  handler: async (ctx, { backendServerId, nodes }) => {
    const now = Date.now();
    for (const n of nodes) {
      const existing = await ctx.db
        .query('remnawaveNodeStats')
        .withIndex('by_placement', (q) => q.eq('placement', n.placement))
        .unique();
      const row = {
        backendServerId,
        placement: n.placement,
        label: n.label,
        usersOnline: n.usersOnline,
        trafficBytesRealtime: n.trafficBytesRealtime,
        online: n.online,
        nodeCount: n.nodeCount,
        lastStatsAt: now,
        updatedAt: now,
      };
      if (existing) await ctx.db.patch(existing._id, row);
      else await ctx.db.insert('remnawaveNodeStats', row);
    }
    return null;
  },
});

/** The cached load/online snapshot for ONE placement (the member node-status
 *  read). Stats only — no secrets. */
export const getPlacementStats = internalQuery({
  args: { placement: v.string() },
  handler: (ctx, { placement }) =>
    ctx.db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', placement))
      .unique(),
});

/**
 * Stampede guard for on-demand node-stats refreshes: a serializable
 * check-and-stamp on a per-instance appState key. Only the FIRST caller inside
 * a freshness window wins the claim (OCC conflicts collapse concurrent
 * claimers); everyone else serves the cached snapshot. Bounds the member
 * node-status endpoint to ≤1 panel sweep per instance per window regardless of
 * how many members are polling.
 */
export const claimStatsRefresh = internalMutation({
  args: { backendServerId: v.id('backendServers'), freshMs: v.number() },
  handler: async (ctx, { backendServerId, freshMs }): Promise<boolean> => {
    const key = `nodestats:refresh:${backendServerId}`;
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) {
      const last = Number(row.value);
      if (Number.isFinite(last) && now - last < freshMs) return false;
      await ctx.db.patch(row._id, { value: String(now), updatedAt: now });
      return true;
    }
    await ctx.db.insert('appState', { key, value: String(now), updatedAt: now });
    return true;
  },
});

/** Per-mode bound-squad counts for the admin placement editor's feedback badge
 *  (pool SIZES only — never the UUIDs themselves). */
export const listModePlacementCounts = internalQuery({
  args: {},
  handler: async (ctx) => {
    const counts = await resolveBoundModeCounts(ctx.db);
    return Object.entries(counts).map(([modeId, boundCount]) => ({ modeId, boundCount }));
  },
});

/** Per-placement node load for the admin CMS (read-only; no secrets — the
 *  placement is a squad UUID the admin set, load numbers are safe). */
export const listNodeStats = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('remnawaveNodeStats').collect();
    return rows
      .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''))
      .map((r) => ({
        placement: r.placement,
        label: r.label ?? null,
        usersOnline: r.usersOnline,
        online: r.online,
        nodeCount: r.nodeCount,
        lastStatsAt: r.lastStatsAt,
      }));
  },
});
