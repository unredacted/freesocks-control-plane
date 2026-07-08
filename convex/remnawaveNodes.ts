/**
 * Remnawave node-load placement — registered wrappers over the pure fns in
 * lib/remnawavePlacement.ts + the node-load cache the healthcheck cron feeds.
 * Remnawave-namespaced; the generic layer never calls these directly (issuance
 * goes through a `backend === 'remnawave'` gate in account.ts / lifecycle.ts).
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

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
