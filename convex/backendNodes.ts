/**
 * Per-NODE inventory cache (`backendNodeInventory`): one row per panel node per
 * instance, refreshed by the backend-healthcheck cron through the provider's
 * optional `getNodeInventory`. The relay block detector reads a node's live
 * users-online here; the per-PLACEMENT cache (remnawaveNodeStats) cannot
 * isolate one node behind a shared relay squad. Stats only, no secrets.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';

export const markNodeInventory = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodes: v.array(
      v.object({
        nodeUuid: v.string(),
        name: v.string(),
        usersOnline: v.number(),
        online: v.boolean(),
        address: v.optional(v.string()),
        port: v.optional(v.number()),
        countryCode: v.optional(v.string()),
      }),
    ),
  },
  handler: async (ctx, { backendServerId, nodes }) => {
    const now = Date.now();
    const existing = await ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const byUuid = new Map(existing.map((r) => [r.nodeUuid, r]));
    const seen = new Set<string>();
    for (const n of nodes) {
      seen.add(n.nodeUuid);
      const row = {
        backendServerId,
        nodeUuid: n.nodeUuid,
        name: n.name,
        usersOnline: n.usersOnline,
        online: n.online,
        lastStatsAt: now,
        address: n.address,
        port: n.port,
        countryCode: n.countryCode,
      };
      const prev = byUuid.get(n.nodeUuid);
      if (prev) await ctx.db.patch(prev._id, row);
      else await ctx.db.insert('backendNodeInventory', row);
    }
    // A node the panel no longer lists is gone (retired/renamed): drop its row so
    // the detector reads "unknown" rather than a frozen snapshot.
    for (const r of existing) if (!seen.has(r.nodeUuid)) await ctx.db.delete(r._id);
    return null;
  },
});

/** One node's cached row by (instance, panel node name). */
export const getByServerName = internalQuery({
  args: { backendServerId: v.id('backendServers'), name: v.string() },
  handler: (ctx, { backendServerId, name }) =>
    ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server_name', (q) => q.eq('backendServerId', backendServerId).eq('name', name))
      .unique(),
});

/** Every cached node row for one instance (small, admin/detector reads). */
export const listByServer = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: (ctx, { backendServerId }) =>
    ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect(),
});

/**
 * Pull the node list from one panel now (Admin → Edges → New relay, "Refresh
 * nodes"). Same provider call as the healthcheck cron; a failure is reported to
 * the caller instead of being swallowed.
 */
export const refreshNodeInventory = internalAction({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }): Promise<{ nodes: number }> => {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: backendServerId });
    if (!server) throw new Error('backend server not found');
    const provider = PROVIDERS[server.backend];
    if (!provider.getNodeInventory) return { nodes: 0 };
    const nodes = await provider.getNodeInventory(server.config as BackendConfig);
    await ctx.runMutation(internal.backendNodes.markNodeInventory, { backendServerId, nodes });
    return { nodes: nodes.length };
  },
});
