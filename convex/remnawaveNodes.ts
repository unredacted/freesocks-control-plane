/**
 * Remnawave node-load placement — registered wrappers over the pure fns in
 * lib/remnawavePlacement.ts + the node-load cache the healthcheck cron feeds.
 * Remnawave-namespaced; the generic layer never calls these directly (issuance
 * goes through a `backend === 'remnawave'` gate in account.ts / lifecycle.ts).
 */
import { internalMutation, internalQuery } from './_generated/server';
import { ConvexError, v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import {
  pickByNodeLoad,
  resolvePlacementPool,
  modePlacementWrites,
  resolveBoundModeIds,
} from './lib/remnawavePlacement';

/**
 * Admin binds each mode's Remnawave placement pool (the squads a mode's keys are
 * issued across). Remnawave-namespaced: squad UUIDs are write-only + audited as a
 * `poolBound` boolean, never logged. Returns which modes now have a pool bound.
 */
export const setModePlacements = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    let writes: Array<{ key: string; value: string }>;
    try {
      writes = modePlacementWrites(patch);
    } catch (e) {
      throw new ConvexError({
        code: 'validation',
        message: e instanceof Error ? e.message : 'invalid mode-placement config',
      });
    }
    if (writes.length === 0) {
      throw new ConvexError({ code: 'validation', message: 'no recognized mode-placement fields' });
    }
    for (const { key, value } of writes) {
      await upsertSettingRow(ctx, key, value, actorAdminId);
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'admin.remnawave.mode_placement.update',
        targetType: 'connection_mode',
        targetId: key,
        payload: { key, poolBound: (JSON.parse(value) as string[]).length > 0 },
      });
    }
    return { bound: [...(await resolveBoundModeIds(ctx.db))] };
  },
});

/** The placement a NEW key issues into: the LEAST-LOADED node of the mode's
 *  placement pool (per-node load cached by the healthcheck cron; single-element
 *  pools short-circuit). Resolves through `resolvePlacementPool`, so an unbound
 *  mode falls back to the default mode's pool → any bound pool; null ONLY when no
 *  pool is bound anywhere on the deploy (the caller then issues squad-less +
 *  audits). The pick is persisted on the subscription row so later tier pushes
 *  re-send the SAME placement (no re-home). */
export const resolvePlacement = internalQuery({
  args: { modeId: v.union(v.string(), v.null()) },
  handler: async (ctx, { modeId }) =>
    pickByNodeLoad(ctx.db, await resolvePlacementPool(ctx.db, modeId)),
});

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
