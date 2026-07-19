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
  resolvePlacementTarget,
  modePlacementWrites,
  resolveBoundModeIds,
  resolveBoundModeCounts,
  resolveModeSquadPool,
} from './lib/remnawavePlacement';

/**
 * Admin binds each mode's Remnawave placement pool (the squads a mode's keys are
 * issued across). Per mode the patch composes full-replace (`squadUuids`) with
 * `addSquadUuids`/`removeSquadUuids`, so a headless node deploy can append or
 * detach just itself. Remnawave-namespaced: squad UUIDs are write-only + audited
 * as a `poolBound` boolean and a pool SIZE, never logged. Returns which modes now
 * have a pool bound + the per-mode counts.
 */
export const setModePlacements = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    let writes: Array<{ key: string; value: string }>;
    try {
      writes = await modePlacementWrites(ctx.db, patch);
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
      const size = (JSON.parse(value) as string[]).length;
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'admin.remnawave.mode_placement.update',
        targetType: 'connection_mode',
        targetId: key,
        payload: { key, poolBound: size > 0, boundCount: size },
      });
    }
    const counts = await resolveBoundModeCounts(ctx.db);
    return {
      bound: [...(await resolveBoundModeIds(ctx.db))],
      placements: Object.entries(counts).map(([modeId, boundCount]) => ({ modeId, boundCount })),
    };
  },
});

/** The (placement, server) pair a NEW key issues into: the LEAST-LOADED node of
 *  the mode's placement pool, narrowed to the member's preferred `location`
 *  (soft) or a single panel via `onlyServerId` (hard — the in-place mode-switch
 *  path). Resolves through `resolvePlacementPool`, so an unbound mode falls back
 *  to the default mode's pool → any bound pool; placement is null ONLY when no
 *  pool is bound anywhere on the deploy (the caller then issues squad-less +
 *  audits) or when a hard pin can't be satisfied (the caller re-issues). The pick
 *  is persisted on the subscription row so later tier pushes re-send the SAME
 *  placement (no re-home); `serverId` pins issueUser to the squad's own panel. */
export const resolveTarget = internalQuery({
  args: {
    modeId: v.union(v.string(), v.null()),
    location: v.optional(v.union(v.string(), v.null())),
    onlyServerId: v.optional(v.union(v.id('backendServers'), v.null())),
    // A [0,1) float minted by the calling ACTION (CSPRNG): the anti-herding
    // pick needs randomness, but a query must stay deterministic for OCC.
    rand: v.optional(v.number()),
  },
  handler: async (ctx, { modeId, location, onlyServerId, rand }) =>
    resolvePlacementTarget(ctx.db, modeId, {
      location: location ?? null,
      onlyServerId: (onlyServerId as string | null | undefined) ?? null,
      rand: typeof rand === 'number' ? () => rand : undefined,
    }),
});

/**
 * Re-issue gate for the member's EFFECTIVE mode (regenerate / switch-backend).
 * WS1's cross-mode placement fallback keeps a key from going squad-less, but
 * applied blindly it silently DOWNGRADES a member whose stored mode's pool was
 * unbound by an admin (e.g. a 'privacy' key re-issued into the CDN-fronted
 * 'evade' pool while the UI still says privacy). `blocked` is true exactly
 * when the effective mode's own pool is empty AND some other mode has a pool —
 * the caller then refuses with an actionable error (the member picks another
 * mode first, mirroring the /connection-mode + switchMode guards). When NO
 * mode is bound anywhere (bring-up), blocked is false and issuance proceeds
 * squad-less + audited (the WS1 safety net stays).
 */
export const effectivePlacementGate = internalQuery({
  args: { modeId: v.union(v.string(), v.null()) },
  handler: async (ctx, { modeId }) => {
    const own = await resolveModeSquadPool(ctx.db, modeId);
    if (own.length > 0) return { blocked: false };
    return { blocked: (await resolveBoundModeIds(ctx.db)).size > 0 };
  },
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
