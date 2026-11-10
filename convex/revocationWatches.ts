/**
 * The revocation watch: a disabled or deleted key whose Hysteria connection
 * outlived the revocation. docs/backends.md "Revoking a key with an open
 * Hysteria connection"; the decision rule is pure in lib/revocationWatch.ts.
 *
 *  - `start`: a Hysteria key FCP just disabled (a lapsed membership, an admin
 *    disable, a delete that drains first) is watched.
 *  - `sweep` (cron `revocation-watch`): reads each due watch's bytes; growth
 *    past `revocation.leakBytes` after the settle time asks for a cut of the
 *    key's node(s); then runs the cuts that are due (at most one restart per
 *    node per `revocation.cutMinIntervalMinutes`).
 *  - `afterAdminDisable`: an admin disable also cuts at once when the key was
 *    online recently (`revocation.adminDisableCutsNow`).
 *  - `drainPlan` / `beginDrain`: the teardown path disables a Hysteria key and
 *    deletes it only after `revocation.drainMinutes`.
 *
 * Everything is off unless `revocation.watch` is on. Only Hysteria-placed keys
 * on a backend that can restart a node are watched: the other transports
 * authenticate every connection (REVOKE_REACHES_OPEN_SESSIONS).
 */
import { v } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import { runWithCronOutcome } from './cronHeartbeat';
import { writeAuditLog } from './lib/audit';
import { CAPABILITIES, REVOKE_REACHES_OPEN_SESSIONS } from './lib/backends/capabilities';
import { poolFromConfig } from './lib/remnawavePlacement';
import {
  CHECK_EVERY_MS,
  CUT_RETRY_MS,
  REVOCATION_DEFAULTS,
  SETTLE_MS,
  cutDue,
  decide,
  onlineRecently,
  revocationConfig,
  type Decision,
  type Probe,
  type RevocationConfig,
} from './lib/revocationWatch';
import { HYSTERIA_MODE_IDS } from '../src/shared/hysteriaModes';

const WATCH_PAGE = 50;
const CUT_PAGE = 20;

const reasonV = v.union(v.literal('lapsed'), v.literal('admin'), v.literal('teardown'));

/** The `revocation.*` settings, read by key (a stored value that fails to parse keeps its default). */
async function configOf(ctx: QueryCtx): Promise<RevocationConfig> {
  const settings: Record<string, unknown> = {};
  for (const key of Object.keys(REVOCATION_DEFAULTS)) {
    const row = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (!row) continue;
    try {
      settings[key] = JSON.parse(row.value);
    } catch {
      /* keep the default */
    }
  }
  return revocationConfig(settings);
}

/**
 * Whether a revocation of this key leaves an open connection served: a
 * Hysteria-placed key (its primary placement is in a Hysteria mode's pool) on a
 * backend that can restart a node.
 */
async function needsWatch(ctx: QueryCtx, sub: Doc<'subscriptions'>): Promise<boolean> {
  if (REVOKE_REACHES_OPEN_SESSIONS.hysteria) return false;
  if (!CAPABILITIES[sub.backend].nodeRestart) return false;
  if (!sub.backendServerId || !sub.backendPlacement) return false;
  for (const slug of HYSTERIA_MODE_IDS) {
    const row = await ctx.db
      .query('modePlacements')
      .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', sub.backend))
      .unique();
    if (row && poolFromConfig(row.config).includes(sub.backendPlacement)) return true;
  }
  return false;
}

async function subByBackendUser(
  ctx: QueryCtx,
  backendUserId: string,
): Promise<Doc<'subscriptions'> | null> {
  return ctx.db
    .query('subscriptions')
    .withIndex('by_backend_user_id', (q) => q.eq('backendUserId', backendUserId))
    .first();
}

async function startWatch(
  ctx: MutationCtx,
  backendUserId: string,
  reason: Doc<'revocationWatches'>['reason'],
): Promise<Id<'revocationWatches'> | null> {
  const cfg = await configOf(ctx);
  if (!cfg.enabled) return null;
  const sub = await subByBackendUser(ctx, backendUserId);
  if (!sub || !(await needsWatch(ctx, sub))) return null;
  const existing = await ctx.db
    .query('revocationWatches')
    .withIndex('by_backend_user', (q) => q.eq('backendUserId', backendUserId))
    .first();
  if (existing) return existing._id;
  const now = Date.now();
  return ctx.db.insert('revocationWatches', {
    subscriptionId: sub._id,
    backend: sub.backend,
    backendUserId,
    backendServerId: sub.backendServerId!,
    placements: [sub.backendPlacement!, ...(sub.backendExtraPlacements ?? [])],
    reason,
    revokedAt: now,
    settleUntil: now + SETTLE_MS,
    nextCheckAt: now + SETTLE_MS,
    state: 'watching',
    cuts: 0,
    updatedAt: now,
  });
}

/**
 * Start watching a key FCP just disabled. A no-op (null) when the watch is
 * off or the key needs none; an existing watch is kept as it is.
 */
export const start = internalMutation({
  args: { backendUserId: v.string(), reason: reasonV },
  handler: (ctx, { backendUserId, reason }): Promise<Id<'revocationWatches'> | null> =>
    startWatch(ctx, backendUserId, reason),
});

// --- the teardown drain -----------------------------------------------------

/**
 * How a delete of this key goes: `now` (no drain: the watch is off, the key
 * needs none, or its drain has passed) or `wait` until `until`. `start` means
 * the caller disables the key and calls `beginDrain`.
 */
export const drainPlan = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (
    ctx,
    { subscriptionId },
  ): Promise<{ kind: 'now' } | { kind: 'wait'; until: number } | { kind: 'start' }> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub) return { kind: 'now' };
    if (sub.revokeDrainUntil !== undefined) {
      return Date.now() >= sub.revokeDrainUntil
        ? { kind: 'now' }
        : { kind: 'wait', until: sub.revokeDrainUntil };
    }
    const cfg = await configOf(ctx);
    if (!cfg.enabled || !(await needsWatch(ctx, sub))) return { kind: 'now' };
    return { kind: 'start' };
  },
});

/** The key is disabled at the backend: stamp its drain and watch it. Returns the drain end. */
export const beginDrain = internalMutation({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { subscriptionId }): Promise<number | null> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub) return null;
    if (sub.revokeDrainUntil !== undefined) return sub.revokeDrainUntil;
    const cfg = await configOf(ctx);
    const until = Date.now() + cfg.drainMs;
    await ctx.db.patch(subscriptionId, { revokeDrainUntil: until, updatedAt: Date.now() });
    await startWatch(ctx, sub.backendUserId, 'teardown');
    return until;
  },
});

// --- the sweep --------------------------------------------------------------

export const listDueWatches = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    const out: Doc<'revocationWatches'>[] = [];
    for (const state of ['watching', 'leaked', 'stuck'] as const) {
      if (out.length >= limit) break;
      const rows = await ctx.db
        .query('revocationWatches')
        .withIndex('by_state_next', (q) => q.eq('state', state).lte('nextCheckAt', now))
        .take(limit - out.length);
      out.push(...rows);
    }
    return out;
  },
});

/** Apply one decision to a watch (and audit what an operator should see). */
export const applyDecision = internalMutation({
  args: {
    watchId: v.id('revocationWatches'),
    decision: v.any(),
    nodeUuids: v.optional(v.array(v.string())),
  },
  handler: async (ctx, { watchId, decision, nodeUuids }) => {
    const w = await ctx.db.get(watchId);
    if (!w) return null;
    const d = decision as Decision | { kind: 'retry' };
    const now = Date.now();
    const cfg = await configOf(ctx);
    switch (d.kind) {
      case 'close':
        await ctx.db.delete(watchId);
        return null;
      case 'retry':
      case 'wait':
        await ctx.db.patch(watchId, { nextCheckAt: now + CHECK_EVERY_MS, updatedAt: now });
        return null;
      case 'baseline':
        await ctx.db.patch(watchId, {
          baselineBytes: d.bytes,
          lastBytes: d.bytes,
          nextCheckAt: now + CHECK_EVERY_MS,
          updatedAt: now,
        });
        return null;
      case 'keep':
        await ctx.db.patch(watchId, {
          lastBytes: d.bytes,
          nextCheckAt: now + CHECK_EVERY_MS,
          updatedAt: now,
        });
        return null;
      case 'leaked': {
        const nodes = nodeUuids ?? [];
        // Re-read when the cut has run (finishCut moves it back to watching) or
        // at the window's end; meanwhile nothing new is learned.
        await ctx.db.patch(watchId, {
          state: 'leaked',
          lastBytes: d.bytes,
          nodeUuids: nodes,
          nextCheckAt: w.revokedAt + cfg.watchMs,
          updatedAt: now,
        });
        for (const nodeUuid of nodes) await requestCutRow(ctx, w.backendServerId, nodeUuid, false);
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'revocation.leak_seen',
          targetType: 'subscription',
          targetId: w.subscriptionId,
          payload: {
            backend: w.backend,
            reason: w.reason,
            moved: d.moved,
            cuts: w.cuts,
            nodeCount: nodes.length,
          },
        });
        return null;
      }
      case 'stuck':
        if (w.state !== 'stuck')
          await writeAuditLog(ctx, {
            actorType: 'system',
            action: 'revocation.stuck',
            targetType: 'subscription',
            targetId: w.subscriptionId,
            payload: { backend: w.backend, reason: w.reason, moved: d.moved, cuts: w.cuts },
          });
        await ctx.db.patch(watchId, {
          state: 'stuck',
          lastBytes: d.bytes,
          nextCheckAt: w.revokedAt + cfg.watchMs,
          updatedAt: now,
        });
        return null;
    }
  },
});

async function requestCutRow(
  ctx: MutationCtx,
  backendServerId: Id<'backendServers'>,
  nodeUuid: string,
  bypassInterval: boolean,
): Promise<void> {
  const now = Date.now();
  const row = await ctx.db
    .query('nodeSessionCuts')
    .withIndex('by_server_node', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeUuid', nodeUuid),
    )
    .unique();
  if (!row) {
    await ctx.db.insert('nodeSessionCuts', {
      backendServerId,
      nodeUuid,
      pendingSince: now,
      ...(bypassInterval ? { bypassInterval: true } : {}),
      leakedKeys: 1,
      updatedAt: now,
    });
    return;
  }
  await ctx.db.patch(row._id, {
    pendingSince: row.pendingSince ?? now,
    ...(bypassInterval ? { bypassInterval: true } : {}),
    leakedKeys: row.leakedKeys + 1,
    updatedAt: now,
  });
}

export const requestCut = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuids: v.array(v.string()),
    bypassInterval: v.boolean(),
  },
  handler: async (ctx, { backendServerId, nodeUuids, bypassInterval }) => {
    for (const nodeUuid of nodeUuids)
      await requestCutRow(ctx, backendServerId, nodeUuid, bypassInterval);
    return null;
  },
});

export const listPendingCuts = internalQuery({
  args: { limit: v.number() },
  handler: async (ctx, { limit }) =>
    ctx.db
      .query('nodeSessionCuts')
      .withIndex('by_pending', (q) => q.gte('pendingSince', 0))
      .take(limit),
});

/** Claim a due cut (re-checked here, serializably). */
export const claimCut = internalMutation({
  args: { id: v.id('nodeSessionCuts') },
  handler: async (ctx, { id }): Promise<boolean> => {
    const row = await ctx.db.get(id);
    if (!row) return false;
    const now = Date.now();
    if (!cutDue(row, now, await configOf(ctx))) return false;
    await ctx.db.patch(id, { claimAt: now, updatedAt: now });
    return true;
  },
});

/**
 * A cut ran (or failed). On success every watch it was for starts over: a key
 * whose bytes still grow after the restart is served by something else.
 */
export const finishCut = internalMutation({
  args: { id: v.id('nodeSessionCuts'), ok: v.boolean() },
  handler: async (ctx, { id, ok }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const now = Date.now();
    const server = await ctx.db.get(row.backendServerId);
    const backend = server?.backend;
    if (!ok) {
      // Nothing still waits on this node (its keys' watches ended): drop it
      // instead of retrying a restart nobody needs.
      const waiting = await ctx.db
        .query('revocationWatches')
        .withIndex('by_server_state', (q) =>
          q.eq('backendServerId', row.backendServerId).eq('state', 'leaked'),
        )
        .take(500);
      if (!waiting.some((w) => (w.nodeUuids ?? []).includes(row.nodeUuid))) {
        await ctx.db.patch(id, {
          pendingSince: undefined,
          bypassInterval: undefined,
          claimAt: undefined,
          leakedKeys: 0,
          lastError: 'restart_failed',
          updatedAt: now,
        });
        return null;
      }
      await ctx.db.patch(id, {
        claimAt: undefined,
        retryAfter: now + CUT_RETRY_MS,
        lastError: 'restart_failed',
        updatedAt: now,
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'revocation.node_cut_failed',
        targetType: 'backendServer',
        targetId: row.backendServerId,
        payload: { backend, error: 'restart_failed' },
      });
      return null;
    }
    await ctx.db.patch(id, {
      pendingSince: undefined,
      bypassInterval: undefined,
      claimAt: undefined,
      lastError: undefined,
      retryAfter: undefined,
      leakedKeys: 0,
      lastCutAt: now,
      updatedAt: now,
    });
    const leaked = await ctx.db
      .query('revocationWatches')
      .withIndex('by_server_state', (q) =>
        q.eq('backendServerId', row.backendServerId).eq('state', 'leaked'),
      )
      .take(500);
    for (const w of leaked) {
      if (!(w.nodeUuids ?? []).includes(row.nodeUuid)) continue;
      await ctx.db.patch(w._id, {
        state: 'watching',
        cuts: w.cuts + 1,
        baselineBytes: undefined,
        settleUntil: now + SETTLE_MS,
        nextCheckAt: now + SETTLE_MS,
        updatedAt: now,
      });
    }
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'revocation.node_cut',
      targetType: 'backendServer',
      targetId: row.backendServerId,
      payload: {
        backend,
        leakedKeys: row.leakedKeys,
        bypassInterval: row.bypassInterval === true,
      },
    });
    return null;
  },
});

async function probeOf(ctx: ActionCtx, w: Doc<'revocationWatches'>): Promise<Probe | null> {
  try {
    return await ctx.runAction(internal.backends.revocationProbe, {
      backendServerId: w.backendServerId,
      backendUserId: w.backendUserId,
    });
  } catch {
    return null; // unreachable backend: read again next round
  }
}

/** Run every cut that is due now. */
async function runDueCuts(ctx: ActionCtx): Promise<number> {
  let ran = 0;
  for (const row of await ctx.runQuery(internal.revocationWatches.listPendingCuts, {
    limit: CUT_PAGE,
  })) {
    if (!(await ctx.runMutation(internal.revocationWatches.claimCut, { id: row._id }))) continue;
    let ok = false;
    try {
      ok = await ctx.runAction(internal.backends.restartNodeForCut, {
        backendServerId: row.backendServerId,
        nodeUuid: row.nodeUuid,
      });
    } catch {
      ok = false;
    }
    await ctx.runMutation(internal.revocationWatches.finishCut, { id: row._id, ok });
    if (ok) ran++;
  }
  return ran;
}

/** Cron `revocation-watch`: read due watches, ask for cuts, run due cuts. */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<{ checked: number; leaked: number; cuts: number }> =>
    runWithCronOutcome(ctx, 'revocation-watch', async () => {
      const cfg = revocationConfig(await ctx.runQuery(internal.appSettings.resolved, {}));
      if (!cfg.enabled) return { checked: 0, leaked: 0, cuts: 0 };
      const now = Date.now();
      const due = await ctx.runQuery(internal.revocationWatches.listDueWatches, {
        now,
        limit: WATCH_PAGE,
      });
      let leaked = 0;
      for (const w of due) {
        // A leaked or stuck watch comes due only at its window's end (a cut
        // moves it back to watching first): it ends there.
        if (w.state !== 'watching') {
          await ctx.runMutation(internal.revocationWatches.applyDecision, {
            watchId: w._id,
            decision: { kind: 'close', reason: 'expired' },
          });
          continue;
        }
        const probe = await probeOf(ctx, w);
        if (!probe) {
          await ctx.runMutation(internal.revocationWatches.applyDecision, {
            watchId: w._id,
            decision: { kind: 'retry' },
          });
          continue;
        }
        const d = decide(w, probe, Date.now(), cfg);
        if (d.kind === 'leaked') {
          let nodes: string[] = [];
          try {
            nodes = await ctx.runAction(internal.backends.placementNodes, {
              backendServerId: w.backendServerId,
              placements: w.placements.slice(0, 1),
            });
          } catch {
            /* the node list is unreadable now: retried next round */
          }
          if (nodes.length === 0) {
            await ctx.runMutation(internal.revocationWatches.applyDecision, {
              watchId: w._id,
              decision: { kind: 'retry' },
            });
            continue;
          }
          leaked++;
          await ctx.runMutation(internal.revocationWatches.applyDecision, {
            watchId: w._id,
            decision: d,
            nodeUuids: nodes,
          });
          continue;
        }
        await ctx.runMutation(internal.revocationWatches.applyDecision, {
          watchId: w._id,
          decision: d,
        });
      }
      const cuts = await runDueCuts(ctx);
      return { checked: due.length, leaked, cuts };
    }),
});

/**
 * After an admin disabled a key: watch it, and cut its node(s) at once when the
 * key was online recently (`revocation.adminDisableCutsNow`). Never throws.
 */
export const afterAdminDisable = internalAction({
  args: { backendUserId: v.string() },
  handler: async (ctx, { backendUserId }): Promise<{ watched: boolean; cut: boolean }> => {
    const cfg = revocationConfig(await ctx.runQuery(internal.appSettings.resolved, {}));
    if (!cfg.enabled) return { watched: false, cut: false };
    const watchId = await ctx.runMutation(internal.revocationWatches.start, {
      backendUserId,
      reason: 'admin',
    });
    if (!watchId || !cfg.adminDisableCutsNow) return { watched: !!watchId, cut: false };
    const w = await ctx.runQuery(internal.revocationWatches.getWatch, { id: watchId });
    if (!w) return { watched: true, cut: false };
    const probe = await probeOf(ctx, w);
    if (!probe || probe.gone || !onlineRecently(probe.onlineAt, Date.now()))
      return { watched: true, cut: false };
    let nodes: string[] = [];
    try {
      nodes = await ctx.runAction(internal.backends.placementNodes, {
        backendServerId: w.backendServerId,
        placements: w.placements.slice(0, 1),
      });
    } catch {
      return { watched: true, cut: false }; // the watch still catches traffic later
    }
    if (nodes.length === 0) return { watched: true, cut: false };
    await ctx.runMutation(internal.revocationWatches.requestCut, {
      backendServerId: w.backendServerId,
      nodeUuids: nodes,
      bypassInterval: true,
    });
    return { watched: true, cut: (await runDueCuts(ctx)) > 0 };
  },
});

export const getWatch = internalQuery({
  args: { id: v.id('revocationWatches') },
  handler: (ctx, { id }) => ctx.db.get(id),
});
