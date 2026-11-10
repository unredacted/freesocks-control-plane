/**
 * The revocation watch: a disabled or deleted key whose Hysteria connection
 * outlived the revocation. docs/backends.md "Revoking a key with an open
 * Hysteria connection"; the decision rule is pure in lib/revocationWatch.ts.
 *
 *  - `start`: a key FCP just disabled (a lapsed membership, an admin disable,
 *    a delete that drains first) that was ever in a Hysteria group
 *    (`subscriptions.hysteriaGroups`) is watched. A key revoked again starts a
 *    new window.
 *  - `sweep` (cron `revocation-watch`): reads each due watch's bytes; growth
 *    past `revocation.leakBytes` after the settle time marks it leaked and asks
 *    for a cut of the node(s) behind its Hysteria groups; then runs the cuts
 *    that are due (at most one restart per node per
 *    `revocation.cutMinIntervalMinutes`). Before a restart, every key waiting
 *    on that node is read again: one that is gone or enabled again no longer
 *    counts, and a node nobody still waits on is not restarted.
 *  - `afterAdminDisable`: an admin disable also cuts at once when the key was
 *    online recently (`revocation.adminDisableCutsNow`); that cut counts as one
 *    of the key's cuts.
 *  - `drainPlan` / `beginDrain`: the teardown path disables a Hysteria key and
 *    deletes it only after `revocation.drainMinutes`.
 *
 * Everything is off unless `revocation.watch` is on. Only keys on a backend
 * that can restart a node are watched: the other transports authenticate every
 * connection (REVOKE_REACHES_OPEN_SESSIONS).
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
import { isHysteriaGroup } from './lib/hysteriaGroups';
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

const WATCH_PAGE = 50;
const CUT_PAGE = 20;
const WAITER_PAGE = 200;
const RESTART_BATCH = 100;

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
 * The Hysteria groups whose nodes a revocation of this key must reach: what
 * the key was ever placed in (`hysteriaGroups`, kept at issuance and on every
 * in-place switch). A row written before that field existed falls back to its
 * current primary group, when that group is a Hysteria one.
 */
async function watchGroups(ctx: QueryCtx, sub: Doc<'subscriptions'>): Promise<string[]> {
  if (REVOKE_REACHES_OPEN_SESSIONS.hysteria) return [];
  if (!CAPABILITIES[sub.backend].nodeRestart || !sub.backendServerId) return [];
  if (sub.hysteriaGroups?.length) return [...sub.hysteriaGroups];
  return (await isHysteriaGroup(ctx.db, sub.backend, sub.backendPlacement))
    ? [sub.backendPlacement!]
    : [];
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
  if (!sub) return null;
  const groups = await watchGroups(ctx, sub);
  if (groups.length === 0) return null;
  const now = Date.now();
  const existing = await ctx.db
    .query('revocationWatches')
    .withIndex('by_backend_user', (q) => q.eq('backendUserId', backendUserId))
    .first();
  if (existing) {
    // Revoked again (it may have been enabled in between): a new window, a new
    // baseline and a fresh cut count. A cut already waiting stays waiting.
    const leaked = existing.state === 'leaked';
    await ctx.db.patch(existing._id, {
      reason,
      placements: groups,
      revokedAt: now,
      settleUntil: now + SETTLE_MS,
      baselineBytes: undefined,
      cuts: 0,
      state: leaked ? 'leaked' : 'watching',
      nextCheckAt: leaked ? now + cfg.watchMs : now + SETTLE_MS,
      updatedAt: now,
    });
    return existing._id;
  }
  return ctx.db.insert('revocationWatches', {
    subscriptionId: sub._id,
    backend: sub.backend,
    backendUserId,
    backendServerId: sub.backendServerId!,
    placements: groups,
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
 * off or the key needs none; a key already watched starts a new window.
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
    if (!cfg.enabled || (await watchGroups(ctx, sub)).length === 0) return { kind: 'now' };
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

// --- watches ----------------------------------------------------------------

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

/** Mark a watch leaked on these nodes and ask for their cut. */
async function markLeaked(
  ctx: MutationCtx,
  w: Doc<'revocationWatches'>,
  nodeUuids: string[],
  bytes: number | undefined,
  bypassInterval: boolean,
  cfg: RevocationConfig,
): Promise<void> {
  const now = Date.now();
  // Re-read when its cut has run (restartWatches moves it back to watching) or
  // at the window's end; meanwhile nothing new is learned.
  await ctx.db.patch(w._id, {
    state: 'leaked',
    ...(bytes !== undefined ? { lastBytes: bytes } : {}),
    nodeUuids,
    nextCheckAt: w.revokedAt + cfg.watchMs,
    updatedAt: now,
  });
  for (const nodeUuid of nodeUuids)
    await requestCutRow(ctx, w.backendServerId, nodeUuid, bypassInterval);
}

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
        await markLeaked(ctx, w, nodes, d.bytes, false, cfg);
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

/** An admin cut: the watch is leaked on these nodes, and their cut skips the interval. */
export const markLeakedNow = internalMutation({
  args: { watchId: v.id('revocationWatches'), nodeUuids: v.array(v.string()) },
  handler: async (ctx, { watchId, nodeUuids }) => {
    const w = await ctx.db.get(watchId);
    if (!w) return null;
    await markLeaked(ctx, w, nodeUuids, undefined, true, await configOf(ctx));
    return null;
  },
});

/**
 * One page of the leaked watches on an instance that wait on this node (a
 * watch names its nodes in an array, so the page is filtered here; the walk
 * goes over every leaked watch of the instance, page by page).
 */
export const waitersPage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    cursor: v.union(v.string(), v.null()),
  },
  handler: async (ctx, { backendServerId, nodeUuid, cursor }) => {
    const page = await ctx.db
      .query('revocationWatches')
      .withIndex('by_server_state', (q) =>
        q.eq('backendServerId', backendServerId).eq('state', 'leaked'),
      )
      .paginate({ cursor, numItems: WAITER_PAGE });
    return {
      waiters: page.page.filter((w) => (w.nodeUuids ?? []).includes(nodeUuid)),
      isDone: page.isDone,
      continueCursor: page.continueCursor,
    };
  },
});

/** After a cut: these watches start over (a new settle time and baseline), one cut counted. */
export const restartWatches = internalMutation({
  args: { watchIds: v.array(v.id('revocationWatches')) },
  handler: async (ctx, { watchIds }) => {
    const now = Date.now();
    for (const id of watchIds) {
      const w = await ctx.db.get(id);
      if (!w || w.state !== 'leaked') continue;
      await ctx.db.patch(id, {
        state: 'watching',
        cuts: w.cuts + 1,
        baselineBytes: undefined,
        settleUntil: now + SETTLE_MS,
        nextCheckAt: now + SETTLE_MS,
        updatedAt: now,
      });
    }
    return null;
  },
});

// --- cuts -------------------------------------------------------------------

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

/** Nobody still waits on this node: no restart. */
export const dropCut = internalMutation({
  args: { id: v.id('nodeSessionCuts') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    await ctx.db.patch(id, {
      pendingSince: undefined,
      bypassInterval: undefined,
      claimAt: undefined,
      retryAfter: undefined,
      leakedKeys: 0,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** A cut ran (or the ledger refused it / it failed: tried again after CUT_RETRY_MS). */
export const finishCut = internalMutation({
  args: { id: v.id('nodeSessionCuts'), ok: v.boolean() },
  handler: async (ctx, { id, ok }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const now = Date.now();
    const server = await ctx.db.get(row.backendServerId);
    const backend = server?.backend;
    if (!ok) {
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

/**
 * The keys still waiting on a node, read again: a key the backend no longer
 * knows, or that is enabled again, stops waiting (its watch ends). A key that
 * cannot be read right now keeps waiting.
 */
async function liveWaiters(
  ctx: ActionCtx,
  row: Doc<'nodeSessionCuts'>,
): Promise<Id<'revocationWatches'>[]> {
  const live: Id<'revocationWatches'>[] = [];
  let cursor: string | null = null;
  for (;;) {
    const page: {
      waiters: Doc<'revocationWatches'>[];
      isDone: boolean;
      continueCursor: string;
    } = await ctx.runQuery(internal.revocationWatches.waitersPage, {
      backendServerId: row.backendServerId,
      nodeUuid: row.nodeUuid,
      cursor,
    });
    for (const w of page.waiters) {
      const probe = await probeOf(ctx, w);
      if (probe && (probe.gone || probe.status === 'active' || probe.status === 'ACTIVE')) {
        await ctx.runMutation(internal.revocationWatches.applyDecision, {
          watchId: w._id,
          decision: { kind: 'close', reason: probe.gone ? 'gone' : 'enabled' },
        });
      } else live.push(w._id);
    }
    if (page.isDone) return live;
    cursor = page.continueCursor;
  }
}

/** Run every cut that is due now, for the keys that still wait on it. */
async function runDueCuts(ctx: ActionCtx, cfg: RevocationConfig): Promise<number> {
  let ran = 0;
  for (const row of await ctx.runQuery(internal.revocationWatches.listPendingCuts, {
    limit: CUT_PAGE,
  })) {
    if (!cutDue(row, Date.now(), cfg)) continue;
    const waiters = await liveWaiters(ctx, row);
    if (waiters.length === 0) {
      await ctx.runMutation(internal.revocationWatches.dropCut, { id: row._id });
      continue;
    }
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
    if (!ok) continue;
    ran++;
    for (let i = 0; i < waiters.length; i += RESTART_BATCH)
      await ctx.runMutation(internal.revocationWatches.restartWatches, {
        watchIds: waiters.slice(i, i + RESTART_BATCH),
      });
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
              placements: w.placements,
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
      const cuts = await runDueCuts(ctx, cfg);
      return { checked: due.length, leaked, cuts };
    }),
});

/**
 * After an admin disabled a key: watch it, and cut its node(s) at once when the
 * key was online recently (`revocation.adminDisableCutsNow`). That cut counts
 * as one of the key's cuts, and a refused one is retried. Never throws.
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
        placements: w.placements,
      });
    } catch {
      return { watched: true, cut: false }; // the watch still catches traffic later
    }
    if (nodes.length === 0) return { watched: true, cut: false };
    await ctx.runMutation(internal.revocationWatches.markLeakedNow, {
      watchId,
      nodeUuids: nodes,
    });
    return { watched: true, cut: (await runDueCuts(ctx, cfg)) > 0 };
  },
});

export const getWatch = internalQuery({
  args: { id: v.id('revocationWatches') },
  handler: (ctx, { id }) => ctx.db.get(id),
});
