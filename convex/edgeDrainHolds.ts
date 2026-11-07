/**
 * Drained L7 fronts held up while apps still use them (docs/edges.md "Fronts
 * kept up for apps that have not refreshed"; the rules are in
 * lib/edges/drainHold.ts).
 *
 * The reconcile asks `judge` before destroying a drained L7 front. A held
 * front stays `draining` (never handed out again, the node keeps accepting it
 * through the CDN) until few enough keys may still hold it, its hard maximum
 * passes, or its account needs the slot. The count pages the node's keys in
 * use by `by_backend_server_pinned`, FRONT_KEYS_PAGE a page, at most hourly
 * per node (`count`, scheduled by `judge`), and stores counts only on the edge
 * (`edges.drainHold`): never a key, a member or an address.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { liveEdgesOfAccount } from './relays';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { FRONT_KEYS_PAGE, keyInUse } from './lib/edges/frontKeys';
import {
  DRAIN_HOLD_EVERY_MS,
  drainHoldDecision,
  heldCandidate,
  keyMayHoldEdge,
  type DrainHoldRecord,
} from './lib/edges/drainHold';

type Edge = Doc<'edges'>;

/** The node whose keys can be counted for an origin, or null (an Outline server, a manual origin). */
function nodeOf(origin: Doc<'relays'> | null): {
  backendServerId: Id<'backendServers'>;
  nodeName: string;
} | null {
  if (!origin?.backendServerId || !origin.nodeName) return null;
  return { backendServerId: origin.backendServerId, nodeName: origin.nodeName };
}

/** The edge's listener exists and is not retired. */
async function listenerLive(db: DatabaseReader, id: Id<'relayListeners'>): Promise<boolean> {
  const l = await db.get(id);
  return !!l && !l.retired;
}

/**
 * Whether this front is the one its account lets go when the account is at its
 * live-edge cap: the held front whose drain began first (one a pass, so the
 * next replacement finds a slot without every held front going at once).
 */
async function accountFullOldest(db: DatabaseReader, edge: Edge, now: number): Promise<boolean> {
  if (!edge.accountId) return false;
  const account = await db.get(edge.accountId);
  if (!account) return false;
  const live = (await liveEdgesOfAccount(db, edge.accountId)).filter((e) => e.managed);
  if (live.length < account.maxLiveEdges) return false;
  const held = live
    .filter((e) => heldCandidate(e, now))
    .sort((a, b) => a.statusChangedAt - b.statusChangedAt || (a._id < b._id ? -1 : 1));
  return held[0]?._id === edge._id;
}

/**
 * Decide one drained L7 front: `hold` true = leave it up this pass. Records the
 * hold (and audits its start once), schedules a count of the node's keys when
 * one is due, and audits the release of a front that was held.
 */
export const judge = internalMutation({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }): Promise<{ hold: boolean; reason?: string }> => {
    const now = Date.now();
    const edge = await ctx.db.get(edgeId);
    if (!edge || !heldCandidate(edge, now)) return { hold: false };
    const cfg = await resolveEdgeConfig(ctx.db);
    const origin = await ctx.db.get(edge.relayId);
    const decision = drainHoldDecision({
      edge,
      cfg: cfg.drainHold,
      now,
      nodeOrigin: nodeOf(origin) !== null,
      originDeleting: origin?.deleting === true,
      listenerLive: await listenerLive(ctx.db, edge.listenerId),
      accountFullOldest: await accountFullOldest(ctx.db, edge, now),
    });
    const slug = origin?.slug ?? null;
    if (!decision.hold) {
      // Only a front that was held for THIS drain has a release worth saying.
      const held = edge.drainHold;
      if (held && held.since === edge.statusChangedAt && held.releasedAt === undefined) {
        await ctx.db.patch(edgeId, {
          drainHold: { ...held, releasedAt: now, releaseReason: decision.reason },
          updatedAt: now,
        });
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'edge.drain_hold.released',
          targetType: 'edge',
          targetId: edgeId,
          payload: {
            relaySlug: slug,
            edgeId,
            reason: decision.reason,
            holders: held.holders ?? null,
            keys: held.keys ?? null,
          },
        });
      }
      return { hold: false, reason: decision.reason };
    }
    const first = edge.drainHold?.since !== decision.record.since;
    let record: DrainHoldRecord = decision.record;
    if (decision.recount) {
      record = { ...record, requestedAt: now };
      // One count a node at a time: another held front of the same node that
      // asked within the hour is counted by that run (it counts them all).
      const others = (await liveEdgesOfRelay(ctx.db, edge.relayId)).filter(
        (e) =>
          e._id !== edgeId &&
          heldCandidate(e, now) &&
          e.drainHold?.requestedAt !== undefined &&
          now - e.drainHold.requestedAt < DRAIN_HOLD_EVERY_MS,
      );
      if (others.length === 0)
        await ctx.scheduler.runAfter(0, internal.edgeDrainHolds.count, { relayId: edge.relayId });
    }
    if (first || decision.recount)
      await ctx.db.patch(edgeId, { drainHold: record, updatedAt: now });
    if (first)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.drain_hold.started',
        targetType: 'edge',
        targetId: edgeId,
        payload: { relaySlug: slug, edgeId, until: record.until },
      });
    return { hold: true };
  },
});

interface CountWindow {
  edgeId: Id<'edges'>;
  from: number;
  to: number;
}

/** What to count for an origin: its node, and the published window of each held front. */
export const countTarget = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    const node = nodeOf(origin);
    if (!node) return null;
    const now = Date.now();
    const windows: CountWindow[] = (await liveEdgesOfRelay(ctx.db, relayId))
      .filter(
        (e) =>
          heldCandidate(e, now) &&
          e.publishedAt !== undefined &&
          e.drainHold?.since === e.statusChangedAt &&
          e.drainHold.releasedAt === undefined,
      )
      .map((e) => ({ edgeId: e._id, from: e.publishedAt!, to: e.statusChangedAt }));
    return { ...node, windows };
  },
});

const windowV = v.object({ edgeId: v.id('edges'), from: v.number(), to: v.number() });

/** One page of the node's keys in one state: how many are in use, and per window how many may hold its front. */
export const countPage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    state: v.union(v.literal('active'), v.literal('disabled')),
    windows: v.array(windowV),
    now: v.number(),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, a) => {
    const res = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q
          .eq('backendServerId', a.backendServerId)
          .eq('pinnedNode', a.nodeName)
          .eq('state', a.state),
      )
      .paginate({ cursor: a.cursor, numItems: a.numItems });
    const inUse = res.page.filter((s) => keyInUse(s, a.now));
    return {
      keys: inUse.length,
      holders: a.windows.map((w) => inUse.filter((s) => keyMayHoldEdge(s, w)).length),
      isDone: res.isDone,
      continueCursor: res.continueCursor,
    };
  },
});

/** Store the counts on each held front that is still in the same drain. */
export const record = internalMutation({
  args: {
    at: v.number(),
    keys: v.number(),
    counts: v.array(v.object({ edgeId: v.id('edges'), since: v.number(), holders: v.number() })),
  },
  handler: async (ctx, { at, keys, counts }) => {
    for (const c of counts) {
      const e = await ctx.db.get(c.edgeId);
      const held = e?.drainHold;
      if (!e || e.status !== 'draining' || !held || held.since !== c.since) continue;
      if (held.releasedAt !== undefined) continue;
      const { requestedAt, ...rest } = held;
      void requestedAt;
      await ctx.db.patch(c.edgeId, {
        drainHold: { ...rest, at, holders: c.holders, keys },
        updatedAt: Date.now(),
      });
    }
    return null;
  },
});

/** Count the keys that may still hold each held front of an origin (scheduled by `judge`). */
export const count = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<{ keys: number; holders: number[] } | null> => {
    const t = await ctx.runQuery(internal.edgeDrainHolds.countTarget, { relayId });
    if (!t || t.windows.length === 0) return null;
    const now = Date.now();
    const holders = t.windows.map(() => 0);
    let keys = 0;
    for (const state of ['active', 'disabled'] as const) {
      let cursor: string | null = null;
      for (;;) {
        const page: {
          keys: number;
          holders: number[];
          isDone: boolean;
          continueCursor: string;
        } = await ctx.runQuery(internal.edgeDrainHolds.countPage, {
          backendServerId: t.backendServerId,
          nodeName: t.nodeName,
          state,
          windows: t.windows,
          now,
          cursor,
          numItems: FRONT_KEYS_PAGE,
        });
        keys += page.keys;
        page.holders.forEach((n, i) => (holders[i]! += n));
        if (page.isDone) break;
        cursor = page.continueCursor;
      }
    }
    await ctx.runMutation(internal.edgeDrainHolds.record, {
      at: now,
      keys,
      counts: t.windows.map((w, i) => ({ edgeId: w.edgeId, since: w.to, holders: holders[i]! })),
    });
    return { keys, holders };
  },
});
