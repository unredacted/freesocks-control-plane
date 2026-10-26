/**
 * Address lanes, the DB half (docs/edges.md "Address enumeration"; the rules
 * are lib/edges/lanes.ts). The member's lane, the switch, the lane an address
 * takes at its first publication, the open lane's own replacement budget, and
 * the reconcile's lane upkeep: fill each transport's lanes, and once a
 * transport's trusted lane is full let its old open addresses go.
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import {
  MAX_DESIRED_PUBLISHED,
  originPolicy,
  resolveEdgeConfig,
  resolvePromoteAfterDays,
  type EdgeConfig,
} from './lib/edgeConfig';
import {
  LANE_TARGET_MAX,
  edgeLaneOf,
  isPaidMember,
  laneAtPublish,
  laneBook,
  laneDesired,
  lanesOn,
  mayBeTrusted,
  memberLane,
  openToRetire,
  type Lane,
} from './lib/edges/lanes';
import { sameAddress } from './lib/edges/hosts';
import { withoutEdge } from './lib/edges/pool';
import { fleetOpenReplacesToday } from './lib/edges/fleet';
import { assertAdmission } from './lib/edges/maintenance';
import {
  assertNoRotationOrQuarantine,
  bumpEpochAndRefresh,
  scheduleMirrorRefresh,
} from './lib/edges/relayGuards';
import { listenersOf } from './relayListeners';
import { suspectedOf } from './edgeTrust';
import { refreshTemplateEdges, todayKey } from './relays';

type Origin = Doc<'relays'>;
type Edge = Doc<'edges'>;

// --- the member -------------------------------------------------------------------------------

/** The lane an account draws from now (lib/edges/lanes.ts `memberLane`). */
export async function memberLaneOfUser(
  db: DatabaseReader,
  userId: Id<'users'>,
  now: number,
  promoteAfterDays?: number,
): Promise<Lane> {
  const user = await db.get(userId);
  if (!user) return 'open';
  const [tier, suspected, days] = await Promise.all([
    db.get(user.tierId),
    suspectedOf(db, userId),
    promoteAfterDays ?? resolvePromoteAfterDays(db),
  ]);
  return memberLane({
    paid: isPaidMember(user, tier, now),
    createdAt: user._creationTime,
    suspected,
    now,
    promoteAfterDays: days,
  });
}

/**
 * The lane of a subscription's account, read by every delivery before it looks
 * at a cached body and again where one is written (the fence: a body rendered
 * for another lane is neither served nor stored). Null for a key that is gone.
 */
export const laneOf = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { subscriptionId }): Promise<Lane | null> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub) return null;
    return memberLaneOfUser(ctx.db, sub.userId, Date.now());
  },
});

// --- an address's lane ------------------------------------------------------------------------

/**
 * Whether FCP handed this address out before under another row: the same
 * node's edges of any status, and the fleet's most recently destroyed ones (a
 * provider may give a released address back). Read once, at a first
 * publication on a node with lanes on.
 */
async function seenBefore(db: DatabaseReader, edge: Edge): Promise<boolean> {
  const mine = [edge.addresses.v4, edge.addresses.v6, edge.addresses.hostname].filter(
    (a): a is string => !!a,
  );
  if (mine.length === 0) return false;
  const same = (e: Edge) =>
    e._id !== edge._id &&
    e.publishedAt !== undefined &&
    [e.addresses.v4, e.addresses.v6, e.addresses.hostname].some(
      (a) => !!a && mine.some((m) => sameAddress(a, m)),
    );
  const ofNode = await db
    .query('edges')
    .withIndex('by_relay_status', (q) => q.eq('relayId', edge.relayId))
    .order('desc')
    .take(1000);
  if (ofNode.some(same)) return true;
  const destroyed = await db
    .query('edges')
    .withIndex('by_status', (q) => q.eq('status', 'destroyed'))
    .order('desc')
    .take(1000);
  return destroyed.some(same);
}

/**
 * The lane `edge` takes now that it is first published on `origin`
 * (`replacing`: the address a replace swaps out). Patch the result onto the
 * edge in the same write that publishes it. A node without lanes, or an
 * address published before, keeps what it has (nothing, or its lane).
 */
export async function laneForPublish(
  db: DatabaseReader,
  origin: Origin,
  edge: Edge,
  replacing?: Edge | null,
): Promise<{ lane?: 'trusted' }> {
  if (!lanesOn(origin) || edge.publishedAt !== undefined) return {};
  const clean = mayBeTrusted(edge, origin, false) && !(await seenBefore(db, edge));
  const published = await publishedOf(db, origin);
  const onListener = published.filter(
    (e) => e.listenerId === edge.listenerId && e._id !== replacing?._id && e._id !== edge._id,
  );
  const trusted = onListener.filter((e) => e.lane === 'trusted').length;
  const lane = laneAtPublish({
    mayBeTrusted: clean,
    targets: origin.lanes!,
    inUse: { open: onListener.length - trusted, trusted },
    ...(replacing ? { replacing: edgeLaneOf(replacing) } : {}),
  });
  return lane === 'trusted' ? { lane: 'trusted' } : {};
}

async function publishedOf(db: DatabaseReader, origin: Origin): Promise<Edge[]> {
  const out: Edge[] = [];
  for (const id of origin.publishedEdgeIds) {
    if (!id) continue;
    const e = await db.get(id);
    if (e && e.publication === 'published') out.push(e);
  }
  return out;
}

// --- the open lane's budget -------------------------------------------------------------------

/** Whether a replace of this target is the open lane's (its own budget, no node or fleet cap). */
export function isOpenLaneReplace(origin: Origin, target: Edge | null): boolean {
  return lanesOn(origin) && !!target && edgeLaneOf(target) === 'open';
}

export function openReplacesToday(origin: Origin, now: number): number {
  return origin.openReplaces?.day === todayKey(now) ? origin.openReplaces.count : 0;
}

/** Whether the open lane may be replaced once more today, on this node and fleet-wide. */
export async function openBudgetLeft(
  db: DatabaseReader,
  origin: Origin,
  cfg: Pick<EdgeConfig, 'lanes'>,
  now: number,
): Promise<boolean> {
  if (openReplacesToday(origin, now) >= cfg.lanes.openReplacesPerDay) return false;
  return (await fleetOpenReplacesToday(db, now)) < cfg.lanes.openReplacesPerFleetDay;
}

// --- the switch -------------------------------------------------------------------------------

/**
 * Switch a node's lanes on (per transport, `open` open and `trusted` trusted
 * addresses) or off (`null`). On: needs the rendezvous pick (a blocked
 * address's holders must scatter); every address in use now is open, since
 * every member may have been handed it, and the reconcile makes fresh trusted
 * ones up to the target, then lets the old open ones above target go. Changing
 * the targets later keeps `lanesSince`. Off: every trusted address becomes open
 * for good (members of every lane are handed it from now), so a later
 * switch-on starts from fresh addresses again.
 */
export const setLanes = internalMutation({
  args: {
    relayId: v.id('relays'),
    lanes: v.union(v.object({ open: v.number(), trusted: v.number() }), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, lanes, actorAdminId }) => {
    await assertAdmission(ctx.db, 'registration');
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const now = Date.now();
    if (lanes) {
      const bad = (n: number, min: number) =>
        !Number.isInteger(n) || n < min || n > LANE_TARGET_MAX;
      if (bad(lanes.open, 0) || bad(lanes.trusted, 1))
        throw new ConvexError({
          code: 'validation',
          message: `open must be 0..${LANE_TARGET_MAX} and trusted 1..${LANE_TARGET_MAX} addresses per transport`,
        });
      if (origin.edgePick !== 'hrw1')
        throw new ConvexError({
          code: 'edge.lanes_need_spread',
          message: 'Spread members over the addresses first: lanes need the rendezvous pick',
        });
    }
    const wasOn = lanesOn(origin);
    let tainted = 0;
    if (!lanes && wasOn) {
      // Every trusted address of this node is handed to every member from now on.
      for (const e of await ctx.db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relayId))
        .collect()) {
        if (e.lane !== 'trusted') continue;
        await ctx.db.patch(e._id, { lane: undefined, updatedAt: now });
        tainted++;
      }
    }
    await ctx.db.patch(relayId, {
      lanes: lanes ?? undefined,
      lanesSince: lanes ? (wasOn ? origin.lanesSince : now) : undefined,
      updatedAt: now,
    });
    // What each member may be handed moved: bodies and mirrors are rendered again.
    await bumpEpochAndRefresh(ctx, (await ctx.db.get(relayId))!);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.lanes',
      targetType: 'relay',
      targetId: relayId,
      payload: {
        relaySlug: origin.slug,
        open: lanes?.open ?? null,
        trusted: lanes?.trusted ?? null,
        tainted,
      },
    });
    return { ok: true as const, lanes, tainted };
  },
});

/** The node page's lanes card: the targets and, per transport, what each lane holds. */
export const lanesView = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const listeners = (await listenersOf(ctx, relayId)).filter(
      (l) => l.deployed && l.enabled && !l.retired,
    );
    const published = await publishedOf(ctx.db, origin);
    const now = Date.now();
    const book = origin.lanes
      ? laneBook(
          listeners.map((l) => l._id as string),
          published.map((e) => ({ listenerId: e.listenerId as string, lane: e.lane })),
          origin.lanes,
        )
      : null;
    return {
      relaySlug: origin.slug,
      edgePick: origin.edgePick ?? null,
      lanes: origin.lanes ?? null,
      since: origin.lanesSince ? new Date(origin.lanesSince).toISOString() : null,
      transports: listeners.map((l) => {
        const mine = published.filter((e) => e.listenerId === l._id);
        const trusted = mine.filter((e) => e.lane === 'trusted').length;
        const entry = book?.get(l._id as string);
        return {
          listenerId: l._id as string,
          listenerKey: l.listenerKey,
          open: mine.length - trusted,
          trusted,
          openExcess: entry?.openExcess ?? 0,
          trustedDeficit: entry?.trustedDeficit ?? 0,
          openDeficit: entry?.openDeficit ?? 0,
        };
      }),
      openReplacesToday: openReplacesToday(origin, now),
      openReplacesPerDay: cfg.lanes.openReplacesPerDay,
    };
  },
});

// --- the reconcile's lane upkeep --------------------------------------------------------------

/**
 * One pass of lane upkeep on one node: the pool size follows the lanes; an old
 * open address above target leaves once its transport's trusted lane is full
 * (drained like a replaced one); else the first transport short of a lane is
 * named, with the spares that could fill it (a trusted gap takes only a spare
 * that may be trusted). The reconcile publishes one of those or provisions.
 */
export const reconcileLanes = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (
    ctx,
    { relayId },
  ): Promise<
    | { kind: 'off' }
    | { kind: 'retired'; edgeId: Id<'edges'> }
    | { kind: 'short'; listenerId: Id<'relayListeners'>; lane: Lane; spares: Id<'edges'>[] }
    | { kind: 'full' }
  > => {
    const origin = await ctx.db.get(relayId);
    if (!origin || !lanesOn(origin)) return { kind: 'off' };
    const targets = origin.lanes!;
    const listeners = (await listenersOf(ctx, relayId)).filter(
      (l) => l.deployed && l.enabled && !l.retired,
    );
    const published = await publishedOf(ctx.db, origin);
    const book = laneBook(
      listeners.map((l) => l._id as string),
      published.map((e) => ({ listenerId: e.listenerId as string, lane: e.lane })),
      targets,
    );
    const desired = Math.min(MAX_DESIRED_PUBLISHED, Math.max(1, laneDesired(book, targets)));
    if (desired !== origin.desiredPublished)
      await ctx.db.patch(relayId, { desiredPublished: desired, updatedAt: Date.now() });
    const templates = new Set(
      listeners.map((l) => l.templateEdgeId as string | undefined).filter((x): x is string => !!x),
    );
    if (!origin.activeRotationId) {
      const retire = openToRetire(
        book,
        published.map((e) => ({
          edgeId: e._id as string,
          listenerId: e.listenerId as string,
          lane: e.lane,
          publishedAt: e.publishedAt,
        })),
        templates,
      );
      if (retire) {
        await retireOpen(ctx, (await ctx.db.get(relayId))!, retire.edgeId as Id<'edges'>);
        return { kind: 'retired', edgeId: retire.edgeId as Id<'edges'> };
      }
    }
    for (const l of listeners) {
      const e = book.get(l._id as string)!;
      const lane: Lane | null =
        e.open === 0 && e.openDeficit > 0
          ? 'open'
          : e.trustedDeficit > 0
            ? 'trusted'
            : e.openDeficit > 0
              ? 'open'
              : null;
      if (!lane) continue;
      const spares: Id<'edges'>[] = [];
      for (const id of origin.standbyEdgeIds) {
        const s = await ctx.db.get(id);
        if (!s || s.listenerId !== l._id || s.status !== 'active') continue;
        if (lane === 'trusted' && !mayBeTrusted(s, origin, false)) continue;
        spares.push(id);
      }
      return { kind: 'short', listenerId: l._id, lane, spares };
    }
    return { kind: 'full' };
  },
});

/** Take an old open address out of use: drained (members move at their next refresh), then destroyed. */
async function retireOpen(ctx: MutationCtx, origin: Origin, edgeId: Id<'edges'>) {
  const cfg = await resolveEdgeConfig(ctx.db);
  const now = Date.now();
  const edge = await ctx.db.get(edgeId);
  if (!edge || edge.publication !== 'published') return;
  await ctx.db.patch(edgeId, {
    publication: 'draining',
    status: 'draining',
    poolIndex: undefined,
    drainUntil: now + originPolicy(origin, cfg).drainMs,
    statusChangedAt: now,
    updatedAt: now,
  });
  const epoch = origin.publicationEpoch + 1;
  await ctx.db.patch(origin._id, {
    publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
    publicationEpoch: epoch,
    updatedAt: now,
  });
  await refreshTemplateEdges(ctx, origin);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'edge.lane_retired',
    targetType: 'edge',
    targetId: edgeId,
    payload: { relaySlug: origin.slug, edgeId, epoch },
  });
  await scheduleMirrorRefresh(ctx);
}

// --- rolling back -----------------------------------------------------------------------------

/**
 * The step before rolling back to a build without address lanes (docs/edges.md
 * § "Deploy notes"): drops `edges.lane`, the lane fields of every origin and
 * `edgeRotations.openLane`, page by page, scheduling itself until done. Every
 * member may then be handed every address again (lanes off everywhere).
 */
export const clearForRollback = internalMutation({
  args: {
    phase: v.optional(v.union(v.literal('edges'), v.literal('rotations'), v.literal('relays'))),
    cursor: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, { phase, cursor }) => {
    let cleared = 0;
    const at = phase ?? 'edges';
    const next = (args: { phase: 'edges' | 'rotations' | 'relays'; cursor?: string }) =>
      ctx.scheduler.runAfter(0, internal.edgeLanes.clearForRollback, args);
    if (at === 'edges') {
      const page = await ctx.db.query('edges').paginate({ cursor: cursor ?? null, numItems: 200 });
      for (const e of page.page)
        if (e.lane !== undefined) {
          await ctx.db.patch(e._id, { lane: undefined });
          cleared++;
        }
      await next(
        page.isDone ? { phase: 'rotations' } : { phase: 'edges', cursor: page.continueCursor },
      );
      return { cleared, done: false };
    }
    if (at === 'rotations') {
      const page = await ctx.db
        .query('edgeRotations')
        .paginate({ cursor: cursor ?? null, numItems: 200 });
      for (const r of page.page)
        if (r.openLane !== undefined) {
          await ctx.db.patch(r._id, { openLane: undefined });
          cleared++;
        }
      await next(
        page.isDone ? { phase: 'relays' } : { phase: 'rotations', cursor: page.continueCursor },
      );
      return { cleared, done: false };
    }
    for (const r of await ctx.db.query('relays').collect())
      if (r.lanes !== undefined || r.lanesSince !== undefined || r.openReplaces !== undefined) {
        await ctx.db.patch(r._id, {
          lanes: undefined,
          lanesSince: undefined,
          openReplaces: undefined,
        });
        await bumpEpochAndRefresh(ctx, (await ctx.db.get(r._id))!);
        cleared++;
      }
    return { cleared, done: true };
  },
});
