/// <reference types="vite/client" />
/**
 * Address lanes, the Convex half (docs/edges.md "Address enumeration"): the
 * switch and its taint rule, which members are trusted, the open lane's own
 * replacement budget beside the node's daily cap, the reconcile's fill and
 * retire, and the lane fence on cached bodies and delivery stamps.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { adoptL4Edge, seedEdgeFixture, verifyL4Edge } from './lib/edges/testing/fixtures';
import { collectStartBlockers } from './edgeRotations';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

beforeEach(() => {
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

type T = ReturnType<typeof convexTest>;

/** An address FCP made itself (not imported), unpublished, then confirmed by the operator. */
async function freshEdge(
  t: T,
  relayId: Id<'relays'>,
  listenerId: Id<'relayListeners'>,
  ipv4: string,
): Promise<Id<'edges'>> {
  const id = await t.run((ctx) =>
    ctx.db.insert('edges', {
      relayId,
      listenerId,
      provider: 'gcore',
      managed: true,
      name: `fresh-${ipv4}`,
      steps: [],
      resources: [],
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
      addresses: { v4: ipv4 },
      layer: 'l4',
      publication: 'unpublished',
      status: 'active',
      statusChangedAt: Date.now(),
      health: 'online',
      destroyAttempts: 0,
      updatedAt: Date.now(),
    }),
  );
  await verifyL4Edge(t, id);
  await t.run(async (ctx) => {
    const r = (await ctx.db.get(relayId))!;
    await ctx.db.patch(relayId, { standbyEdgeIds: [...r.standbyEdgeIds, id] });
  });
  return id;
}

/** A node with two old addresses in use (imported before lanes), on the rendezvous pick. */
async function seedNode(t: T) {
  const f = await seedEdgeFixture(t);
  await t.run((ctx) => ctx.db.patch(f.relayId, { desiredPublished: 6 }));
  const old1 = (
    await adoptL4Edge(t, f.relayId, f.listenerId, { ipv4: '198.51.100.1', publish: true })
  ).edgeId as Id<'edges'>;
  const old2 = (
    await adoptL4Edge(t, f.relayId, f.listenerId, {
      ipv4: '198.51.100.2',
      publish: true,
      port: 444,
    })
  ).edgeId as Id<'edges'>;
  return { ...f, old1, old2 };
}

const relayOf = (t: T, id: Id<'relays'>) => t.query(internal.relays.get, { id });
const edgeOf = (t: T, id: Id<'edges'>) => t.run((ctx) => ctx.db.get(id));

async function seedUser(t: T, opts: { ageDays: number; paid?: boolean }) {
  return t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: opts.paid ? 'paid' : 'free',
      name: 'Tier',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: !opts.paid,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      updatedAt: Date.now(),
      ...(opts.paid ? { membershipExpiresAt: Date.now() + 30 * DAY } : {}),
    });
    const subscriptionId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: `bu-${userId}`,
      backendShortId: `s-${userId}`,
      subscriptionUrl: `https://sub.example/${userId}`,
      subscriptionMirrors: [],
      state: 'active',
      updatedAt: Date.now(),
    });
    return { userId, subscriptionId };
  });
}

describe('switching lanes on and off', () => {
  test('needs the rendezvous pick; every address in use then is open, fresh ones become trusted', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId, old1, old2 } = await seedNode(t);
    await t.run((ctx) => ctx.db.patch(relayId, { edgePick: undefined }));
    await expect(
      t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 2 } }),
    ).rejects.toThrow(/lanes_need_spread|Spread members/);
    await t.mutation(internal.edgeAdmin.setEdgePick, { relayId, version: 'hrw1' });
    // A spare made BEFORE the switch: never trusted, even though nobody was handed it.
    const before = await freshEdge(t, relayId, listenerId, '198.51.100.30');
    vi.useFakeTimers({ now: Date.now() + 1000 });
    const epoch = (await relayOf(t, relayId))!.publicationEpoch;
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 2 } });
    const relay = (await relayOf(t, relayId))!;
    expect(relay.lanes).toEqual({ open: 1, trusted: 2 });
    expect(relay.lanesSince).toBeGreaterThan(0);
    expect(relay.publicationEpoch).toBe(epoch + 1);
    for (const id of [old1, old2]) expect((await edgeOf(t, id))!.lane).toBeUndefined();

    vi.setSystemTime(Date.now() + 1000);
    const fresh = await freshEdge(t, relayId, listenerId, '198.51.100.31');
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: before });
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: fresh });
    expect((await edgeOf(t, before))!.lane).toBeUndefined();
    expect((await edgeOf(t, fresh))!.lane).toBe('trusted');

    // Off: every trusted address is open for good; on again: still open (made before).
    const off = await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: null });
    expect(off.tainted).toBe(1);
    expect((await edgeOf(t, fresh))!.lane).toBeUndefined();
    vi.setSystemTime(Date.now() + 1000);
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 2 } });
    expect((await edgeOf(t, fresh))!.lane).toBeUndefined();
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'relay.lanes'))
        .collect(),
    );
    expect(audits.map((a) => (a.payload as { tainted: number }).tainted)).toEqual([0, 1, 0]);
  });

  test('an address handed out before under another row is never trusted', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId } = await seedNode(t);
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 2 } });
    vi.useFakeTimers({ now: Date.now() + 1000 });
    // The provider gave back the address of one of the old (published) rows.
    const reused = await freshEdge(t, relayId, listenerId, '198.51.100.1');
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: reused });
    expect((await edgeOf(t, reused))!.lane).toBeUndefined();
  });
});

describe('who is handed what', () => {
  test('new free accounts are open; old or paid ones trusted', async () => {
    const t = convexTest(schema, modules);
    const fresh = await seedUser(t, { ageDays: 0 });
    const paid = await seedUser(t, { ageDays: 0, paid: true });
    const lane = (s: Id<'subscriptions'>) =>
      t.query(internal.edgeLanes.laneOf, { subscriptionId: s });
    expect(await lane(fresh.subscriptionId)).toBe('open');
    expect(await lane(paid.subscriptionId)).toBe('trusted');
    vi.useFakeTimers({ now: Date.now() + 14 * DAY + 1000 });
    expect(await lane(fresh.subscriptionId)).toBe('trusted');
  });
});

describe("the open lane's own budget", () => {
  test('an open replace never takes the daily cap; a trusted one after it still starts; the budget holds', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId, old1 } = await seedNode(t);
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 1 } });
    vi.useFakeTimers({ now: Date.now() + 1000 });
    const trusted = await freshEdge(t, relayId, listenerId, '198.51.100.40');
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: trusted });
    expect((await edgeOf(t, trusted))!.lane).toBe('trusted');
    await freshEdge(t, relayId, listenerId, '198.51.100.41');
    // One short of the node's daily cap.
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        maxRotationsPerDay: 1,
        rotationsToday: 0,
        rotationsDayKey: new Date().toISOString().slice(0, 10),
      }),
    );
    const blockers = (target: Id<'edges'>) =>
      t.run(async (ctx) =>
        (
          await collectStartBlockers(ctx, {
            relayId,
            kind: 'replace',
            trigger: 'manual',
            burn: true,
            targetEdgeId: target,
          })
        ).blockers.map((b) => b.code),
      );
    expect(await blockers(old1)).not.toContain('edge.open_lane_budget');
    const { rotationId } = await t.mutation(internal.edgeRotations.start, {
      relayId,
      kind: 'replace',
      trigger: 'manual',
      burn: true,
      targetEdgeId: old1,
    });
    const relay = (await relayOf(t, relayId))!;
    expect(relay.rotationsToday).toBe(0);
    expect(relay.openReplaces?.count).toBe(1);
    expect(relay.cooldownUntil ?? 0).toBeLessThan(Date.now());
    expect((await t.query(internal.edgeRotations.get, { id: rotationId }))!.openLane).toBe(true);
    // (The open replace is still running: the trusted one would wait for it,
    // `edge.busy`, but never for a cap the open lane used.)
    // The trusted lane's cap is whole: its replace is not refused for the cap.
    const trustedBlockers = await blockers(trusted);
    expect(trustedBlockers).not.toContain('edge.daily_cap');
    expect(trustedBlockers).not.toContain('edge.cooldown');
    // The open lane's budget for today is used up.
    expect(await blockers(old1)).toContain('edge.open_lane_budget');
  });
});

describe('the reconcile keeps the lanes', () => {
  test('a short trusted lane is named with only clean spares; once full, the oldest open address leaves', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId, old1, old2 } = await seedNode(t);
    const unclean = await freshEdge(t, relayId, listenerId, '198.51.100.50');
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 1 } });
    vi.useFakeTimers({ now: Date.now() + 1000 });
    const clean = await freshEdge(t, relayId, listenerId, '198.51.100.51');
    const short = await t.mutation(internal.edgeLanes.reconcileLanes, { relayId });
    expect(short).toMatchObject({ kind: 'short', lane: 'trusted', spares: [clean] });
    expect(short.kind === 'short' && short.spares).not.toContain(unclean);
    // Pool: both old open ones stay until the trusted lane is full (1 + 1 excess + 1).
    expect((await relayOf(t, relayId))!.desiredPublished).toBe(3);
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: clean });
    const retired = await t.mutation(internal.edgeLanes.reconcileLanes, { relayId });
    expect(retired.kind).toBe('retired');
    // The template address (the first one, which the backend Host points at) stays.
    const left = retired.kind === 'retired' ? retired.edgeId : null;
    expect([old1, old2]).toContain(left);
    expect((await edgeOf(t, left!))!.publication).toBe('draining');
    expect(await t.mutation(internal.edgeLanes.reconcileLanes, { relayId })).toEqual({
      kind: 'full',
    });
    expect((await relayOf(t, relayId))!.desiredPublished).toBe(2);
  });
});

describe('the lane fence', () => {
  test('a body or snapshot rendered for another lane is neither cached nor stamped', async () => {
    const t = convexTest(schema, modules);
    const { subscriptionId } = await seedUser(t, { ageDays: 0 });
    const entry = (lane: 'open' | 'trusted') =>
      JSON.stringify({ v: 2, content: 'x', contentType: 'text/plain', ua: 'ua', at: 1, lane });
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId,
      entry: entry('trusted'),
    });
    expect((await t.run((ctx) => ctx.db.get(subscriptionId)))!.subCache ?? null).toBeNull();
    await t.mutation(internal.subscriptions.writeContentCache, {
      subscriptionId,
      entry: entry('open'),
    });
    expect((await t.run((ctx) => ctx.db.get(subscriptionId)))!.subCache).toContain('"open"');
    const render = { epoch: 1, family: 'other', listenerKeys: ['a'] };
    await t.mutation(internal.subscriptions.markDelivered, {
      subscriptionId,
      contentAt: 1,
      renderedEpoch: 1,
      render,
      lane: 'trusted',
    });
    expect((await t.run((ctx) => ctx.db.get(subscriptionId)))!.lastRender).toBeUndefined();
    await t.mutation(internal.subscriptions.markDelivered, {
      subscriptionId,
      contentAt: 1,
      renderedEpoch: 1,
      render,
      lane: 'open',
    });
    expect((await t.run((ctx) => ctx.db.get(subscriptionId)))!.lastRender).toMatchObject(render);
  });
});

describe('rolling back', () => {
  test('clearForRollback leaves no lane anywhere', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId } = await seedNode(t);
    await t.mutation(internal.edgeLanes.setLanes, { relayId, lanes: { open: 1, trusted: 2 } });
    vi.useFakeTimers({ now: Date.now() + 1000 });
    const fresh = await freshEdge(t, relayId, listenerId, '198.51.100.61');
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: fresh });
    expect((await edgeOf(t, fresh))!.lane).toBe('trusted');
    await t.mutation(internal.edgeLanes.clearForRollback, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    expect((await edgeOf(t, fresh))!.lane).toBeUndefined();
    const relay = (await relayOf(t, relayId))!;
    expect([relay.lanes, relay.lanesSince, relay.openReplaces]).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
  });
});
