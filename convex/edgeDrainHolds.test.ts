/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import {
  createAccount,
  FIXTURE_NODE,
  insertPanelServer,
  registerRelay,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => {
  vi.useRealTimers();
});

const H = 3_600_000;
const DAY = 24 * H;

async function setup(opts: { maxLiveEdges?: number } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  // The hold reads only the account's live-edge cap; its provider is beside the point.
  const accountId = await createAccount(t, {
    name: 'acct-a',
    ...(opts.maxLiveEdges !== undefined ? { maxLiveEdges: opts.maxLiveEdges } : {}),
  });
  const r = await registerRelay(t, { listeners: [wsListener()] });
  const now = Date.now();
  const drainStart = now - 3 * H;
  const publishedAt = now - 5 * DAY;
  const insertEdge = (name: string, o: { drainStart?: number; layer?: 'l4' | 'l7' } = {}) =>
    t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId: r.relayId,
        listenerId: r.listenerId,
        accountId,
        provider: 'fastly',
        managed: true,
        name,
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
        addresses: { hostname: `${name}.example.org` },
        layer: o.layer ?? 'l7',
        publication: 'draining',
        status: 'draining',
        publishedAt,
        statusChangedAt: o.drainStart ?? drainStart,
        drainUntil: (o.drainStart ?? drainStart) + 2 * H,
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: now,
      }),
    );
  const userId = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: now,
    });
    return ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
  });
  const insertKey = (o: { renderedAt?: number; state?: 'active' | 'disabled'; node?: string }) =>
    t.run((ctx) =>
      ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: `u-${Math.random()}`,
        backendShortId: 'short',
        subscriptionUrl: 'https://panel.example/sub/x',
        subscriptionMirrors: [],
        backendServerId: serverId,
        pinnedNode: o.node ?? FIXTURE_NODE,
        state: o.state ?? 'active',
        ...(o.renderedAt !== undefined ? { lastRenderedAt: o.renderedAt } : {}),
        updatedAt: now,
      }),
    );
  return { t, r, accountId, now, drainStart, publishedAt, insertEdge, insertKey };
}

type T = Awaited<ReturnType<typeof setup>>['t'];

const getEdge = (t: T, id: Id<'edges'>) => t.run((ctx) => ctx.db.get(id));
const audits = (t: T, action: string) =>
  t.run((ctx) =>
    ctx.db
      .query('auditLog')
      .withIndex('by_action', (q) => q.eq('action', action))
      .collect(),
  );

describe('edgeDrainHolds', () => {
  test('a drained front is held, counted, and let go once its holders refreshed', async () => {
    const { t, r, now, drainStart, insertEdge, insertKey } = await setup();
    const edgeId = await insertEdge('front-a');
    // Holders: rendered while it was published and not since.
    for (let i = 0; i < 12; i++) await insertKey({ renderedAt: drainStart - DAY });
    // Not holders: refreshed after the drain began, rendered before it was
    // published, never fetched, another node.
    const fresh = await insertKey({ renderedAt: drainStart + H });
    await insertKey({ renderedAt: drainStart - 10 * DAY });
    await insertKey({});
    await insertKey({ renderedAt: drainStart - DAY, node: 'other-node' });

    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId })).toEqual({ hold: true });
    let e = (await getEdge(t, edgeId))!;
    expect(e.drainHold).toMatchObject({ since: drainStart, until: drainStart + 30 * DAY });
    expect(e.drainHold!.requestedAt).toBeGreaterThanOrEqual(now);
    expect(await audits(t, 'edge.drain_hold.started')).toHaveLength(1);

    expect(await t.action(internal.edgeDrainHolds.count, { relayId: r.relayId })).toEqual({
      keys: 15,
      holders: [12],
    });
    e = (await getEdge(t, edgeId))!;
    expect(e.drainHold).toMatchObject({ holders: 12, keys: 15 });
    expect(e.drainHold!.requestedAt).toBeUndefined();

    // Counted and above the threshold (10): held, no new count within the hour.
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId })).toEqual({ hold: true });
    expect(await audits(t, 'edge.drain_hold.started')).toHaveLength(1);

    // Two more apps refresh; the next count lands at 10 and the front is let go.
    const holders = await t.run((ctx) =>
      ctx.db
        .query('subscriptions')
        .filter((q) => q.eq(q.field('lastRenderedAt'), drainStart - DAY))
        .take(2),
    );
    for (const s of holders)
      await t.run((ctx) => ctx.db.patch(s._id, { lastRenderedAt: Date.now() }));
    void fresh;
    await t.action(internal.edgeDrainHolds.count, { relayId: r.relayId });
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId })).toEqual({
      hold: false,
      reason: 'refreshed',
    });
    e = (await getEdge(t, edgeId))!;
    expect(e.drainHold).toMatchObject({ releaseReason: 'refreshed', holders: 10 });
    const released = await audits(t, 'edge.drain_hold.released');
    expect(released).toHaveLength(1);
    expect(released[0]!.payload).toMatchObject({ reason: 'refreshed', holders: 10, keys: 15 });
  });

  test('an L4 address, a forced drain and the switch off are never held', async () => {
    const { t, drainStart, insertEdge } = await setup();
    const l4 = await insertEdge('lb-a', { layer: 'l4' });
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId: l4 })).toEqual({
      hold: false,
    });
    const forced = await insertEdge('front-forced');
    await t.run((ctx) => ctx.db.patch(forced, { drainUntil: drainStart }));
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId: forced })).toEqual({
      hold: false,
      reason: 'forced',
    });
    const front = await insertEdge('front-off');
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.drainHold.enabled', 'false'));
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId: front })).toEqual({
      hold: false,
      reason: 'off',
    });
    // Nothing was held, so nothing is said.
    expect(await audits(t, 'edge.drain_hold.released')).toHaveLength(0);
  });

  test('a full account lets its oldest held front go first', async () => {
    const { t, drainStart, insertEdge } = await setup({ maxLiveEdges: 2 });
    const older = await insertEdge('front-old', { drainStart: drainStart - DAY });
    const newer = await insertEdge('front-new');
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId: newer })).toEqual({
      hold: true,
    });
    expect(await t.mutation(internal.edgeDrainHolds.judge, { edgeId: older })).toEqual({
      hold: false,
      reason: 'account_full',
    });
  });

  test('a count only touches fronts still in the same drain', async () => {
    const { t, r, drainStart, insertEdge, insertKey } = await setup();
    const edgeId = await insertEdge('front-a');
    await insertKey({ renderedAt: drainStart - DAY });
    await t.mutation(internal.edgeDrainHolds.judge, { edgeId });
    // Kept as a spare meanwhile (the drain ended): the count is dropped.
    await t.run((ctx) =>
      ctx.db.patch(edgeId, { status: 'active', publication: 'unpublished', drainUntil: undefined }),
    );
    expect(await t.action(internal.edgeDrainHolds.count, { relayId: r.relayId })).toBeNull();
    expect((await getEdge(t, edgeId))!.drainHold!.holders).toBeUndefined();
  });
});
