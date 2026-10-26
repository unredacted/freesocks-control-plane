/// <reference types="vite/client" />
/**
 * Address enumeration, the account half (docs/edges.md "Address
 * enumeration"): the seat lives on the account, so re-issuing never re-draws
 * the addresses an account is handed, even after every old subscription row
 * was swept; and an origin's address pick is switched by an explicit, audited
 * operator action whose preview says how many members move.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { adoptL4Edge, seedEdgeFixture } from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

async function seedUser(t: ReturnType<typeof convexTest>): Promise<Id<'users'>> {
  return t.run(async (ctx) => {
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
      updatedAt: Date.now(),
    });
    return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
  });
}

const issue = (t: ReturnType<typeof convexTest>, userId: Id<'users'>, n: number) =>
  t.mutation(internal.subscriptions.insertSubscription, {
    userId,
    backend: 'remnawave',
    backendUserId: `bu-${n}`,
    backendShortId: `short-${n}`,
    subscriptionUrl: `https://sub.example/${n}`,
    subscriptionMirrors: [],
  });

const keyOf = (t: ReturnType<typeof convexTest>, id: Id<'subscriptions'>) =>
  t.run(async (ctx) => (await ctx.db.get(id))!.renderKey);

describe('the seat', () => {
  test('every re-issue keeps it, also after every old row was swept', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const first = await keyOf(t, await issue(t, userId, 1));
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(await t.run(async (ctx) => (await ctx.db.get(userId))!.renderSeat)).toBe(first);
    expect(await keyOf(t, await issue(t, userId, 2))).toBe(first);
    // The 90-day retention sweep removed every row the account ever had.
    await t.run(async (ctx) => {
      for (const s of await ctx.db
        .query('subscriptions')
        .withIndex('by_user', (q) => q.eq('userId', userId))
        .collect())
        await ctx.db.delete(s._id);
    });
    expect(await keyOf(t, await issue(t, userId, 3))).toBe(first);
  });

  test('an account from before the seat keeps its newest row’s key: nobody moves', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const legacy = 'ab'.repeat(32);
    await t.run(async (ctx) => {
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old',
        backendShortId: 'old',
        subscriptionUrl: 'https://sub.example/old',
        subscriptionMirrors: [],
        renderKey: 'cd'.repeat(32),
        state: 'deleted',
        updatedAt: 1,
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'cur',
        backendShortId: 'cur',
        subscriptionUrl: 'https://sub.example/cur',
        subscriptionMirrors: [],
        renderKey: legacy,
        state: 'active',
        updatedAt: 2,
      });
    });
    expect(await keyOf(t, await issue(t, userId, 4))).toBe(legacy);
    expect(await t.run(async (ctx) => (await ctx.db.get(userId))!.renderSeat)).toBe(legacy);
  });

  test('a row that predates the key is given the seat, not a new draw', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);
    const seat = await keyOf(t, await issue(t, userId, 5));
    const bare = await t.run((ctx) =>
      ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'bare',
        backendShortId: 'bare',
        subscriptionUrl: 'https://sub.example/bare',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      }),
    );
    expect(await t.mutation(internal.subscriptions.ensureRenderKey, { subscriptionId: bare })).toBe(
      seat,
    );
    expect(await keyOf(t, bare)).toBe(seat);
  });
});

describe('the origin’s address pick', () => {
  test('new origins start on rendezvous; the switch previews, moves the epoch once and is audited', async () => {
    const t = convexTest(schema, modules);
    const { relayId, listenerId } = await seedEdgeFixture(t);
    const relay = async () => (await t.query(internal.relays.get, { id: relayId }))!;
    expect((await relay()).edgePick).toBe('hrw1');
    // An origin from before the pick: the legacy walk.
    await t.run((ctx) => ctx.db.patch(relayId, { edgePick: undefined, desiredPublished: 3 }));
    for (const [i, ipv4] of ['198.51.100.7', '198.51.100.8', '198.51.100.9'].entries())
      await adoptL4Edge(t, relayId, listenerId, { ipv4, publish: true, port: 443 + i });
    const view = (await t.query(internal.edgeAdmin.edgePickView, { relayId }))!;
    expect(view).toMatchObject({ edgePick: null, switchTo: 'hrw1', published: 3 });
    expect(view.sampled).toBeGreaterThan(500);
    expect(view.moved).toBeGreaterThan(0);
    expect(view.moved).toBeLessThan(view.sampled);

    const epoch = (await relay()).publicationEpoch;
    expect(await t.mutation(internal.edgeAdmin.setEdgePick, { relayId, version: 'hrw1' })).toEqual({
      ok: true,
      changed: true,
      edgePick: 'hrw1',
    });
    expect((await relay()).edgePick).toBe('hrw1');
    expect((await relay()).publicationEpoch).toBe(epoch + 1);
    // Saying it again changes nothing members see.
    expect(
      (await t.mutation(internal.edgeAdmin.setEdgePick, { relayId, version: 'hrw1' })).changed,
    ).toBe(false);
    expect((await relay()).publicationEpoch).toBe(epoch + 1);
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'relay.edge_pick'))
        .collect(),
    );
    expect(audits).toHaveLength(2);
    expect(audits[0]!.payload).toMatchObject({ version: 'hrw1' });
    // Back to the legacy walk is the same explicit action.
    await t.mutation(internal.edgeAdmin.setEdgePick, { relayId, version: null });
    expect((await relay()).edgePick).toBeUndefined();
  });
});
