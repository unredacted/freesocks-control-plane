/// <reference types="vite/client" />
/**
 * The edge address limits (src/shared/contracts/edgeLimits.ts): what a new
 * account gets, the ceilings every writer enforces, and the operator-run raise
 * of accounts still on an old default pair (`raiseOldDefaultLimits`).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { createAccount } from './lib/edges/testing/fixtures';
import { EDGE_CONFIG_BOUNDS, EDGE_DEFAULTS, sanitizeRelayConfig } from './lib/edgeConfig';
import {
  DAILY_ALLOCATION_CEILING,
  DEFAULT_DAILY_ALLOCATION_BUDGET,
  DEFAULT_MAX_LIVE_EDGES,
  MAX_DESIRED_PUBLISHED,
  MAX_DESIRED_PUBLISHED_DEFAULT,
  MAX_LIVE_EDGES_CEILING,
} from '../src/shared/contracts/edgeLimits';
import {
  EdgeLocationCreateRequest,
  EdgeLocationUpdateRequest,
} from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');

type T = TestConvex<typeof schema>;

const accountOf = (t: T, id: Id<'edgeProviderAccounts'>) => t.run((ctx) => ctx.db.get(id));

async function defaultLocationOf(t: T, id: Id<'edgeProviderAccounts'>) {
  const row = await accountOf(t, id);
  return row!.defaultLocationId!;
}

describe('edge limits: the numbers', () => {
  test('raised for every provider: 100 live and 50 a day by default, 1000 at most, a pool of 64', () => {
    expect(DEFAULT_MAX_LIVE_EDGES).toBe(100);
    expect(MAX_LIVE_EDGES_CEILING).toBe(1000);
    expect(DEFAULT_DAILY_ALLOCATION_BUDGET).toBe(50);
    expect(DAILY_ALLOCATION_CEILING).toBe(1000);
    expect(MAX_DESIRED_PUBLISHED).toBe(64);
    expect(MAX_DESIRED_PUBLISHED_DEFAULT).toBe(64);
    // Every address costs money: the fleet default stays small.
    expect(EDGE_DEFAULTS.desiredPublishedDefault).toBe(2);
  });

  test('the fleet default pool size takes up to 64 and clamps above it', () => {
    expect(EDGE_CONFIG_BOUNDS.desiredPublishedDefault).toEqual({ min: 1, max: 64 });
    expect(sanitizeRelayConfig({ desiredPublishedDefault: 64 }).desiredPublishedDefault).toBe(64);
    expect(sanitizeRelayConfig({ desiredPublishedDefault: 65 }).desiredPublishedDefault).toBe(64);
  });

  test('the location request contracts take the ceiling and refuse past it', () => {
    const placement = {};
    expect(
      EdgeLocationCreateRequest.safeParse({ placement, maxLiveEdges: MAX_LIVE_EDGES_CEILING })
        .success,
    ).toBe(true);
    expect(
      EdgeLocationCreateRequest.safeParse({ placement, maxLiveEdges: MAX_LIVE_EDGES_CEILING + 1 })
        .success,
    ).toBe(false);
    expect(
      EdgeLocationUpdateRequest.safeParse({ maxLiveEdges: MAX_LIVE_EDGES_CEILING }).success,
    ).toBe(true);
    expect(
      EdgeLocationUpdateRequest.safeParse({ maxLiveEdges: MAX_LIVE_EDGES_CEILING + 1 }).success,
    ).toBe(false);
  });
});

describe('edge limits: accounts and locations', () => {
  test('a new account left without limits gets the new defaults', async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t);
    expect(await accountOf(t, id)).toMatchObject({
      maxLiveEdges: DEFAULT_MAX_LIVE_EDGES,
      dailyAllocationBudget: DEFAULT_DAILY_ALLOCATION_BUDGET,
    });
  });

  test('an account takes up to 1000 live and 1000 a day; past that, zero live or a fraction is refused', async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t, {
      maxLiveEdges: MAX_LIVE_EDGES_CEILING,
      dailyAllocationBudget: DAILY_ALLOCATION_CEILING,
    });
    expect(await accountOf(t, id)).toMatchObject({
      maxLiveEdges: 1000,
      dailyAllocationBudget: 1000,
    });
    await expect(
      createAccount(t, { name: 'too-many', maxLiveEdges: MAX_LIVE_EDGES_CEILING + 1 }),
    ).rejects.toThrow('maxLiveEdges must be 1..1000');
    await expect(
      createAccount(t, { name: 'too-fast', dailyAllocationBudget: DAILY_ALLOCATION_CEILING + 1 }),
    ).rejects.toThrow('dailyAllocationBudget must be 0..1000');
    const update = (patch: { maxLiveEdges?: number; dailyAllocationBudget?: number }) =>
      t.mutation(internal.edgeProviderAccounts.update, { id, ...patch });
    await expect(update({ maxLiveEdges: 0 })).rejects.toThrow('maxLiveEdges must be 1..1000');
    await expect(update({ maxLiveEdges: 2.5 })).rejects.toThrow('maxLiveEdges must be 1..1000');
    await expect(update({ maxLiveEdges: 1001 })).rejects.toThrow('maxLiveEdges must be 1..1000');
    await expect(update({ dailyAllocationBudget: 1001 })).rejects.toThrow(
      'dailyAllocationBudget must be 0..1000',
    );
    // No daily limit stays a development-only choice.
    await expect(update({ dailyAllocationBudget: 0 })).rejects.toThrow(/only in development/);
    await update({ maxLiveEdges: 400, dailyAllocationBudget: 200 });
    expect(await accountOf(t, id)).toMatchObject({ maxLiveEdges: 400, dailyAllocationBudget: 200 });
  });

  test("a location's own cap takes up to 1000", async () => {
    const t = convexTest(schema, modules);
    const id = await createAccount(t);
    const loc = await defaultLocationOf(t, id);
    await t.mutation(internal.edgeLocations.update, {
      id: loc,
      maxLiveEdges: MAX_LIVE_EDGES_CEILING,
    });
    expect((await t.run((ctx) => ctx.db.get(loc)))!.maxLiveEdges).toBe(1000);
    await expect(
      t.mutation(internal.edgeLocations.update, {
        id: loc,
        maxLiveEdges: MAX_LIVE_EDGES_CEILING + 1,
      }),
    ).rejects.toThrow('maxLiveEdges must be 1..1000');
  });

  test('an origin wants up to 64 published addresses', async () => {
    const t = convexTest(schema, modules);
    await createAccount(t);
    const relayId = await t.run(async (ctx) => {
      const now = Date.now();
      const serverId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'panel',
        slug: 'panel',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: now,
      });
      return ctx.db.insert('relays', {
        slug: 'origin',
        backendServerId: serverId,
        origin: { kind: 'panel-node', backendServerId: serverId, nodeName: 'node-a' },
        nodeName: 'node-a',
        originAddress: '198.51.100.7',
        enabled: true,
        autoRotate: false,
        hostMode: 'fcp',
        delivery: 'edge-required',
        desiredPublished: 2,
        standbyPerRelay: 0,
        cooldownMs: 1,
        maxRotationsPerDay: 3,
        drainMs: 1,
        publicationEpoch: 0,
        publishedEdgeIds: [],
        standbyEdgeIds: [],
        rotationsToday: 0,
        updatedAt: now,
      });
    });
    await t.mutation(internal.relays.update, { id: relayId, desiredPublished: 64 });
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.desiredPublished).toBe(64);
    await expect(
      t.mutation(internal.relays.update, { id: relayId, desiredPublished: 65 }),
    ).rejects.toThrow('desiredPublished must be 1..64');
  });
});

describe('edge limits: raiseOldDefaultLimits', () => {
  /** Accounts as earlier builds stored them (the limits are written straight to the row). */
  async function seedAccounts(t: T) {
    const make = async (name: string, maxLiveEdges: number, dailyAllocationBudget: number) => {
      const id = await createAccount(t, { name });
      await t.run((ctx) => ctx.db.patch(id, { maxLiveEdges, dailyAllocationBudget }));
      return id;
    };
    return {
      serverDefaults: await make('server-defaults', 6, 10),
      formDefaults: await make('form-defaults', 4, 6),
      // Either limit changed afterwards: an admin's choice, both kept.
      liveChanged: await make('live-changed', 12, 10),
      budgetChanged: await make('budget-changed', 4, 20),
      // One field of each old pair is not an old pair.
      mixed: await make('mixed', 6, 6),
      chosen: await make('chosen', 300, 80),
    };
  }

  const audits = (t: T) =>
    t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'admin.edge.limits_raised'))
        .collect(),
    );

  test('a dry run (the default) reports what it would raise and writes nothing', async () => {
    const t = convexTest(schema, modules);
    const ids = await seedAccounts(t);
    const res = await t.mutation(internal.edgeProviderAccounts.raiseOldDefaultLimits, {});
    expect(res.dryRun).toBe(true);
    expect(res.to).toEqual({ maxLiveEdges: 100, dailyAllocationBudget: 50 });
    expect(res.raised.map((r) => r.id).sort()).toEqual(
      [ids.serverDefaults, ids.formDefaults].sort(),
    );
    expect(res.raised.find((r) => r.id === ids.formDefaults)?.from).toEqual({
      maxLiveEdges: 4,
      dailyAllocationBudget: 6,
    });
    expect(res.kept).toBe(4);
    expect(await accountOf(t, ids.serverDefaults)).toMatchObject({
      maxLiveEdges: 6,
      dailyAllocationBudget: 10,
    });
    expect(await audits(t)).toEqual([]);
  });

  test('a real run raises only the old default pairs, audits each, and a second run finds nothing', async () => {
    const t = convexTest(schema, modules);
    const ids = await seedAccounts(t);
    const loc = await defaultLocationOf(t, ids.serverDefaults);
    await t.mutation(internal.edgeLocations.update, { id: loc, maxLiveEdges: 6 });

    const res = await t.mutation(internal.edgeProviderAccounts.raiseOldDefaultLimits, {
      dryRun: false,
    });
    expect(res.dryRun).toBe(false);
    expect(res.raised).toHaveLength(2);
    expect(res.kept).toBe(4);
    expect(res.locationCaps).toBe(1);
    for (const id of [ids.serverDefaults, ids.formDefaults])
      expect(await accountOf(t, id)).toMatchObject({
        maxLiveEdges: 100,
        dailyAllocationBudget: 50,
      });
    expect(await accountOf(t, ids.liveChanged)).toMatchObject({
      maxLiveEdges: 12,
      dailyAllocationBudget: 10,
    });
    expect(await accountOf(t, ids.budgetChanged)).toMatchObject({
      maxLiveEdges: 4,
      dailyAllocationBudget: 20,
    });
    expect(await accountOf(t, ids.mixed)).toMatchObject({
      maxLiveEdges: 6,
      dailyAllocationBudget: 6,
    });
    expect(await accountOf(t, ids.chosen)).toMatchObject({
      maxLiveEdges: 300,
      dailyAllocationBudget: 80,
    });
    // A location's cap is always an operator's: counted, never changed.
    expect((await t.run((ctx) => ctx.db.get(loc)))!.maxLiveEdges).toBe(6);

    const rows = await audits(t);
    expect(rows).toHaveLength(2);
    const server = rows.find((r) => r.targetId === ids.serverDefaults);
    expect(server).toMatchObject({ actorType: 'system', targetType: 'edge_provider_account' });
    expect(server?.payload).toEqual({
      name: 'server-defaults',
      provider: 'gcore',
      fromMaxLiveEdges: 6,
      maxLiveEdges: 100,
      fromDailyAllocationBudget: 10,
      dailyAllocationBudget: 50,
    });

    const again = await t.mutation(internal.edgeProviderAccounts.raiseOldDefaultLimits, {
      dryRun: false,
    });
    expect(again.raised).toEqual([]);
    expect(again.kept).toBe(6);
    expect(await audits(t)).toHaveLength(2);
  });
});
