/// <reference types="vite/client" />
/**
 * A country's default picks end to end (docs/edges.md "A country's default
 * picks"): saving one and its guards, the preview with the cost, upkeep
 * writing them onto a ready freedom node and then filling their count, a node
 * waiting for the rendezvous walk, a node's own entry winning, opting out,
 * removing a default, and the rollback. Adopted RFC 5737 edges; no provider call.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import {
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { refuseNetwork } from './lib/edges/testing/mockFetch';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  refuseNetwork();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/**
 * A freedom node (its transport's mode is a freedom one) picking locations A
 * and B, an address everyone is handed in use at each; location C (a third
 * account) it does not pick. Steering on, the rendezvous walk, upkeep buying.
 */
async function world(opts: { legacy?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.autoProvisionToDesired', 'true');
    await upsertSettingRow(ctx, 'delivery.country.steer', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
  });
  const accounts = [
    await createAccount(t, { name: 'acct-a', qualified: true }),
    await createAccount(t, { provider: 'upcloud', name: 'acct-b', qualified: true }),
    await createAccount(t, { name: 'acct-c', qualified: true }),
  ];
  for (const id of accounts)
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id, ok: true });
  const [a, b, c] = await t.run(async (ctx) => {
    const locs = await ctx.db.query('edgeLocations').collect();
    return accounts.map((id) => locs.find((l) => l.accountId === id)!);
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example', 'b.example'] })],
  });
  const listener = await t.run(async (ctx) => (await ctx.db.get(listenerId))!);
  // Its transport is a freedom mode's: the node takes country defaults.
  await t.run(async (ctx) => {
    const now = Date.now();
    const row = {
      backendServerId: serverId,
      desired: '{}',
      desiredHash: 'h',
      generation: 1,
      state: 'ready' as const,
      profileName: 'FreeSocks-Config',
      modes: [
        {
          slug: 'freedom-reality',
          name: 'REALITY',
          shape: { transport: 'reality' as const, fronting: 'edge-l4' as const },
          acceptProxyProtocol: false,
          tag: listener.panelBinding!.inboundTag,
          placement: 'bound' as const,
          family: 'none' as const,
        },
      ],
      templates: [],
      adopted: false,
      readyAt: now,
      gateVersion: 0,
      createdAt: now,
      updatedAt: now,
    };
    const existing = await ctx.db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
      .unique();
    if (existing) await ctx.db.replace(existing._id, row);
    else await ctx.db.insert('panelSetups', row);
    await ctx.db.patch(relayId, {
      desiredPublished: 4,
      ...(opts.legacy ? { edgePick: undefined } : { edgePick: 'hrw1' as const }),
      providerSet: [
        { locationId: a!._id, addedAt: 1 },
        { locationId: b!._id, addedAt: 1 },
      ],
    });
  });
  for (const [ip, accountId] of [
    ['198.51.100.19', accounts[0]!],
    ['198.51.100.20', accounts[1]!],
  ] as const)
    await adoptL4Edge(t, relayId, listenerId, { ipv4: ip, publish: true, accountId });
  return { t, relayId, listenerId, a: a!, b: b!, c: c! };
}
type World = Awaited<ReturnType<typeof world>>;

const relayOf = (w: World) => w.t.run(async (ctx) => (await ctx.db.get(w.relayId))!);
const setDefault = (
  w: World,
  codes: string[],
  picks: Array<{ locationId: Id<'edgeLocations'>; want?: number | null }>,
) => w.t.mutation(internal.edgeCountryDefaults.setCountryDefault, { codes, picks });
const apply = (w: World) =>
  w.t.mutation(internal.edgeCountryDefaults.applyToNode, { relayId: w.relayId });
const irDefault = (w: World) =>
  setDefault(
    w,
    ['IR'],
    [
      { locationId: w.a._id, want: 1 },
      { locationId: w.c._id, want: null },
    ],
  );

describe('saving a default', () => {
  test('listed countries, a count somewhere, no country in two defaults, no only location', async () => {
    const w = await world();
    await expect(setDefault(w, ['CN'], [{ locationId: w.a._id, want: 1 }])).rejects.toThrow(
      /not on the censored-country list/,
    );
    await expect(setDefault(w, ['IR'], [{ locationId: w.a._id, want: null }])).rejects.toThrow(
      /needs a count/,
    );
    await expect(
      setDefault(
        w,
        ['IR'],
        [
          { locationId: w.a._id, want: 1 },
          { locationId: w.a._id, want: 1 },
        ],
      ),
    ).rejects.toThrow(/named twice/);
    expect(await irDefault(w)).toMatchObject({ changed: true });
    expect(await irDefault(w)).toMatchObject({ changed: false });
    await expect(setDefault(w, ['IR', 'RU'], [{ locationId: w.b._id, want: 1 }])).rejects.toThrow(
      /IR already has default picks/,
    );
    await w.t.run((ctx) =>
      ctx.db.patch(w.b._id, { forCountries: { codes: ['RU'], only: { since: 1 }, updatedAt: 1 } }),
    );
    await expect(setDefault(w, ['RU'], [{ locationId: w.b._id, want: 1 }])).rejects.toThrow(
      /only for some countries/,
    );
  });

  test('the preview: what each node would take, the new addresses and their price', async () => {
    const w = await world();
    const p = await w.t.query(internal.edgeCountryDefaults.preview, {
      codes: ['IR'],
      picks: [
        { locationId: w.a._id, want: 1 },
        { locationId: w.c._id, want: null },
      ],
    });
    expect(p.refusal).toBeNull();
    expect(p.nodes).toEqual([
      {
        relaySlug: expect.any(String),
        waiting: null,
        added: ['IR'],
        removed: [],
        places: [
          { locationId: w.a._id, label: expect.any(String), adds: 1, each: expect.any(Object) },
        ],
      },
    ]);
    // Nothing was written.
    expect((await relayOf(w)).providerSet!.some((p) => p.audiences)).toBe(false);
  });
});

describe('upkeep writing the defaults', () => {
  test('written on a ready node, audited; then its count is filled at the first place', async () => {
    const w = await world();
    await irDefault(w);
    await w.t.action(internal.edgeReconcile.run, {});
    const set = (await relayOf(w)).providerSet!;
    expect(set.find((p) => p.locationId === w.a._id)!.audiences).toEqual([
      { codes: ['IR'], want: 1, addedAt: expect.any(Number), fromDefault: true },
    ]);
    expect(set.find((p) => p.locationId === w.c._id)).toMatchObject({
      audienceOnly: true,
      fromDefault: true,
      audiences: [{ codes: ['IR'], fromDefault: true }],
    });
    const audit = await w.t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.relay.country_defaults'))
        .collect(),
    );
    expect(audit.map((x) => x.payload)).toMatchObject([{ added: 'IR', removed: '' }]);
    // Applied again: nothing to do.
    expect(await apply(w)).toEqual({ changed: false });
    // The next pass makes Iran's address at the first place.
    await w.t.action(internal.edgeReconcile.run, {});
    const forIran = await w.t.run(async (ctx) =>
      (await ctx.db.query('edgeRotations').collect()).filter((r) => r.audience?.length),
    );
    expect(forIran.map((r) => [r.audience, r.onlyLocationId])).toEqual([[['IR'], w.a._id]]);
  });

  test('a node whose transport is a privacy mode takes none', async () => {
    const w = await world();
    await w.t.run(async (ctx) => {
      const setup = (await ctx.db.query('panelSetups').collect())[0]!;
      await ctx.db.patch(setup._id, {
        modes: setup.modes.map((m) => ({ ...m, slug: 'privacy-reality' })),
      });
    });
    await irDefault(w);
    expect(await apply(w)).toEqual({ changed: false });
    expect((await relayOf(w)).providerSet!.some((p) => p.audiences?.length)).toBe(false);
  });

  test('a node without the rendezvous walk waits, and says so', async () => {
    const w = await world({ legacy: true });
    await irDefault(w);
    expect(await apply(w)).toMatchObject({ waiting: 'edge.audience_needs_spread' });
    expect((await relayOf(w)).countryDefaultsWaiting).toMatchObject({
      code: 'edge.audience_needs_spread',
    });
    const items = (await w.t.query(internal.edgeOperator.attention, {})).items.filter(
      (i: { kind: string }) => i.kind === 'country_defaults_waiting',
    );
    expect(items.map((i: { code: string | null }) => i.code)).toEqual([
      'edge.audience_needs_spread',
    ]);
    await w.t.mutation(internal.edgeAdmin.setEdgePick, { relayId: w.relayId, version: 'hrw1' });
    expect(await apply(w)).toMatchObject({ changed: true });
    expect((await relayOf(w)).countryDefaultsWaiting).toBeUndefined();
  });

  test("the node's own entry wins: the defaults' go, at that pick and elsewhere", async () => {
    const w = await world();
    await irDefault(w);
    await apply(w);
    await w.t.mutation(internal.edgeAudiences.setPickAudience, {
      relayId: w.relayId,
      locationId: w.b._id,
      codes: ['IR'],
      want: 1,
    });
    await apply(w);
    const set = (await relayOf(w)).providerSet!;
    expect(set.find((p) => p.locationId === w.a._id)!.audiences).toBeUndefined();
    // The pick the defaults added (nothing live there) is gone.
    expect(set.find((p) => p.locationId === w.c._id)).toBeUndefined();
    expect(set.find((p) => p.locationId === w.b._id)!.audiences).toEqual([
      { codes: ['IR'], want: 1, addedAt: expect.any(Number) },
    ]);
  });

  test("a node's own entry at the defaults' pick replaces theirs there (no clash)", async () => {
    const w = await world();
    await irDefault(w);
    await apply(w);
    await w.t.mutation(internal.edgeAudiences.setPickAudience, {
      relayId: w.relayId,
      locationId: w.a._id,
      codes: ['IR', 'RU'],
      want: 2,
    });
    expect(
      (await relayOf(w)).providerSet!.find((p) => p.locationId === w.a._id)!.audiences,
    ).toEqual([{ codes: ['IR', 'RU'], want: 2, addedAt: expect.any(Number) }]);
  });

  test('a node opted out takes none; a removed default takes its entries away', async () => {
    const w = await world();
    await irDefault(w);
    await apply(w);
    await w.t.mutation(internal.edgeCountryDefaults.setOptOut, {
      relayId: w.relayId,
      code: 'ir',
      optOut: true,
    });
    await apply(w);
    expect((await relayOf(w)).providerSet!.some((p) => p.audiences?.length)).toBe(false);
    await w.t.mutation(internal.edgeCountryDefaults.setOptOut, {
      relayId: w.relayId,
      code: 'IR',
      optOut: false,
    });
    await apply(w);
    expect((await relayOf(w)).providerSet!.some((p) => p.audiences?.length)).toBe(true);
    await w.t.mutation(internal.edgeCountryDefaults.removeCountryDefault, { codes: ['IR'] });
    expect(await apply(w)).toMatchObject({ changed: true, removed: ['IR'] });
    expect((await relayOf(w)).providerSet).toEqual([
      { locationId: w.a._id, addedAt: 1 },
      { locationId: w.b._id, addedAt: 1 },
    ]);
  });
});

describe('the rollback', () => {
  test('every default goes; nodes keep what they wrote as their own entries', async () => {
    const w = await world();
    await irDefault(w);
    await apply(w);
    await w.t.mutation(internal.edgeCountryDefaults.setOptOut, {
      relayId: w.relayId,
      code: 'RU',
      optOut: true,
    });
    expect(
      await w.t.mutation(internal.edgeCountryDefaults.clearCountryDefaultsForRollback, {}),
    ).toEqual({ rows: 1, nodes: 1 });
    const r = await relayOf(w);
    expect(r.countryDefaultsOptOut).toBeUndefined();
    expect(JSON.stringify(r.providerSet)).not.toContain('fromDefault');
    expect(r.providerSet!.find((p) => p.locationId === w.a._id)!.audiences).toEqual([
      { codes: ['IR'], want: 1, addedAt: expect.any(Number) },
    ]);
    expect(await w.t.run((ctx) => ctx.db.query('countryDefaults').collect())).toEqual([]);
  });
});
