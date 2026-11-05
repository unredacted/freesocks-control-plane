/// <reference types="vite/client" />
/**
 * Latency over the whole path end to end (docs/edges.md "Latency over the
 * whole path"): a node in the middle of the US with one address at a location
 * in the US and one far from it (meant for Iran). The preview as a member in the
 * US, Iran, Germany and Brazil; the switch and what it needs; the measured
 * member legs taken from probe runs (only bare TCP connects from in-country
 * vantages count), committed only when they move, moving the epoch while
 * latency ordering is on; and the rollback helper.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import {
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { refuseNetwork } from './lib/edges/testing/mockFetch';
import { PER_HOUR, figureMoves, figureOf, keptSamples } from './edgeLatency';

const modules = import.meta.glob('./**/*.*s');
const NOW = 1_900_000_000_000;

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

async function setup(opts: { latency?: boolean; node?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    await upsertSettingRow(ctx, 'delivery.country.detect', 'true');
    await upsertSettingRow(ctx, 'delivery.country.steer', 'true');
    if (opts.latency !== false) await upsertSettingRow(ctx, 'delivery.country.latency', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
    // The node sits in the middle of the US (its backend server's map position).
    if (opts.node !== false) await ctx.db.patch(serverId, { locationLat: 40, locationLng: -100 });
  });
  const usAccount = await createAccount(t, { provider: 'gcore', name: 'one' });
  const farAccount = await createAccount(t, { provider: 'upcloud', name: 'two' });
  const locationOf = async (accountId: Id<'edgeProviderAccounts'>) =>
    (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!
      .id as Id<'edgeLocations'>;
  const usLocation = await locationOf(usAccount);
  const farLocation = await locationOf(farAccount);
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example', 'b.example'] })],
  });
  const adopt = async (ipv4: string) =>
    (
      await t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        ipv4,
        publish: true,
        verified: true,
      })
    ).edgeId as Id<'edges'>;
  const us = await adopt('198.51.100.1');
  const far = await adopt('198.51.100.2');
  await t.run(async (ctx) => {
    // Each address carries its location's place key, as every address made there does.
    await ctx.db.patch(usLocation, {
      placeKey: 'a-1',
      memberPlace: { name: 'Town', country: 'US', updatedAt: 1 },
    });
    await ctx.db.patch(farLocation, {
      placeKey: 'b-1',
      memberPlace: { name: 'City', country: 'GE', updatedAt: 1 },
      forCountries: { codes: ['IR'], updatedAt: 1 },
    });
    await ctx.db.patch(us, { locationId: usLocation, provider: 'gcore', placeKey: 'a-1' });
    await ctx.db.patch(far, { locationId: farLocation, provider: 'upcloud', placeKey: 'b-1' });
  });
  return { t, relayId, us, far };
}

type World = Awaited<ReturnType<typeof setup>>;

const preview = (w: World, country?: string) =>
  w.t.query(internal.edgeAdmin.renderPreview, {
    relayId: w.relayId,
    family: 'xray-links',
    ...(country ? { country } : {}),
  });

/** Which address the body hands out first. */
const firstIn = (body: string) => {
  const a = body.indexOf('198.51.100.1');
  const b = body.indexOf('198.51.100.2');
  return a >= 0 && (b < 0 || a < b) ? 'us' : b >= 0 ? 'far' : 'none';
};

describe('the preview as a member in each country', () => {
  test('the US, Germany and Brazil start in the US; Iran far away (meant for it)', async () => {
    const w = await setup();
    for (const [country, want] of [
      ['US', 'us'],
      ['DE', 'us'],
      ['BR', 'us'],
      ['IR', 'far'],
    ] as const) {
      const p = await preview(w, country);
      expect(p.steered).toBe(true);
      expect(firstIn(p.body)).toBe(want);
      // Over the whole path even the far address is near for Iran: the node is in the US either way.
      expect(p.primaryWhy?.latency?.band).toBe('near');
      expect(p.primaryWhy?.latency?.ms).toBeGreaterThan(0);
      expect(p.primaryWhy?.meantFor).toBe(country === 'IR');
    }
  });

  test('a country off the list needs latency ordering on; without it nothing says latency', async () => {
    const w = await setup({ latency: false });
    await expect(preview(w, 'DE')).rejects.toThrow(/censored-country list/);
    const p = await preview(w, 'IR');
    expect(p.primaryWhy?.latency).toBeUndefined();
    expect(firstIn(p.body)).toBe('far');
  });

  test('no node position: no figures, so no band moves anyone', async () => {
    const w = await setup({ node: false });
    const p = await preview(w, 'US');
    expect(p.primaryWhy?.latency).toMatchObject({ band: 'near', ms: null });
  });

  test('no country (and the opt-out): the same body with or without latency ordering', async () => {
    const w = await setup();
    const on = await preview(w);
    await w.t.run((ctx) => upsertSettingRow(ctx, 'delivery.country.latency', 'false'));
    const off = await preview(w);
    expect(on.body).toBe(off.body);
    expect(on.primaryWhy ?? null).toBeNull();
  });
});

describe('the switch', () => {
  test('turning latency ordering on or off moves every origin epoch', async () => {
    vi.useFakeTimers();
    const w = await setup({ latency: false });
    const epoch = async () =>
      w.t.run(async (ctx) => (await ctx.db.get(w.relayId))!.publicationEpoch);
    const before = await epoch();
    await w.t.mutation(internal.appSettings.setMany, {
      entries: [{ key: 'delivery.country.latency', value: 'true' }],
    });
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await epoch()).toBe(before + 1);
    // The same value again moves nothing.
    await w.t.mutation(internal.appSettings.setMany, {
      entries: [{ key: 'delivery.country.latency', value: 'true' }],
    });
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await epoch()).toBe(before + 1);
  });
});

describe("the node's map position", () => {
  test('moving it moves the epoch while latency ordering is on; the same position again does not', async () => {
    vi.useFakeTimers();
    const w = await setup();
    const serverId = await w.t.run(async (ctx) => (await ctx.db.get(w.relayId))!.backendServerId!);
    const epoch = async () =>
      w.t.run(async (ctx) => (await ctx.db.get(w.relayId))!.publicationEpoch);
    const before = await epoch();
    const move = (lat: number | null, lng: number | null) =>
      w.t.mutation(internal.adminApi.updateBackendServer, {
        id: serverId,
        locationLat: lat,
        locationLng: lng,
      });
    await move(40, -100);
    expect(await epoch()).toBe(before);
    await move(41, -88);
    expect(await epoch()).toBe(before + 1);
    await move(null, null);
    expect(await epoch()).toBe(before + 2);
    // Without a position there is no node leg: the preview has no figures.
    expect((await preview(w, 'US')).primaryWhy?.latency).toMatchObject({ ms: null });
  });
});

describe('measured member legs', () => {
  /** One finished probe run of `edgeId` with these in-country results. */
  const run = (
    w: World,
    edgeId: Id<'edges'>,
    results: Array<{ country: string; rttMs: number; asn: string; control?: boolean }>,
    over: Partial<{
      source: 'globalping' | 'checkhost' | 'ripeatlas';
      probeProtocol: 'tcp' | 'tls';
      at: number;
    }> = {},
  ) =>
    w.t.run((ctx) =>
      ctx.db.insert('probeRuns', {
        targetKind: 'edge',
        targetRef: edgeId,
        source: over.source ?? 'globalping',
        target: '198.51.100.2:443',
        probeProtocol: over.probeProtocol ?? 'tcp',
        ipVersion: 4,
        status: 'finished',
        trigger: 'cron',
        requestedAt: over.at ?? NOW - 3_600_000,
        finishedAt: over.at ?? NOW - 3_600_000,
        results: results.map((r) => ({
          country: r.country,
          asn: r.asn,
          vantageClass: 'eyeball' as const,
          ok: true,
          rttMs: r.rttMs,
          ...(r.control ? { control: true } : {}),
        })),
      }),
    );
  const rows = (w: World) => w.t.run((ctx) => ctx.db.query('edgeLatency').collect());
  /** One hourly pass at `now`: the cron and the per-location jobs it schedules. */
  const pass = async (w: World, now: number) => {
    await w.t.mutation(internal.edgeLatency.refresh, { now });
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
  };
  const epoch = (w: World) =>
    w.t.run(async (ctx) => (await ctx.db.get(w.relayId))!.publicationEpoch);

  test('five bare connects from two networks there make a figure; it moves the epoch once', async () => {
    vi.useFakeTimers();
    const w = await setup();
    await run(w, w.far, [
      { country: 'IR', rttMs: 48, asn: 'AS1' },
      { country: 'IR', rttMs: 52, asn: 'AS1' },
      { country: 'IR', rttMs: 50, asn: 'AS2' },
    ]);
    await run(w, w.far, [
      { country: 'IR', rttMs: 49, asn: 'AS2' },
      { country: 'IR', rttMs: 300, asn: 'AS3' },
      // A control vantage says nothing about the country it stands in.
      { country: 'DE', rttMs: 1, asn: 'AS9', control: true },
    ]);
    // Neither a TLS-timed run nor RIPE Atlas counts.
    await run(w, w.far, [{ country: 'IR', rttMs: 999, asn: 'AS4' }], { probeProtocol: 'tls' });
    await run(w, w.far, [{ country: 'IR', rttMs: 999, asn: 'AS5' }], { source: 'ripeatlas' });
    const before = await epoch(w);
    await pass(w, NOW);
    expect(
      (await rows(w)).map((r) => [r.groupKey, r.country, r.ms, r.samples, r.networks]),
    ).toEqual([['upcloud:b-1', 'IR', 50, 5, 3]]);
    expect(await epoch(w)).toBe(before + 1);
    // The next pass reads only what is new: nothing, so nothing moves.
    await pass(w, NOW + 3_600_000);
    expect((await rows(w))[0]!.samples).toBe(5);
    expect(await epoch(w)).toBe(before + 1);
    // The preview now says Iran's leg was timed.
    expect((await preview(w, 'IR')).primaryWhy?.latency?.measured).toBe(true);
  });

  test('passes add up over the week; one network, nothing recent: no figure (and a committed one lapses)', async () => {
    vi.useFakeTimers();
    const w = await setup();
    const five = (asn: (i: number) => string) =>
      Array.from({ length: 5 }, (_, i) => ({ country: 'IR', rttMs: 50, asn: asn(i) }));
    await run(
      w,
      w.far,
      five(() => 'AS1'),
    );
    await pass(w, NOW);
    expect(await rows(w)).toEqual([]);
    // An hour later, more of the same network still makes no figure; another one does.
    await run(
      w,
      w.far,
      five(() => 'AS1'),
      { at: NOW + 3_600_000 },
    );
    await pass(w, NOW + 2 * 3_600_000);
    expect(await rows(w)).toEqual([]);
    await run(w, w.far, [{ country: 'IR', rttMs: 60, asn: 'AS2' }], { at: NOW + 2.5 * 3_600_000 });
    await pass(w, NOW + 4 * 3_600_000);
    const got = await rows(w);
    expect(got.map((r) => [r.ms, r.samples, r.networks])).toEqual([[50, 11, 2]]);
    // Three days on, the newest result is too old: the figure goes.
    const before = await epoch(w);
    await pass(w, NOW + 3 * 86_400_000);
    expect(await rows(w)).toEqual([]);
    expect(await epoch(w)).toBe(before + 1);
  });

  test('with latency ordering off figures are kept but move no epoch', async () => {
    vi.useFakeTimers();
    const w = await setup({ latency: false });
    await run(
      w,
      w.far,
      Array.from({ length: 5 }, (_, i) => ({ country: 'IR', rttMs: 50, asn: `AS${i}` })),
    );
    const before = await epoch(w);
    await pass(w, NOW);
    expect(await rows(w)).toHaveLength(1);
    expect(await epoch(w)).toBe(before);
  });

  test('rollback: every figure, every kept sample and the switch go', async () => {
    vi.useFakeTimers();
    const w = await setup();
    await run(
      w,
      w.far,
      Array.from({ length: 5 }, (_, i) => ({ country: 'IR', rttMs: 50, asn: `AS${i}` })),
    );
    await pass(w, NOW);
    await w.t.mutation(internal.edgeLatency.purgeForRollback, {});
    await w.t.finishAllScheduledFunctions(vi.runAllTimers);
    expect(await rows(w)).toEqual([]);
    expect(await w.t.run((ctx) => ctx.db.query('edgeLatencySamples').collect())).toEqual([]);
    const key = await w.t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'delivery.country.latency'))
        .unique(),
    );
    expect(key).toBeNull();
  });
});

describe('kept samples (pure)', () => {
  const H = 3_600_000;
  const at = (h: number, ms = 50, net: string | null = 'AS1') => ({ at: NOW + h * H, ms, net });

  test('at most twelve per clock hour, the first ones, spread over the whole week', () => {
    const burst = Array.from({ length: 30 }, (_, i) => at(0, 40 + i));
    const kept = keptSamples([], burst, NOW + H);
    expect(kept).toHaveLength(PER_HOUR);
    expect(kept.map((s) => s.ms)).toEqual(burst.slice(0, PER_HOUR).map((s) => s.ms));
    // A week of hourly bursts keeps every hour, not only the newest ones.
    const week = Array.from({ length: 7 * 24 }, (_, h) => at(h - 7 * 24 + 1));
    expect(keptSamples([], week, NOW + H)).toHaveLength(7 * 24);
  });

  test('older than the week goes; a figure needs five samples from two networks, the newest fresh', () => {
    expect(keptSamples([at(-8 * 24)], [at(0)], NOW)).toEqual([at(0)]);
    const five = [
      at(0, 50, 'AS1'),
      at(0, 50, 'AS1'),
      at(0, 60, 'AS2'),
      at(0, 40, 'AS2'),
      at(0, 55, null),
    ];
    expect(figureOf(five, NOW)).toBe(50);
    expect(figureOf(five.slice(1), NOW)).toBeNull();
    expect(
      figureOf(
        five.map((s) => ({ ...s, net: 'AS1' })),
        NOW,
      ),
    ).toBeNull();
    expect(figureOf(five, NOW + 49 * H)).toBeNull();
    expect(figureMoves(100, 112)).toBe(false);
    expect(figureMoves(100, 116)).toBe(true);
    expect(figureMoves(40, 49)).toBe(false);
  });
});
