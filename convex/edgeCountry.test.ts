/// <reference types="vite/client" />
/**
 * Per-country checks of edges end to end (edgeCountry.ts): rounds with
 * controls through the real executor, the address and handshake tracks, the
 * repeat planning, groups and marks, expiry, source health, and the tests
 * budget. A source that errors is no evidence, never a block.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { upsertSettingRow } from './appSettings';
import { __setGlobalpingFactory, __setInternalProbeDeps } from './probeOps';
import { __setEdgePlumbingForTests } from './lib/edgeConfig';
import type { GlobalpingLike } from './lib/edges/probes/globalping';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { blockedCountries, noteNameBatch, settleRoundIfDone } from './edgeCountry';
import { internalRunsOf } from './edgeVerification';
import { liveCountryState } from './lib/edges/country/group';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const EDGE = '198.51.100.9';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setGlobalpingFactory(null);
  __setEdgePlumbingForTests(null);
  __setInternalProbeDeps(null);
});

type Outcome = 'ok' | 'fail' | 'silent';

/** Globalping answering each asked location with `limit` vantages on distinct networks. */
function fakeGlobalping(
  outcome: (country: string) => Outcome,
  opts: { create?: 'ok' | 429; remaining?: number } = {},
): GlobalpingLike & { requests: Array<{ locations: Array<{ country: string; limit: number }> }> } {
  const requests: Array<{ locations: Array<{ country: string; limit: number }> }> = [];
  return {
    requests,
    async createMeasurement(req) {
      if (opts.create === 429) return { ok: false, response: new Response(null, { status: 429 }) };
      requests.push(req as (typeof requests)[number]);
      return { ok: true, data: { id: `m-${requests.length}` } };
    },
    async getMeasurement(id) {
      const req = requests[Number(id.slice(2)) - 1]!;
      const results = req.locations.flatMap((l) => {
        const o = outcome(l.country);
        if (o === 'silent') return [];
        return Array.from({ length: l.limit }, (_, k) => ({
          probe: {
            country: l.country,
            asn: l.country.charCodeAt(0) * 1000 + l.country.charCodeAt(1) * 10 + k,
            network: `net-${l.country}-${k}`,
            tags: ['eyeball-network'],
          },
          result:
            o === 'ok'
              ? { status: 'finished', stats: { loss: 0, avg: 30 } }
              : { status: 'finished', stats: { loss: 100, avg: null } },
        }));
      });
      return { ok: true, data: { id, status: 'finished', results } };
    },
    ...(opts.remaining !== undefined
      ? {
          async getLimits() {
            return {
              ok: true,
              data: {
                rateLimit: {
                  measurements: {
                    create: { type: 'ip', limit: 250, remaining: opts.remaining, reset: 60 },
                  },
                },
              },
            };
          },
        }
      : {}),
  };
}

async function seed(
  opts: { checks?: boolean; internalOk?: boolean; extra?: Record<string, string> } = {},
) {
  vi.useFakeTimers();
  const t = convexTest(schema, modules);
  await t.run(async (ctx) => {
    await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify(
        ['IR', 'RU'].map((code) => ({ code, checkEdges: true, checkNamesInside: false })),
      ),
    );
    await upsertSettingRow(ctx, 'edge.probe.sources.checkhost', 'false');
    await upsertSettingRow(ctx, 'edge.probe.perCountryLimit', '3');
    await upsertSettingRow(ctx, 'edge.country.enabled', JSON.stringify(opts.checks ?? true));
    await upsertSettingRow(ctx, 'edge.country.controlCountries', JSON.stringify('DE US'));
    for (const [k, v] of Object.entries(opts.extra ?? {})) await upsertSettingRow(ctx, k, v);
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example'] })],
  });
  const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    listenerId,
    ipv4: EDGE,
    publish: true,
    verified: true,
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(null, { status: 400 })),
  );
  __setInternalProbeDeps({
    tlsConnect: async () =>
      opts.internalOk === false ? { ok: false, error: 'ECONNREFUSED' } : { ok: true },
  });
  return { t, relayId, listenerId, edgeId: edgeId as Id<'edges'> };
}

async function drainRuns(t: T) {
  for (let i = 0; i < 60; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const pending = await t.run(async (ctx) =>
      (await ctx.db.query('probeRuns').collect()).filter(
        (r) => r.status === 'requested' || r.status === 'running',
      ),
    );
    if (pending.length === 0) return;
  }
  throw new Error('probe runs did not settle');
}

const evidence = (t: T, edgeId: Id<'edges'>, country: string) =>
  t.run((ctx) =>
    ctx.db
      .query('edgeCountryEvidence')
      .withIndex('by_edge_country', (q) => q.eq('edgeId', edgeId).eq('country', country))
      .unique(),
  );
const edgeDoc = (t: T, edgeId: Id<'edges'>) =>
  t.run((ctx) => ctx.db.get(edgeId)) as Promise<Doc<'edges'>>;

async function round(t: T, edgeId: Id<'edges'>) {
  await t.mutation(internal.probes.requestProbes, {
    target: { kind: 'edge', ref: edgeId },
    trigger: 'manual',
  });
  await drainRuns(t);
}

/** A settled round written straight into the table (for edges no executor reaches). */
async function syntheticRound(
  t: T,
  edgeId: Id<'edges'>,
  ir: 'ok' | 'fail',
  opts: { controls?: boolean; at?: number } = {},
) {
  await t.run(async (ctx) => {
    const edge = (await ctx.db.get(edgeId))!;
    const now = opts.at ?? Date.now();
    const roundId = `edge:${edgeId}:${now}:x`;
    const base = {
      targetKind: 'edge' as const,
      targetRef: edgeId as string,
      target: `${edge.addresses.v4}:443`,
      port: 443,
      ipVersion: 4 as const,
      addressKind: 'ip' as const,
      requestedFamily: 4 as const,
      status: 'finished' as const,
      trigger: 'cron' as const,
      requestedAt: now,
      finishedAt: now,
      roundId,
    };
    const v = (country: string, ok: boolean, k: number, control = false) => ({
      country,
      // A numeric ASN per (country, vantage): a real network id.
      asn: `AS${country.charCodeAt(0) * 100 + country.charCodeAt(1) * 10 + k}`,
      vantageClass: 'eyeball' as const,
      ok,
      ...(control ? { control: true } : {}),
    });
    await ctx.db.insert('probeRuns', {
      ...base,
      source: 'globalping',
      probeProtocol: 'tcp',
      controls: ['DE', 'US'],
      results: [
        ...[1, 2, 3].map((k) => v('IR', ir === 'ok', k)),
        v('DE', opts.controls !== false, 1, true),
        v('US', opts.controls !== false, 1, true),
      ],
    });
    await ctx.db.insert('probeRuns', {
      ...base,
      source: 'internal',
      probeProtocol: 'tls-sni',
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: opts.controls !== false }],
    });
    await settleRoundIfDone(ctx, roundId, now);
  });
}

describe('edgeCountry: rounds with controls', () => {
  test('the controls ride in the same measurement and never reach the rollup; IR needs a repeat, RU is proven', async () => {
    const gp = fakeGlobalping((c) => (c === 'IR' ? 'fail' : 'ok'));
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed();
    await round(t, edgeId);
    // One measurement: IR and RU with three vantages each, DE and US with one.
    expect(gp.requests[0]!.locations.map((l) => [l.country, l.limit])).toEqual([
      ['IR', 3],
      ['RU', 3],
      ['DE', 1],
      ['US', 1],
    ]);
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    const g = runs.find((r) => r.source === 'globalping')!;
    expect(g.controls).toEqual(['DE', 'US']);
    expect(g.tests).toBe(8);
    expect(g.results.filter((x) => x.control).map((x) => x.country)).toEqual(['DE', 'US']);
    // Control vantages are counted apart: IR fails 3, RU works 3.
    expect([g.okVantages, g.failVantages]).toEqual([3, 3]);
    expect(new Set(runs.map((r) => r.roundId)).size).toBe(1);
    // The rollup the detector, scoring and the rung read knows nothing of DE or US.
    const rows = await t.run((ctx) => ctx.db.query('probeReachability').collect());
    expect(rows.map((r) => r.country).sort()).toEqual(['IR', 'RU', 'XX']);
    // IR: blocked once, so not yet (a proven edge needs two rounds 30 min apart).
    const ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.lastRound).toMatchObject({ result: 'blocked', ok: 0, fail: 3, controlsOk: 3 });
    expect(ir.address).toMatchObject({
      state: 'unknown',
      reason: 'needs_repeat',
      blockedRounds: 1,
    });
    expect(ir.address.repeatAt).toBe(ir.lastRound!.at + 30 * MIN);
    expect(ir.paths).toEqual([
      expect.objectContaining({ family: 4, port: 443, address: EDGE, tcp: 'fails' }),
    ]);
    const ru = (await evidence(t, edgeId, 'RU'))!;
    expect(ru.combined).toBe('proven');
    expect((await edgeDoc(t, edgeId)).countryState?.byCountry).toEqual([
      expect.objectContaining({ country: 'RU', state: 'proven', from: 'edge' }),
    ]);
    // The round reads the same through preUse (what setup runs and rotations wait for).
    const pu = await t.query(internal.edgeCountry.preUse, { edgeId, since: 0 });
    expect(pu).toMatchObject({ enabled: true, state: 'settled', blockedIn: ['IR'] });

    // Not due again before the repeat time; at it, the repeat goes first.
    let due = await t.query(internal.probes.due, { now: Date.now() + 10 * MIN });
    expect(due.dueTargets.find((d) => d.rank === 0)).toBeUndefined();
    vi.setSystemTime(Date.now() + 31 * MIN);
    due = await t.query(internal.probes.due, { now: Date.now() });
    expect(due.dueTargets[0]).toMatchObject({ target: { kind: 'edge', ref: edgeId }, rank: 0 });
    await round(t, edgeId);
    const after = (await evidence(t, edgeId, 'IR'))!;
    expect(after.address).toMatchObject({ state: 'blocked', blockedRounds: 2 });
    expect(after.address.repeatAt).toBeUndefined();
    const state = (await edgeDoc(t, edgeId)).countryState!.byCountry;
    expect(state.map((c) => [c.country, c.state])).toEqual([
      ['IR', 'blocked'],
      ['RU', 'proven'],
    ]);
    expect(blockedCountries(await edgeDoc(t, edgeId), Date.now())).toBe(1);
    // Audited in slugs, countries and states only.
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const states = audit.filter((a) => a.action === 'edge.country.state');
    expect(states.map((a) => [a.payload?.country, a.payload?.state])).toEqual(
      expect.arrayContaining([
        ['RU', 'proven'],
        ['IR', 'blocked'],
      ]),
    );
    expect(JSON.stringify(audit)).not.toContain(EDGE);
    // The admin read carries no address either.
    const overview = await t.query(internal.edgeCountry.overview, {});
    expect(overview.controls).toEqual(['DE', 'US']);
    expect(JSON.stringify(overview)).not.toContain(EDGE);
  });

  test('with the checks off nothing changes: no controls, no rounds read', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed({ checks: false });
    await round(t, edgeId);
    expect(gp.requests[0]!.locations.map((l) => l.country)).toEqual(['IR', 'RU']);
    expect(await t.run((ctx) => ctx.db.query('edgeCountryEvidence').collect())).toEqual([]);
    expect((await edgeDoc(t, edgeId)).countryState).toBeUndefined();
  });

  test('controls that fail too make it down, not blocked', async () => {
    const gp = fakeGlobalping((c) => (c === 'RU' ? 'ok' : 'fail'));
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed({ internalOk: false });
    await round(t, edgeId);
    const ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.lastRound).toMatchObject({ result: 'down', reason: 'controls_failed' });
    expect(ir.address.state).toBe('unknown');
    expect(ir.address.repeatAt).toBeUndefined();
  });
});

describe('edgeCountry: a source that errors is no evidence', () => {
  test('a refused Globalping never blocks anything, and shows up as a failing source', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'fail', { create: 429 }));
    const { t, edgeId } = await seed();
    for (let i = 0; i < 3; i++) {
      await round(t, edgeId);
      vi.setSystemTime(Date.now() + 10 * MIN);
    }
    const ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.lastRound).toMatchObject({ result: 'unknown', reason: 'no_evidence' });
    expect(ir.address).toMatchObject({ state: 'unknown', blockedRounds: 0 });
    expect((await edgeDoc(t, edgeId)).countryState).toBeUndefined();
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    expect(runs.filter((r) => r.source === 'globalping').map((r) => [r.status, r.error])).toEqual([
      ['failed', 'rate_limited'],
      ['failed', 'rate_limited'],
      ['failed', 'rate_limited'],
    ]);
    const health = await t.query(internal.probes.sourceHealthView, {});
    expect(health.sources.find((s) => s.source === 'globalping')).toMatchObject({
      failing: true,
      streak: 3,
      lastError: 'rate_limited',
    });
    expect(health.sources.find((s) => s.source === 'internal')).toMatchObject({ failing: false });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'probe_source_failing')).toMatchObject({
      id: 'probe_source_failing:globalping',
      code: 'rate_limited',
      action: 'open_settings',
    });
  });

  test('Globalping preflight: a measurement that does not fit its limit is not started', async () => {
    const gp = fakeGlobalping(() => 'ok', { remaining: 5 });
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed();
    await round(t, edgeId);
    expect(gp.requests).toHaveLength(0);
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    expect(runs.find((r) => r.source === 'globalping')).toMatchObject({
      status: 'failed',
      error: 'globalping_limit',
    });
  });

  test('the tests budget: a round that would pass it runs without Globalping', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setGlobalpingFactory(() => gp);
    const { t, edgeId } = await seed({ extra: { 'edge.probe.globalpingTestsPerHour': '10' } });
    await round(t, edgeId);
    expect(gp.requests).toHaveLength(1);
    await t.mutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId },
      trigger: 'manual',
    });
    await drainRuns(t);
    const runs = await t.query(internal.probes.listRuns, { target: { kind: 'edge', ref: edgeId } });
    expect(runs.map((r) => r.source).sort()).toEqual(['globalping', 'internal', 'internal']);
    expect(gp.requests).toHaveLength(1);
  });
});

describe('edgeCountry: groups and marks', () => {
  test('two blocked edges block their location; an undecided edge of it inherits; marks win', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, relayId, listenerId, edgeId: a } = await seed();
    const more: Id<'edges'>[] = [];
    for (const ip of ['198.51.100.10', '198.51.100.11']) {
      const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        ipv4: ip,
        publish: false,
        verified: true,
      });
      more.push(edgeId as Id<'edges'>);
    }
    const [b, c] = more as [Id<'edges'>, Id<'edges'>];
    // One provider location for all three (an adopted edge is its own group otherwise).
    await t.run(async (ctx) => {
      for (const id of [a, b, c])
        await ctx.db.patch(id, { managed: true, provider: 'upcloud', placeKey: 'zone-a' });
    });
    const t0 = Date.now();
    for (const id of [a, b]) {
      await syntheticRound(t, id, 'fail', { at: t0 });
      await syntheticRound(t, id, 'fail', { at: t0 + 31 * MIN });
    }
    vi.setSystemTime(t0 + 32 * MIN);
    expect((await evidence(t, a, 'IR'))!.combined).toBe('blocked');
    const grade = await t.run((ctx) =>
      ctx.db
        .query('countryGroupGrades')
        .withIndex('by_group_country', (q) =>
          q.eq('groupKey', 'upcloud:zone-a').eq('country', 'IR'),
        )
        .unique(),
    );
    expect(grade).toMatchObject({ state: 'blocked', counts: { edges: 2, proven: 0, blocked: 2 } });
    // C has nothing of its own: it inherits the group's block.
    expect((await edgeDoc(t, c)).countryState?.byCountry).toEqual([
      expect.objectContaining({ country: 'IR', state: 'blocked', from: 'group' }),
    ]);
    // ...and a never-decided edge of a blocked group is blocked on its first blocked round.
    await syntheticRound(t, c, 'fail', { at: t0 + 33 * MIN });
    expect((await evidence(t, c, 'IR'))!.address).toMatchObject({
      state: 'blocked',
      reason: 'group_blocked',
    });
    // An operator's group mark wins over every check; removing it gives the checks back.
    await t.mutation(internal.edgeCountry.setMark, {
      scope: 'group',
      ref: 'upcloud:zone-a',
      country: 'IR',
      state: 'proven',
    });
    for (const id of [a, b, c])
      expect((await edgeDoc(t, id)).countryState?.byCountry).toEqual([
        expect.objectContaining({ country: 'IR', state: 'proven', from: 'mark' }),
      ]);
    // An edge mark beats the group mark.
    await t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: c,
      country: 'IR',
      state: 'blocked',
    });
    expect((await edgeDoc(t, c)).countryState?.byCountry[0]).toMatchObject({
      state: 'blocked',
      from: 'mark',
    });
    await t.mutation(internal.edgeCountry.setMark, {
      scope: 'group',
      ref: 'upcloud:zone-a',
      country: 'IR',
      state: null,
    });
    expect((await edgeDoc(t, a)).countryState?.byCountry[0]).toMatchObject({
      state: 'blocked',
      from: 'edge',
    });
    // Only a listed country can be marked.
    await expect(
      t.mutation(internal.edgeCountry.setMark, {
        scope: 'edge',
        ref: c,
        country: 'DE',
        state: 'blocked',
      }),
    ).rejects.toThrow(/censored-country list/);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.filter((x) => x.action === 'edge.country.mark')).toHaveLength(3);
  });
});

describe('edgeCountry: what the admin reads', () => {
  test('a new spare blocked from its first round asks for attention; the overview says since when', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, relayId, listenerId, edgeId: live } = await seed();
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: '198.51.100.20',
      publish: false,
      verified: true,
    });
    const spare = edgeId as Id<'edges'>;
    const t0 = Date.now();
    await syntheticRound(t, spare, 'fail', { at: t0 });
    // The address in use failing too is the detector's business, not this item's.
    await syntheticRound(t, live, 'fail', { at: t0 });
    const blockedItems = async () =>
      (await t.query(internal.edgeOperator.attention, {})).items.filter(
        (i) => i.kind === 'new_edge_blocked_in',
      );
    // One blocked round (waiting for its repeat) is enough to warn about a NEW address.
    expect(await blockedItems()).toEqual([
      expect.objectContaining({
        id: `new_edge_blocked_in:${spare}`,
        edgeId: spare,
        listenerKey: 'u',
        severity: 'warning',
        action: 'open_edge',
        facts: { countries: ['IR'] },
      }),
    ]);
    vi.setSystemTime(t0 + 31 * MIN);
    await syntheticRound(t, spare, 'fail', { at: t0 + 31 * MIN });
    const overview = await t.query(internal.edgeCountry.overview, {});
    const ir = overview.edges
      .find((e) => e.edgeId === spare)!
      .countries.find((c) => c.country === 'IR')!;
    expect(ir.combined).toBe('blocked');
    expect(ir.lastRound?.roundId).toBe(`edge:${spare}:${t0 + 31 * MIN}:x`);
    // Since the transition to blocked (the audit row of the second round), not the
    // last confirmation, which moves with every blocked round.
    expect(Date.parse(ir.blockedSince!)).toBeGreaterThanOrEqual(t0 + 31 * MIN);
    expect(Date.parse(ir.blockedSince!)).toBeLessThan(t0 + 32 * MIN);
    vi.setSystemTime(t0 + 70 * MIN);
    await syntheticRound(t, spare, 'fail', { at: t0 + 70 * MIN });
    const again = (await t.query(internal.edgeCountry.overview, {})).edges
      .find((e) => e.edgeId === spare)!
      .countries.find((c) => c.country === 'IR')!;
    expect(again.blockedSince).toBe(ir.blockedSince);
    expect(
      overview.edges.find((e) => e.edgeId === live)!.countries.find((c) => c.country === 'IR')!
        .blockedSince,
    ).toBeNull();
    // A mark leaves it to the operator's word.
    await t.mutation(internal.edgeCountry.setMark, {
      scope: 'edge',
      ref: spare,
      country: 'IR',
      state: 'proven',
    });
    expect(await blockedItems()).toEqual([]);
  });

  test('a country where most addresses fail at once raises country_wide_failure, not blocks', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, relayId, listenerId, edgeId: a } = await seed();
    const more: Id<'edges'>[] = [];
    for (const ip of ['198.51.100.30', '198.51.100.31']) {
      const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        ipv4: ip,
        publish: false,
        verified: true,
      });
      more.push(edgeId as Id<'edges'>);
    }
    const [b, c] = more as [Id<'edges'>, Id<'edges'>];
    await t.run(async (ctx) => {
      for (const [id, place] of [
        [a, 'zone-a'],
        [b, 'zone-a'],
        [c, 'zone-b'],
      ] as const)
        await ctx.db.patch(id, { managed: true, provider: 'upcloud', placeKey: place });
    });
    const t0 = Date.now();
    for (const id of [a, b, c]) await syntheticRound(t, id, 'fail', { at: t0 });
    // The third edge's block, in a second group, makes every checked edge blocked: held.
    expect((await evidence(t, c, 'IR'))!.address).toMatchObject({
      state: 'unknown',
      reason: 'country_wide',
    });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.find((i) => i.kind === 'country_wide_failure')).toMatchObject({
      id: 'country_wide_failure:IR',
      relayId: null,
      severity: 'warning',
      action: 'open_probes',
      facts: { countries: ['IR'], edges: 1, groups: 1 },
    });
    // A held round is not the new address's own block.
    expect(items.find((i) => i.id === `new_edge_blocked_in:${c}`)).toBeUndefined();
    // Many older rounds in the window (one row per edge checked there) never hide
    // the newest hold: the scan reads newest first.
    await t.run(async (ctx) => {
      const row = (await ctx.db
        .query('edgeCountryEvidence')
        .withIndex('by_edge_country', (q) => q.eq('edgeId', a).eq('country', 'IR'))
        .unique())!;
      for (let i = 0; i < 600; i++)
        await ctx.db.insert('edgeCountryEvidence', {
          edgeId: a,
          relayId: row.relayId,
          groupKey: 'upcloud:zone-a',
          country: 'IR',
          address: { state: 'proven', blockedRounds: 0 },
          handshake: { state: 'none', pathBatches: [] },
          combined: 'proven',
          lastRoundAt: t0 - 60 * MIN - i,
          updatedAt: t0 - 60 * MIN,
        });
    });
    const crowded = await t.query(internal.edgeOperator.attention, {});
    expect(crowded.items.find((i) => i.kind === 'country_wide_failure')).toMatchObject({
      id: 'country_wide_failure:IR',
      facts: { countries: ['IR'], edges: 1 },
    });
    // With the checks off, neither item is raised.
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.country.enabled', 'false'));
    const off = await t.query(internal.edgeOperator.attention, {});
    expect(
      off.items.filter((i) => ['country_wide_failure', 'new_edge_blocked_in'].includes(i.kind)),
    ).toEqual([]);
  });
});

describe('edgeCountry: the handshake track', () => {
  const batch = (outcome: 'reset' | 'ok') =>
    ['a.example', 'b.example'].map((name) => ({
      name,
      source: 'globalping',
      results: [1, 2, 3].map((k) => ({ asn: `AS${k}`, outcome })),
    }));

  test('a path batch needs pairing with working TCP; two paired an hour apart block; TCP never clears it; recovery does', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const t0 = Date.now();
    const note = (at: number, outcome: 'reset' | 'ok') =>
      t.run((ctx) =>
        noteNameBatch(ctx, {
          targetKind: 'edge',
          targetRef: edgeId,
          address: EDGE,
          port: 443,
          country: 'IR',
          measurements: batch(outcome),
          at,
        }),
      );
    // No TCP reading yet: the batch is recorded unpaired and asks for a round at once.
    await note(t0, 'reset');
    let ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.handshake).toMatchObject({
      state: 'none',
      reason: 'no_tcp_pairing',
      pathBatches: [],
    });
    expect(ir.address.repeatAt).toBeLessThanOrEqual(Date.now());
    // A working round, then a paired batch: one so far.
    await syntheticRound(t, edgeId, 'ok', { at: t0 + MIN });
    ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.address.repeatAt).toBeUndefined();
    await note(t0 + 2 * MIN, 'reset');
    expect((await evidence(t, edgeId, 'IR'))!.handshake).toMatchObject({
      state: 'none',
      reason: 'needs_repeat',
    });
    // Over an hour later, paired again with a fresh working round: blocked.
    await syntheticRound(t, edgeId, 'ok', { at: t0 + 70 * MIN });
    await note(t0 + 75 * MIN, 'reset');
    ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.handshake).toMatchObject({ state: 'blocked', reason: 'handshake' });
    expect(ir.combined).toBe('blocked');
    expect(ir.address.state).toBe('proven');
    // Another working TCP round does not clear it.
    await syntheticRound(t, edgeId, 'ok', { at: t0 + 80 * MIN });
    expect((await evidence(t, edgeId, 'IR'))!.combined).toBe('blocked');
    expect((await edgeDoc(t, edgeId)).countryState?.byCountry).toEqual([
      expect.objectContaining({ country: 'IR', state: 'blocked', from: 'edge' }),
    ]);
    // Names reaching the address again do.
    await note(t0 + 90 * MIN, 'ok');
    ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.handshake).toMatchObject({ state: 'none', reason: 'recovered' });
    expect(ir.combined).toBe('proven');
  });

  test('a handshake block outlives an earlier address proof (read without the expiry worker)', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const t0 = Date.now();
    const note = (at: number) =>
      t.run((ctx) =>
        noteNameBatch(ctx, {
          targetKind: 'edge',
          targetRef: edgeId,
          address: EDGE,
          port: 443,
          country: 'IR',
          measurements: batch('reset'),
          at,
        }),
      );
    await syntheticRound(t, edgeId, 'ok', { at: t0 });
    await note(t0 + 2 * MIN);
    await syntheticRound(t, edgeId, 'ok', { at: t0 + 65 * MIN });
    await note(t0 + 70 * MIN);
    const ir = (await evidence(t, edgeId, 'IR'))!;
    expect(ir.combined).toBe('blocked');
    expect(ir.address.until).toBeLessThan(ir.handshake.until!);
    expect(ir.until).toBe(ir.address.until);
    expect(ir.stateUntil).toBe(ir.handshake.until);
    // The address proof has lapsed, the handshake block has not; no expiry pass ran.
    const now = ir.address.until! + MIN;
    const edge = await edgeDoc(t, edgeId);
    expect(liveCountryState(edge.countryState?.byCountry, now)).toEqual([
      expect.objectContaining({ country: 'IR', state: 'blocked' }),
    ]);
    expect(blockedCountries(edge, now)).toBe(1);
  });

  test('a TCP reading of another port or address does not pair', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    const t0 = Date.now();
    await syntheticRound(t, edgeId, 'ok', { at: t0 });
    await t.run((ctx) =>
      noteNameBatch(ctx, {
        targetKind: 'edge',
        targetRef: edgeId,
        address: EDGE,
        port: 8443,
        country: 'IR',
        measurements: batch('reset'),
        at: t0 + MIN,
      }),
    );
    expect((await evidence(t, edgeId, 'IR'))!.handshake.reason).toBe('no_tcp_pairing');
  });
});

describe('edgeCountry: expiry', () => {
  test('a decided result lapses after the window, the copy follows, the row goes a window later', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    await round(t, edgeId);
    expect((await evidence(t, edgeId, 'RU'))!.combined).toBe('proven');
    vi.setSystemTime(Date.now() + 14 * DAY + MIN);
    await t.mutation(internal.edgeCountry.expire, {});
    const ru = (await evidence(t, edgeId, 'RU'))!;
    expect(ru.address).toMatchObject({ state: 'unknown', reason: 'expired' });
    expect(ru.combined).toBe('unknown');
    expect((await edgeDoc(t, edgeId)).countryState).toBeUndefined();
    vi.setSystemTime(Date.now() + 14 * DAY + MIN);
    await t.mutation(internal.edgeCountry.expire, {});
    expect(await evidence(t, edgeId, 'RU')).toBeNull();
    const beats = await t.run((ctx) => ctx.db.query('cronHeartbeats').collect());
    expect(beats.some((b) => b.name === 'edge-country-expiry')).toBe(true);
  });

  test('proofs of many edges in many places lapsing together stay within one execution, every copy follows', async () => {
    vi.useFakeTimers();
    const t = convexTest({ schema, modules, transactionLimits: true });
    await insertPanelServer(t);
    const { relayId, listenerId } = await registerRelay(t, {
      listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example'] })],
    });
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4: EDGE,
      publish: true,
      verified: true,
    });
    const countries = ['AA', 'BB', 'CC', 'DD', 'EE', 'FF', 'GG', 'HH', 'II', 'JJ'];
    const now = Date.now();
    const lapsed = now - MIN;
    const edges = await t.run(async (ctx) => {
      const { _id, _creationTime, ...base } = (await ctx.db.get(edgeId as Id<'edges'>))!;
      void _id;
      void _creationTime;
      const out: Id<'edges'>[] = [];
      for (let g = 0; g < 10; g++) {
        const groupKey = `upcloud:place-${g}`;
        for (let k = 0; k < 15; k++) {
          const id = await ctx.db.insert('edges', {
            ...base,
            managed: true,
            provider: 'upcloud',
            placeKey: `place-${g}`,
            name: `edge-${g}-${k}`,
            countryState: {
              byCountry: countries.map((country) => ({
                country,
                state: 'proven' as const,
                from: 'edge' as const,
                until: lapsed,
              })),
              updatedAt: lapsed - DAY,
            },
          });
          out.push(id);
          for (const country of countries)
            await ctx.db.insert('edgeCountryEvidence', {
              edgeId: id,
              relayId,
              groupKey,
              country,
              address: {
                state: 'proven',
                decidedAt: lapsed - DAY,
                until: lapsed,
                blockedRounds: 0,
              },
              handshake: { state: 'none', pathBatches: [] },
              combined: 'proven',
              stateUntil: lapsed,
              until: lapsed,
              updatedAt: lapsed - DAY,
            });
        }
        for (const country of countries)
          await ctx.db.insert('countryGroupGrades', {
            groupKey,
            country,
            state: 'proven',
            counts: { edges: 15, proven: 15, blocked: 0 },
            until: lapsed,
            updatedAt: lapsed - DAY,
          });
      }
      return out;
    });
    await t.mutation(internal.edgeCountry.expire, { now });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    const left = await t.run(async (ctx) => {
      const rows = await ctx.db.query('edgeCountryEvidence').collect();
      return {
        proven: rows.filter((r) => r.combined === 'proven').length,
        copies: (await Promise.all(edges.map((id) => ctx.db.get(id)))).filter(
          (e) => e?.countryState !== undefined,
        ).length,
      };
    });
    expect(left).toEqual({ proven: 0, copies: 0 });
  });
});

describe('edgeCountry: the verification rung reads its own runs', () => {
  test('many external runs never push the internal shape check out of the window', async () => {
    __setGlobalpingFactory(() => fakeGlobalping(() => 'ok'));
    const { t, edgeId } = await seed();
    await round(t, edgeId);
    await t.run(async (ctx) => {
      const now = Date.now();
      for (let i = 0; i < 60; i++)
        await ctx.db.insert('probeRuns', {
          targetKind: 'edge',
          targetRef: edgeId as string,
          source: 'globalping',
          target: `${EDGE}:443`,
          port: 443,
          status: 'finished',
          trigger: 'cron',
          requestedAt: now + i + 1,
          results: [],
        });
    });
    const internalRuns = await t.run((ctx) => internalRunsOf(ctx.db, edgeId));
    expect(internalRuns.length).toBeGreaterThan(0);
    expect(internalRuns.every((r) => r.source === 'internal')).toBe(true);
  });
});
