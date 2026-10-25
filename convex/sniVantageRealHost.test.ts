/// <reference types="vite/client" />
/**
 * Real-host controls end to end (sniVantage.ts + sniVantageOps.ts): with
 * `edge.sni.vantage.realHost` on, every name of a batch is also presented to
 * its real site (resolved on FCP's host, public, not FCP's, seen serving the
 * name from FCP's host) from the same vantages; the pair is read per vantage
 * and stored beside the name's evidence, never in it; the budget counts the
 * twins; a real site that fails a guard is never dialled.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { upsertSettingRow } from './appSettings';
import {
  adoptL4Edge,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import type { GlobalpingLike } from './lib/edges/probes/globalping';
import { __setRealHostDeps, __setVantageGlobalpingFactory } from './sniVantageOps';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const T0 = Date.parse('2026-10-01T00:00:00Z');
const EDGE = '198.51.100.9';
const REAL = '192.0.2.50';
const NAMES = ['x.example', 'y.example', 'z.example'];
const ASNS = [64501, 64502, 64503];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
});
afterEach(() => {
  vi.useRealTimers();
  __setVantageGlobalpingFactory(null);
  __setRealHostDeps(null);
});

type Outcome = 'ok' | 'handshake' | 'connect';

/** Three IR probes on three networks; `outcome(target, name)` answers each measurement. */
function fakeGlobalping(outcome: (target: string, name: string) => Outcome) {
  const requests: Array<{ target: string; locations: unknown; host: string }> = [];
  const client: GlobalpingLike = {
    async createMeasurement(req) {
      const r = req as {
        target: string;
        locations: unknown;
        measurementOptions: { request: { host: string } };
      };
      requests.push({
        target: r.target,
        locations: r.locations,
        host: r.measurementOptions.request.host,
      });
      return { ok: true, data: { id: `m-${requests.length}` } };
    },
    async getMeasurement(id) {
      const req = requests[Number(id.slice(2)) - 1]!;
      const o = outcome(req.target, req.host);
      // The fake answers in a different order each time: pairing must not rely on it.
      const asns = Number(id.slice(2)) % 2 === 0 ? [...ASNS].reverse() : ASNS;
      const results = asns.map((asn) => ({
        probe: { country: 'IR', asn, network: `net-${asn}`, city: `c${asn}`, tags: [] },
        result:
          o === 'ok'
            ? {
                status: 'finished',
                statusCode: 200,
                tls: { authorized: true },
                // FCP's address carries the node-to-target leg in its handshake.
                timings:
                  req.target === EDGE ? { tcp: 50, tls: 200 + (asn % 10) } : { tcp: 35, tls: 40 },
              }
            : {
                status: 'failed',
                rawOutput:
                  o === 'handshake'
                    ? 'read ECONNRESET'
                    : 'Request timed out while establishing the TCP connection.',
              },
      }));
      return { ok: true, data: { id, status: 'finished', results } };
    },
  };
  return { client, requests };
}

async function seed(settings: Record<string, unknown> = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.sni.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.sni.vantage.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.sni.vantage.countries', JSON.stringify(['IR']));
    for (const [k, v] of Object.entries({ 'edge.sni.vantage.realHost': true, ...settings }))
      await upsertSettingRow(ctx, k, JSON.stringify(v));
  });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-a',
    label: 'Family A',
    targetAddress: 'target.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, { slug: 'fam-a', lines: NAMES });
  await t.run(async (ctx) => {
    for (const n of await ctx.db.query('sniNames').collect())
      await ctx.db.patch(n._id, {
        qualification: { state: 'ok', consecutiveFails: 0, tlsVersion: 'TLSv1.3' },
        checkedAt: Date.now(),
      });
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: NAMES })],
  });
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE, publish: true });
  return { t, edgeId };
}

async function drain(t: T) {
  for (let i = 0; i < 80; i++) {
    await vi.runAllTimersAsync();
    await t.finishInProgressScheduledFunctions();
    const open = await t.run(async (ctx) =>
      (await ctx.db.query('sniVantageProbes').collect()).filter(
        (r) => r.status === 'requested' || r.status === 'running',
      ),
    );
    if (open.length === 0) return;
  }
  throw new Error('vantage measurements did not settle');
}

const rows = (t: T) => t.run((ctx) => ctx.db.query('sniVantageProbes').collect());
const evidence = (t: T, name: string) =>
  t.run((ctx) =>
    ctx.db
      .query('sniVantageEvidence')
      .withIndex('by_name_country', (q) => q.eq('name', name).eq('country', 'IR'))
      .unique(),
  );

describe('real-host controls', () => {
  test('a twin per name, the same vantages, the real site resolved and checked on FCP’s host first', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping((target, name) =>
      target === EDGE && name === 'x.example' ? 'handshake' : 'ok',
    );
    __setVantageGlobalpingFactory(() => gp.client);
    const lookups: string[] = [];
    const served: Array<[string, string]> = [];
    __setRealHostDeps({
      lookup: async (name, family) => {
        lookups.push(`${name}/${family}`);
        return [REAL];
      },
      serves: async (host, name) => {
        served.push([host, name]);
        return true;
      },
    });
    const r = await t.mutation(internal.sniVantage.tick, {});
    expect(r).toMatchObject({ started: 1, measurements: 6 });
    await drain(t);
    const all = await rows(t);
    expect(all.filter((x) => x.role === 'real_host')).toHaveLength(3);
    expect(all.every((x) => x.status === 'finished')).toBe(true);
    // The twin keeps FCP's address as what the batch is about, and records the real site.
    for (const x of all.filter((y) => y.role === 'real_host'))
      expect(x).toMatchObject({ address: EDGE, realAddress: REAL });
    expect(lookups.sort()).toEqual(['x.example/4', 'y.example/4', 'z.example/4']);
    expect(served.every(([h]) => h === REAL)).toBe(true);
    // Every measurement after the first reuses the first's probes; the real site on 443.
    expect(gp.requests[0]!.locations).not.toBe('m-1');
    expect(gp.requests.slice(1).every((q) => q.locations === 'm-1')).toBe(true);
    expect(gp.requests.filter((q) => q.target === REAL)).toHaveLength(3);
    const x = await evidence(t, 'x.example');
    expect(x?.realHost).toMatchObject({
      reading: 'ip_name_match',
      realAddress: REAL,
      vantages: 3,
      networks: 3,
      counts: { ipNameMatch: 3, works: 0, inconclusive: 0 },
    });
    expect(x?.realHost?.target).toContain(EDGE);
    const y = await evidence(t, 'y.example');
    expect(y?.realHost?.reading).toBe('works');
    // What the target adds, from the same measurements: 151..153 beyond one
    // round trip on FCP's address, 5 on the real site.
    expect(y?.realHost?.timing).toEqual({ pairs: 3, oursMs: 152, realMs: 5, addsMs: 147 });
    // A failed handshake on our side gives no timing.
    expect(x?.realHost?.timing).toBeUndefined();
    // The name's own evidence is about FCP's address only: the twins never count in it.
    expect(x).toMatchObject({ latest: 'failing', measurements: 1 });
    expect(x?.streak).toMatchObject({ nameFailures: 3, singled: 3, pathFailures: 0 });
  });

  test('our address failing to connect while the real site works reads as the address', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping((target) => (target === EDGE ? 'connect' : 'ok'));
    __setVantageGlobalpingFactory(() => gp.client);
    __setRealHostDeps({ lookup: async () => [REAL], serves: async () => true });
    await t.mutation(internal.sniVantage.tick, {});
    await drain(t);
    for (const name of NAMES)
      expect((await evidence(t, name))?.realHost?.reading).toBe('address_blocked');
  });

  test('both failing from vantages that reach other names reads as the name', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping((_target, name) => (name === 'x.example' ? 'handshake' : 'ok'));
    __setVantageGlobalpingFactory(() => gp.client);
    __setRealHostDeps({ lookup: async () => [REAL], serves: async () => true });
    await t.mutation(internal.sniVantage.tick, {});
    await drain(t);
    expect((await evidence(t, 'x.example'))?.realHost?.reading).toBe('name_blocked');
  });

  test('a real site that is private, FCP’s own, or not serving the name is never dialled', async () => {
    for (const [deps, code] of [
      [{ lookup: async () => ['10.0.0.5'], serves: async () => true }, 'real_private'],
      [{ lookup: async () => [EDGE], serves: async () => true }, 'real_is_ours'],
      [{ lookup: async () => [REAL], serves: async () => false }, 'real_not_serving'],
      [
        {
          lookup: async () => {
            throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
          },
          serves: async () => true,
        },
        'real_resolve',
      ],
    ] as const) {
      const { t } = await seed();
      const gp = fakeGlobalping(() => 'ok');
      __setVantageGlobalpingFactory(() => gp.client);
      __setRealHostDeps(deps);
      await t.mutation(internal.sniVantage.tick, {});
      await drain(t);
      const twins = (await rows(t)).filter((x) => x.role === 'real_host');
      expect(twins.map((x) => [x.status, x.error])).toEqual(NAMES.map(() => ['failed', code]));
      expect(gp.requests.every((q) => q.target === EDGE)).toBe(true);
      expect((await evidence(t, 'x.example'))?.realHost).toBeUndefined();
    }
  });

  test('turned off after the plan: the twins are settled without visiting the real site', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const lookups: string[] = [];
    __setRealHostDeps({
      lookup: async (name) => {
        lookups.push(name);
        return [REAL];
      },
      serves: async () => true,
    });
    await t.mutation(internal.sniVantage.tick, {});
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.sni.vantage.realHost', 'false'));
    await drain(t);
    const all = await rows(t);
    expect(all.filter((x) => x.role === 'real_host').map((x) => [x.status, x.error])).toEqual(
      NAMES.map(() => ['failed', 'gate_real_host']),
    );
    expect(all.filter((x) => x.role === undefined).every((x) => x.status === 'finished')).toBe(
      true,
    );
    expect(lookups).toEqual([]);
    expect(gp.requests.every((q) => q.target === EDGE)).toBe(true);
  });

  test('the real site is the lowest public answer, compared with FCP’s own in canonical form', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    __setRealHostDeps({
      lookup: async () => ['192.0.2.60', EDGE, '192.0.2.50'],
      serves: async () => true,
    });
    await t.mutation(internal.sniVantage.tick, {});
    await drain(t);
    for (const x of (await rows(t)).filter((y) => y.role === 'real_host'))
      expect(x.realAddress).toBe('192.0.2.50');
  });

  test('a real-host reading whose own measurement failed still ages out', async () => {
    const { t } = await seed();
    const gp = fakeGlobalping(() => 'ok');
    // FCP's address cannot be measured at all; the real sites can.
    const create = gp.client.createMeasurement.bind(gp.client);
    gp.client.createMeasurement = async (req) =>
      (req as { target: string }).target === EDGE
        ? { ok: false, response: new Response(null, { status: 500 }) }
        : create(req);
    __setVantageGlobalpingFactory(() => gp.client);
    __setRealHostDeps({ lookup: async () => [REAL], serves: async () => true });
    await t.mutation(internal.sniVantage.tick, {});
    await drain(t);
    const x = await evidence(t, 'x.example');
    expect(x?.realHost?.reading).toBe('thin');
    expect(x?.oldestAt).toBe(T0);
  });

  test('the rollback clear leaves only what an older schema accepts', async () => {
    const { t } = await seed();
    __setVantageGlobalpingFactory(
      () => fakeGlobalping((target) => (target === EDGE ? 'handshake' : 'ok')).client,
    );
    __setRealHostDeps({ lookup: async () => [REAL], serves: async () => true });
    await t.mutation(internal.sniVantage.tick, {});
    await drain(t);
    let next: { phase?: 'probes' | 'evidence'; cursor?: string | null } = {};
    let calls = 0;
    for (;;) {
      const r = await t.mutation(internal.sniVantage.clearRealHostForRollback, next);
      calls++;
      if (r.done) break;
      expect(calls).toBeLessThan(10);
      next = { phase: r.phase, cursor: r.cursor };
    }
    // Both phases ran: the measurements, then the evidence.
    expect(calls).toBeGreaterThanOrEqual(2);
    const left = await rows(t);
    expect(left).toHaveLength(3);
    expect(left.some((x) => x.role !== undefined || x.realAddress !== undefined)).toBe(false);
    expect(
      left.flatMap((x) => x.results).some((x) => x.stage !== undefined || x.vantage !== undefined),
    ).toBe(false);
    for (const name of NAMES) expect((await evidence(t, name))?.realHost).toBeUndefined();
  });

  test('the twins count against the hourly budget; off, nothing changes', async () => {
    const tight = await seed({ 'edge.sni.vantage.hourlyBudget': 4 });
    __setVantageGlobalpingFactory(() => fakeGlobalping(() => 'ok').client);
    __setRealHostDeps({ lookup: async () => [REAL], serves: async () => true });
    // Four measurements an hour: two names and their twins, never three names.
    expect(await tight.t.mutation(internal.sniVantage.tick, {})).toMatchObject({
      started: 1,
      measurements: 4,
    });
    const off = await seed({ 'edge.sni.vantage.realHost': false });
    expect(await off.t.mutation(internal.sniVantage.tick, {})).toMatchObject({ measurements: 3 });
    await drain(off.t);
    expect((await rows(off.t)).some((x) => x.role === 'real_host')).toBe(false);
  });
});
