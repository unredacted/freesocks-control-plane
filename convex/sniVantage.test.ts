/// <reference types="vite/client" />
/**
 * Checks of server names from inside a country, end to end with fake sources:
 * the `sni-vantage` tick plans one batch, the executor measures every name of
 * it from the same vantages (fake Globalping / stubbed RIPE Atlas), the
 * evidence is aggregated, and the family page judges it now.
 *
 *  - dormant by default, and gated per country;
 *  - a batch carries a control, never touches an address the address-level
 *    probes find unreachable there, and fits the hourly budget;
 *  - a name failing where its control got through is suggested blocked only
 *    after a second look (or a transition / member reports);
 *  - Apply records the operator's own mark; autoApply writes `probe` marks,
 *    never over an operator's mark and never a block that empties a listener;
 *  - audit rows carry slugs, the country and counts, never a name or an address;
 *  - rows age out with the window, and a measurement left open times out.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { signValue } from './lib/cookies';
import {
  adoptL4Edge,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import type { GlobalpingLike } from './lib/edges/probes/globalping';
import { __setVantageCertCovers, __setVantageGlobalpingFactory } from './sniVantageOps';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;

const H = 3_600_000;
const T0 = Date.parse('2026-10-01T00:00:00Z');
const EDGE = '198.51.100.9';
const NAMES = ['x.example', 'y.example', 'z.example'];
const ASNS = [64501, 64502, 64503];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  __setVantageGlobalpingFactory(null);
  __setVantageCertCovers(null);
});

type Outcome = 'ok' | 'reset' | 'timeout';

/**
 * A Globalping fake: three IR probes on three networks, each name answered by
 * `outcome(name, asn)`. Records every request so a test can check what left.
 */
function fakeGlobalping(outcome: (name: string, asn: number) => Outcome) {
  const requests: Array<Record<string, unknown>> = [];
  const client: GlobalpingLike = {
    async createMeasurement(req) {
      requests.push(req as Record<string, unknown>);
      return { ok: true, data: { id: `m-${requests.length}` } };
    },
    async getMeasurement(id) {
      const req = requests[Number(id.slice(2)) - 1] as {
        measurementOptions: { request: { host: string } };
      };
      const name = req.measurementOptions.request.host;
      const results = ASNS.map((asn) => {
        const o = outcome(name, asn);
        return {
          probe: { country: 'IR', asn, network: `net-${asn}`, tags: ['eyeball-network'] },
          result:
            o === 'ok'
              ? { status: 'finished', statusCode: 200, tls: { authorized: true } }
              : {
                  status: 'failed',
                  rawOutput: o === 'reset' ? `read ECONNRESET ${name}` : 'Connect Timeout Error',
                },
        };
      });
      return { ok: true, data: { id, status: 'finished', results } };
    },
  };
  return { client, requests };
}

async function seed(
  opts: {
    on?: boolean;
    countries?: string[];
    settings?: Record<string, unknown>;
    edge?: boolean;
    probeNode?: boolean;
    names?: string[];
  } = {},
) {
  const names = opts.names ?? NAMES;
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.sni.enabled', 'true');
    if (opts.on ?? true) await upsertSettingRow(ctx, 'edge.sni.vantage.enabled', 'true');
    await upsertSettingRow(
      ctx,
      'edge.sni.vantage.countries',
      JSON.stringify(opts.countries ?? ['IR']),
    );
    for (const [k, v] of Object.entries(opts.settings ?? {}))
      await upsertSettingRow(ctx, k, JSON.stringify(v));
  });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-a',
    label: 'Family A',
    targetAddress: 'target.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, { slug: 'fam-a', lines: names });
  // Every name serves from the target (what qualification would record).
  await t.run(async (ctx) => {
    for (const n of await ctx.db.query('sniNames').collect())
      await ctx.db.patch(n._id, {
        qualification: { state: 'ok', consecutiveFails: 0, tlsVersion: 'TLSv1.3' },
        checkedAt: Date.now(),
      });
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: names })],
  });
  if (opts.probeNode) await t.run((ctx) => ctx.db.patch(relayId, { probeNode: true }));
  if (opts.edge === false)
    return { t, relayId, listenerId, edgeId: null as unknown as Id<'edges'> };
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: EDGE, publish: true });
  return { t, relayId, listenerId, edgeId: edgeId as Id<'edges'> };
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
const detailRow = async (t: T, name: string) =>
  (await t.query(internal.sniFamilies.detail, { slug: 'fam-a' })).names.find(
    (n) => n.name === name,
  )!;
const vantageAudit = (t: T) =>
  t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter((a) =>
      a.action.startsWith('edge.sni.vantage.'),
    ),
  );

/** One tick, its executor, settled. */
async function tickAndDrain(t: T) {
  const r = await t.mutation(internal.sniVantage.tick, {});
  await drain(t);
  return r;
}

describe('dormant and gated', () => {
  test('off by default, off without a country, and nothing else runs either way', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const off = await seed({ on: false });
    expect((await off.t.mutation(internal.sniVantage.tick, {})).reason).toBe('off');
    const none = await seed({ countries: [] });
    expect((await none.t.mutation(internal.sniVantage.tick, {})).reason).toBe('no_country');
    // A country that is not curated is never checked, whatever the setting says.
    const odd = await seed({ countries: ['DE'] });
    expect((await odd.t.mutation(internal.sniVantage.tick, {})).reason).toBe('no_country');
    expect(gp.requests).toHaveLength(0);
    expect(await rows(off.t)).toHaveLength(0);
  });

  test('the defaults in the config view are dormant', async () => {
    const t = convexTest(schema, modules);
    const view = await t.query(internal.sniFamilies.configView, {});
    expect(view.vantage).toMatchObject({ enabled: false, countries: [], autoApply: false });
    expect(view.vantageSources).toEqual({ globalping: true, ripeatlas: false });
  });

  test('an address the address-level probes find unreachable from there is never dialled', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t, edgeId } = await seed();
    await t.run((ctx) =>
      ctx.db.patch(edgeId, {
        reachability: {
          byCountry: [
            {
              country: 'IR',
              verdict: 'unreachable',
              okVantages: 0,
              failVantages: 3,
              lastAt: Date.now(),
            },
          ],
          updatedAt: Date.now(),
        },
      }),
    );
    expect((await t.mutation(internal.sniVantage.tick, {})).reason).toBe('nothing_due');
    expect(gp.requests).toHaveLength(0);
  });
});

describe('a batch', () => {
  test('every name of the batch from the same probes, HEAD with the name as SNI, nothing identifying', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t } = await seed();
    const r = await tickAndDrain(t);
    expect(r).toMatchObject({ started: 1, measurements: 3 });
    expect(gp.requests).toHaveLength(3);
    expect(gp.requests[0]).toMatchObject({
      type: 'http',
      target: EDGE,
      locations: [{ country: 'IR', limit: 3, tags: ['eyeball-network'] }],
      measurementOptions: { protocol: 'HTTPS', request: { method: 'HEAD', path: '/' } },
    });
    // The rest reuse the first measurement's probes.
    expect(gp.requests.slice(1).map((q) => q.locations)).toEqual(['m-1', 'm-1']);
    expect(
      gp.requests.map((q) => (q.measurementOptions as { request: { host: string } }).request.host),
    ).toEqual(NAMES);
    expect(JSON.stringify(gp.requests)).not.toMatch(/freesocks/i);
    const all = await rows(t);
    expect(all.every((x) => x.status === 'finished' && x.results.length === 3)).toBe(true);
    expect(new Set(all.map((x) => x.batch)).size).toBe(1);
    // Nothing is due again until the interval passes.
    expect((await t.mutation(internal.sniVantage.tick, {})).reason).toBe('nothing_due');
  });

  test('a batch that does not fit the hour waits; one that fits is trimmed, never below a control', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const one = await seed({ settings: { 'edge.sni.vantage.hourlyBudget': 1 } });
    expect((await one.t.mutation(internal.sniVantage.tick, {})).reason).toBe('budget');
    const two = await seed({ settings: { 'edge.sni.vantage.hourlyBudget': 2 } });
    expect(await tickAndDrain(two.t)).toMatchObject({ started: 1, measurements: 2 });
    // The hour is spent.
    expect((await two.t.mutation(internal.sniVantage.tick, {})).reason).toBe('budget');
  });

  test('a name that left the listener before its turn is not dialled', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t, listenerId } = await seed();
    await t.mutation(internal.sniVantage.tick, {});
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        tlsNames: (l.tlsNames ?? []).map((n) =>
          n.name === 'z.example' ? { ...n, status: 'retired' as const, retiredAt: Date.now() } : n,
        ),
      });
    });
    await drain(t);
    const z = (await rows(t)).find((r) => r.name === 'z.example')!;
    expect(z).toMatchObject({ status: 'failed', error: 'target_moved' });
    expect(gp.requests).toHaveLength(2);
  });
});

describe('evidence and suggestions', () => {
  /** x is reset from every vantage; y and z work. */
  const blockX = (name: string): Outcome => (name === 'x.example' ? 'reset' : 'ok');

  test('one look waits, the second look three days later suggests blocked; its controls are proven', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(blockX).client);
    const { t } = await seed();
    await tickAndDrain(t);
    expect(await evidence(t, 'x.example')).toMatchObject({
      latest: 'failing',
      streak: { nameFailures: 3, networks: 3, singled: 3, batches: 1, transition: false },
    });
    let x = await detailRow(t, 'x.example');
    expect(x.vantage[0]).toMatchObject({
      country: 'IR',
      suggestion: null,
      reason: 'needs_repeat',
      decision: 'none',
    });
    const y = await detailRow(t, 'y.example');
    expect(y.vantage[0]).toMatchObject({
      suggestion: 'proven',
      decision: 'suggest',
      okNetworks: 3,
    });

    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    x = await detailRow(t, 'x.example');
    expect(x.vantage[0]).toMatchObject({ suggestion: 'blocked', decision: 'suggest' });
    // A block suggestion puts it in front of the operator; nothing was applied.
    expect(x.blockedIn).toEqual([]);
  });

  test('member reports corroborate a single look', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(blockX).client);
    const { t } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('sniReportCounts', {
        name: 'x.example',
        country: 'IR',
        day: new Date(T0).toISOString().slice(0, 10),
        weight: 5,
        updatedAt: T0,
      }),
    );
    await tickAndDrain(t);
    const x = await detailRow(t, 'x.example');
    expect(x.suspectIn).toEqual(['IR']);
    expect(x.vantage[0]).toMatchObject({ suggestion: 'blocked', reportsAgree: true });
  });

  test("Apply records the operator's own mark and moves the listener", async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(blockX).client);
    const { t, listenerId } = await seed();
    await tickAndDrain(t);
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    const r = await t.mutation(internal.sniVantage.applySuggestions, {
      slug: 'fam-a',
      names: NAMES,
      country: 'IR',
    });
    expect(r).toEqual({ proven: 2, blocked: 1, skipped: 0 });
    const marks = await t.run((ctx) => ctx.db.query('sniNameCountry').collect());
    expect(marks.map((m) => [m.name, m.state, m.source]).sort()).toEqual([
      ['x.example', 'blocked', 'operator'],
      ['y.example', 'proven', 'operator'],
      ['z.example', 'proven', 'operator'],
    ]);
    const l = await t.run((ctx) => ctx.db.get(listenerId));
    expect(l!.tlsNames!.find((n) => n.name === 'x.example')!.blockedIn).toEqual(['IR']);
    // Applying again changes nothing.
    expect(
      await t.mutation(internal.sniVantage.applySuggestions, {
        slug: 'fam-a',
        names: NAMES,
        country: 'IR',
      }),
    ).toEqual({ proven: 0, blocked: 0, skipped: 3 });
    const audit = await vantageAudit(t);
    const applied = audit.find((a) => a.action === 'edge.sni.vantage.apply')!;
    expect(applied.payload).toEqual({ slug: 'fam-a', country: 'IR', proven: 2, blocked: 1 });
    expect(JSON.stringify(audit)).not.toMatch(/\.example|198\.51\.100/);
  });

  test('autoApply never replaces an operator mark: the evidence shows as a conflict', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(blockX).client);
    const { t } = await seed({ settings: { 'edge.sni.vantage.autoApply': true } });
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['x.example'],
      country: 'IR',
      state: 'proven',
    });
    await tickAndDrain(t);
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    const x = await detailRow(t, 'x.example');
    expect(x.provenIn).toEqual(['IR']);
    expect(x.vantage[0]).toMatchObject({ suggestion: 'blocked', decision: 'conflict' });
    const mark = await t.run((ctx) =>
      ctx.db
        .query('sniNameCountry')
        .withIndex('by_name_country', (q) => q.eq('name', 'x.example').eq('country', 'IR'))
        .unique(),
    );
    expect(mark).toMatchObject({ state: 'proven', source: 'operator' });
  });

  test('autoApply writes probe marks where nobody judged, but holds a block that would empty a listener', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(blockX).client);
    const { t } = await seed({ settings: { 'edge.sni.vantage.autoApply': true } });
    // y and z are already blocked in IR by an operator: blocking x too would
    // leave that listener with nothing for members there.
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['y.example', 'z.example'],
      country: 'IR',
      state: 'blocked',
    });
    await tickAndDrain(t);
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    let x = await detailRow(t, 'x.example');
    expect(x.blockedIn).toEqual([]);
    expect(x.vantage[0]).toMatchObject({ suggestion: 'blocked', decision: 'suggest' });
    const held = (await vantageAudit(t)).find(
      (a) => a.action === 'edge.sni.vantage.auto_apply' && (a.payload as { held: number }).held > 0,
    );
    expect(held?.payload).toMatchObject({
      slug: 'fam-a',
      country: 'IR',
      state: 'blocked',
      held: 1,
    });

    // Once the operator brings y back for IR, the next look applies x by itself.
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['y.example'],
      country: 'IR',
      state: 'unknown',
    });
    vi.setSystemTime(T0 + 146 * H);
    await tickAndDrain(t);
    x = await detailRow(t, 'x.example');
    expect(x.blockedIn).toEqual(['IR']);
    expect(x.probeMarkedIn).toEqual(['IR']);
    // y works from every vantage: written as a probe mark too (nobody judges it now).
    const y = await detailRow(t, 'y.example');
    expect(y.provenIn).toEqual(['IR']);
    expect(y.probeMarkedIn).toEqual(['IR']);
  });

  test('two blocks of one listener in one batch are weighed one after the other', async () => {
    // x and y fail where z gets through; z is already blocked there by an
    // operator, so only ONE of x, y may be blocked by itself.
    __setVantageGlobalpingFactory(
      () => fakeGlobalping((name) => (name === 'z.example' ? 'ok' : 'reset')).client,
    );
    const { t } = await seed({ settings: { 'edge.sni.vantage.autoApply': true } });
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['z.example'],
      country: 'IR',
      state: 'blocked',
    });
    await tickAndDrain(t);
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    const marks = await t.run(async (ctx) =>
      (await ctx.db.query('sniNameCountry').collect()).filter((m) => m.source === 'probe'),
    );
    expect(marks.map((m) => [m.name, m.state])).toEqual([['x.example', 'blocked']]);
    const held = (await vantageAudit(t)).filter((a) => a.action === 'edge.sni.vantage.auto_apply');
    expect(held.map((a) => a.payload)).toContainEqual({
      slug: 'fam-a',
      country: 'IR',
      state: 'blocked',
      count: 1,
      held: 1,
    });
  });
});

describe('what is dialled', () => {
  test('an origin is dialled only when it opted into probing, at its own address and port', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const closed = await seed({ edge: false });
    expect((await closed.t.mutation(internal.sniVantage.tick, {})).reason).toBe('nothing_due');
    const open = await seed({ edge: false, probeNode: true });
    expect(await tickAndDrain(open.t)).toMatchObject({ started: 1, measurements: 3 });
    expect(new Set(gp.requests.map((q) => q.target))).toEqual(new Set(['203.0.113.10']));
    expect((await rows(open.t)).every((r) => r.targetKind === 'relay' && r.port === 443)).toBe(
      true,
    );
  });
});

describe('RIPE Atlas', () => {
  test('one private request on pinned probes; the leaf is checked against the name', async () => {
    const posts: unknown[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes('/probes/'))
          return Response.json({
            results: ASNS.map((asn, i) => ({ id: 100 + i, asn_v4: asn })),
          });
        if (url.endsWith('/measurements/') && init?.method === 'POST') {
          posts.push(JSON.parse(String(init.body)));
          return Response.json({ measurements: [901, 902, 903] });
        }
        const m = /measurements\/(\d+)\/results/.exec(url);
        if (m) {
          const name = NAMES[Number(m[1]) - 901]!;
          return Response.json(
            ASNS.map((_, i) =>
              name === 'x.example'
                ? { prb_id: 100 + i, err: 'connect: Connection reset by peer' }
                : { prb_id: 100 + i, cert: [`CERT:${name}`], rt: 50 },
            ),
          );
        }
        return new Response('not found', { status: 404 });
      }),
    );
    __setVantageCertCovers((pem, name) => pem === `CERT:${name}`);
    const { t } = await seed({
      settings: {
        'edge.sni.vantage.sources.globalping': false,
        'edge.sni.vantage.sources.ripeatlas': true,
        'edge.secret.probe.ripeatlas.key': 'atlas-key',
      },
    });
    expect(await tickAndDrain(t)).toMatchObject({ started: 1, measurements: 3 });
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({
      probes: [{ type: 'probes', value: '100,101,102', requested: 3 }],
    });
    const body = posts[0] as { definitions: Array<Record<string, unknown>> };
    expect(body.definitions.every((d) => d.is_public === false && d.target === EDGE)).toBe(true);
    const all = await rows(t);
    expect(all.find((r) => r.name === 'y.example')!.results.map((r) => r.outcome)).toEqual([
      'ok',
      'ok',
      'ok',
    ]);
    expect(all.find((r) => r.name === 'x.example')!.results.map((r) => r.outcome)).toEqual([
      'reset',
      'reset',
      'reset',
    ]);
    expect((await evidence(t, 'x.example'))!.streak?.singled).toBe(3);
  });
});

describe('check now', () => {
  async function adminCall(t: T) {
    const adminUserId = await t.run((ctx) =>
      ctx.db.insert('adminUsers', {
        username: 'op',
        displayName: 'Op',
        isActive: true,
        updatedAt: Date.now(),
      }),
    );
    const sid = `asid-${Math.random().toString(36).slice(2)}`;
    await t.mutation(internal.sessions.create, {
      sid,
      kind: 'admin',
      adminUserId,
      ttlMs: 3_600_000,
    });
    const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
    return (path: string, body: unknown) =>
      t.fetch(`/api/v1/admin/edges/sni/${path}`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
  }

  test('a lone picked name gets a control, a second press within the hour is refused', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t } = await seed();
    const call = await adminCall(t);
    const res = await call('families/fam-a/vantage', { snis: ['y.example'], country: 'IR' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ batches: 1, measurements: 2, skipped: 0 });
    await drain(t);
    expect(new Set((await rows(t)).map((r) => r.name)).size).toBe(2);
    const again = await call('families/fam-a/vantage', { snis: ['y.example'], country: 'IR' });
    expect(((await again.json()) as { error: { code: string } }).error.code).toBe(
      'edge.sni.vantage_too_soon',
    );
    const notOn = await call('families/fam-a/vantage', { snis: ['y.example'], country: 'RU' });
    expect(((await notOn.json()) as { error: { code: string } }).error.code).toBe(
      'edge.sni.vantage_country',
    );
    const request = (await vantageAudit(t)).find((a) => a.action === 'edge.sni.vantage.request')!;
    expect(request.payload).toEqual({ slug: 'fam-a', country: 'IR', count: 1, batches: 1 });
    const applied = await call('families/fam-a/vantage/apply', {
      snis: ['y.example'],
      country: 'IR',
    });
    expect(applied.status).toBe(200);
  });
});

describe('retention', () => {
  test('a measurement left open times out; rows past the window go', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t } = await seed();
    await t.mutation(internal.sniVantage.tick, {});
    // The executor never ran (scheduled functions not drained): 20 minutes later it is late.
    vi.setSystemTime(T0 + 20 * 60_000);
    const late = await t.mutation(internal.sniVantage.sweep, {});
    expect(late.timedOut).toBe(3);
    vi.setSystemTime(T0 + 15 * 24 * H);
    const swept = await t.mutation(internal.sniVantage.sweep, {});
    expect(swept.deleted).toBe(3);
    // The evidence row stays (its transition marker outlives the window).
    expect(await evidence(t, 'x.example')).not.toBeNull();
  });
});

/** RIPE Atlas, stubbed: `outcome(name, probeIndex)` per pinned probe (three probes, three networks). */
function stubAtlas(outcome: (name: string, i: number) => Outcome, names = NAMES) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.includes('/probes/'))
        return Response.json({
          results: [7, 8, 9].map((k) => ({ id: 100 + k, asn_v4: 64510 + k })),
        });
      if (url.endsWith('/measurements/') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as { definitions: unknown[] };
        return Response.json({ measurements: body.definitions.map((_, i) => 901 + i) });
      }
      const m = /measurements\/(\d+)\/results/.exec(url);
      if (m) {
        const name = names[Number(m[1]) - 901]!;
        return Response.json(
          [7, 8, 9].map((k, i) =>
            outcome(name, i) === 'ok'
              ? { prb_id: 100 + k, cert: [`CERT:${name}`], rt: 50 }
              : { prb_id: 100 + k, err: 'connect: Connection reset by peer' },
          ),
        );
      }
      return new Response('not found', { status: 404 });
    }),
  );
  __setVantageCertCovers((pem, name) => pem === `CERT:${name}`);
}

describe('review fixes', () => {
  test('two sources are one look: nothing is applied until both settled, and they disagree', async () => {
    // Globalping gets through for every name; RIPE Atlas sees x singled out.
    __setVantageGlobalpingFactory(() => fakeGlobalping(() => 'ok').client);
    stubAtlas((name) => (name === 'x.example' ? 'reset' : 'ok'));
    const { t } = await seed({
      settings: {
        'edge.sni.vantage.autoApply': true,
        'edge.sni.vantage.sources.ripeatlas': true,
        'edge.secret.probe.ripeatlas.key': 'atlas-key',
      },
    });
    await tickAndDrain(t);
    const x = await detailRow(t, 'x.example');
    expect(x.vantage[0]).toMatchObject({ latest: 'mixed', suggestion: null, reason: 'mixed' });
    // Globalping finished first, but x was never marked proven on its word alone.
    expect(x.provenIn).toEqual([]);
    expect((await detailRow(t, 'y.example')).provenIn).toEqual(['IR']);
  });

  test('a gate that closes between the plan and the run stops the dial', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const { t } = await seed();
    expect((await t.mutation(internal.sniVantage.tick, {})).started).toBe(1);
    await t.run((ctx) => upsertSettingRow(ctx, 'edge.sni.vantage.countries', '[]'));
    await drain(t);
    expect(gp.requests).toHaveLength(0);
    expect((await rows(t)).map((r) => [r.status, r.error])).toEqual([
      ['failed', 'gate_country'],
      ['failed', 'gate_country'],
      ['failed', 'gate_country'],
    ]);
  });

  test('a control is never checked more often than the interval; the waiting name goes first next time', async () => {
    const gp = fakeGlobalping(() => 'ok');
    __setVantageGlobalpingFactory(() => gp.client);
    const four = ['a.example', 'b.example', 'c.example', 'd.example'];
    const { t } = await seed({ names: four });
    await tickAndDrain(t);
    expect(new Set((await rows(t)).map((r) => r.name))).toEqual(new Set(four.slice(0, 3)));
    // Ten minutes later only d is due, and no spare control exists: it waits.
    vi.setSystemTime(T0 + 10 * 60_000);
    expect((await t.mutation(internal.sniVantage.tick, {})).reason).toBe('nothing_due');
    // Once the others are due again, d (never checked) leads the batch.
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    const second = (await rows(t)).filter((r) => r.requestedAt === T0 + 73 * H);
    expect(second.map((r) => r.name)).toContain('d.example');
  });

  test('a name removed and imported into another family starts its evidence over', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(() => 'ok').client);
    const { t } = await seed();
    await tickAndDrain(t);
    expect((await evidence(t, 'x.example'))!.measurements).toBe(1);
    await t.mutation(internal.sniFamilies.remove, { slug: 'fam-a' });
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-b',
      label: 'Family B',
      targetAddress: 'target.example',
      targetPort: 443,
    });
    await t.mutation(internal.sniFamilies.importNames, { slug: 'fam-b', lines: NAMES });
    await t.run(async (ctx) => {
      for (const n of await ctx.db.query('sniNames').collect())
        await ctx.db.patch(n._id, {
          qualification: { state: 'ok', consecutiveFails: 0, tlsVersion: 'TLSv1.3' },
          checkedAt: Date.now(),
        });
    });
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    // The old family's measurement is still stored, but it is not this family's evidence.
    expect((await rows(t)).filter((r) => r.name === 'x.example')).toHaveLength(2);
    expect((await evidence(t, 'x.example'))!.measurements).toBe(1);
  });

  test('an origin that moved address is another address: old successes do not make a transition', async () => {
    let block = false;
    __setVantageGlobalpingFactory(
      () => fakeGlobalping((name) => (block && name === 'x.example' ? 'reset' : 'ok')).client,
    );
    const { t, relayId } = await seed({ edge: false, probeNode: true });
    await tickAndDrain(t);
    await t.run((ctx) => ctx.db.patch(relayId, { originAddress: '203.0.113.20' }));
    block = true;
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    expect((await detailRow(t, 'x.example')).vantage[0]).toMatchObject({
      latest: 'mixed',
      suggestion: null,
    });
  });

  test('a name on two addresses is checked on each in turn', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(() => 'ok').client);
    const { t, relayId } = await seed();
    // A second origin carries the same names behind its own published edge.
    const two = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      originAddress: '203.0.113.30',
      listeners: [realityListener({ tlsNames: NAMES })],
    });
    await adoptL4Edge(t, two.relayId, two.listenerId, { ipv4: '198.51.100.30', publish: true });
    await tickAndDrain(t);
    vi.setSystemTime(T0 + 73 * H);
    await tickAndDrain(t);
    const x = (await rows(t)).filter((r) => r.name === 'x.example');
    expect(new Set(x.map((r) => r.address))).toEqual(new Set([EDGE, '198.51.100.30']));
    expect(relayId).toBeTruthy();
  });

  test('evidence is aggregated again when its measurements leave the window', async () => {
    __setVantageGlobalpingFactory(() => fakeGlobalping(() => 'ok').client);
    const { t } = await seed();
    await tickAndDrain(t);
    expect((await detailRow(t, 'y.example')).vantage[0]).toMatchObject({ suggestion: 'proven' });
    // Fifteen days on, nothing new was measured: the suggestion goes with its measurements.
    vi.setSystemTime(T0 + 15 * 24 * H);
    const swept = await t.mutation(internal.sniVantage.sweep, {});
    expect(swept.aged).toBe(3);
    const y = (await detailRow(t, 'y.example')).vantage[0]!;
    expect(y).toMatchObject({ latest: 'none', suggestion: null, reason: 'no_data', okVantages: 0 });
    // The transition marker outlives the window.
    const everOkAt = (await evidence(t, 'y.example'))!.everOkAt!;
    expect(everOkAt >= T0 && everOkAt < T0 + H).toBe(true);
    // ...and nothing is re-aggregated twice.
    expect((await t.mutation(internal.sniVantage.sweep, {})).aged).toBe(0);
  });

  test("another country's reports cannot crowd out this country's", async () => {
    __setVantageGlobalpingFactory(
      () => fakeGlobalping((name) => (name === 'x.example' ? 'reset' : 'ok')).client,
    );
    const { t } = await seed();
    const day = new Date(T0).toISOString().slice(0, 10);
    await t.run(async (ctx) => {
      await ctx.db.insert('sniReportCounts', {
        name: 'x.example',
        country: 'IR',
        day,
        weight: 5,
        updatedAt: T0,
      });
      // Newer rows of the same day for another country, more than the cap.
      for (let i = 0; i < 8001; i++)
        await ctx.db.insert('sniReportCounts', {
          name: `r${i}.example`,
          country: 'RU',
          day,
          weight: 1,
          updatedAt: T0,
        });
    });
    await tickAndDrain(t);
    const x = await detailRow(t, 'x.example');
    expect(x.suspectIn).toEqual(['IR']);
    expect(x.vantage[0]).toMatchObject({ suggestion: 'blocked', reportsAgree: true });
  }, 60_000);
});
