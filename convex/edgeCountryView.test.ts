/// <reference types="vite/client" />
/**
 * The country view end to end (edgeCountryView.ts): the stored evidence of a
 * real origin (graded states, marks, probes, the names' marks, the checks from
 * inside, member reports) read into the view of one country and the summary of
 * every listed one, through the admin routes and their contracts.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { refuseNetwork } from './lib/edges/testing/mockFetch';
import { dayOf } from './lib/edges/sni/health';
import { CountryViewResponse, CountryViewSummaryResponse } from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
const H = 3_600_000;
const NAMES = ['a.example', 'b.example', 'c.example'];

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  refuseNetwork();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function setup() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.sni.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.sni.vantage.enabled', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify([
        { code: 'IR', checkEdges: true, checkNamesInside: true },
        { code: 'RU', checkEdges: true, checkNamesInside: false },
      ]),
    );
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: NAMES })],
  });
  const adopt = (ipv4: string, publish: boolean) =>
    t.mutation(internal.relays.adoptEdge, { relayId, listenerId, ipv4, publish, verified: true });
  const blocked = (await adopt('198.51.100.1', true)).edgeId as Id<'edges'>;
  const works = (await adopt('198.51.100.2', true)).edgeId as Id<'edges'>;
  const spare = (await adopt('198.51.100.3', false)).edgeId as Id<'edges'>;
  const now = Date.now();
  await t.run(async (ctx) => {
    // One address blocked in IR by its own rounds, one reached by the probes.
    await ctx.db.patch(blocked, {
      countryState: {
        byCountry: [{ country: 'IR', state: 'blocked', from: 'edge', until: now + 24 * H }],
        updatedAt: now,
      },
      reachability: {
        byCountry: [
          {
            country: 'IR',
            verdict: 'unreachable',
            okVantages: 0,
            failVantages: 3,
            lastAt: now - H,
          },
          { country: 'DE', verdict: 'reachable', okVantages: 3, failVantages: 0, lastAt: now - H },
        ],
        updatedAt: now,
      },
    });
    await ctx.db.insert('edgeCountryEvidence', {
      edgeId: blocked,
      relayId,
      groupKey: `adopted:${blocked}`,
      country: 'IR',
      address: {
        state: 'blocked',
        reason: 'blocked',
        decidedAt: now - H,
        until: now + 24 * H,
        blockedRounds: 2,
      },
      lastRound: {
        roundId: 'r1',
        at: now - H,
        result: 'blocked',
        ok: 0,
        fail: 3,
        networks: 2,
        controlsOk: 2,
      },
      handshake: { state: 'none', pathBatches: [] },
      combined: 'blocked',
      stateUntil: now + 24 * H,
      until: now + 24 * H,
      lastRoundAt: now - H,
      updatedAt: now,
    });
    await ctx.db.patch(works, {
      reachability: {
        byCountry: [
          {
            country: 'IR',
            verdict: 'reachable',
            okVantages: 3,
            failVantages: 0,
            lastAt: now - 2 * H,
          },
        ],
        updatedAt: now,
      },
    });
    // Names: one family, one marked blocked in IR (the copy rides on the listener),
    // one the checks from inside single out, one members report.
    const familyId = await ctx.db.insert('sniFamilies', {
      slug: 'fam',
      label: 'Fam',
      target: { kind: 'static', address: 'target.example', port: 443 },
      enabled: true,
      requireH2: false,
      nextSeq: NAMES.length,
      updatedAt: now,
    });
    for (const [seq, name] of NAMES.entries())
      await ctx.db.insert('sniNames', {
        familyId,
        name,
        seq,
        status: 'active',
        qualification: { state: 'ok', consecutiveFails: 0 },
        checkedAt: now,
        updatedAt: now,
      });
    await ctx.db.insert('sniNameCountry', {
      name: 'a.example',
      country: 'IR',
      state: 'blocked',
      source: 'operator',
      updatedAt: now - 3 * H,
    });
    const l = (await ctx.db.get(listenerId))!;
    await ctx.db.patch(listenerId, {
      tlsNames: (l.tlsNames ?? []).map((n) =>
        n.name === 'a.example' ? { ...n, blockedIn: ['IR'] } : n,
      ),
    });
    await ctx.db.insert('sniVantageEvidence', {
      familyId,
      name: 'b.example',
      country: 'IR',
      lastRequestedAt: now - H,
      measurements: 4,
      okVantages: 0,
      okNetworks: 0,
      lastFailAt: now - H,
      lastAt: now - H,
      everOkAt: now - 48 * H,
      oldestAt: now - 30 * H,
      latest: 'failing',
      streak: {
        nameFailures: 4,
        networks: 2,
        singled: 3,
        pathFailures: 0,
        batches: 2,
        startedAt: now - 30 * H,
        transition: true,
      },
      updatedAt: now,
    });
    await ctx.db.insert('sniReportCounts', {
      name: 'c.example',
      country: 'IR',
      day: dayOf(now),
      weight: 2.5,
      updatedAt: now,
    });
  });
  return { t, relayId, listenerId, blocked, works, spare };
}

async function adminCookie(t: ReturnType<typeof convexTest>) {
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
}

describe('the country view', () => {
  test('one country: addresses with their basis, names with theirs, what members are handed', async () => {
    const { t, blocked, works, spare } = await setup();
    const v = CountryViewResponse.parse(
      await t.query(internal.edgeCountryView.country, { country: 'ir' }),
    );
    expect(v.country).toBe('IR');
    expect(v.listed).toEqual({ checkEdges: true, checkNamesInside: true, nameChecksRun: true });
    expect(v.switches).toMatchObject({ render: true, probes: true, steering: false });
    const l = v.origins[0]!.listeners[0]!;
    expect(l.addresses.map((a) => [a.edgeId, a.state, a.basis, a.publication])).toEqual([
      [blocked, 'blocked', 'checks', 'published'],
      [works, 'proven', 'probes', 'published'],
      [spare, 'unknown', 'none', 'unpublished'],
    ]);
    expect(l.addresses[0]!.evidence.round).toMatchObject({ result: 'blocked', controlsOk: 2 });
    expect(l.addresses[0]!.evidence.probes).toMatchObject({ verdict: 'unreachable' });
    const byName = Object.fromEntries(l.names.map((n) => [n.name, n]));
    expect(byName['a.example']).toMatchObject({ state: 'blocked', basis: 'mark', family: 'fam' });
    expect(byName['b.example']).toMatchObject({ state: 'blocked', basis: 'checks' });
    expect(byName['b.example']!.checks).toMatchObject({ suggestion: 'blocked', failNetworks: 2 });
    expect(byName['c.example']!.reports).toEqual({ weight: 2.5, suspect: false });
    // Steering is off: members there are spread over both published addresses.
    expect(l.members.computed).toBe(true);
    expect(l.members.primary.map((p) => p.id).sort()).toEqual([blocked, works].sort());
    expect(l.members.onBlockedAddress).toBeGreaterThan(0);
    expect(v.totals.addresses).toEqual({ proven: 1, blocked: 1, unknown: 0 });
    // Totals count what delivery acts on: the checks' unapplied suggestion is not judged.
    expect(v.totals.names).toEqual({ proven: 0, blocked: 1, unknown: 2 });
  });

  test('with steering on, members there leave the blocked address', async () => {
    const { t, works } = await setup();
    await t.run((ctx) => upsertSettingRow(ctx, 'delivery.country.steer', 'true'));
    const v = await t.query(internal.edgeCountryView.country, { country: 'IR' });
    const m = v.origins[0]!.listeners[0]!.members;
    expect(m.steered).toBe(true);
    expect(m.primary).toEqual([{ id: works, share: 1 }]);
    expect(m.onBlockedFirst).toBe(0);
  });

  test('summary: every listed country with its totals; the routes answer with the contracts', async () => {
    const { t } = await setup();
    const cookie = await adminCookie(t);
    const get = (path: string) => t.fetch(`/api/v1/admin/edges/${path}`, { headers: { cookie } });
    const s = await get('countries/summary');
    expect(s.status).toBe(200);
    const summary = CountryViewSummaryResponse.parse(await s.json());
    expect(summary.countries.map((c) => c.country)).toEqual(['IR', 'RU']);
    const ir = summary.countries[0]!;
    expect(ir.totals.addresses).toEqual({ proven: 1, blocked: 1, unknown: 0 });
    expect(ir.worstOnBlocked).toBeGreaterThan(0);
    const ru = summary.countries[1]!;
    expect(ru.totals.addresses).toEqual({ proven: 0, blocked: 0, unknown: 2 });
    expect(ru.listed.nameChecksRun).toBe(false);
    const one = await get('countries/IR');
    expect(one.status).toBe(200);
    expect(CountryViewResponse.parse(await one.json()).origins).toHaveLength(1);
    // A country off the list answers too, and says so.
    const off = CountryViewResponse.parse(await (await get('countries/de')).json());
    expect(off).toMatchObject({ country: 'DE', listed: null, curated: false });
    expect((await t.fetch('/api/v1/admin/edges/countries/summary')).status).toBe(401);
  });

  test('a report suspect is judged against every name of its family, shown or not', async () => {
    const { t } = await setup();
    await t.run(async (ctx) => {
      const fam = (await ctx.db.query('sniFamilies').first())!;
      // A name of the family no listener carries, reported as much as a shown one.
      await ctx.db.insert('sniNames', {
        familyId: fam._id,
        name: 'd.example',
        seq: 9,
        status: 'active',
        qualification: { state: 'ok', consecutiveFails: 0 },
        checkedAt: Date.now(),
        updatedAt: Date.now(),
      });
      for (const r of await ctx.db.query('sniReportCounts').collect()) await ctx.db.delete(r._id);
      for (const name of ['c.example', 'd.example'])
        await ctx.db.insert('sniReportCounts', {
          name,
          country: 'IR',
          day: dayOf(Date.now()),
          weight: 4,
          updatedAt: Date.now(),
        });
    });
    const v = await t.query(internal.edgeCountryView.country, { country: 'IR' });
    const c = v.origins[0]!.listeners[0]!.names.find((n) => n.name === 'c.example')!;
    expect(c.reports).toEqual({ weight: 4, suspect: false });
  });

  test('the summary of a full country list fits one transaction', async () => {
    const t = convexTest({ schema, modules, transactionLimits: true });
    await insertPanelServer(t);
    const codes =
      'IR RU CN TR AE KZ BY MM VN PK EG SA QA OM BH KW IQ SY TM TJ UZ AZ ET ER SD VE CU NI BD LK TH LA KH ID MY UG RW ZW KP AF'.split(
        ' ',
      );
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
      await upsertSettingRow(
        ctx,
        CENSORED_COUNTRIES_KEY,
        JSON.stringify(codes.map((code) => ({ code, checkEdges: true, checkNamesInside: false }))),
      );
    });
    const names = Array.from({ length: 12 }, (_, i) => `n${i}.example`);
    const { relayId, listenerId } = await registerRelay(t, {
      listeners: [realityListener({ listenerKey: 'u', tlsNames: names })],
    });
    for (let i = 0; i < 20; i++)
      await t.mutation(internal.relays.adoptEdge, {
        relayId,
        listenerId,
        ipv4: `198.51.100.${i + 1}`,
        publish: i === 0,
        verified: true,
      });
    const s = await t.query(internal.edgeCountryView.summary, {});
    expect(s.countries).toHaveLength(40);
    expect(s.countries[0]!.totals.addresses.unknown).toBe(1);
  });
});
