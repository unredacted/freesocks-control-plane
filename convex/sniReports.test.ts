/// <reference types="vite/client" />
/**
 * Member reports attributed to server names.
 *
 *  - pure rule: a floor, and "singled out" against the family's other reported
 *    names; reports with no country never make a suspect;
 *  - a counted report about ONE address adds 1/K to each name the member holds
 *    on it, for their saved or consented curated country, and stores nothing
 *    about the member;
 *  - a duplicate report (weight 0), a report about no particular address, and a
 *    listener without ranked names attribute nothing;
 *  - counts leave after the window.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { NO_COUNTRY, dayOf, shareOf, suspectNames } from './lib/edges/sni/health';

const modules = import.meta.glob('./**/*.*s');

describe('suspectNames (pure)', () => {
  const c = (name: string, country: string, weight: number) => ({ name, country, weight });

  test('a floor: a little weight is nothing', () => {
    expect(suspectNames([c('a.example', 'IR', 2.9)]).size).toBe(0);
    expect(suspectNames([c('a.example', 'IR', 3)]).get('a.example')).toEqual(['IR']);
  });

  test('singled out, not merely reported: when every name gathers alike it is not the name', () => {
    const even = [c('a.example', 'IR', 5), c('b.example', 'IR', 5), c('c.example', 'IR', 4)];
    expect(suspectNames(even).size).toBe(0);
    const skewed = [c('a.example', 'IR', 9), c('b.example', 'IR', 2), c('c.example', 'IR', 1)];
    expect([...suspectNames(skewed).keys()]).toEqual(['a.example']);
  });

  test('per country, summed over days, and never for reports without a country', () => {
    const rows = [
      c('a.example', 'IR', 2),
      c('a.example', 'IR', 2),
      c('a.example', 'CN', 1),
      c('a.example', NO_COUNTRY, 50),
    ];
    expect(suspectNames(rows).get('a.example')).toEqual(['IR']);
  });

  test('shares and days', () => {
    expect(shareOf(['a', 'b', 'c'])).toBeCloseTo(1 / 3);
    expect(shareOf([])).toBe(0);
    expect(dayOf(Date.UTC(2026, 0, 2, 23, 59))).toBe('2026-01-02');
  });
});

describe('sweep', () => {
  beforeEach(() => vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper'));
  afterEach(() => vi.unstubAllEnvs());

  test('counts leave after the window', async () => {
    const t = convexTest(schema, modules);
    const now = Date.UTC(2026, 5, 30);
    await t.run(async (ctx) => {
      for (const daysAgo of [0, 13, 15, 40])
        await ctx.db.insert('sniReportCounts', {
          name: 'a.example',
          country: 'IR',
          day: dayOf(now - daysAgo * 86_400_000),
          weight: 1,
          updatedAt: now,
        });
    });
    expect(await t.mutation(internal.sniReports.sweep, { now })).toEqual({ deleted: 2 });
    const left = await t.run((ctx) => ctx.db.query('sniReportCounts').collect());
    expect(left.map((r) => r.day).sort()).toEqual([dayOf(now - 13 * 86_400_000), dayOf(now)]);
  });
});

// --- through the member's report ---------------------------------------------------------------

import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { realityListener, registerRelay } from './lib/edges/testing/fixtures';

const NAMES = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example'];

async function seedMember(opts: { hrw?: boolean; sniRegion?: string } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await t.run(async (ctx) => {
    const id = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    return id;
  });
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ tlsNames: NAMES })],
  });
  if (opts.hrw !== false)
    await t.mutation(internal.relayListeners.setSniPick, { id: listenerId, version: 'hrw1' });
  const edge = await t.mutation(internal.relays.adoptEdge, {
    relayId,
    listenerId,
    ipv4: '198.51.100.1',
    publish: true,
    verified: true,
  });
  const edgeId = edge.edgeId as Id<'edges'>;
  const userId = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      supportId: 'SUP-1',
      updatedAt: Date.now(),
    });
    const relay = (await ctx.db.get(relayId))!;
    await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId: 'uuid-1',
      backendShortId: 'short-1',
      backendServerId: serverId,
      subscriptionUrl: 'https://panel.example/sub/short-1',
      subscriptionMirrors: [],
      subToken: 'tok_1',
      state: 'active',
      pinnedNode: 'node-one',
      renderKey: 'a'.repeat(64),
      sniRegion: opts.sniRegion,
      lastRenderedEpoch: relay.publicationEpoch,
      lastRender: {
        at: Date.now(),
        epoch: relay.publicationEpoch,
        family: 'other',
        listenerKeys: ['a'],
        primaryEdgeId: edgeId,
      },
      updatedAt: Date.now(),
    });
    return userId;
  });
  const report = (over: Record<string, unknown> = {}) =>
    t.mutation(internal.issueReports.reportIssue, {
      userId,
      reason: 'cant_connect',
      country: null,
      city: null,
      asn: null,
      connectionChoice: 'primary',
      markKey: 'mark-1',
      ...over,
    });
  const counts = () => t.run((ctx) => ctx.db.query('sniReportCounts').collect());
  return { t, report, counts, listenerId };
}

describe('a report, attributed', () => {
  beforeEach(() => {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
  });
  afterEach(() => vi.unstubAllEnvs());

  test('one counted report about one address: 1/3 to each of the three names the member holds', async () => {
    const { report, counts } = await seedMember();
    await report({ country: 'IR' });
    const rows = await counts();
    expect(rows).toHaveLength(3);
    expect(new Set(rows.map((r) => r.name)).size).toBe(3);
    for (const r of rows) {
      expect(NAMES).toContain(r.name);
      expect(r.weight).toBeCloseTo(1 / 3);
      expect(r.country).toBe('IR');
      // Name, country, day, weight: nothing that points at who reported.
      expect(Object.keys(r).sort()).toEqual(
        ['_creationTime', '_id', 'country', 'day', 'name', 'updatedAt', 'weight'].sort(),
      );
    }
  });

  test('a repeat inside the window is weight 0 and attributes nothing more', async () => {
    const { report, counts } = await seedMember();
    await report({ country: 'IR' });
    await report({ country: 'IR' });
    expect((await counts()).reduce((n, r) => n + r.weight, 0)).toBeCloseTo(1);
  });

  test("the member's saved choice beats what they typed; a country that is not curated is ZZ", async () => {
    const saved = await seedMember({ sniRegion: 'CN' });
    await saved.report({ country: 'IR' });
    expect(new Set((await saved.counts()).map((r) => r.country))).toEqual(new Set(['CN']));
    const other = await seedMember();
    await other.report({ country: 'NL' });
    expect(new Set((await other.counts()).map((r) => r.country))).toEqual(new Set([NO_COUNTRY]));
  });

  test('a name blocked in the country is not one the member holds there, so it gets nothing', async () => {
    const { t, report, counts, listenerId } = await seedMember();
    await t.run(async (ctx) => {
      const l = (await ctx.db.get(listenerId))!;
      await ctx.db.patch(listenerId, {
        tlsNames: (l.tlsNames ?? []).map((n) =>
          n.name === 'a.example' || n.name === 'b.example' ? { ...n, blockedIn: ['IR'] } : n,
        ),
      });
    });
    await report({ country: 'IR' });
    expect((await counts()).map((r) => r.name).sort()).toEqual([
      'c.example',
      'd.example',
      'e.example',
    ]);
  });

  test('no particular address, or a listener without ranked names: nothing is attributed', async () => {
    const unsure = await seedMember();
    await unsure.report({ country: 'IR', connectionChoice: 'unsure' });
    expect(await unsure.counts()).toEqual([]);
    const legacy = await seedMember({ hrw: false });
    await legacy.report({ country: 'IR' });
    expect(await legacy.counts()).toEqual([]);
  });
});

describe('the hint on the family page', () => {
  beforeEach(() => vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper'));
  afterEach(() => vi.unstubAllEnvs());

  test('a singled-out name is a suspect there, until it is judged blocked there', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-a',
      label: 'Family A',
      targetAddress: 'target.example',
      targetPort: 443,
      requireH2: false,
    });
    await t.mutation(internal.sniFamilies.importNames, { slug: 'fam-a', lines: NAMES });
    const day = dayOf(Date.now());
    await t.run(async (ctx) => {
      const add = (name: string, country: string, weight: number) =>
        ctx.db.insert('sniReportCounts', { name, country, day, weight, updatedAt: Date.now() });
      await add('a.example', 'IR', 6);
      await add('b.example', 'IR', 1);
      // Another family's name, and an old country that is no longer curated: ignored.
      await add('other.example', 'IR', 40);
      await add('c.example', 'NL', 40);
    });
    const suspectsOf = async () =>
      Object.fromEntries(
        (await t.query(internal.sniFamilies.detail, { slug: 'fam-a' })).names.map((n) => [
          n.name,
          n.suspectIn,
        ]),
      );
    expect(await suspectsOf()).toMatchObject({
      'a.example': ['IR'],
      'b.example': [],
      'c.example': [],
    });
    await t.mutation(internal.sniFamilies.setCountry, {
      slug: 'fam-a',
      names: ['a.example'],
      country: 'IR',
      state: 'blocked',
    });
    expect((await suspectsOf())['a.example']).toEqual([]);
  });
});
