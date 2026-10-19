/// <reference types="vite/client" />
/**
 * The censored-country list (lib/censoredCountries.ts): the admin routes, the
 * seed copy, the live fallback to the five keys it replaced, and everything
 * that now reads it (probe countries, server-name countries, the opt-in for
 * checks from inside, the members' choices, the status page's matrix rows).
 */
import { convexTest, type TestConvex } from 'convex-test';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import { upsertSettingRow } from './appSettings';
import { CENSORED_COUNTRIES_KEY } from './lib/censoredCountries';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { resolveSniConfig, resolveSniVantageConfig } from './lib/sniConfig';
import { resolvePublicStatusPage, STATUS_KEYS } from './lib/statusPage';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

const ADMIN_SIGN_KEY = 'test-admin-sign';
beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});

async function adminCookie(t: T) {
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

async function setup() {
  const t = convexTest(schema, modules);
  const cookie = await adminCookie(t);
  const call = (method: string, body?: unknown) =>
    t.fetch('/api/v1/admin/censored-countries', {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const setting = (key: string, value: unknown) =>
    t.run((ctx) => upsertSettingRow(ctx, key, JSON.stringify(value)));
  const raw = (key: string) =>
    t.run(async (ctx) => {
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      return row ? (JSON.parse(row.value) as unknown) : null;
    });
  return { t, call, setting, raw };
}

const entry = (code: string, checkEdges = false, checkNamesInside = false) => ({
  code,
  checkEdges,
  checkNamesInside,
});

describe('the admin routes', () => {
  test('read the old keys until a list is stored, then only the list', async () => {
    const { call, setting, raw } = await setup();
    await setting('edge.sni.curatedCountries', ['IR', 'RU']);
    await setting('edge.probe.countries', ['RU', 'TR']);
    await setting('edge.sni.vantage.countries', ['IR']);
    await setting('delivery.privacyCountries', ['EG']);
    const before = await (await call('GET')).json();
    expect(before).toEqual({
      stored: false,
      max: 40,
      countries: [entry('IR', false, true), entry('RU', true), entry('TR', true), entry('EG')],
      legacyChanged: [],
    });

    const res = await call('PUT', { countries: [entry('RU', true), entry('ir', false, true)] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      stored: true,
      max: 40,
      countries: [entry('RU', true), entry('IR', false, true)],
      legacyChanged: [],
    });
    // The saved list supersedes the old keys: they are retired (their values
    // kept for a rollback), and one written again is ignored and flagged.
    expect(await raw('edge.probe.countries')).toBeNull();
    await setting('edge.probe.countries', ['CN']);
    const after = await (await call('GET')).json();
    expect(after.countries).toEqual([entry('RU', true), entry('IR', false, true)]);
    expect(after.legacyChanged).toEqual(['edge.probe.countries']);
  });

  test('refuse a malformed list without storing anything', async () => {
    const { call, raw } = await setup();
    for (const countries of [
      'IR',
      [{ code: 'IRN' }],
      [{ code: 'ZZ' }],
      [entry('IR'), entry('ir')],
      [{ code: 'IR', checkEdges: 'true' }],
    ]) {
      const res = await call('PUT', { countries });
      expect(res.status).toBe(400);
    }
    expect(await raw(CENSORED_COUNTRIES_KEY)).toBeNull();
  });

  test('need an admin', async () => {
    const t = convexTest(schema, modules);
    const res = await t.fetch('/api/v1/admin/censored-countries', { method: 'GET' });
    expect(res.status).toBe(401);
  });

  test('audit the codes that changed and the new length', async () => {
    const { t, call } = await setup();
    await call('PUT', { countries: [entry('IR', true), entry('RU', true)] });
    await call('PUT', { countries: [entry('IR', false), entry('TR')] });
    const rows = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const updates = rows.filter((r) => r.action === 'censorship.countries.update');
    expect(updates).toHaveLength(2);
    expect(updates[1]!.payload).toEqual({
      added: 'TR',
      removed: 'RU',
      flagsChanged: 'IR',
      count: 2,
    });
  });
});

describe('seed.seedCensoredCountries', () => {
  test('copies what is in effect once and never overwrites a stored list', async () => {
    const { t, setting, raw } = await setup();
    await setting('edge.probe.countries', ['IR']);
    // The curated default (CN, RU, IR, MM) plus the stored probe list (IR only).
    expect(await t.mutation(internal.seed.seedCensoredCountries, {})).toEqual({ copied: 4 });
    const copied = (await raw(CENSORED_COUNTRIES_KEY)) as { code: string; checkEdges: boolean }[];
    expect(copied.map((c) => c.code)).toEqual(['CN', 'RU', 'IR', 'MM']);
    expect(copied.filter((c) => c.checkEdges).map((c) => c.code)).toEqual(['IR']);
    // The old key stays.
    expect(await raw('edge.probe.countries')).toEqual(['IR']);
    // Idempotent, and an admin's list wins.
    await setting(CENSORED_COUNTRIES_KEY, [entry('RU', true)]);
    expect(await t.mutation(internal.seed.seedCensoredCountries, {})).toEqual({ copied: null });
    expect(await raw(CENSORED_COUNTRIES_KEY)).toEqual([entry('RU', true)]);
  });

  test('refuses to copy a union longer than the cap, which stays live and whole', async () => {
    const { t, call, setting, raw } = await setup();
    const codes = Array.from({ length: 70 }, (_, i) =>
      String.fromCharCode(65 + Math.floor(i / 26), 65 + (i % 26)),
    ).filter((c) => c !== 'XX' && c !== 'ZZ');
    await setting('edge.sni.curatedCountries', codes.slice(0, 32));
    await setting('edge.probe.countries', codes.slice(25, 65));
    expect(await t.mutation(internal.seed.seedCensoredCountries, {})).toEqual({
      copied: null,
      overCap: 65,
    });
    expect(await raw(CENSORED_COUNTRIES_KEY)).toBeNull();
    // Every country still counts until an admin trims the list.
    const view = await (await call('GET')).json();
    expect(view.stored).toBe(false);
    expect(view.countries).toHaveLength(65);
    // Saving needs a list within the cap.
    expect((await call('PUT', { countries: view.countries })).status).toBe(400);
    expect((await call('PUT', { countries: view.countries.slice(0, 40) })).status).toBe(200);
  });
});

describe('seed.retireLegacyCountryKeys', () => {
  const OLD = [
    'edge.sni.curatedCountries',
    'edge.probe.countries',
    'edge.sni.vantage.countries',
    'delivery.privacyCountries',
  ];
  const backup = (t: T) =>
    t.run(async (ctx) => {
      const row = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'censorship:legacyKeys'))
        .unique();
      return row ? (JSON.parse(row.value) as Record<string, string>) : null;
    });

  test('deletes the four old lists once the list is stored, keeping their values; the matrix stays', async () => {
    const { t, setting, raw } = await setup();
    await setting('edge.sni.curatedCountries', ['IR', 'RU']);
    await setting('edge.probe.countries', ['IR']);
    await setting('edge.sni.vantage.countries', ['IR']);
    await setting('delivery.privacyCountries', ['RU']);
    await setting('status.censorship', { rows: [] });
    // The copy first: the list is stored from what was in effect.
    await t.mutation(internal.seed.seedCensoredCountries, {});
    const listBefore = await raw(CENSORED_COUNTRIES_KEY);
    const r = await t.mutation(internal.seed.retireLegacyCountryKeys, {});
    expect([...r.retired].sort()).toEqual([...OLD].sort());
    for (const key of OLD) expect(await raw(key)).toBeNull();
    expect(await raw('status.censorship')).toEqual({ rows: [] });
    // Nothing anyone reads changed.
    expect(await raw(CENSORED_COUNTRIES_KEY)).toEqual(listBefore);
    const b = (await backup(t))!;
    expect(JSON.parse(b['edge.probe.countries']!)).toEqual(['IR']);
    expect(JSON.parse(b['delivery.privacyCountries']!)).toEqual(['RU']);
    // Audited by key name only.
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const row = audit.find((a) => a.action === 'censorship.legacy_keys.retire')!;
    expect(row.payload).toMatchObject({ count: 4 });
    expect(JSON.stringify(row.payload)).not.toContain('IR');
    // Idempotent: a second deploy finds nothing to do and keeps the backup.
    expect(await t.mutation(internal.seed.retireLegacyCountryKeys, {})).toEqual({ retired: [] });
    expect(await backup(t)).toEqual(b);
  });

  test('keeps them while the list is not stored (they are still what is in effect)', async () => {
    const { t, setting, raw } = await setup();
    await setting('edge.probe.countries', ['IR']);
    expect(await t.mutation(internal.seed.retireLegacyCountryKeys, {})).toEqual({
      retired: [],
      skipped: 'not_stored',
    });
    expect(await raw('edge.probe.countries')).toEqual(['IR']);
    expect(await backup(t)).toBeNull();
  });

  test('restore puts back what is missing, never over a key written since', async () => {
    const { t, setting, raw } = await setup();
    await setting('edge.probe.countries', ['IR']);
    await setting('delivery.privacyCountries', ['RU']);
    await setting(CENSORED_COUNTRIES_KEY, [entry('IR', true)]);
    await t.mutation(internal.seed.retireLegacyCountryKeys, {});
    // A key written again after the retirement is left alone.
    await setting('delivery.privacyCountries', ['TR']);
    const r = await t.mutation(internal.seed.restoreLegacyCountryKeys, {});
    expect(r.restored).toEqual(['edge.probe.countries']);
    expect(await raw('edge.probe.countries')).toEqual(['IR']);
    expect(await raw('delivery.privacyCountries')).toEqual(['TR']);
    // With the list stored, the restored keys change nothing.
    expect(await raw(CENSORED_COUNTRIES_KEY)).toEqual([entry('IR', true)]);
  });

  test('a key changed under an older build after a restore is kept and flagged, and saving the list retires it', async () => {
    const { t, call, setting, raw } = await setup();
    await setting('edge.probe.countries', ['IR']);
    await setting('delivery.privacyCountries', ['RU']);
    await setting(CENSORED_COUNTRIES_KEY, [entry('IR', true), entry('RU')]);
    await t.mutation(internal.seed.retireLegacyCountryKeys, {});
    // A rollback: the keys come back, the older build runs, the operator changes one.
    await t.mutation(internal.seed.restoreLegacyCountryKeys, {});
    await setting('edge.probe.countries', ['IR', 'TR']);
    // The next deploy keeps the changed key (the list does not have that change)...
    const r = await t.mutation(internal.seed.retireLegacyCountryKeys, {});
    expect(r).toEqual({ retired: ['delivery.privacyCountries'], kept: ['edge.probe.countries'] });
    expect(await raw('edge.probe.countries')).toEqual(['IR', 'TR']);
    expect(await raw('delivery.privacyCountries')).toBeNull();
    // ...the backup still holds the value from before, and the card says so.
    expect(JSON.parse((await backup(t))!['edge.probe.countries']!)).toEqual(['IR']);
    const view = await (await call('GET')).json();
    expect(view.legacyChanged).toEqual(['edge.probe.countries']);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'censorship.legacy_keys.changed')).toBe(true);
    // Later deploys keep it too, until the list is saved.
    expect((await t.mutation(internal.seed.retireLegacyCountryKeys, {})).kept).toEqual([
      'edge.probe.countries',
    ]);
    const saved = await call('PUT', { countries: [entry('IR', true), entry('TR', true)] });
    expect(saved.status).toBe(200);
    expect((await saved.json()).legacyChanged).toEqual([]);
    expect(await raw('edge.probe.countries')).toBeNull();
    // The newest value is the one a further rollback would get.
    expect(JSON.parse((await backup(t))!['edge.probe.countries']!)).toEqual(['IR', 'TR']);
  });

  test('the deploy seed copies, then retires, in one pass', async () => {
    const { t, setting, raw } = await setup();
    await setting('edge.probe.countries', ['IR']);
    await t.action(internal.seed.seedCutover, {});
    expect(await raw(CENSORED_COUNTRIES_KEY)).not.toBeNull();
    expect(await raw('edge.probe.countries')).toBeNull();
    expect(JSON.parse((await backup(t))!['edge.probe.countries']!)).toEqual(['IR']);
  });
});

describe('readers', () => {
  test('probe countries, server-name countries and checks from inside come from the list', async () => {
    const { t, setting } = await setup();
    await setting(CENSORED_COUNTRIES_KEY, [
      entry('RU', true),
      entry('IR', false, true),
      entry('CN', true, true),
    ]);
    const [edge, sni, vantage] = await t.run(async (ctx) => [
      await resolveEdgeConfig(ctx.db),
      await resolveSniConfig(ctx.db),
      await resolveSniVantageConfig(ctx.db),
    ]);
    expect(edge.probe.countries).toEqual(['RU', 'CN']);
    expect(sni.curatedCountries).toEqual(['RU', 'IR', 'CN']);
    expect(vantage.countries).toEqual(['IR', 'CN']);
  });

  test('the server-name settings no longer write country lists', async () => {
    const { t, raw } = await setup();
    const { changedKeys } = await t.mutation(internal.sniFamilies.patchConfig, {
      patch: { curatedCountries: ['DE'], vantage: { countries: ['DE'], enabled: true } },
    });
    expect(changedKeys).toEqual(['vantage.enabled']);
    expect(await raw('edge.sni.curatedCountries')).toBeNull();
    expect(await raw('edge.sni.vantage.countries')).toBeNull();
  });

  test('members choose among the listed countries, and only those', async () => {
    const { t, setting } = await setup();
    await setting(CENSORED_COUNTRIES_KEY, [entry('TR'), entry('IR')]);
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
        updatedAt: Date.now(),
      });
      return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
    });
    // A member without a key has no country to choose (and no list to choose from).
    expect(await t.query(internal.memberCountry.memberView, { userId })).toMatchObject({
      applies: false,
      options: [],
    });
    await expect(
      t.mutation(internal.memberCountry.setChoice, { userId, region: 'RU' }),
    ).rejects.toThrow(/unknown region/);
  });
});

describe('the status page matrix', () => {
  test('shows listed countries in list order; a save keeps the rows of unlisted ones', async () => {
    const { t, setting, raw } = await setup();
    await setting(CENSORED_COUNTRIES_KEY, [entry('RU'), entry('IR')]);
    await setting(STATUS_KEYS.censorship, {
      rows: [
        { countryCode: 'DE', cells: { 'freedom-ws': 'available' } },
        { countryCode: 'IR', cells: { 'freedom-ws': 'partial' } },
        { countryCode: 'RU', cells: { 'freedom-ws': 'blocked' } },
      ],
    });
    const page = await t.run((ctx) => resolvePublicStatusPage(ctx.db));
    expect(page.censorship.rows.map((r) => r.countryCode)).toEqual(['RU', 'IR']);

    const view = await t.query(internal.statusPage.getPageConfig, {});
    expect(view.countries).toEqual(['RU', 'IR']);

    // The editor submits the listed rows only; an emptied row is dropped.
    const out = await t.mutation(internal.statusPage.setPageConfig, {
      rows: [
        { countryCode: 'RU', cells: {} },
        { countryCode: 'IR', cells: { 'freedom-ws': 'available' } },
      ],
    });
    expect(out.countries).toEqual(['RU', 'IR']);
    const stored = (await raw(STATUS_KEYS.censorship)) as {
      rows: { countryCode: string; cells: Record<string, string> }[];
    };
    expect(stored.rows.map((r) => [r.countryCode, r.cells['freedom-ws']])).toEqual([
      ['DE', 'available'],
      ['IR', 'available'],
    ]);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((r) => r.action === 'status.page.update')?.payload).toEqual({
      censorshipRows: 2,
    });
  });
});
