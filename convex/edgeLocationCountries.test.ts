/// <reference types="vite/client" />
/**
 * Locations meant for a country end to end (docs/edges.md "Locations meant
 * for a country"): saving the countries (listed only, the origins with an
 * address in use there move their epoch), the estimate before saving, the
 * preview's reason, the country view's block, the attention item and the
 * rollback helper.
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
import { CountryViewResponse } from '../src/shared/contracts/edges';

const modules = import.meta.glob('./**/*.*s');
const H = 3_600_000;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  refuseNetwork();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** One node with two addresses in use: one in the account's location, one elsewhere. */
async function setup(opts: { steer?: boolean } = {}) {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
    if (opts.steer !== false) await upsertSettingRow(ctx, 'delivery.country.steer', 'true');
    await upsertSettingRow(
      ctx,
      CENSORED_COUNTRIES_KEY,
      JSON.stringify([
        { code: 'IR', checkEdges: true, checkNamesInside: false },
        { code: 'RU', checkEdges: true, checkNamesInside: false },
      ]),
    );
  });
  const accountId = await createAccount(t, { provider: 'upcloud', name: 'acc' });
  const locationId = (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!
    .id as Id<'edgeLocations'>;
  const { relayId, listenerId } = await registerRelay(t, {
    listeners: [realityListener({ listenerKey: 'u', tlsNames: ['a.example', 'b.example'] })],
  });
  const adopt = (ipv4: string) =>
    t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      ipv4,
      publish: true,
      verified: true,
    });
  const here = (await adopt('198.51.100.1')).edgeId as Id<'edges'>;
  const elsewhere = (await adopt('198.51.100.2')).edgeId as Id<'edges'>;
  // The first address lives in the account's location (an adopted edge records none).
  await t.run(async (ctx) => {
    await ctx.db.patch(here, { locationId, provider: 'upcloud', placeKey: 'de-fra1' });
  });
  return { t, accountId, locationId, relayId, here, elsewhere };
}

const epochOf = (t: Awaited<ReturnType<typeof setup>>['t'], relayId: Id<'relays'>) =>
  t.run(async (ctx) => (await ctx.db.get(relayId))!.publicationEpoch);

describe('saving the countries a location is meant for', () => {
  test('listed codes only, at most eight; the origins with an address in use there move', async () => {
    const { t, accountId, locationId, relayId } = await setup();
    await expect(
      t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['TR'] }),
    ).rejects.toThrow(/not on the censored-country list/);
    const before = await epochOf(t, relayId);
    const r = await t.mutation(internal.edgeLocations.setForCountries, {
      id: locationId,
      codes: ['ir', 'RU', 'IR'],
    });
    expect(r).toEqual({ ok: true, changed: true, codes: ['IR', 'RU'], nodes: 1 });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const loc = (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!;
    expect(loc.meantFor).toEqual(['IR', 'RU']);
    // The same codes again change nothing and move nothing.
    expect(
      await t.mutation(internal.edgeLocations.setForCountries, {
        id: locationId,
        codes: ['IR', 'RU'],
      }),
    ).toMatchObject({ changed: false });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.location.countries'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ countries: 'IR RU', nodes: 1 });
  });

  test('the estimate says how many members of each country added would start here', async () => {
    const { t, locationId } = await setup();
    const e = await t.query(internal.edgeLocations.forCountriesEstimate, {
      id: locationId,
      codes: ['IR'],
    });
    expect(e.valid).toBe(true);
    expect(e.steering).toBe(true);
    expect(e.countries).toHaveLength(1);
    const node = e.countries[0]!.nodes[0]!;
    // About half the members were on the other address: they move here.
    expect(node.sampled).toBeGreaterThan(0);
    expect(node.moved / node.sampled).toBeGreaterThan(0.3);
    expect(node.moved / node.sampled).toBeLessThan(0.7);
    expect(
      (
        await t.query(internal.edgeLocations.forCountriesEstimate, {
          id: locationId,
          codes: ['TR'],
        })
      ).code,
    ).toBe('meant_for_unlisted');
  });

  test('with steering off nothing moves, and the estimate says so', async () => {
    const { t, locationId } = await setup({ steer: false });
    const e = await t.query(internal.edgeLocations.forCountriesEstimate, {
      id: locationId,
      codes: ['IR'],
    });
    expect(e).toMatchObject({ valid: true, steering: false, countries: [] });
  });
});

describe('what a member there is handed', () => {
  test('the preview puts the meant-for address first and says why', async () => {
    const { t, locationId, relayId, here } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR'] });
    for (const sampleKey of ['0a', '7f', 'c3', 'ee'].map((p) => p.repeat(32))) {
      const ir = await t.query(internal.edgeAdmin.renderPreview, {
        relayId,
        family: 'other',
        country: 'IR',
        sampleKey,
      });
      expect(ir.steered).toBe(true);
      expect(ir.primaryWhy).toEqual({ meantFor: true });
      expect(ir.backupWhy).toEqual({ meantFor: false });
      expect(ir.body).toContain('198.51.100.1');
      // A member in another listed country gets no reason of the kind.
      const ru = await t.query(internal.edgeAdmin.renderPreview, {
        relayId,
        family: 'other',
        country: 'RU',
        sampleKey,
      });
      expect(ru.primaryWhy).toEqual({ meantFor: false });
    }
    // The published pool carries the location's countries.
    const view = CountryViewResponse.parse(
      await t.query(internal.edgeCountryView.country, { country: 'IR' }),
    );
    const members = view.origins[0]!.listeners[0]!.members;
    expect(members.steered).toBe(true);
    expect(members.onMeantFirst).toBe(1);
    expect(members.primary).toEqual([{ id: here, share: 1 }]);
    expect(view.meantFor).toEqual([
      expect.objectContaining({
        locationId,
        blocked: false,
        nodes: [expect.objectContaining({ published: 1, blocked: 0 })],
      }),
    ]);
  });

  test('blocked there: members get the other address, the view and attention say so', async () => {
    const { t, locationId, relayId, here, elsewhere } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR'] });
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.patch(here, {
        countryState: {
          byCountry: [{ country: 'IR', state: 'blocked', from: 'edge', until: now + 24 * H }],
          updatedAt: now,
        },
      });
    });
    const ir = await t.query(internal.edgeAdmin.renderPreview, {
      relayId,
      family: 'other',
      country: 'IR',
    });
    expect(ir.primaryTier).toBe(1);
    expect(ir.primaryWhy).toEqual({ meantFor: false });
    const view = CountryViewResponse.parse(
      await t.query(internal.edgeCountryView.country, { country: 'IR' }),
    );
    expect(view.origins[0]!.listeners[0]!.members.primary).toEqual([{ id: elsewhere, share: 1 }]);
    expect(view.meantFor[0]).toMatchObject({
      blocked: true,
      nodes: [{ published: 1, blocked: 1 }],
    });
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.find((i) => i.kind === 'meant_for_blocked')).toMatchObject({
      severity: 'warning',
      facts: { country: 'IR' },
      action: 'open_account',
    });
    const summary = await t.query(internal.edgeCountryView.summary, {});
    expect(summary.countries.find((c) => c.country === 'IR')!.meantFor).toEqual({
      locations: 1,
      blocked: 1,
    });
  });
});

describe('what counts as blocked there, and as in use', () => {
  test('a location grade past its until counts for nothing', async () => {
    const { t, locationId } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR'] });
    const grade = (until: number) =>
      t.run(async (ctx) => {
        for (const g of await ctx.db.query('countryGroupGrades').collect())
          await ctx.db.delete(g._id);
        await ctx.db.insert('countryGroupGrades', {
          groupKey: 'upcloud:de-fra1',
          country: 'IR',
          state: 'blocked',
          counts: { edges: 2, proven: 0, blocked: 2 },
          until,
          updatedAt: Date.now(),
        });
      });
    const blockedNow = async () => ({
      view: CountryViewResponse.parse(
        await t.query(internal.edgeCountryView.country, { country: 'IR' }),
      ).meantFor[0]!.blocked,
      attention: (await t.query(internal.edgeOperator.attention, {})).items.some(
        (i) => i.kind === 'meant_for_blocked',
      ),
    });
    await grade(Date.now() - 1000);
    expect(await blockedNow()).toEqual({ view: false, attention: false });
    await grade(Date.now() + 24 * H);
    expect(await blockedNow()).toEqual({ view: true, attention: true });
  });

  test('an address no member can be handed is not in use there', async () => {
    const { t, locationId, here } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR'] });
    const now = Date.now();
    // Its confirmation gone stale: still published, but nothing is rendered for it.
    await t.run(async (ctx) => {
      await ctx.db.patch(here, {
        verification: undefined,
        countryState: {
          byCountry: [{ country: 'IR', state: 'blocked', from: 'edge', until: now + 24 * H }],
          updatedAt: now,
        },
      });
    });
    const view = CountryViewResponse.parse(
      await t.query(internal.edgeCountryView.country, { country: 'IR' }),
    );
    expect(view.meantFor[0]).toMatchObject({ blocked: false, nodes: [] });
    const attention = await t.query(internal.edgeOperator.attention, {});
    expect(attention.items.some((i) => i.kind === 'meant_for_blocked')).toBe(false);
    const e = await t.query(internal.edgeLocations.forCountriesEstimate, {
      id: locationId,
      codes: [],
    });
    expect(e.countries).toEqual([{ country: 'IR', nodes: [] }]);
  });

  test('a country that left the censored list may stay or be removed, never added', async () => {
    const { t, locationId } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, {
      id: locationId,
      codes: ['IR', 'RU'],
    });
    await t.run(async (ctx) => {
      await upsertSettingRow(
        ctx,
        CENSORED_COUNTRIES_KEY,
        JSON.stringify([{ code: 'RU', checkEdges: true, checkNamesInside: false }]),
      );
    });
    // Another edit keeps it; the estimate moves nobody for it.
    expect(
      await t.query(internal.edgeLocations.forCountriesEstimate, { id: locationId, codes: ['IR'] }),
    ).toMatchObject({ valid: true, countries: [{ country: 'RU' }] });
    expect(
      await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['RU'] }),
    ).toMatchObject({ changed: true, codes: ['RU'] });
    // Once removed it is like any other country off the list.
    await expect(
      t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR', 'RU'] }),
    ).rejects.toThrow(/not on the censored-country list/);
  });
});

describe('rollback', () => {
  test('clearCountriesForRollback removes every location’s countries and moves their origins', async () => {
    const { t, accountId, locationId, relayId } = await setup();
    await t.mutation(internal.edgeLocations.setForCountries, { id: locationId, codes: ['IR'] });
    const before = await epochOf(t, relayId);
    expect(await t.mutation(internal.edgeLocations.clearCountriesForRollback, {})).toEqual({
      cleared: 1,
      origins: 1,
    });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const loc = (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!;
    expect(loc.meantFor).toEqual([]);
    const row = await t.run((ctx) => ctx.db.get(locationId));
    expect(row!.forCountries).toBeUndefined();
  });
});
