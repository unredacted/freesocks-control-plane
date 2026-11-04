/// <reference types="vite/client" />
/**
 * Where members are told a location is, end to end (docs/edges.md "Names in
 * apps"): saving the place name and country (cleaned, checked, the origins
 * with an address in use there move their epoch), what the published pool and
 * the admin preview's "Names in apps" then say, the provider's region name
 * never reaching a member, and the rollback helper.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { publishedEdgesOf } from './edgeRender';
import {
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { refuseNetwork } from './lib/edges/testing/mockFetch';
import { EdgeRenderPreviewResponse } from '../src/shared/contracts/edges';

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
});

/** One node with two addresses in use: one in the account's location, one elsewhere. */
async function setup() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  await t.run(async (ctx) => {
    await upsertSettingRow(ctx, 'edge.enabled', 'true');
    await upsertSettingRow(ctx, 'edge.render.enabled', 'true');
  });
  const accountId = await createAccount(t, { provider: 'upcloud', name: 'acc' });
  const location = (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!;
  const locationId = location.id as Id<'edgeLocations'>;
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
  await t.run(async (ctx) => {
    await ctx.db.patch(here, { locationId, provider: 'upcloud', placeKey: 'de-fra1' });
  });
  return { t, accountId, locationId, providerLabel: location.label, relayId, here, elsewhere };
}

const epochOf = (t: Awaited<ReturnType<typeof setup>>['t'], relayId: Id<'relays'>) =>
  t.run(async (ctx) => (await ctx.db.get(relayId))!.publicationEpoch);

describe("a location's name in apps", () => {
  test('cleaned and checked; the origins with an address in use there move; audited as members read it', async () => {
    const { t, accountId, locationId, relayId } = await setup();
    // Private use (a backend's "unknown") and unassigned codes are refused alike.
    for (const country of ['XX', 'AB', 'AN'])
      await expect(
        t.mutation(internal.edgeLocations.setMemberPlace, {
          id: locationId,
          name: 'Example City',
          country,
        }),
      ).rejects.toThrow(/not a country code/);
    const before = await epochOf(t, relayId);
    const r = await t.mutation(internal.edgeLocations.setMemberPlace, {
      id: locationId,
      name: '  Example,  City | ',
      country: 'br',
    });
    expect(r).toEqual({
      ok: true,
      changed: true,
      name: 'Example City',
      country: 'BR',
      nodes: 1,
    });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const loc = (await t.query(internal.edgeLocations.listForAccount, { accountId }))[0]!;
    expect(loc.memberPlace).toEqual({ name: 'Example City', country: 'BR' });
    // The same again changes nothing and moves nothing.
    expect(
      await t.mutation(internal.edgeLocations.setMemberPlace, {
        id: locationId,
        name: 'Example City',
        country: 'BR',
      }),
    ).toMatchObject({ changed: false });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'edge.location.member_place'))
        .collect(),
    );
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload).toMatchObject({ memberName: '🇧🇷 via Example City', nodes: 1 });
    // Both empty: the field goes, and members read `via relay A` again.
    await t.mutation(internal.edgeLocations.setMemberPlace, {
      id: locationId,
      name: '',
      country: null,
    });
    expect((await t.run((ctx) => ctx.db.get(locationId)))!.memberPlace).toBeUndefined();
  });

  test('the published pool carries it, and members read it; never the provider’s region name', async () => {
    const { t, locationId, providerLabel, relayId, here, elsewhere } = await setup();
    await t.mutation(internal.edgeLocations.setMemberPlace, {
      id: locationId,
      name: 'Example City',
      country: 'BR',
    });
    const { published } = await t.run(async (ctx) =>
      publishedEdgesOf(ctx, (await ctx.db.get(relayId))!, { kind: 'member' }),
    );
    expect(published.find((e) => e.edgeId === here)?.memberPlace).toEqual({
      name: 'Example City',
      country: 'BR',
    });
    expect(published.find((e) => e.edgeId === elsewhere)?.memberPlace).toBeUndefined();
    for (const family of ['other', 'singbox', 'mihomo'] as const) {
      const preview = EdgeRenderPreviewResponse.parse(
        await t.query(internal.edgeAdmin.renderPreview, { relayId, family }),
      );
      expect(preview.names.entries.sort(), family).toEqual(
        ['🇧🇷 via Example City', 'via relay A'].sort(),
      );
      if (family !== 'other')
        expect(preview.names.groups.sort(), family).toEqual(
          ['FreeSocks', '⚡ Auto (fastest)'].sort(),
        );
      expect(preview.body).not.toContain(providerLabel);
    }
  });

  test('a CDN zone has no place name', async () => {
    const { t } = await setup();
    const zone = await t.run(async (ctx) => {
      const id = (await ctx.db.query('edgeLocations').first())!;
      await ctx.db.patch(id._id, { provider: 'fastly' });
      return id._id;
    });
    await expect(
      t.mutation(internal.edgeLocations.setMemberPlace, {
        id: zone,
        name: 'Example',
        country: null,
      }),
    ).rejects.toThrow(/CDN zone/);
  });

  test('rollback clears every place and moves the origins', async () => {
    const { t, locationId, relayId } = await setup();
    await t.mutation(internal.edgeLocations.setMemberPlace, {
      id: locationId,
      name: 'Example City',
      country: null,
    });
    const before = await epochOf(t, relayId);
    expect(await t.mutation(internal.edgeLocations.clearMemberPlacesForRollback, {})).toEqual({
      cleared: 1,
      origins: 1,
    });
    expect(await epochOf(t, relayId)).toBe(before + 1);
    expect((await t.run((ctx) => ctx.db.get(locationId)))!.memberPlace).toBeUndefined();
    expect(await t.mutation(internal.edgeLocations.clearMemberPlacesForRollback, {})).toEqual({
      cleared: 0,
      origins: 0,
    });
  });
});

describe('the retired entry-name settings', () => {
  test('removed from the table, values handed back; running it again finds nothing', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.render.primaryLabel', JSON.stringify('Ours'));
      await upsertSettingRow(ctx, 'edge.render.autoGroupName', JSON.stringify('Ours Auto'));
      await upsertSettingRow(
        ctx,
        'edge.render.clients.singbox',
        JSON.stringify({ enabled: true, autoGroup: true, backupLabel: 'Spare', maxEntries: 4 }),
      );
    });
    const r = await t.mutation(internal.edgeRender.retireEntryLabels, {});
    expect(r.removed).toEqual([
      { key: 'edge.render.autoGroupName', value: JSON.stringify('Ours Auto') },
      { key: 'edge.render.primaryLabel', value: JSON.stringify('Ours') },
      { key: 'edge.render.clients.singbox.backupLabel', value: JSON.stringify('Spare') },
    ]);
    const rows = await t.run((ctx) => ctx.db.query('appSettings').collect());
    expect(rows.map((x) => x.key)).toEqual(['edge.render.clients.singbox']);
    expect(JSON.parse(rows[0]!.value)).toEqual({ enabled: true, autoGroup: true, maxEntries: 4 });
    expect((await t.mutation(internal.edgeRender.retireEntryLabels, {})).removed).toEqual([]);
  });
});
