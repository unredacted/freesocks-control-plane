/// <reference types="vite/client" />
/**
 * The L7 locations migration (convex/edgeL7Locations.ts): a CDN account's zone
 * moves from its settings onto its existing location in one transaction, so
 * the account can front in every zone its token reaches. Location ids never
 * change (provider sets, runs, trust and spares keep pointing at them) and
 * edges are never touched (their intent froze the zone).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { placementHashOf } from './lib/edges/locations';
import { l7PlaceOf } from './lib/edges/l7Place';

const modules = import.meta.glob('./**/*.*s');

type T = ReturnType<typeof convexTest>;
const ZONE = 'a'.repeat(32);

/** An account as the single-zone shape stored it: the zone in settings, an empty `anycast` location. */
async function legacyAccount(
  t: T,
  provider: 'cloudflare' | 'fastly',
  name: string,
  settings: Record<string, unknown>,
  observed?: Record<string, string>,
): Promise<{ accountId: Id<'edgeProviderAccounts'>; locationId: Id<'edgeLocations'> }> {
  return t.run(async (ctx) => {
    const now = Date.now();
    const accountId = await ctx.db.insert('edgeProviderAccounts', {
      provider,
      name,
      credentials: { type: provider, apiToken: 'tok' } as never,
      settings: { type: provider, ...settings } as never,
      enabled: true,
      priority: 0,
      dailyAllocationBudget: 10,
      allocationsToday: 0,
      maxLiveEdges: 6,
      lastTestOkAt: now,
      ...(observed ? { observedSettings: JSON.stringify(observed), observedAt: now } : {}),
      updatedAt: now,
    });
    const empty = { type: provider };
    const locationId = await ctx.db.insert('edgeLocations', {
      accountId,
      provider,
      placeKey: 'anycast',
      placement: empty as never,
      placementHash: placementHashOf(empty),
      label: 'Anycast',
      enabled: true,
      qualified: true,
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.patch(accountId, { defaultLocationId: locationId });
    return { accountId, locationId };
  });
}

describe('L7 locations migration', () => {
  test("each CDN account's zone moves onto its own location; ids, trust and edges stay", async () => {
    const t = convexTest(schema, modules);
    const dns = await legacyAccount(
      t,
      'cloudflare',
      'acct-dns',
      { zoneId: ZONE, zoneName: 'example.org', accountId: 'b'.repeat(32) },
      { zoneSslMode: 'full', websockets: 'on' },
    );
    const front = await legacyAccount(t, 'fastly', 'acct-front', {
      dnsAccountId: dns.accountId,
      certificateAuthority: 'certainly',
      tlsConfigurationId: 'tls-1',
    });
    // A live front whose intent froze the zone: the migration never rewrites it.
    const intent = JSON.stringify({
      hostname: 'x.example.org',
      zoneId: ZONE,
      zoneName: 'example.org',
    });
    const edgeId = await t.run(async (ctx) => {
      const serverId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'panel-a',
        slug: 'panel-a',
        config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      const relayId = await ctx.db.insert('relays', {
        slug: 'node-one',
        backendServerId: serverId,
        origin: { kind: 'panel-node', backendServerId: serverId, nodeName: 'node-one' },
        nodeName: 'node-one',
        originAddress: '203.0.113.10',
        enabled: true,
        autoRotate: false,
        hostMode: 'fcp',
        delivery: 'edge-required',
        desiredPublished: 2,
        standbyPerRelay: 0,
        cooldownMs: 1,
        maxRotationsPerDay: 4,
        drainMs: 1,
        publicationEpoch: 0,
        publishedEdgeIds: [],
        standbyEdgeIds: [],
        rotationsToday: 0,
        providerSet: [{ locationId: front.locationId, addedAt: Date.now() }],
        updatedAt: Date.now(),
      });
      const listenerId = await ctx.db.insert('relayListeners', {
        relayId,
        listenerKey: 'w',
        protocol: 'vless',
        streamTransport: 'ws',
        security: 'tls',
        transport: 'tcp',
        originPort: 443,
        tlsNames: [],
        transportParams: { path: '/ws' },
        matchRule: { kind: 'remark', remark: 'node-one-relay-w' },
        source: 'admin',
        configHash: 'h',
        enabled: true,
        deployed: true,
        retired: false,
        revision: 1,
        updatedAt: Date.now(),
      });
      return ctx.db.insert('edges', {
        relayId,
        listenerId,
        accountId: front.accountId,
        locationId: front.locationId,
        placeKey: 'anycast',
        placement: { type: 'fastly' },
        provider: 'fastly',
        managed: true,
        name: 'fcp-relay-node-one-1',
        steps: [],
        resources: [],
        listeners: [],
        addresses: { hostname: 'x.example.org' },
        layer: 'l7',
        provisionIntent: intent,
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      });
    });
    expect(await t.query(internal.edgeL7Locations.status, {})).toMatchObject({
      l7Accounts: 2,
      legacyAccounts: 2,
      locationsWithoutZone: 2,
    });

    const res = await t.mutation(internal.edgeL7Locations.migrate, {});
    expect(res).toEqual({ moved: 2, created: 0, incomplete: [], edgesDiffer: 0 });

    const after = await t.run(async (ctx) => ({
      dnsAcct: (await ctx.db.get(dns.accountId))!,
      dnsLoc: (await ctx.db.get(dns.locationId))!,
      frontAcct: (await ctx.db.get(front.accountId))!,
      frontLoc: (await ctx.db.get(front.locationId))!,
      edge: (await ctx.db.get(edgeId))!,
    }));
    // The zone is the location's; the account keeps only its own keys.
    expect(after.dnsAcct.settings).toEqual({ type: 'cloudflare', accountId: 'b'.repeat(32) });
    expect(after.dnsLoc).toMatchObject({
      placement: { type: 'cloudflare', zoneId: ZONE, zoneName: 'example.org' },
      placeKey: 'anycast',
      label: 'example.org',
      qualified: true,
      observed: JSON.stringify({ zoneSslMode: 'full', websockets: 'on' }),
    });
    expect(after.frontAcct.settings).toEqual({ type: 'fastly', certificateAuthority: 'certainly' });
    expect(after.frontLoc.placement).toEqual({
      type: 'fastly',
      zoneId: ZONE,
      zoneName: 'example.org',
      dnsAccountId: dns.accountId,
      tlsConfigurationId: 'tls-1',
    });
    expect(after.frontLoc.placementHash).toBe(placementHashOf(after.frontLoc.placement));
    // The edge is untouched: its intent stays the authority for its calls.
    expect(after.edge.provisionIntent).toBe(intent);
    expect(after.edge.placement).toEqual({ type: 'fastly' });
    expect(await t.query(internal.edgeL7Locations.status, {})).toMatchObject({
      legacyAccounts: 0,
      locationsWithoutZone: 0,
    });
    const audits = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audits.filter((a) => a.action === 'edge.locations.l7_migrated')).toHaveLength(1);

    // Idempotent: a second deploy finds nothing to move and writes nothing.
    expect(await t.mutation(internal.edgeL7Locations.migrate, {})).toEqual({
      moved: 0,
      created: 0,
      incomplete: [],
      edgesDiffer: 0,
    });
    expect(
      (await t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
        (a) => a.action === 'edge.locations.l7_migrated',
      ),
    ).toHaveLength(1);
  });

  test("a front account's shared certificate moves onto the location of its zone", async () => {
    const t = convexTest(schema, modules);
    const dns = await legacyAccount(t, 'cloudflare', 'acct-dns', {
      zoneId: ZONE,
      zoneName: 'example.org',
    });
    const front = await legacyAccount(t, 'fastly', 'acct-front', {
      dnsAccountId: dns.accountId,
      certificateAuthority: 'certainly',
    });
    const shared = { name: '*.example.org', state: 'issued', checkedAt: 1 };
    await t.run((ctx) => ctx.db.patch(front.accountId, { sharedCertificate: shared }));
    await t.mutation(internal.edgeL7Locations.migrate, {});
    const after = await t.run(async (ctx) => ({
      acct: (await ctx.db.get(front.accountId))!,
      loc: (await ctx.db.get(front.locationId))!,
    }));
    expect(after.loc.sharedCertificate).toEqual(shared);
    expect(after.acct.sharedCertificate).toBeUndefined();
  });

  test('a front whose DNS account names no zone keeps its keys and is reported', async () => {
    const t = convexTest(schema, modules);
    const dns = await legacyAccount(t, 'cloudflare', 'acct-dns', {});
    await legacyAccount(t, 'fastly', 'acct-front', {
      dnsAccountId: dns.accountId,
      certificateAuthority: 'certainly',
    });
    const res = await t.mutation(internal.edgeL7Locations.migrate, {});
    expect(res.incomplete).toEqual(['acct-front']);
    expect(await t.query(internal.edgeL7Locations.status, {})).toMatchObject({ legacyAccounts: 1 });
  });

  test('the reverse leaves nothing an older schema refuses: the zone facts and wildcard go back to the account', async () => {
    const t = convexTest(schema, modules);
    const dns = await legacyAccount(t, 'cloudflare', 'acct-dns', {
      zoneId: ZONE,
      zoneName: 'example.org',
    });
    const front = await legacyAccount(t, 'fastly', 'acct-front', {
      dnsAccountId: dns.accountId,
      certificateAuthority: 'certainly',
    });
    await t.mutation(internal.edgeL7Locations.migrate, {});
    await t.mutation(internal.edgeLocations.recordCheck, {
      id: front.locationId,
      ok: false,
      code: 'caa_forbids_ca',
      observed: { caa: 'forbids', zoneStatus: 'active' },
    });
    await t.mutation(internal.edgeLocations.recordSharedCertificate, {
      id: front.locationId,
      status: { name: '*.example.org', subscriptionId: 'WILD1', state: 'issued' },
    });
    await t.mutation(internal.edgeProviderCatalog.record, {
      accountId: dns.accountId,
      lists: [{ kind: 'zones', items: [{ id: ZONE, label: 'example.org' }] }],
      errors: [],
    });
    expect(
      await t.mutation(internal.edgeL7Locations.unmigrate, {
        confirm: 'restore-single-zone-settings',
      }),
    ).toEqual({ restored: 2, skipped: [] });
    const back = await t.run(async (ctx) => ({
      acct: (await ctx.db.get(front.accountId))!,
      loc: (await ctx.db.get(front.locationId))!,
      catalog: await ctx.db.query('edgeProviderCatalog').collect(),
    }));
    expect(back.acct.settings).toMatchObject({ type: 'fastly', dnsAccountId: dns.accountId });
    expect(back.acct.sharedCertificate).toMatchObject({ name: '*.example.org', state: 'issued' });
    expect(JSON.parse(back.acct.observedSettings!)).toMatchObject({ caa: 'forbids' });
    for (const k of [
      'observed',
      'observedAt',
      'checkError',
      'checkErrorDetail',
      'sharedCertificate',
    ])
      expect(back.loc).not.toHaveProperty(k);
    expect(back.loc.placement).toEqual({ type: 'fastly' });
    expect(back.catalog).toEqual([]);
  });

  test('before it runs, planning reads the legacy zone; the reverse puts the single-zone shape back', async () => {
    const t = convexTest(schema, modules);
    const cf = await legacyAccount(
      t,
      'cloudflare',
      'acct-cf',
      { zoneId: ZONE, zoneName: 'example.org' },
      { zoneSslMode: 'strict' },
    );
    // The fallback: a location with no zone of its own reads the account's.
    const place = await t.run(async (ctx) =>
      l7PlaceOf(ctx.db, (await ctx.db.get(cf.accountId))!, await ctx.db.get(cf.locationId)),
    );
    expect(place).toEqual({
      zoneId: ZONE,
      zoneName: 'example.org',
      observed: { zoneSslMode: 'strict' },
    });
    await t.mutation(internal.edgeL7Locations.migrate, {});
    expect(
      await t.mutation(internal.edgeL7Locations.unmigrate, {
        confirm: 'restore-single-zone-settings',
      }),
    ).toEqual({ restored: 1, skipped: [] });
    const back = await t.run(async (ctx) => ({
      acct: (await ctx.db.get(cf.accountId))!,
      loc: (await ctx.db.get(cf.locationId))!,
    }));
    expect(back.acct.settings).toEqual({
      type: 'cloudflare',
      zoneId: ZONE,
      zoneName: 'example.org',
    });
    expect(back.loc.placement).toEqual({ type: 'cloudflare' });
    // An account with a second zone has no single-zone shape to go back to.
    await t.mutation(internal.edgeL7Locations.migrate, {});
    await t.mutation(internal.edgeLocations.create, {
      accountId: cf.accountId,
      placement: { zoneId: 'c'.repeat(32), zoneName: 'example.net' },
    });
    expect(
      await t.mutation(internal.edgeL7Locations.unmigrate, {
        confirm: 'restore-single-zone-settings',
      }),
    ).toEqual({ restored: 0, skipped: ['acct-cf'] });
  });
});
