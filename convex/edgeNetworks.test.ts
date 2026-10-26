/// <reference types="vite/client" />
/**
 * Networks (docs/edges.md "Networks", convex/edgeNetworks.ts):
 *
 *  - a network is ASNs plus the ranges they announce (read with the ASN only)
 *    and ranges by hand; a failed read keeps what was read before;
 *  - a family on a network qualifies a name only on it, and its names wait
 *    while the network has no ranges;
 *  - binding such a family scopes the transport: refused while an address in
 *    use is off the network, the listeners carry the network (registration
 *    too), an unbind clears it;
 *  - an address off the network is never published on the transport, and one
 *    already published that falls off it is an attention item;
 *  - a location learns its network from its edges, unless an operator set it.
 *
 * Fixtures use documentation ranges and private ASNs only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { __setNetworkFetchForTests } from './edgeNetworks';
import { selectionContext } from './edgeRotations';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { carries } from './lib/edges/setState';
import {
  adoptL4Edge,
  createAccount,
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  __setNetworkFetchForTests(null);
  vi.unstubAllEnvs();
});

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
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
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  await t.run((ctx) =>
    ctx.db.insert('panelProfiles', {
      backendServerId: serverId,
      profileUuid: PROFILE,
      name: 'Default',
      shapeHash: 'x',
      changeToken: 'y',
      digestKeyId: 'k',
      inbounds: [
        {
          tag: 'REALITY_IN',
          inboundUuid: INBOUND,
          protocol: 'vless',
          port: 443,
          network: 'tcp',
          security: 'reality',
          reality: { target: 'target.example:443', serverNames: ['a.example', 'b.example'] },
        },
      ],
      observedAt: Date.now(),
    }),
  );
  await call('PATCH', 'sni/config', { enabled: true });
  return { t, serverId, call };
}

/** A fake announced-ranges service: records the URLs it is asked, answers per ASN. */
function fakeAnnounced(byAsn: Record<number, string[]>, status = 200) {
  const asked: string[] = [];
  __setNetworkFetchForTests(async (url) => {
    asked.push(url);
    const asn = Number(/resource=AS(\d+)/.exec(url)?.[1]);
    return {
      ok: status === 200,
      status,
      text: async () =>
        JSON.stringify({
          status: 'ok',
          data: { prefixes: (byAsn[asn] ?? []).map((prefix) => ({ prefix })) },
        }),
    };
  });
  return asked;
}

const network = (t: T, slug: string) =>
  t.run(
    async (ctx) =>
      (await ctx.db
        .query('edgeNetworks')
        .withIndex('by_slug', (q) => q.eq('slug', slug))
        .unique())!,
  );

describe('networks', () => {
  test('created, its ranges read with the ASN only, a failed read keeps them', async () => {
    const { t, call } = await seed();
    const asked = fakeAnnounced({ 64500: ['192.0.2.0/24', '2001:db8:10::/48'] });
    const res = await call('POST', 'networks', {
      slug: 'net-a',
      label: 'Net A',
      asns: ['AS64500'],
    });
    expect(res.status).toBe(200);
    await t.action(internal.edgeNetworks.refresh, { slug: 'net-a' });
    expect(asked).toEqual([
      'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500',
    ]);
    const list = await (await call('GET', 'networks')).json();
    expect(list.networks[0]).toMatchObject({
      slug: 'net-a',
      asns: [64500],
      ranges: { v4: 1, v6: 1 },
      refreshError: null,
    });
    // The ranges themselves never leave the server.
    expect(JSON.stringify(list)).not.toContain('192.0.2.0');
    // A failed read: the code is kept, the ranges stay.
    fakeAnnounced({}, 503);
    await call('POST', 'networks/net-a/refresh', {});
    const n = await network(t, 'net-a');
    expect(n.refreshError).toBe('service_error');
    expect(n.prefixes.v4).toEqual(['192.0.2.0/24']);
  });

  test('refusals: not an ASN, nothing at all, a range that is not one', async () => {
    const { call } = await seed();
    const codeOf = async (r: Response) => [r.status, (await r.json()).error.code];
    expect(
      await codeOf(await call('POST', 'networks', { slug: 'n', label: 'N', asns: ['x'] })),
    ).toEqual([400, 'edge.network.bad_asn']);
    expect(
      await codeOf(await call('POST', 'networks', { slug: 'n', label: 'N', asns: [] })),
    ).toEqual([400, 'edge.network.empty']);
    expect(
      await codeOf(
        await call('POST', 'networks', {
          slug: 'n',
          label: 'N',
          asns: [],
          manualPrefixes: ['192.0.2.1'],
        }),
      ),
    ).toEqual([400, 'edge.network.bad_prefix']);
  });
});

describe('a family on a network', () => {
  test('its names wait for ranges, then carry the network to qualification', async () => {
    const { t, call } = await seed();
    fakeAnnounced({});
    await call('POST', 'networks', { slug: 'net-a', label: 'Net A', asns: [64500] });
    await call('POST', 'sni/families', {
      slug: 'fam-a',
      label: 'Fam A',
      targetAddress: 'target.example',
      targetPort: 443,
      network: 'net-a',
    });
    await call('POST', 'sni/families/fam-a/names', { lines: ['a.example'] });
    // No ranges yet: the name is not checked (never failed for it).
    expect((await t.query(internal.sniFamilies.dueForQualification, {})).names).toEqual([]);
    await call('PATCH', 'networks/net-a', { manualPrefixes: ['192.0.2.0/24'] });
    const due = await t.query(internal.sniFamilies.dueForQualification, {});
    expect(due.names.map((n) => n.name)).toEqual(['a.example']);
    expect(due.networks[due.names[0]!.network!]).toEqual({ v4: ['192.0.2.0/24'], v6: [] });
    const detail = await (await call('GET', 'sni/families/fam-a')).json();
    expect(detail.family.network).toEqual({ slug: 'net-a', label: 'Net A', ranges: 1 });
    // Names waiting for their network never crowd out other families' due names.
    await call('PATCH', 'networks/net-a', { manualPrefixes: [], asns: [64500] });
    await call('PATCH', 'sni/config', { qualifyPerTick: 1 });
    await call('POST', 'sni/families/fam-a/names', {
      lines: ['w1.example', 'w2.example', 'w3.example', 'w4.example', 'w5.example'],
    });
    await call('POST', 'sni/families', {
      slug: 'fam-b',
      label: 'Fam B',
      targetAddress: 'target.example',
      targetPort: 443,
    });
    await call('POST', 'sni/families/fam-b/names', { lines: ['other.example'] });
    expect(
      (await t.query(internal.sniFamilies.dueForQualification, {})).names.map((n) => n.name),
    ).toEqual(['other.example']);
    // A network in use is not removed.
    expect((await (await call('DELETE', 'networks/net-a')).json()).error.code).toBe(
      'edge.network.in_use',
    );
  });
});

describe('a transport scoped to a network', () => {
  async function bound() {
    const s = await seed();
    const { t, call } = s;
    await call('POST', 'networks', {
      slug: 'net-a',
      label: 'Net A',
      asns: [],
      manualPrefixes: ['192.0.2.0/24'],
    });
    await call('POST', 'sni/families', {
      slug: 'fam-a',
      label: 'Fam A',
      targetAddress: 'target.example',
      targetPort: 443,
      network: 'net-a',
    });
    const relay = await registerRelay(t, {
      listeners: [realityListener({ tlsNames: ['a.example', 'b.example'] })],
    });
    return { ...s, relay };
  }
  const bind = (call: (m: string, p: string, b?: unknown) => Promise<Response>) =>
    call('POST', 'sni/families/fam-a/bind', { backendSlug: 'panel-a', transportTag: 'REALITY_IN' });

  test('binding is refused while an address in use is off the network', async () => {
    const { t, call, relay } = await bound();
    await adoptL4Edge(t, relay.relayId, relay.listenerId, { ipv4: '198.51.100.7', publish: true });
    const r = await bind(call);
    expect((await r.json()).error.code).toBe('edge.sni.network_edges_off');
    // With the address's range added, it binds, and the listener carries the network.
    await call('PATCH', 'networks/net-a', { manualPrefixes: ['192.0.2.0/24', '198.51.100.0/24'] });
    expect((await bind(call)).status).toBe(200);
    const n = await network(t, 'net-a');
    expect((await t.run((ctx) => ctx.db.get(relay.listenerId)))!.networkId).toBe(n._id);
  });

  test('the listeners carry it (registration too), an unbind clears it', async () => {
    const { t, call, relay } = await bound();
    const { id } = await (await bind(call)).json();
    const n = await network(t, 'net-a');
    const other = await registerRelay(t, {
      slug: 'node-two',
      nodeName: 'node-two',
      listeners: [realityListener()],
    });
    const scoped = async () =>
      t.run(async (ctx) => [
        (await ctx.db.get(relay.listenerId))!.networkId ?? null,
        (await ctx.db.get(other.listenerId))!.networkId ?? null,
      ]);
    expect(await scoped()).toEqual([n._id, n._id]);
    // The family's network cannot change while it is bound.
    expect(
      (await (await call('PATCH', 'sni/families/fam-a', { network: null })).json()).error.code,
    ).toBe('edge.sni.network_bound');
    await call('DELETE', `sni/bindings/${id}`);
    expect(await scoped()).toEqual([null, null]);
  });

  test('a spare off the network is never the standby a rotation takes', async () => {
    const { t, call, relay } = await bound();
    expect((await bind(call)).status).toBe(200);
    const select = () =>
      t.run(async (ctx) =>
        selectionContext(
          ctx,
          {
            kind: 'provision',
            trigger: 'manual',
            listenerId: relay.listenerId,
            publishOnDone: true,
          },
          (await ctx.db.get(relay.relayId))!,
          null,
          await resolveEdgeConfig(ctx.db),
        ),
      );
    // A tested spare from before the transport was scoped, off its network.
    const healthy = (id: string) =>
      t.run((ctx) => ctx.db.patch(id as Id<'edges'>, { health: 'online' }));
    const off = await adoptL4Edge(t, relay.relayId, relay.listenerId, { ipv4: '198.51.100.9' });
    await healthy(off.edgeId);
    expect((await select()).standbyId).toBeNull();
    const on = await adoptL4Edge(t, relay.relayId, relay.listenerId, { ipv4: '192.0.2.9' });
    await healthy(on.edgeId);
    expect((await select()).standbyId).toBe(on.edgeId);
  });

  test('when its ranges move, every name of a family on it is checked again; with none, addresses in use are named', async () => {
    const { t, call, relay } = await bound();
    await call('POST', 'sni/families/fam-a/names', { lines: ['a.example'] });
    const name = async () =>
      t.run(
        async (ctx) =>
          (await ctx.db
            .query('sniNames')
            .withIndex('by_name', (q) => q.eq('name', 'a.example'))
            .unique())!,
      );
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: (await name())._id,
      ok: true,
      tlsVersion: 'TLSv1.3',
    });
    expect((await name()).checkedAt).toBeGreaterThan(0);
    await call('PATCH', 'networks/net-a', { manualPrefixes: ['192.0.2.0/24', '203.0.113.0/24'] });
    const scheduled = await t.run(async (ctx) =>
      (await ctx.db.system.query('_scheduled_functions').collect()).map((f) => f.name),
    );
    expect(scheduled.some((n) => n.includes('requeueFamilyNames'))).toBe(true);
    const fam = await t.run(
      async (ctx) =>
        (await ctx.db
          .query('sniFamilies')
          .withIndex('by_slug', (q) => q.eq('slug', 'fam-a'))
          .unique())!,
    );
    await t.mutation(internal.edgeNetworks.requeueFamilyNames, { familyId: fam._id });
    expect((await name()).checkedAt).toBe(0);
    // A network left with no ranges: the address in use is named, whatever it is.
    expect((await bind(call)).status).toBe(200);
    const inUse = await adoptL4Edge(t, relay.relayId, relay.listenerId, {
      ipv4: '192.0.2.7',
      publish: true,
    });
    await t.run(async (ctx) => {
      const n = (await ctx.db
        .query('edgeNetworks')
        .withIndex('by_slug', (q) => q.eq('slug', 'net-a'))
        .unique())!;
      await ctx.db.patch(n._id, { manualPrefixes: [], prefixes: { v4: [], v6: [] } });
    });
    const items = (await t.query(internal.edgeOperator.attention, {})).items.filter(
      (i: { kind: string }) => i.kind === 'edge_off_network',
    );
    expect(
      items.map((i: { edgeId: string | null; code: string | null }) => [i.edgeId, i.code]),
    ).toEqual([[inUse.edgeId, 'network_no_ranges']]);
  });

  test('a bound family on a network with fewer than three names that qualify is named', async () => {
    const { t, call } = await bound();
    expect((await bind(call)).status).toBe(200);
    await call('POST', 'sni/families/fam-a/names', {
      lines: ['a.example', 'b.example', 'c.example'],
    });
    const thin = async () =>
      (await t.query(internal.edgeOperator.attention, {})).items.filter(
        (i: { kind: string }) => i.kind === 'sni_family_thin',
      );
    const [item] = await thin();
    expect(item).toMatchObject({
      severity: 'info',
      action: 'find_names',
      facts: { family: 'fam-a', qualifying: 0 },
    });
    // Three names that qualify: enough.
    await t.run(async (ctx) => {
      for (const n of await ctx.db.query('sniNames').collect())
        await ctx.db.patch(n._id, {
          qualification: { state: 'ok', consecutiveFails: 0, tlsVersion: 'TLSv1.3' },
        });
    });
    expect(await thin()).toEqual([]);
  });

  test('an address off the network is never published there; one that falls off is named', async () => {
    const { t, call, relay } = await bound();
    expect((await bind(call)).status).toBe(200);
    await expect(
      adoptL4Edge(t, relay.relayId, relay.listenerId, { ipv4: '198.51.100.7', publish: true }),
    ).rejects.toThrow(/off_network/);
    const on = await adoptL4Edge(t, relay.relayId, relay.listenerId, {
      ipv4: '192.0.2.7',
      publish: true,
    });
    const attention = async () =>
      (await t.query(internal.edgeOperator.attention, {})).items.filter(
        (i: { kind: string }) => i.kind === 'edge_off_network',
      );
    expect(await attention()).toEqual([]);
    // The network's ranges move: the published address is now off it.
    await call('PATCH', 'networks/net-a', { manualPrefixes: ['203.0.113.0/24'] });
    expect((await attention()).map((i: { edgeId: string | null }) => i.edgeId)).toEqual([
      on.edgeId,
    ]);
  });
});

describe('where a location is', () => {
  test('carries: a scoped transport only from a location on its network', () => {
    const account = { _id: 'a1', provider: 'gcore' } as never;
    const listener = {
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
      originPort: 443,
      tlsNames: [{ name: 'a.example', status: 'active' }],
    } as const;
    const scoped = { ...listener, networkId: 'n1' } as never;
    expect(carries({ account, location: { networkId: 'n1' as never } }, scoped)).toBe(true);
    expect(carries({ account, location: { networkId: 'n2' as never } }, scoped)).toBe(false);
    expect(carries({ account, location: {} }, scoped)).toBe(false);
    // A region not yet a location is no place on any network.
    expect(carries({ account }, scoped)).toBe(false);
    // A transport on no network: wherever it was carried before.
    expect(carries({ account, location: { networkId: 'n1' as never } }, listener as never)).toBe(
      true,
    );
  });

  test('learned from the addresses of its edges, unless an operator set it', async () => {
    const { t, call } = await seed();
    await call('POST', 'networks', {
      slug: 'net-a',
      label: 'Net A',
      asns: [],
      manualPrefixes: ['192.0.2.0/24'],
    });
    await call('POST', 'networks', {
      slug: 'net-b',
      label: 'Net B',
      asns: [],
      manualPrefixes: ['203.0.113.0/24'],
    });
    const accountId = await createAccount(t, { qualified: true });
    const loc = await t.run(
      async (ctx) =>
        (await ctx.db
          .query('edgeLocations')
          .withIndex('by_account', (q) => q.eq('accountId', accountId))
          .first())!,
    );
    const relay = await registerRelay(t, { listeners: [realityListener()] });
    await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId: relay.relayId,
        listenerId: relay.listenerId,
        accountId,
        locationId: loc._id,
        placeKey: loc.placeKey,
        provider: 'gcore',
        managed: true,
        name: 'e1',
        steps: [],
        resources: [],
        listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
        addresses: { v4: '192.0.2.44' },
        layer: 'l4',
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: Date.now(),
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.edgeNetworks.learnLocations, {});
    const a = await network(t, 'net-a');
    let row = (await t.run((ctx) => ctx.db.get(loc._id as Id<'edgeLocations'>)))!;
    expect([row.networkId, row.networkSource]).toEqual([a._id, 'address']);
    // An operator's choice wins and stays.
    await call('POST', `providers/${accountId}/locations/${loc._id}/network`, { network: 'net-b' });
    await t.mutation(internal.edgeNetworks.learnLocations, {});
    row = (await t.run((ctx) => ctx.db.get(loc._id as Id<'edgeLocations'>)))!;
    expect(row.networkSource).toBe('operator');
    expect(row.networkId).toBe((await network(t, 'net-b'))._id);
  });
});
