/// <reference types="vite/client" />
/**
 * A backend's REALITY transports and their names (docs/edges.md "A transport's
 * names"):
 *
 *  - every REALITY transport is listed with its target, its names, the nodes
 *    behind it and the addresses a test can go through, managed or not;
 *  - managing a transport's names is one call: a family with its own target,
 *    bound, its names taken in, nothing written to the backend; refused while
 *    server names are off, and never twice;
 *  - each name's step on its way to members is the same on the transports view
 *    and on the family page;
 *  - a dry run suggests a network only when the target and every address in
 *    use are on it; managing on a network without a place takes the node's.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import {
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  adoptL4Edge,
  insertPanelServer,
  realityListener,
  registerRelay,
} from './lib/edges/testing/fixtures';
import { __setManageDepsForTests } from './sniTransportOps';
import {
  SniFamilyDetail,
  SniManageDryRun,
  SniManaged,
  SniTransportsView,
} from '../src/shared/contracts/sni';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;
const TAG = 'VLESS_RELAY_A';
const NODE_UUID = '33333333-3333-4333-8333-333333333333';

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  __setManageDepsForTests(null);
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function seed(opts: { edgeIp?: string } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  await t.run((ctx) => ctx.db.patch(serverId, { locationLabel: 'Example City, ST' }));
  // What Servers last read: the transport the node's listener is bound to, names set by hand.
  await t.run(async (ctx) => {
    await ctx.db.insert('panelProfiles', {
      backendServerId: serverId,
      profileUuid: PROFILE,
      name: 'Default',
      shapeHash: 'x',
      changeToken: 'y',
      digestKeyId: 'k',
      inbounds: [
        {
          tag: TAG,
          inboundUuid: INBOUND,
          protocol: 'vless',
          port: 443,
          network: 'tcp',
          security: 'reality',
          reality: { target: 'target.example:443', serverNames: ['a.example', 'b.example'] },
        },
        {
          tag: 'WS_IN',
          inboundUuid: 'i-ws',
          protocol: 'vless',
          port: 8443,
          network: 'ws',
          security: 'tls',
        },
      ],
      observedAt: Date.now(),
    });
    await ctx.db.insert('panelNodes', {
      backendServerId: serverId,
      nodeUuid: NODE_UUID,
      name: 'node-one',
      countryCode: 'US',
      online: true,
      isDisabled: false,
      usersOnline: 0,
      configProfileUuid: PROFILE,
      activeInboundUuids: [INBOUND],
      tags: [],
      observedAt: Date.now(),
    });
  });
  // The node is protected: one listener handing out the two names, one verified address.
  const { relayId, listenerIds } = await registerRelay(t, { listeners: [realityListener()] });
  const listenerId = listenerIds.a as Id<'relayListeners'>;
  const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
    publish: true,
    ...(opts.edgeIp ? { ipv4: opts.edgeIp } : {}),
  });
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
    t.fetch(`/api/v1/admin/edges/sni/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const view = async () =>
    SniTransportsView.parse(await (await call('GET', 'transports?backend=panel-a')).json());
  return { t, serverId, relayId, listenerId, edgeId: edgeId as Id<'edges'>, call, view };
}

const manageBody = { backendSlug: 'panel-a', transportUuid: INBOUND };

/** Every name of the family qualified against its target. */
async function qualifyAll(t: T) {
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
    });
}

describe('the transports of a backend', () => {
  test('a transport whose names were set by hand: its target, names, nodes and test addresses', async () => {
    const { t, call, view, edgeId } = await seed();
    // A family with the same target that nothing uses is offered.
    await t.mutation(internal.sniFamilies.create, {
      slug: 'spare',
      label: 'Spare',
      targetAddress: 'target.example',
      targetPort: 443,
    });
    const v = await view();
    expect(v.switches).toEqual({
      names: false,
      findNames: false,
      backendChanges: false,
      backendSetUp: false,
    });
    expect(v.transports).toHaveLength(1);
    expect(v.transports[0]).toMatchObject({
      transportUuid: INBOUND,
      tag: TAG,
      port: 443,
      coverSite: 'target.example:443',
      listed: 2,
      profileNodes: [{ nodeUuid: NODE_UUID, name: 'node-one' }],
      list: null,
      send: null,
      sameCoverSite: [{ slug: 'spare', label: 'Spare', names: 0 }],
      nodes: [
        {
          nodeUuid: NODE_UUID,
          nodeName: 'node-one',
          inUse: 0,
          waitingTest: 0,
          testable: [{ edgeId }],
        },
      ],
    });
    expect((await call('GET', 'transports')).status).toBe(400);
    expect((await call('GET', 'transports?backend=nope')).status).toBe(404);
  });

  test('managing its names: one call, the names taken in, each step the same on both pages', async () => {
    const { t, call, view } = await seed();
    // Off, nothing is created.
    expect((await call('POST', 'transports/manage', manageBody)).status).toBe(409);
    expect(await t.run((ctx) => ctx.db.query('sniFamilies').collect())).toEqual([]);
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
    const res = await call('POST', 'transports/manage', manageBody);
    expect(res.status).toBe(200);
    const done = SniManaged.parse(await res.json());
    expect(done).toMatchObject({
      dryRun: false,
      family: 'vless-relay-a',
      created: true,
      imported: { added: 2 },
      placeSet: false,
      cert: null,
    });
    // Nothing was written to the backend: the names are being checked.
    let tr = (await view()).transports[0]!;
    expect(tr.list).toMatchObject({ slug: 'vless-relay-a', label: `${TAG} names` });
    expect(tr.list!.counts).toMatchObject({ checking: 2, inUse: 0 });
    // Members are still handed both while they are checked: in use on the node.
    expect(tr.nodes[0]).toMatchObject({ inUse: 2, waitingTest: 0 });
    expect(await t.run((ctx) => ctx.db.query('panelOps').collect())).toEqual([]);
    // Checked: the node already hands both out.
    await qualifyAll(t);
    tr = (await view()).transports[0]!;
    expect(tr.list!.counts).toMatchObject({ inUse: 2, toSend: 0, checking: 0 });
    expect(tr.nodes[0]).toMatchObject({ inUse: 2, waitingTest: 0 });
    // A new name: to send, then (a confirmed rollout carrying it) waiting for a test.
    await t.mutation(internal.sniFamilies.importNames, {
      slug: 'vless-relay-a',
      lines: ['c.example'],
    });
    await qualifyAll(t);
    expect((await view()).transports[0]!.list!.counts).toMatchObject({ inUse: 2, toSend: 1 });
    await t.run(async (ctx) => {
      const b = (await ctx.db.query('sniInboundBindings').first())!;
      await ctx.db.insert('sniRollouts', {
        bindingId: b._id,
        backendServerId: b.backendServerId,
        generation: 1,
        names: ['a.example', 'b.example', 'c.example'],
        added: ['c.example'],
        removed: [],
        witness: 'c.example',
        expectedToken: 'z',
        phase: 'panel_confirmed',
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
      const p = (await ctx.db.query('panelProfiles').first())!;
      await ctx.db.patch(p._id, {
        inbounds: p.inbounds.map((i) =>
          i.reality
            ? {
                ...i,
                reality: { ...i.reality, serverNames: ['a.example', 'b.example', 'c.example'] },
              }
            : i,
        ),
      });
    });
    tr = (await view()).transports[0]!;
    expect(tr.list!.counts).toMatchObject({ inUse: 2, waitingTest: 1, toSend: 0 });
    expect(tr.nodes[0]).toMatchObject({ inUse: 2, waitingTest: 1 });
    expect(tr.send).toMatchObject({ generation: 1, phase: 'panel_confirmed' });
    // The family page says the same, name by name.
    const detail = SniFamilyDetail.parse(
      await (await call('GET', 'families/vless-relay-a')).json(),
    );
    expect(Object.fromEntries(detail.names.map((n) => [n.name, n.delivery]))).toEqual({
      'a.example': { state: 'in_use', inUseOn: 1, nodes: 1 },
      'b.example': { state: 'in_use', inUseOn: 1, nodes: 1 },
      'c.example': { state: 'waiting_test', inUseOn: 0, nodes: 1 },
    });
    expect(detail.suggestions).toBe(0);
    // Never twice.
    expect((await call('POST', 'transports/manage', manageBody)).status).toBe(409);
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'edge.sni.transport.manage',
    )!;
    expect(audit.payload).toMatchObject({
      slug: 'vless-relay-a',
      backendSlug: 'panel-a',
      inboundTag: TAG,
      created: true,
      imported: 2,
    });
    expect(JSON.stringify(audit.payload)).not.toContain('.example');
  });

  test('an existing family with the same target is bound instead of a new one', async () => {
    const { t, call } = await seed();
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
    await t.mutation(internal.sniFamilies.create, {
      slug: 'spare',
      label: 'Spare',
      targetAddress: 'target.example',
      targetPort: 443,
    });
    const done = SniManaged.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, family: 'spare' })).json(),
    );
    expect(done).toMatchObject({ family: 'spare', created: false, imported: { added: 2 } });
    expect(await t.run((ctx) => ctx.db.query('sniFamilies').collect())).toHaveLength(1);
  });
});

describe('refusals and edges of the view', () => {
  test('a dry run on a transport that is not REALITY is refused by name', async () => {
    const { call } = await seed();
    const res = await call('POST', 'transports/manage', {
      backendSlug: 'panel-a',
      transportUuid: 'i-ws',
      dryRun: true,
    });
    expect(res.status).not.toBe(200);
    expect((await res.json()).error.code).toBe('servers.not_reality');
  });

  test('a family another transport uses is never taken', async () => {
    const { t, call } = await seed();
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
    await t.mutation(internal.sniFamilies.create, {
      slug: 'shared',
      label: 'Shared',
      targetAddress: 'target.example',
      targetPort: 443,
    });
    await t.run(async (ctx) => {
      const f = (await ctx.db.query('sniFamilies').first())!;
      const serverId = (await ctx.db.query('backendServers').first())!._id;
      await ctx.db.insert('sniInboundBindings', {
        backendServerId: serverId,
        profileUuid: PROFILE,
        inboundTag: 'OTHER',
        inboundUuid: 'i-other',
        familyId: f._id,
        generation: 0,
        panelConfirmedGeneration: 0,
        updatedAt: Date.now(),
      });
    });
    const res = await call('POST', 'transports/manage', { ...manageBody, family: 'shared' });
    expect(res.status).toBe(409);
    expect((await res.json()).error.code).toBe('edge.sni.family_in_use');
    expect(await t.run((ctx) => ctx.db.query('sniNames').collect())).toEqual([]);
  });

  test('a backend set up once stays set up through a later setup run', async () => {
    const { t, serverId, view } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('panelSetups', {
        backendServerId: serverId,
        desired: '{}',
        desiredHash: 'fixture',
        generation: 2,
        state: 'failed',
        readyAt: Date.now() - 60_000,
        profileName: 'FreeSocks-Config',
        modes: [],
        templates: [],
        originDns: null,
        adopted: false,
        gateVersion: 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    expect((await view()).switches.backendSetUp).toBe(true);
  });

  test('an IPv6 target is a valid host and port', async () => {
    const { t, view } = await seed();
    await t.run(async (ctx) => {
      const p = (await ctx.db.query('panelProfiles').first())!;
      await ctx.db.patch(p._id, {
        inbounds: p.inbounds.map((i) =>
          i.reality ? { ...i, reality: { ...i.reality, target: '[2001:db8::1]:443' } } : i,
        ),
      });
    });
    expect((await view()).transports[0]!.coverSite).toBe('[2001:db8::1]:443');
  });
});

describe('the network', () => {
  async function network(t: T) {
    const NET = { v4: ['192.0.2.0/24'], v6: [] as string[] };
    return t.run((ctx) =>
      ctx.db.insert('edgeNetworks', {
        slug: 'net-a',
        label: 'Net A',
        asns: [64500],
        announced: NET,
        manualPrefixes: [],
        prefixes: NET,
        updatedAt: Date.now(),
      }),
    );
  }

  test('a dry run suggests the network holding the target and every address in use', async () => {
    const { t, call } = await seed({ edgeIp: '192.0.2.7' });
    await network(t);
    __setManageDepsForTests({ lookup: async () => ['192.0.2.10'] });
    const on = SniManageDryRun.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, dryRun: true })).json(),
    );
    expect(on).toEqual({
      dryRun: true,
      coverSite: 'target.example:443',
      resolved: true,
      network: { slug: 'net-a', label: 'Net A' },
      label: `${TAG} names`,
    });
    // The target off the network: never suggested (every name would fail there).
    __setManageDepsForTests({ lookup: async () => ['203.0.113.5'] });
    const off = SniManageDryRun.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, dryRun: true })).json(),
    );
    expect(off.network).toBeNull();
    // Nothing was created by either.
    expect(await t.run((ctx) => ctx.db.query('sniFamilies').collect())).toEqual([]);
  });

  test('an address in use off the network: nothing suggested', async () => {
    const { t, call } = await seed();
    await network(t);
    __setManageDepsForTests({ lookup: async () => ['192.0.2.10'] });
    const r = SniManageDryRun.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, dryRun: true })).json(),
    );
    expect(r.network).toBeNull();
  });

  test("nodes in different countries: the place is the asking node's, or none", async () => {
    const { t, call } = await seed({ edgeIp: '192.0.2.7' });
    const networkId = await network(t);
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
    const other = '44444444-4444-4444-8444-444444444444';
    await t.run(async (ctx) => {
      const n = (await ctx.db.query('panelNodes').first())!;
      const { _id: _i, _creationTime: _c, ...row } = n;
      await ctx.db.insert('panelNodes', {
        ...row,
        nodeUuid: other,
        name: 'node-two',
        countryCode: 'DE',
      });
    });
    // Nobody named, and the nodes disagree: no place is guessed.
    const done = SniManaged.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, network: 'net-a' })).json(),
    );
    expect(done.placeSet).toBe(false);
    expect((await t.run((ctx) => ctx.db.get(networkId)))!.hunt).toBeUndefined();
    // Asked from the second node's page: its country.
    await call('DELETE', `bindings/${done.bindingId}`);
    await call('DELETE', `families/${done.family}`);
    const again = SniManaged.parse(
      await (
        await call('POST', 'transports/manage', {
          ...manageBody,
          network: 'net-a',
          nodeUuid: other,
        })
      ).json(),
    );
    expect(again.placeSet).toBe(true);
    expect((await t.run((ctx) => ctx.db.get(networkId)))!.hunt?.place).toEqual({
      country: 'DE',
      city: 'Example City',
    });
  });

  test("managed on a network without a place, the network takes the node's", async () => {
    const { t, call } = await seed({ edgeIp: '192.0.2.7' });
    const networkId = await network(t);
    await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
    const done = SniManaged.parse(
      await (await call('POST', 'transports/manage', { ...manageBody, network: 'net-a' })).json(),
    );
    expect(done.placeSet).toBe(true);
    expect((await t.run((ctx) => ctx.db.get(networkId)))!.hunt).toEqual({
      enabled: false,
      place: { country: 'US', city: 'Example City' },
      placeFrom: 'node',
    });
    // An operator saving the same place keeps where it came from; another place is theirs.
    await t.mutation(internal.edgeNetworks.setHunt, {
      slug: 'net-a',
      enabled: true,
      place: { country: 'US', city: 'Example City' },
    });
    expect((await t.run((ctx) => ctx.db.get(networkId)))!.hunt?.placeFrom).toBe('node');
    await t.mutation(internal.edgeNetworks.setHunt, {
      slug: 'net-a',
      enabled: true,
      place: { country: 'US', city: 'Other Town' },
    });
    expect((await t.run((ctx) => ctx.db.get(networkId)))!.hunt?.placeFrom).toBeUndefined();
  });
});
