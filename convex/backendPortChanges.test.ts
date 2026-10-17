/// <reference types="vite/client" />
/**
 * A port change waits for the nodes' firewalls (docs/servers.md "Firewall
 * acknowledgement"), and a new transport is added from a template:
 *
 *  - staging sends nothing and claims nothing; the role reads the pending port;
 *  - the role's applied report confirms ONLY the ports it lists; the last
 *    confirmation sends the edit through the ledger, under the maintenance
 *    transition, and the enrolled node's own address follows the port;
 *  - a node FCP does not run the role for is confirmed by an admin, never the
 *    other way round;
 *  - what cannot move is refused before anything is staged;
 *  - a busy profile leaves the change waiting and the sweep sends it later; a
 *    node that started serving the transport meanwhile gets its own requirement;
 *  - a new REALITY transport's key is made in the attempt, and appears in no
 *    row, response or audit entry.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { installFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { claimKey } from './lib/backend/ops';
import { jsonRes, routeFetch, type Captured } from './lib/edges/testing/mockFetch';
import { signValue } from './lib/cookies';
import { PortChangeView, ProfilePatchPreview } from '../src/shared/contracts/servers';
import { gateOfNode } from './lib/edges/testing/reads';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;
const TAG = 'PRIVACY_REALITY';
const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
/**
 * The test's backend work still running (a reconcile the report scheduled)
 * must finish against THIS test's fake backend, never the next test's.
 */
let current: T | null = null;
afterEach(async () => {
  if (current) {
    const t = current;
    current = null;
    await until(
      () => t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
  }
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const setupInput = {
  profileName: 'FreeSocks-Config',
  modes: [
    {
      slug: 'privacy-reality',
      name: 'Privacy-Reality',
      shape: { transport: 'reality' as const, fronting: 'direct' as const },
      familySlug: 'fam-direct',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-ws',
      name: 'Freedom-WebSocket',
      shape: { transport: 'ws' as const, fronting: 'edge-l7' as const },
      acceptProxyProtocol: false,
      ws: { path: '/ws', port: 8443 },
    },
  ],
  originDns: null,
  adopt: false,
};

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 600; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

/** A set-up backend with one enrolled direct node (`node-a`) at machine_ready, and an admin. */
async function seed() {
  const t = convexTest(schema, modules);
  current = t;
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend();
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  await t.mutation(internal.sniFamilies.create, {
    slug: 'fam-direct',
    label: 'fam-direct',
    targetAddress: 'decoy-a.example',
    targetPort: 443,
  });
  await t.mutation(internal.sniFamilies.importNames, {
    slug: 'fam-direct',
    lines: ['decoy-a.example'],
  });
  for (const n of (await t.query(internal.sniFamilies.dueForQualification, {})).names)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input: setupInput,
  });
  await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim,
  );
  const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
    backendServerId: serverId,
    name: 'node-a',
    mode: 'privacy-reality',
    contractVersion: 2,
    observed: {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    },
  });
  const idle = () =>
    until(
      () => t.run((ctx) => ctx.db.get(intentId)),
      (r) => !!r && !r.claim,
    );
  await idle();
  await t.mutation(internal.nodeIntents.applied, {
    intentId,
    appliedRevision: 1,
    nodeStarted: true,
  });
  await idle();

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
  const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const profileUuid = panel.profiles[0].uuid as string;
  const transportUuid = (panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
    (i) => i.tag === TAG,
  )!.uuid;
  return { t, serverId, panel, intentId, call, profileUuid, transportUuid, idle };
}

type Seeded = Awaited<ReturnType<typeof seed>>;

async function previewPort(s: Seeded, port: number) {
  const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
    ops: [{ op: 'setInboundPort', transportTag: TAG, port }],
  });
  expect(res.status).toBe(200);
  return ProfilePatchPreview.parse(await res.json());
}

async function stagePort(s: Seeded, port: number, unmanaged?: 'hold' | 'acknowledge') {
  const p = await previewPort(s, port);
  const res = await s.call('POST', `profiles/${s.profileUuid}/port-change`, {
    ops: p.ops,
    baseToken: p.baseToken,
    expectedToken: p.expectedToken,
    transportUuids: p.transportUuids,
    ...(unmanaged ? { unmanaged } : {}),
  });
  return res;
}

const portOf = (panel: FakeBackend) =>
  (panel.profiles[0].config.inbounds as { tag: string; port: number }[]).find((i) => i.tag === TAG)!
    .port;
const profileWrites = (panel: FakeBackend) =>
  panel.writes.filter((w) => w.call === 'PATCH /api/config-profiles');
const roleView = async (s: Seeded) =>
  (await s.call('GET', 'nodes/by-name/node-a')).json() as Promise<{
    firewall: { ports: { port: number; reason: string }[] };
  }>;
const changeOf = (s: Seeded, id: string) =>
  s.t.query(internal.backendPortChanges.view, { changeId: id as Id<'panelPortChanges'> });

/** A node the role does not run, serving the same transport. */
async function addStranger(s: Seeded, name = 'stranger') {
  s.panel.nodes.push({
    uuid: UUID(900 + s.panel.nodes.length),
    name,
    address: '203.0.113.30',
    port: 2222,
    countryCode: 'XX',
    isDisabled: false,
    lastStatusChange: 't0',
    configProfile: {
      activeConfigProfileUuid: s.profileUuid,
      activeInbounds: [{ uuid: s.transportUuid, tag: TAG }],
    },
  });
  await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
}

describe('a port change waits for the firewalls', () => {
  test('staged, confirmed by the role, then sent under the maintenance transition', async () => {
    const s = await seed();
    const preview = await previewPort(s, 8443);
    expect(preview.changes).toEqual([
      { transportTag: TAG, field: 'port', before: 443, after: 8443 },
    ]);
    expect(preview.firewall).toEqual({
      port: 8443,
      nodes: [{ name: 'node-a', confirmedBy: 'role', enrolled: true }],
    });
    // The enrolled node's own address follows the port; nothing else is on the transport.
    expect(preview.otherAddresses).toEqual([]);

    // The plain apply route never sends a port change.
    const direct = await s.call('POST', `profiles/${s.profileUuid}/apply`, {
      ops: preview.ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      transportUuids: preview.transportUuids,
    });
    expect(direct.status).toBe(409);
    expect((await direct.json()).error.code).toBe('servers.port_change_staged');

    const staged = await stagePort(s, 8443);
    expect(staged.status).toBe(200);
    const change = PortChangeView.parse(await staged.json());
    expect(change).toMatchObject({
      state: 'waiting',
      fromPort: 443,
      toPort: 8443,
      transportTag: TAG,
      nodes: [{ name: 'node-a', confirmedBy: 'role', state: 'waiting' }],
    });
    // Nothing was sent and nothing was claimed: members keep the old port.
    expect(profileWrites(s.panel)).toHaveLength(0);
    expect(await s.t.run((ctx) => ctx.db.query('panelClaims').collect())).toHaveLength(0);
    // The role reads what it must open.
    expect((await roleView(s)).firewall.ports).toEqual([
      { port: 443, protocol: 'tcp', reason: 'serving' },
      { port: 8443, protocol: 'tcp', reason: 'pending' },
    ]);

    // A report without the new port confirms nothing.
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443],
    });
    expect((await changeOf(s, change.id)).state).toBe('waiting');
    expect(profileWrites(s.panel)).toHaveLength(0);

    // Over HTTP, as the role sends it: the port is open now.
    const report = await s.call('POST', 'nodes/by-name/node-a/applied', {
      appliedRevision: 1,
      nodeStarted: true,
      firewall: {
        ports: [
          { port: 443, protocol: 'tcp' },
          { port: 8443, protocol: 'tcp' },
        ],
      },
    });
    expect(report.status).toBe(200);
    const applied = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(applied.state).toBe('applied');
    expect(applied.nodes[0]!.state).toBe('confirmed');
    expect(portOf(s.panel)).toBe(8443);
    expect(profileWrites(s.panel)).toHaveLength(1);
    // The transport keeps its uuid (the backend keys it on tag and protocol).
    expect(
      (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find((i) => i.tag === TAG)!
        .uuid,
    ).toBe(s.transportUuid);

    // The node closed for maintenance before the write, and its own address follows.
    const intent = await s.idle();
    expect(intent!.maintenance?.reason).toBe('profile');
    await until(
      async () => s.panel.hosts.filter((h) => h.remark.startsWith('node-a')),
      (hs) => hs.length > 0 && hs.every((h) => h.port === 8443),
    );
    const setup = await s.t.run((ctx) =>
      ctx.db
        .query('panelSetups')
        .withIndex('by_server', (q) => q.eq('backendServerId', s.serverId))
        .unique(),
    );
    expect(setup!.modes!.find((m) => m.slug === 'privacy-reality')!.transport!.port).toBe(8443);
    // The old port is no longer one the role must keep open.
    expect((await roleView(s)).firewall.ports).toEqual([
      { port: 8443, protocol: 'tcp', reason: 'serving' },
    ]);
    // FCP's own edit is not a foreign one.
    const profile = await s.t.run((ctx) =>
      ctx.db
        .query('panelProfiles')
        .withIndex('by_server', (q) => q.eq('backendServerId', s.serverId))
        .first(),
    );
    expect(profile!.foreignEditAt).toBeUndefined();
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining([
        'servers.port_change.staged',
        'servers.port_change.confirmed',
        'servers.port_change.admitted',
        'servers.profile.patch',
      ]),
    );
  });

  test('a node no role runs is confirmed by an admin; a role node never is', async () => {
    const s = await seed();
    await addStranger(s);
    // Nodes FCP does not manage need a treatment, as with every shared change.
    const bare = await stagePort(s, 8443);
    expect(bare.status).toBe(409);
    expect((await bare.json()).error.code).toBe('servers.unmanaged_nodes_affected');

    const change = PortChangeView.parse(await (await stagePort(s, 8443, 'hold')).json());
    expect(change.nodes.map((n) => [n.name, n.confirmedBy])).toEqual([
      ['node-a', 'role'],
      ['stranger', 'operator'],
    ]);
    const ack = (nodeNames: string[]) =>
      s.call('POST', `port-changes/${change.id}/acknowledge`, { nodeNames });
    const wrong = await ack(['node-a']);
    expect(wrong.status).toBe(409);
    expect((await wrong.json()).error.code).toBe('servers.firewall_role_confirms');
    expect((await ack(['stranger'])).status).toBe(200);
    // Still waiting on the role.
    expect((await changeOf(s, change.id)).state).toBe('waiting');
    expect(profileWrites(s.panel)).toHaveLength(0);
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(done.state).toBe('applied');
    // Held closed by name until released.
    const gate = await gateOfNode(s.t, {
      backendServerId: s.serverId,
      nodeName: 'stranger',
    });
    expect(gate.state).toBe('blocked');
    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    const confirmed = audit.filter((a) => a.action === 'servers.port_change.confirmed');
    expect(confirmed.map((a) => (a.payload as { by: string }).by).sort()).toEqual([
      'operator',
      'role',
    ]);
  });

  test('cancelled before anything was sent', async () => {
    const s = await seed();
    const change = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    const res = await s.call('POST', `port-changes/${change.id}/cancel`);
    expect(res.status).toBe(200);
    expect(PortChangeView.parse(await res.json()).state).toBe('cancelled');
    // A late report confirms nothing and sends nothing.
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    expect(profileWrites(s.panel)).toHaveLength(0);
    expect((await roleView(s)).firewall.ports.map((p) => p.port)).toEqual([443]);
    // A new change of the same profile may be staged now.
    expect((await stagePort(s, 9443)).status).toBe(200);
  });
});

describe('what is refused before anything is staged', () => {
  const codeOf = async (res: Response) => ({
    status: res.status,
    code: ((await res.json()) as { error: { code: string } }).error.code,
  });

  test('a loopback transport, the node API port, and a second change', async () => {
    const s = await seed();
    const ws = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [{ op: 'setInboundPort', transportTag: 'FREEDOM_WEBSOCKET', port: 9000 }],
    });
    expect(await codeOf(ws)).toEqual({ status: 409, code: 'servers.port_loopback' });
    // node-a's API port.
    const api = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [{ op: 'setInboundPort', transportTag: TAG, port: 2222 }],
    });
    expect(await codeOf(api)).toEqual({ status: 409, code: 'servers.port_taken' });
    expect((await stagePort(s, 8443)).status).toBe(200);
    expect(await codeOf(await stagePort(s, 9443))).toEqual({
      status: 409,
      code: 'servers.port_change_waiting',
    });
  });

  test('a transport an origin forwards to', async () => {
    const s = await seed();
    await registerRelay(s.t, {
      slug: 'node-a',
      nodeName: 'node-a',
      originAddress: '203.0.113.10',
      listeners: [
        realityListener({
          panelBinding: {
            inboundTag: TAG,
            configProfileUuid: s.profileUuid,
            configProfileInboundUuid: s.transportUuid,
          },
        }),
      ],
    });
    const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [{ op: 'setInboundPort', transportTag: TAG, port: 8443 }],
    });
    expect(await codeOf(res)).toEqual({ status: 409, code: 'servers.port_edge_bound' });
  });
});

describe('a change that cannot go out yet keeps waiting', () => {
  test('a busy profile: the sweep sends it once the other change has settled', async () => {
    const s = await seed();
    const change = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    // Another write holds the profile's claim when the last confirmation lands.
    const blocker = await s.t.run(async (ctx) => {
      const now = Date.now();
      const opId = await ctx.db.insert('panelOps', {
        backendServerId: s.serverId,
        kind: 'profile',
        verb: 'patch',
        generation: 1,
        claimKeys: [claimKey.profile(s.profileUuid)],
        label: 'FreeSocks-Config',
        objectUuid: s.profileUuid,
        intent: '{}',
        postcondition: '{}',
        request: 'acknowledged',
        panelState: 'unobserved',
        asyncEffect: 'none',
        open: true,
        quietLooks: 0,
        createdAt: now,
        updatedAt: now,
      });
      const claimId = await ctx.db.insert('panelClaims', {
        backendServerId: s.serverId,
        key: claimKey.profile(s.profileUuid),
        opId,
        generation: 1,
        claimedAt: now,
      });
      return { opId, claimId };
    });
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const held = await until(
      () => changeOf(s, change.id),
      (c) => c.code === 'servers.op_running',
    );
    expect(held.state).toBe('waiting');
    expect(profileWrites(s.panel)).toHaveLength(0);
    // Not admitted, so nothing of the transition was committed: the node is not
    // closed and no hold was written for a change that was not sent.
    const meanwhile = await s.t.run(async (ctx) => ({
      intent: await ctx.db.get(s.intentId),
      holds: await ctx.db.query('panelMaintenanceHolds').collect(),
    }));
    expect(meanwhile.intent!.maintenance).toBeUndefined();
    expect(meanwhile.holds).toEqual([]);
    // The confirmed port stays listed for the role until the change is over:
    // a role run now must not close it again.
    expect((await roleView(s)).firewall.ports).toEqual([
      { port: 443, protocol: 'tcp', reason: 'serving' },
      { port: 8443, protocol: 'tcp', reason: 'pending' },
    ]);
    // The other change settles; the sweep (backend-reconcile) sends this one.
    await s.t.run(async (ctx) => {
      await ctx.db.delete(blocker.claimId);
      await ctx.db.patch(blocker.opId, { open: false });
    });
    await s.t.action(internal.backendPortChanges.sweep, {});
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(done.state).toBe('applied');
    expect(portOf(s.panel)).toBe(8443);
  });

  test('a node that started serving the transport meanwhile is waited for too', async () => {
    const s = await seed();
    const change = PortChangeView.parse(await (await stagePort(s, 8443, 'acknowledge')).json());
    await addStranger(s, 'late-node');
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const held = await until(
      () => changeOf(s, change.id),
      (c) => c.nodes.length === 2,
    );
    expect(held.state).toBe('waiting');
    expect(held.code).toBe('servers.firewall_unconfirmed');
    expect(held.nodes.find((n) => n.name === 'late-node')).toMatchObject({
      confirmedBy: 'operator',
      state: 'waiting',
    });
    expect(profileWrites(s.panel)).toHaveLength(0);
    await s.call('POST', `port-changes/${change.id}/acknowledge`, { nodeNames: ['late-node'] });
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(done.state).toBe('applied');
  });

  test('a profile edited between the preview and the send is refused with nothing sent', async () => {
    const s = await seed();
    const change = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    // Somebody edits the profile on the backend meanwhile.
    s.panel.profiles[0].config.inbounds[0].streamSettings.realitySettings.serverNames = [
      'decoy-a.example',
      'other.example',
    ];
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(done).toMatchObject({ state: 'refused', code: 'servers.profile_changed' });
    expect(profileWrites(s.panel)).toHaveLength(0);
    expect(portOf(s.panel)).toBe(443);
  });
});

describe('a transport from a template', () => {
  test('its key is made in the attempt and is nowhere in FCP; no node serves it yet', async () => {
    const s = await seed();
    const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [
        {
          op: 'addInboundFromTemplate',
          transportTag: 'FREEDOM_REALITY',
          template: { kind: 'reality', port: 443, familySlug: 'fam-direct' },
        },
      ],
    });
    expect(res.status).toBe(200);
    const p = ProfilePatchPreview.parse(await res.json());
    // The family resolved to its target and the names usable today.
    expect(p.ops).toEqual([
      {
        op: 'addInboundFromTemplate',
        transportTag: 'FREEDOM_REALITY',
        template: {
          kind: 'reality',
          port: 443,
          target: 'decoy-a.example:443',
          serverNames: ['decoy-a.example'],
          acceptProxyProtocol: false,
        },
      },
    ]);
    // The key does not exist yet, so nothing predicts the token.
    expect(p.expectedToken).toBeNull();
    expect(p.firewall).toBeNull();
    expect(profileWrites(s.panel)).toHaveLength(0);

    const applied = await s.call('POST', `profiles/${s.profileUuid}/apply`, {
      ops: p.ops,
      baseToken: p.baseToken,
      expectedToken: null,
      transportUuids: p.transportUuids,
    });
    expect(applied.status).toBe(200);
    const op = (await applied.json()) as { state: string };
    expect(['done', 'waiting_for_nodes']).toContain(op.state);
    const added = (
      s.panel.profiles[0].config.inbounds as {
        tag: string;
        streamSettings: { realitySettings: { privateKey: string } };
      }[]
    ).find((i) => i.tag === 'FREEDOM_REALITY')!;
    const key = added.streamSettings.realitySettings.privateKey;
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The key is in no row, no response and no audit entry.
    const everything = JSON.stringify(
      await s.t.run(async (ctx) => ({
        ops: await ctx.db.query('panelOps').collect(),
        profiles: await ctx.db.query('panelProfiles').collect(),
        audit: await ctx.db.query('auditLog').collect(),
      })),
    );
    expect(everything).not.toContain(key);
    expect(JSON.stringify(op)).not.toContain(key);
    // The token the attempt made is the one the look settled on: FCP's own edit.
    const profile = await s.t.run((ctx) =>
      ctx.db
        .query('panelProfiles')
        .withIndex('by_server', (q) => q.eq('backendServerId', s.serverId))
        .first(),
    );
    expect(profile!.inbounds.map((i) => i.tag)).toContain('FREEDOM_REALITY');
    expect(profile!.foreignEditAt).toBeUndefined();
    // No node serves the new transport: the node keeps exactly its own.
    const node = s.panel.nodes.find((n) => n.name === 'node-a')!;
    expect(node.configProfile.activeInbounds.map((i: { uuid: string }) => i.uuid)).toEqual([
      s.transportUuid,
    ]);
    // Nothing closed for it.
    expect((await s.idle())!.maintenance).toBeUndefined();
  });

  test('a tag another transport of the backend has is refused', async () => {
    const s = await seed();
    const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [
        {
          op: 'addInboundFromTemplate',
          transportTag: TAG,
          template: { kind: 'ws', port: 9443, path: '/feed' },
        },
      ],
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      'servers.tag_taken',
    );
  });
});

describe('review follow-ups', () => {
  const codeOf = async (res: Response) =>
    ((await res.json()) as { error: { code: string } }).error.code;

  test('a transport uuid must be the one its tag names', async () => {
    const s = await seed();
    const p = await previewPort(s, 8443);
    const wsUuid = (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
      (i) => i.tag === 'FREEDOM_WEBSOCKET',
    )!.uuid;
    const forged = { ...p.transportUuids, [TAG]: wsUuid };
    const body = {
      ops: p.ops,
      baseToken: p.baseToken,
      expectedToken: p.expectedToken,
      transportUuids: forged,
    };
    expect(await codeOf(await s.call('POST', `profiles/${s.profileUuid}/port-change`, body))).toBe(
      'servers.unknown_inbound',
    );
    // The plain apply path checks the same, for every edit.
    const names = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [{ op: 'setRealityTarget', transportTag: TAG, target: 'decoy-b.example:443' }],
    });
    const n = ProfilePatchPreview.parse(await names.json());
    const applied = await s.call('POST', `profiles/${s.profileUuid}/apply`, {
      ops: n.ops,
      baseToken: n.baseToken,
      expectedToken: n.expectedToken,
      transportUuids: { ...n.transportUuids, [TAG]: wsUuid },
    });
    expect(await codeOf(applied)).toBe('servers.unknown_inbound');
    expect(profileWrites(s.panel)).toHaveLength(0);
  });

  test('a node that stopped serving the transport is no longer waited for', async () => {
    const s = await seed();
    await addStranger(s);
    const change = PortChangeView.parse(await (await stagePort(s, 8443, 'acknowledge')).json());
    // The stranger is moved off the transport before it was ever confirmed.
    const stranger = s.panel.nodes.find((n) => n.name === 'stranger')!;
    stranger.configProfile.activeInbounds = [];
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    // The stranger's wait still stands until the change is looked at again.
    expect((await changeOf(s, change.id)).state).toBe('waiting');
    await s.t.action(internal.backendPortChanges.sweep, {});
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applied' || c.state === 'refused',
    );
    expect(done.state).toBe('applied');
    expect(done.nodes.find((x) => x.name === 'stranger')!.state).toBe('cancelled');
  });

  test('a change settled by a recovery is not reported as applied', async () => {
    const s = await seed();
    // The backend's answer is lost and the profile never shows the edit.
    s.panel.stub.route(
      routeFetch(
        (c: Captured) =>
          c.method === 'PATCH' && c.path === '/api/config-profiles'
            ? jsonRes({ message: 'bad gateway' }, 502)
            : null,
        s.panel.handle,
      ),
    );
    const change = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const applying = await until(
      () => changeOf(s, change.id),
      (c) => c.state === 'applying' && c.op?.state === 'outcome_unknown',
    );
    await s.t.action(internal.backendWrites.recoverOp, {
      opId: applying.op!.id as Id<'panelOps'>,
      credentialsRevoked: true,
      noInFlightExecutor: true,
      queueDrained: true,
    });
    expect((await changeOf(s, change.id)).state).toBe('recovered');
  });

  test('every open change is listed, however many settled ones are newer', async () => {
    const s = await seed();
    const open = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    await s.t.run(async (ctx) => {
      const now = Date.now();
      for (let i = 0; i < 25; i++)
        await ctx.db.insert('panelPortChanges', {
          backendServerId: s.serverId,
          profileUuid: `other-${i}`,
          profileName: 'Other',
          inboundTag: 'T',
          inboundUuid: 'u',
          toPort: 9000 + i,
          ops: '[]',
          baseToken: 'a',
          expectedToken: 'b',
          inboundUuids: {},
          state: 'cancelled',
          createdAt: now + i + 1,
          updatedAt: now + i + 1,
        });
    });
    const list = (await (await s.call('GET', 'port-changes')).json()) as {
      changes: { id: string }[];
    };
    expect(list.changes.map((c) => c.id)).toContain(open.id);
  });

  test('the sweep finds a ready change behind more than 50 waiting ones', async () => {
    const s = await seed();
    const ready = await s.t.run(async (ctx) => {
      const now = Date.now();
      const base = {
        backendServerId: s.serverId,
        profileName: 'P',
        inboundTag: 'T',
        inboundUuid: 'u',
        toPort: 9000,
        ops: '[]',
        baseToken: 'a',
        expectedToken: 'b',
        inboundUuids: {},
        state: 'waiting' as const,
      };
      for (let i = 0; i < 60; i++) {
        const changeId = await ctx.db.insert('panelPortChanges', {
          ...base,
          profileUuid: `w-${i}`,
          createdAt: now + i,
          updatedAt: now + i,
        });
        await ctx.db.insert('panelPortRequirements', {
          backendServerId: s.serverId,
          changeId,
          nodeName: 'n',
          port: 9000,
          confirmedBy: 'operator',
          state: 'waiting',
          createdAt: now,
          updatedAt: now,
        });
      }
      return ctx.db.insert('panelPortChanges', {
        ...base,
        profileUuid: 'ready',
        createdAt: now + 100,
        updatedAt: now + 100,
      });
    });
    expect(await s.t.query(internal.backendPortChanges.ready, {})).toContain(ready);
    // Nothing to send for these bare rows: drop them before the sweep of later tests.
    await s.t.run(async (ctx) => {
      for (const c of await ctx.db.query('panelPortChanges').collect())
        await ctx.db.patch(c._id, { state: 'cancelled' });
    });
  });

  test("the node's own listeners count as taken ports", async () => {
    const s = await seed();
    // The API port FCP is about to give the node, not yet on the backend's row.
    await s.t.run(async (ctx) => {
      const intent = (await ctx.db.get(s.intentId))!;
      await ctx.db.patch(s.intentId, { settings: { ...intent.settings, nodePort: 9443 } });
    });
    const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [{ op: 'setInboundPort', transportTag: TAG, port: 9443 }],
    });
    expect(await codeOf(res)).toBe('servers.port_taken');
  });

  test('a family that is turned off gives no transport its names', async () => {
    const s = await seed();
    await s.t.mutation(internal.sniFamilies.update, { slug: 'fam-direct', enabled: false });
    const res = await s.call('POST', `profiles/${s.profileUuid}/preview`, {
      ops: [
        {
          op: 'addInboundFromTemplate',
          transportTag: 'FREEDOM_REALITY',
          template: { kind: 'reality', port: 443, familySlug: 'fam-direct' },
        },
      ],
    });
    expect(await codeOf(res)).toBe('servers.family_missing');
  });

  test('a moved uuid fences the port bridge: nothing is re-pointed at the old one', async () => {
    const s = await seed();
    // The backend replaces the transport's uuid on the write (it should not).
    s.panel.stub.route(
      routeFetch((c: Captured) => {
        if (c.method !== 'PATCH' || c.path !== '/api/config-profiles') return null;
        const res = s.panel.handle(c);
        const ib = (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
          (i) => i.tag === TAG,
        )!;
        ib.uuid = UUID(990);
        return res;
      }, s.panel.handle),
    );
    const change = PortChangeView.parse(await (await stagePort(s, 8443)).json());
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId: s.intentId,
      appliedRevision: 1,
      nodeStarted: true,
      firewallPorts: [443, 8443],
    });
    const done = await until(
      () => changeOf(s, change.id),
      (c) => c.state !== 'waiting' && c.state !== 'applying',
    );
    expect(done.op?.errorCode).toBe('servers.inbound_uuid_changed');
    const setup = await s.t.run((ctx) =>
      ctx.db
        .query('panelSetups')
        .withIndex('by_server', (q) => q.eq('backendServerId', s.serverId))
        .unique(),
    );
    expect(setup!.modes!.find((m) => m.slug === 'privacy-reality')!.transport!.port).toBe(443);
  });

  test('a reconcile asked for while another holds the lease fences that attempt', async () => {
    const s = await seed();
    const before = (await s.t.run((ctx) => ctx.db.get(s.intentId)))!;
    await s.t.run((ctx) =>
      ctx.db.patch(s.intentId, { claim: { attemptId: 'busy', expiresAt: Date.now() + 60_000 } }),
    );
    expect(await s.t.mutation(internal.nodeIntents.reconcileNow, { intentId: s.intentId })).toBe(
      false,
    );
    const after = (await s.t.run((ctx) => ctx.db.get(s.intentId)))!;
    expect(after.generation).toBe(before.generation + 1);
    // Its handover reconciles the node again under the new generation.
    await s.t.mutation(internal.nodeIntents.releaseOvertaken, {
      intentId: s.intentId,
      generation: before.generation,
      attemptId: 'busy',
    });
    await s.idle();
    // A retry a lease later stands behind it, in case the attempt died: it is
    // cancelled here so the test does not wait ten minutes for it.
    await s.t.run(async (ctx) => {
      const later = (await ctx.db.system.query('_scheduled_functions').collect()).filter(
        (f) => f.name.includes('reconcileNow') && f.state.kind === 'pending',
      );
      expect(later).toHaveLength(1);
      for (const f of later) await ctx.scheduler.cancel(f._id);
    });
  });
});
