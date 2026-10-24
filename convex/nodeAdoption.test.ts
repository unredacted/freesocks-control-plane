/// <reference types="vite/client" />
/**
 * Adopting nodes laid out the way the node role (contract v1) left them, on
 * the fake backend: a direct node whose Host is remarked `<node>-reality` and
 * dials a public name while the backend row holds a private management
 * address, and a front node whose edge an earlier tool made. Adoption finds
 * the Hosts members dial; the test link, the review, a failed re-approval, a
 * rename and a retirement work from them; the role's routes never act for an
 * adopted machine. Fixtures use RFC 5737 addresses and `*.example` /
 * `*.example.net` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { installFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { gateOfNode } from './lib/edges/testing/reads';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
/** Work a test scheduled finishes against ITS fake backend, never the next test's. */
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

const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;
const TAG = 'PRIVACY_REALITY';

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 600; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

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

/** A backend set up for a direct and a WebSocket mode, with nothing enrolled yet. */
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
  const setup = await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim,
  );
  expect(setup!.state).toBe('ready');
  // What the profile observation derives is the real public key: align the fake's bodies.
  const priv = panel.profiles[0].config.inbounds[0].streamSettings.realitySettings.privateKey;
  const { realityPublicKey } = await import('./lib/backend/digest');
  panel.profiles[0].publicKeyByTag[TAG] = realityPublicKey(priv);
  const [reality, ws] = panel.profiles[0].inbounds as { uuid: string; tag: string }[];
  return { t, serverId, panel, reality: reality!, ws: ws! };
}
type Seeded = Awaited<ReturnType<typeof seed>>;

/**
 * A direct node as prod has them: the row holds a private management address,
 * and members dial the Host's public name under the role's `<node>-reality`.
 */
async function legacyDirect(
  s: Seeded,
  opts: { name?: string; uuid?: number; remark?: string; hostUuid?: number } = {},
) {
  const name = opts.name ?? 'legacy-a';
  const nodeUuid = UUID(opts.uuid ?? 200);
  const hostUuid = UUID(opts.hostUuid ?? 201);
  s.panel.nodes.push({
    uuid: nodeUuid,
    name,
    address: '192.0.2.50',
    port: 2222,
    countryCode: 'XX',
    isDisabled: false,
    lastStatusChange: 't0',
    configProfile: {
      activeConfigProfileUuid: s.panel.profiles[0].uuid,
      activeInbounds: [s.reality],
    },
  });
  s.panel.hosts.push({
    uuid: hostUuid,
    remark: opts.remark ?? `${name}-reality`,
    address: `${name}.example.net`,
    port: 443,
    sni: 'decoy-a.example',
    inbound: {
      configProfileUuid: s.panel.profiles[0].uuid,
      configProfileInboundUuid: s.reality.uuid,
    },
    isDisabled: false,
  });
  await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
  return { nodeUuid, hostUuid };
}

const intentOf = (t: T, id: Id<'panelNodeIntents'>) => t.run((ctx) => ctx.db.get(id));
const idle = async (t: T, id: Id<'panelNodeIntents'>) =>
  (await until(
    () => intentOf(t, id),
    (r) => !!r && !r.claim,
  ))!;

/** Close an adopted node for maintenance, finish it, and wait for its reconcile. */
async function throughMaintenance(t: T, intentId: Id<'panelNodeIntents'>) {
  await t.mutation(internal.nodeIntents.startMaintenance, { intentId });
  await t.mutation(internal.nodeIntents.finishMaintenance, { intentId });
  return idle(t, intentId);
}

describe('adopting a direct node the node role set up', () => {
  test("finds the Host members dial under the role's remark, at a name other than the row's address", async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const r = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    expect(r.addresses).toBe(1);
    const adopted = (await intentOf(s.t, r.intentId))!;
    expect(adopted).toMatchObject({
      addressUuids: [hostUuid],
      approved: { committed: { hostUuids: [hostUuid] } },
      delivery: { disposition: 'live', exposure: { hosts: [hostUuid] } },
    });
    // The private management address is never taken for where members go.
    expect(adopted.observed.management.address).toBe('192.0.2.50');
    expect(adopted.observed.publicIps.v4).toBeUndefined();
  });

  test('a node with no address FCP can tell is its own is refused, unless the admin names its addresses', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s, { remark: 'Region | VLESS' });
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid,
        mode: 'privacy-reality',
      }),
    ).rejects.toThrow(/servers\.adopt_addresses_missing/);
    // A Host on another transport, or one that is not on the backend, is not this node's.
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid,
        mode: 'privacy-reality',
        hostUuids: [UUID(999)],
      }),
    ).rejects.toThrow(/servers\.adopt_address_unknown/);
    const r = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
      hostUuids: [hostUuid],
    });
    expect(r.addresses).toBe(1);
    expect((await intentOf(s.t, r.intentId))!.addressUuids).toEqual([hostUuid]);
  });

  test("another node's recorded address cannot be named", async () => {
    const s = await seed();
    const a = await legacyDirect(s);
    const b = await legacyDirect(s, { name: 'legacy-b', uuid: 300, hostUuid: 301 });
    await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid: a.nodeUuid,
      mode: 'privacy-reality',
    });
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid: b.nodeUuid,
        mode: 'privacy-reality',
        hostUuids: [a.hostUuid],
      }),
    ).rejects.toThrow(/servers\.adopt_address_unknown/);
  });

  test('the test link and the review use the Host members dial, never the management address', async () => {
    const s = await seed();
    const { nodeUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    expect(built.binding.endpoint).toBe('legacy-a.example.net:443');
    expect(built.link).toContain('@legacy-a.example.net:443?');
    expect(built.link).not.toContain('192.0.2.50');
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    expect(review.shape.addressTuples).toEqual([
      { address: 'legacy-a.example.net', port: 443, sni: 'decoy-a.example' },
    ]);
    // The tick binds to what was tested.
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    const confirmed = await s.t.mutation(internal.nodeActivation.confirmDirect, {
      intentId,
      binding,
    });
    expect(confirmed.stage).toBe('live');
  });

  // A rename moves only FCP's remark forms: the role's would keep naming the
  // old name (and node pinning reads them), so the rename is refused rather
  // than leaving them behind.
  test('is not renamed while its role-remarked Host would keep the old name', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await expect(
      s.t.mutation(internal.backendNodeRenames.request, {
        backendServerId: s.serverId,
        nodeUuid,
        name: 'legacy-b',
      }),
    ).rejects.toThrow(/servers\.node_rename_foreign_hosts/);
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.remark).toBe('legacy-a-reality');
    expect(s.panel.nodes.find((n) => n.uuid === nodeUuid)!.name).toBe('legacy-a');
    expect((await intentOf(s.t, intentId))!.name).toBe('legacy-a');
  });

  test("a front node's role-remarked Hosts refuse the rename too, though none is recorded", async () => {
    const s = await seed();
    s.panel.nodes.push({
      uuid: UUID(400),
      name: 'legacy-f',
      address: '192.0.2.60',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: {
        activeConfigProfileUuid: s.panel.profiles[0].uuid,
        activeInbounds: [s.ws],
      },
    });
    s.panel.hosts.push({
      uuid: UUID(401),
      remark: 'legacy-f-ws-6a536a',
      address: 'cdn-a.example.net',
      port: 443,
      sni: 'front-a.example.net',
      inbound: {
        configProfileUuid: s.panel.profiles[0].uuid,
        configProfileInboundUuid: s.ws.uuid,
      },
      isDisabled: false,
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid: UUID(400),
      mode: 'freedom-ws',
      externallyFronted: true,
    });
    await expect(
      s.t.mutation(internal.backendNodeRenames.request, {
        backendServerId: s.serverId,
        nodeUuid: UUID(400),
        name: 'legacy-g',
      }),
    ).rejects.toThrow(/servers\.node_rename_foreign_hosts/);
  });

  test("its retirement takes the operator's Host out with it", async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    const retirementId = await s.t.run((ctx) =>
      ctx.db.insert('panelRetirements', {
        backendServerId: s.serverId,
        intentId,
        stage: 'draining',
        disposition: 'keep-dark',
        requestedBy: 'admin',
        events: [],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    const c = (await s.t.query(internal.nodeRetirement.context, { retirementId }))!;
    expect(c.addresses.map((h) => h.hostUuid)).toEqual([hostUuid]);
  });
});

describe('re-approving an adopted direct node', () => {
  test('a failed rehearsal leaves the Host it found enabled: the run turned nothing on, so it turns nothing off', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    const parked = await throughMaintenance(s.t, intentId);
    expect(parked.activation.stage).toBe('awaiting_approval');
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    // The backend's bodies will not carry the node (another key).
    s.panel.profiles[0].publicKeyByTag[TAG] = 'not-the-key';
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    expect(review.blockers).toEqual([]);
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    const run = await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    expect(run!).toMatchObject({ state: 'blocked', code: 'servers.rehearsal_failed' });
    expect(run!.enabledHostUuids ?? []).toEqual([]);
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(false);
    expect(
      s.panel.writes.filter((w) => w.call === 'PATCH /api/hosts' && w.body.uuid === hostUuid),
    ).toEqual([]);
  });

  test('a run that turned an address on turns it off again, and a newer approval takes that over', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await throughMaintenance(s.t, intentId);
    // The operator turned the Host off meanwhile: the run turns it on as a candidate.
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = true;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    s.panel.profiles[0].publicKeyByTag[TAG] = 'not-the-key';
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    const run = await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    expect(run!.state).toBe('blocked');
    expect(run!.enabledHostUuids).toEqual([hostUuid]);
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(true);
  });
});

describe('an adopted node whose edge FCP does not run', () => {
  test('comes back live after maintenance: the approval commits, nothing is left waiting', async () => {
    const s = await seed();
    s.panel.nodes.push({
      uuid: UUID(400),
      name: 'legacy-f',
      address: '192.0.2.60',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: {
        activeConfigProfileUuid: s.panel.profiles[0].uuid,
        activeInbounds: [s.ws],
      },
    });
    s.panel.hosts.push({
      uuid: UUID(401),
      remark: 'legacy-f-ws-6a536a',
      address: 'cdn-a.example.net',
      port: 443,
      sni: 'front-a.example.net',
      host: 'front-a.example.net',
      securityLayer: 'TLS',
      inbound: {
        configProfileUuid: s.panel.profiles[0].uuid,
        configProfileInboundUuid: s.ws.uuid,
      },
      isDisabled: false,
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid: UUID(400),
      mode: 'freedom-ws',
      externallyFronted: true,
    });
    const parked = await throughMaintenance(s.t, intentId);
    expect(parked.delivery.disposition).toBe('staged');
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    expect(review.blockers).toEqual([]);
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    expect((await s.t.run((ctx) => ctx.db.get(runId)))!.state).toBe('committed');
    const live = (await intentOf(s.t, intentId))!;
    expect(live).toMatchObject({
      activation: { stage: 'live' },
      delivery: { disposition: 'live' },
    });
    expect(live.activation.currentRunId).toBeUndefined();
    expect(
      (await gateOfNode(s.t, { backendServerId: s.serverId, nodeName: 'legacy-f' })).state,
    ).toBe('open');
  });
});

describe("the node role's routes never act for an adopted machine", () => {
  test('bootstrap (the node secret) and the applied report are refused', async () => {
    const s = await seed();
    const { nodeUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await expect(s.t.action(internal.nodeIntents.bootstrap, { intentId })).rejects.toThrow(
      /servers\.node_adopted/,
    );
    await expect(
      s.t.mutation(internal.nodeIntents.applied, {
        intentId,
        appliedRevision: 1,
        nodeStarted: true,
        firewallPorts: [443],
      }),
    ).rejects.toThrow(/servers\.node_adopted/);
    // Nothing reached the backend for the secret.
    expect(s.panel.writes.filter((w) => w.call.includes('keygen'))).toEqual([]);
  });
});

describe('an enrolled node', () => {
  async function enrolled(s: Seeded) {
    const { intentId } = await s.t.mutation(internal.nodeIntents.enroll, {
      backendServerId: s.serverId,
      name: 'node-a',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4: '203.0.113.10' },
        capabilities: { caddy: false, ipv6: false },
      },
    });
    await idle(s.t, intentId);
    await s.t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    const ready = await idle(s.t, intentId);
    expect(ready.activation.stage).toBe('machine_ready');
    return intentId;
  }

  test('a country-only settings change reaches the backend row', async () => {
    const s = await seed();
    const intentId = await enrolled(s);
    const row = () => s.panel.nodes.find((n) => n.name === 'node-a')!;
    expect(row().countryCode).toBe('XX');
    const out = await s.t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { countryCode: 'de' },
    });
    expect(out.change).toBe('none');
    await until(
      async () => row().countryCode,
      (c) => c === 'DE',
    );
    expect((await idle(s.t, intentId)).settings.countryCode).toBe('DE');
  });

  test('its test link is built while the backend is out of the issuance pool', async () => {
    const s = await seed();
    const intentId = await enrolled(s);
    await s.t.run((ctx) => ctx.db.patch(s.serverId, { isActive: false }));
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    expect(built.binding.endpoint).toBe('203.0.113.10:443');
    // Member issuance still skips it.
    await expect(
      s.t.action(internal.backends.issueUser, {
        backend: 'remnawave',
        pinServerId: s.serverId,
        spec: {
          username: 'member_a',
          trafficLimitBytes: 0,
          expireAt: null,
          tag: 'MEMBER',
          description: 'member',
        },
      }),
    ).rejects.toThrow(/backend\.unavailable/);
  });
});

/**
 * Removing a backend server: refused while a node FCP manages on it is not
 * retired, or its setup is running; once it goes, every server-management row
 * and the server-name binding go with it (a family rollout reads the binding).
 * The rows an earlier release left behind for a backend already removed are
 * cleared by a one-off that reports before it deletes.
 */
describe('removing a backend server', () => {
  const tables = [
    'panelSetups',
    'panelObserveState',
    'panelNodeIntents',
    'panelOwnership',
    'panelRetirements',
    'panelNodeAliases',
    'panelNodeRenames',
    'panelNodes',
    'panelHosts',
    'panelProfiles',
    'panelSquads',
    'panelOps',
    'sniInboundBindings',
    'sniInboundNameHistory',
  ] as const;
  const counts = (t: T) =>
    t.run(async (ctx) => {
      const out: Record<string, number> = {};
      for (const name of tables) out[name] = (await ctx.db.query(name).collect()).length;
      return out;
    });

  async function adoptedAndRetired(s: Seeded) {
    const { nodeUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    return intentId;
  }

  const retire = (s: Seeded, intentId: Id<'panelNodeIntents'>) =>
    s.t.run(async (ctx) => {
      const id = await ctx.db.insert('panelRetirements', {
        backendServerId: s.serverId,
        intentId,
        stage: 'retired',
        disposition: 'keep-dark',
        requestedBy: 'admin',
        events: [],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.patch(intentId, { state: 'retired', retirementId: id });
      // A rename it went through earlier, and the alias that left.
      const renameId = await ctx.db.insert('panelNodeRenames', {
        backendServerId: s.serverId,
        nodeUuid: UUID(200),
        from: 'legacy-old',
        to: 'legacy-a',
        intentId,
        relayIds: [],
        state: 'done',
        step: 'done',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('panelNodeAliases', {
        backendServerId: s.serverId,
        formerName: 'legacy-old',
        name: 'legacy-a',
        nodeUuid: UUID(200),
        renameId,
        at: Date.now(),
      });
    });

  test('refused while a node FCP manages on it is not retired', async () => {
    const s = await seed();
    await adoptedAndRetired(s);
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId }),
    ).rejects.toThrow(/server\.has_nodes/);
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServerBySlug, { slug: 'panel-a' }),
    ).rejects.toThrow(/server\.has_nodes/);
    expect(await s.t.run((ctx) => ctx.db.get(s.serverId))).not.toBeNull();
  });

  test('once its nodes are retired, it goes with every server-management row', async () => {
    const s = await seed();
    const intentId = await adoptedAndRetired(s);
    await retire(s, intentId);
    const before = await counts(s.t);
    expect(before.panelSetups).toBe(1);
    expect(before.sniInboundBindings).toBe(1);
    await s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId });
    const after = await until(
      () => counts(s.t),
      (c) => Object.values(c).every((n) => n === 0),
    );
    expect(after).toEqual(Object.fromEntries(tables.map((name) => [name, 0])));
  });

  test('rows left for a backend removed before are listed, reported, then cleared', async () => {
    const s = await seed();
    const intentId = await adoptedAndRetired(s);
    await retire(s, intentId);
    // As an earlier release removed a backend: the row alone.
    await s.t.run((ctx) => ctx.db.delete(s.serverId));
    const orphans = await s.t.query(internal.serverAdmin.removedBackends, {});
    expect(orphans).toEqual([s.serverId]);
    const before = await counts(s.t);
    const dry = await s.t.mutation(internal.serverAdmin.purgeRemovedBackend, {
      backendServerId: s.serverId,
    });
    expect(dry.dryRun).toBe(true);
    expect(dry.rows).toMatchObject({ panelSetups: 1, panelNodeIntents: 1, sniInboundBindings: 1 });
    expect(await counts(s.t)).toEqual(before);
    await s.t.mutation(internal.serverAdmin.purgeRemovedBackend, {
      backendServerId: s.serverId,
      dryRun: false,
    });
    await until(
      () => counts(s.t),
      (c) => Object.values(c).every((n) => n === 0),
    );
    expect(await s.t.query(internal.serverAdmin.removedBackends, {})).toEqual([]);
  });

  test('a backend that is still there is never cleared', async () => {
    const s = await seed();
    await expect(
      s.t.mutation(internal.serverAdmin.purgeRemovedBackend, {
        backendServerId: s.serverId,
        dryRun: false,
      }),
    ).rejects.toThrow(/server\.still_there/);
  });
});
