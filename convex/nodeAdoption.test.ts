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
import { adoptL4Edge, insertPanelServer, registerRelay } from './lib/edges/testing/fixtures';
import { enrolledOriginOf } from './nodeIntents';
import { installFakeBackend, type FakeBackend } from './lib/edges/testing/fakeBackend';
import { jsonRes, routeFetch, type Captured } from './lib/edges/testing/mockFetch';
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
    // The private management address is never taken for where members go:
    // the name its Host dials is what edges dial once Edges protects it.
    expect(adopted.observed.management.address).toBe('192.0.2.50');
    expect(adopted.observed.publicIps.v4).toBeUndefined();
    const origin = await s.t.run((ctx) => enrolledOriginOf(ctx, s.serverId, 'legacy-a'));
    expect(origin!.originAddress).toBe('legacy-a.example.net');
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

  test('a turned-off Host is never adopted as live, found or named', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    s.panel.hosts.push({
      uuid: UUID(202),
      remark: 'legacy-a-reality-0a0b0c',
      address: 'old-a.example.net',
      port: 443,
      sni: 'decoy-a.example',
      inbound: {
        configProfileUuid: s.panel.profiles[0].uuid,
        configProfileInboundUuid: s.reality.uuid,
      },
      isDisabled: true,
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid,
        mode: 'privacy-reality',
        hostUuids: [hostUuid, UUID(202)],
      }),
    ).rejects.toThrow(/servers\.adopt_address_unknown/);
    const r = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    expect((await intentOf(s.t, r.intentId))!).toMatchObject({
      addressUuids: [hostUuid],
      approved: { committed: { hostUuids: [hostUuid] } },
    });
  });

  test('an IPv6 Host is dialed in brackets by the test link and its binding', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.address = '2001:db8::50';
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    expect(built.link).toContain('@[2001:db8::50]:443?');
    expect(built.binding.endpoint).toBe('[2001:db8::50]:443');
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
  });

  test('two Hosts with one name and two endpoints get a test link each, told apart by endpoint', async () => {
    const s = await seed();
    const { nodeUuid } = await legacyDirect(s);
    s.panel.hosts.push({
      uuid: UUID(202),
      remark: 'legacy-a-reality-0a0b0c',
      address: 'fwd-a.example.net',
      port: 8443,
      sni: 'decoy-a.example',
      inbound: {
        configProfileUuid: s.panel.profiles[0].uuid,
        configProfileInboundUuid: s.reality.uuid,
      },
      isDisabled: false,
    });
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    expect(built.links.map((l) => [l.sni, l.endpoint])).toEqual([
      ['decoy-a.example', 'legacy-a.example.net:443'],
      ['decoy-a.example', 'fwd-a.example.net:8443'],
    ]);
    expect(new Set(built.links.map((l) => l.link)).size).toBe(2);
  });

  test('a list of named addresses too long is refused whole, never cut short', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid,
        mode: 'privacy-reality',
        hostUuids: [hostUuid, ...Array.from({ length: 64 }, (_, i) => UUID(500 + i))],
      }),
    ).rejects.toThrow(/at most 64/);
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
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(true);
    // Turned off again, so the run owns it no more.
    const settled = await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !r?.enabledHostUuids,
    );
    expect(settled!.enabledHostUuids).toBeUndefined();

    // The operator turns it on again: a later failed approval never takes
    // over the earlier run's ownership, so it stays on.
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = false;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const again = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId: runId2 } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: again.reviewHash,
    });
    const run2 = await until(
      () => s.t.run((ctx) => ctx.db.get(runId2)),
      (r) => !!r && r.state !== 'running',
    );
    expect(run2!).toMatchObject({ state: 'blocked', code: 'servers.rehearsal_failed' });
    expect(run2!.enabledHostUuids).toBeUndefined();
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(false);
  });
});

describe('a run that throws after turning an address on', () => {
  test('turns it off again', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await throughMaintenance(s.t, intentId);
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = true;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    // The rehearsal's body fetch fails outright.
    s.panel.stub.route(
      routeFetch(
        (c: Captured) =>
          c.path.startsWith('/api/sub/') ? jsonRes({ message: 'down' }, 500) : null,
        s.panel.handle,
      ),
    );
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    await until(
      () => s.t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
    expect((await s.t.run((ctx) => ctx.db.get(runId)))!.state).toBe('blocked');
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(true);
    expect((await s.t.run((ctx) => ctx.db.get(runId)))!.enabledHostUuids).toBeUndefined();
  });
});

describe('an enable whose outcome is not known yet', () => {
  test('stays owned, and the next approval takes it over though the cache still shows it off', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await throughMaintenance(s.t, intentId);
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = true;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    // The backend never answers the enable clearly.
    s.panel.stub.route(
      routeFetch((c: Captured) => {
        const body = c.body as { isDisabled?: boolean } | undefined;
        return c.method === 'PATCH' && c.path === '/api/hosts' && body?.isDisabled === false
          ? jsonRes({ message: 'Bad Gateway' }, 502)
          : null;
      }, s.panel.handle),
    );
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    await until(
      () => s.t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
    expect((await s.t.run((ctx) => ctx.db.get(runId)))!.enabledHostUuids).toEqual([hostUuid]);
    const again = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId: runId2 } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: again.reviewHash,
    });
    const [older, newer] = await s.t.run(async (ctx) => [
      await ctx.db.get(runId),
      await ctx.db.get(runId2),
    ]);
    expect(newer!.enabledHostUuids).toEqual([hostUuid]);
    expect(older!.enabledHostUuids).toBeUndefined();
  });
});

describe('a commit that refuses the candidate after its rehearsal passed', () => {
  test('turns off what the run turned on', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await throughMaintenance(s.t, intentId);
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = true;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    // Something of the node's is still outstanding: only the commit checks it.
    await s.t.run((ctx) =>
      ctx.db.insert('backendObligations', {
        backendServerId: s.serverId,
        ownerKind: 'intent',
        ownerId: intentId,
        ownerGeneration: 1,
        attemptId: 'a1',
        kind: 'dns.record',
        identity: 'legacy-a.example.net',
        verb: 'create',
        ownership: 'created',
        state: 'unresolved',
        intent: '{}',
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    await until(
      () => s.t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
    const run = (await s.t.run((ctx) => ctx.db.get(runId)))!;
    expect(run).toMatchObject({ state: 'blocked', code: 'servers.obligation_unresolved' });
    expect(run.rehearsal?.ok).toBe(true);
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(true);
    expect(run.enabledHostUuids).toBeUndefined();
  });
});

describe('a rollback the backend refuses', () => {
  test('keeps the address owned, so the next approval can still turn it off', async () => {
    const s = await seed();
    const { nodeUuid, hostUuid } = await legacyDirect(s);
    const { intentId } = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    await throughMaintenance(s.t, intentId);
    s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled = true;
    await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    await s.t.mutation(internal.nodeActivation.confirmDirect, { intentId, binding });
    s.panel.profiles[0].publicKeyByTag[TAG] = 'not-the-key';
    // The backend refuses every write that turns a Host off.
    s.panel.stub.route(
      routeFetch((c: Captured) => {
        const body = c.body as { isDisabled?: boolean } | undefined;
        return c.method === 'PATCH' && c.path === '/api/hosts' && body?.isDisabled === true
          ? jsonRes({ message: 'Bad Request' }, 400)
          : null;
      }, s.panel.handle),
    );
    const review = await s.t.query(internal.nodeActivation.review, { intentId });
    const { runId } = await s.t.mutation(internal.nodeActivation.approve, {
      intentId,
      reviewHash: review.reviewHash,
    });
    await until(
      () => s.t.run((ctx) => ctx.db.get(runId)),
      (r) => !!r && r.state !== 'running',
    );
    // Let the rollback finish trying.
    await until(
      () => s.t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect()),
      (rows) => rows.every((r) => r.state.kind !== 'pending' && r.state.kind !== 'inProgress'),
    );
    expect(s.panel.hosts.find((h) => h.uuid === hostUuid)!.isDisabled).toBe(false);
    expect((await s.t.run((ctx) => ctx.db.get(runId)))!.enabledHostUuids).toEqual([hostUuid]);
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

describe('a node Edges already protect', () => {
  /** The node, and an origin Edges built for it while FCP did not manage it, with one L4 address. */
  async function protectedLegacy(s: Seeded, opts: { verified: boolean; publish: boolean }) {
    const { nodeUuid } = await legacyDirect(s);
    const { relayId, listenerId } = await registerRelay(s.t, { nodeName: 'legacy-a' });
    const { edgeId } = await adoptL4Edge(s.t, relayId, listenerId, opts);
    return { nodeUuid, edgeId };
  }
  const retestItems = async (t: T, edgeId: Id<'edges'>) =>
    (await t.query(internal.edgeOperator.attention, {})).items.filter(
      (i) => i.id === `retest_needed:${edgeId}`,
    );

  test('is refused while a tested address of its origin would need a new test', async () => {
    const s = await seed();
    const { nodeUuid, edgeId } = await protectedLegacy(s, { verified: true, publish: true });
    // Its confirmation was taken with no REALITY authentication component (the
    // node was not enrolled); enrolling it adds one, so the render gate would
    // withhold the address from members until it is tested again.
    await expect(
      s.t.mutation(internal.nodeIntents.adoptNode, {
        backendServerId: s.serverId,
        nodeUuid,
        mode: 'privacy-reality',
      }),
    ).rejects.toThrow(/servers\.adopt_edges_retest/);
    expect(await s.t.run((ctx) => ctx.db.query('panelNodeIntents').collect())).toEqual([]);
    expect(await retestItems(s.t, edgeId)).toEqual([]);
  });

  test('goes ahead when no address of its origin holds a confirmation adoption would undo', async () => {
    const s = await seed();
    const { nodeUuid } = await protectedLegacy(s, { verified: false, publish: false });
    const r = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    expect(r.addresses).toBe(1);
  });

  test('goes ahead when the only tested address is a spare members are not handed', async () => {
    const s = await seed();
    const { nodeUuid, edgeId } = await protectedLegacy(s, { verified: true, publish: false });
    const r = await s.t.mutation(internal.nodeIntents.adoptNode, {
      backendServerId: s.serverId,
      nodeUuid,
      mode: 'privacy-reality',
    });
    expect(r.addresses).toBe(1);
    // The spare needs its test again before a rotation uses it; nobody held it.
    expect((await retestItems(s.t, edgeId)).map((i) => i.code)).toEqual(['reality_key_changed']);
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
    // Cleared, the row carries the backend's own "no country" again.
    await s.t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { countryCode: null },
    });
    await until(
      async () => row().countryCode,
      (c) => c === 'XX',
    );
  });

  test('one reached at an IPv6 address is confirmed at the bracketed endpoint it was tested at', async () => {
    const s = await seed();
    const intentId = await enrolled(s);
    await s.t.run(async (ctx) => {
      const i = (await ctx.db.get(intentId))!;
      await ctx.db.patch(intentId, {
        settings: { ...i.settings, originAddressOverride: '2001:db8::10' },
      });
    });
    const built = await s.t.action(internal.nodeActivation.buildDirectTestLink, { intentId });
    expect(built.binding.endpoint).toBe('[2001:db8::10]:443');
    const { intentId: _i, issuedAt: _t, ...binding } = built.binding;
    const confirmed = await s.t.mutation(internal.nodeActivation.confirmDirect, {
      intentId,
      binding,
    });
    expect(confirmed.stage).toBe('candidates_verified');
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
    'sniRollouts',
    'sniAcceptanceReceipts',
    'edgeDeliveryBindings',
    'edgeHostHides',
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
      // What a removed origin's keep-dark left of its delivery.
      await ctx.db.insert('edgeDeliveryBindings', {
        backendServerId: s.serverId,
        nodeName: 'legacy-a',
        policy: 'edge-required',
        policyVersion: 1,
        relaySlug: 'legacy-a',
        state: 'released',
        updatedAt: Date.now(),
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

  test('refused while Edges still protect an origin on it', async () => {
    const s = await seed();
    await registerRelay(s.t, { kind: 'backend-server', slug: 'whole-a' });
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId }),
    ).rejects.toThrow(/server\.has_origins/);
    expect(await s.t.run((ctx) => ctx.db.get(s.serverId))).not.toBeNull();
  });

  test('refused while a temporary test key FCP made there is not removed yet', async () => {
    const s = await seed();
    const keyId = await s.t.run((ctx) =>
      ctx.db.insert('edgeTestCredentials', {
        backendServerId: s.serverId,
        backend: 'remnawave',
        username: 'fcp_test_a',
        purpose: 'test_link',
        expiresAt: Date.now() + 3_600_000,
        removal: 'pending',
        attempts: 0,
        updatedAt: Date.now(),
      }),
    );
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId }),
    ).rejects.toThrow(/server\.keys_pending/);
    await s.t.run((ctx) => ctx.db.patch(keyId, { removal: 'failed' }));
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId }),
    ).rejects.toThrow(/server\.keys_pending/);
    await s.t.run((ctx) => ctx.db.patch(keyId, { removal: 'done' }));
    await s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId });
    expect(await s.t.run((ctx) => ctx.db.get(s.serverId))).toBeNull();
  });

  test("refused while a removed origin's key cleanup has not run yet", async () => {
    const s = await seed();
    const jobId = await s.t.run((ctx) =>
      ctx.scheduler.runAfter(600_000, internal.relayQualification.removeByUsername, {
        backendServerId: s.serverId,
        username: 'fcp_qual_a',
      }),
    );
    await expect(
      s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId }),
    ).rejects.toThrow(/server\.keys_pending/);
    await s.t.run((ctx) => ctx.scheduler.cancel(jobId));
    await s.t.mutation(internal.adminApi.deleteBackendServer, { id: s.serverId });
    expect(await s.t.run((ctx) => ctx.db.get(s.serverId))).toBeNull();
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
    // A rollout of its binding with an acceptance receipt.
    const { relayId, listenerId } = await registerRelay(s.t, { nodeName: 'legacy-a' });
    const { edgeId } = await adoptL4Edge(s.t, relayId, listenerId);
    await s.t.run(async (ctx) => {
      const binding = (await ctx.db.query('sniInboundBindings').first())!;
      const rolloutId = await ctx.db.insert('sniRollouts', {
        bindingId: binding._id,
        backendServerId: s.serverId,
        generation: 2,
        names: ['decoy-a.example'],
        added: [],
        removed: [],
        expectedToken: 'tok',
        phase: 'panel_confirmed',
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
      // A hide a keep-dark removal left confirmed.
      await ctx.db.insert('edgeHostHides', {
        relayId,
        backendServerId: s.serverId,
        hostUuid: UUID(201),
        observed: {
          remark: 'legacy-a-reality',
          address: 'legacy-a.example.net',
          port: 443,
          sni: 'decoy-a.example',
          host: null,
          inboundUuid: null,
          isDisabled: false,
        },
        intent: 'disable',
        state: 'confirmed',
        attempt: 1,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('sniAcceptanceReceipts', {
        rolloutId,
        generation: 2,
        relayId,
        listenerId,
        edgeId,
        sni: 'decoy-a.example',
        isWitness: false,
        expectedToken: 'tok',
        endpoint: '198.51.100.7:443',
        listenerRevision: 1,
        configHash: 'h',
        evidenceKind: 'adopted',
        state: 'confirmed',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
      });
    });
    // As an earlier release removed a backend: the row alone.
    await s.t.run((ctx) => ctx.db.delete(s.serverId));
    const orphans = await s.t.action(internal.serverAdmin.removedBackends, {});
    expect(orphans).toEqual([s.serverId]);
    const before = await counts(s.t);
    const dry = await s.t.mutation(internal.serverAdmin.purgeRemovedBackend, {
      backendServerId: s.serverId,
    });
    expect(dry.dryRun).toBe(true);
    expect(dry.rows).toMatchObject({
      panelSetups: 1,
      panelNodeIntents: 1,
      sniInboundBindings: 1,
      sniRollouts: 1,
      sniAcceptanceReceipts: 1,
      edgeHostHides: 1,
    });
    expect(await counts(s.t)).toEqual(before);
    await s.t.mutation(internal.serverAdmin.purgeRemovedBackend, {
      backendServerId: s.serverId,
      dryRun: false,
    });
    await until(
      () => counts(s.t),
      (c) => Object.values(c).every((n) => n === 0),
    );
    expect(await s.t.action(internal.serverAdmin.removedBackends, {})).toEqual([]);
  });

  test('a removed backend is found however many rows come before its own', async () => {
    const s = await seed();
    // A live backend's rows fill the first pages.
    await s.t.run(async (ctx) => {
      for (let i = 0; i < 1_100; i++)
        await ctx.db.insert('panelOwnership', {
          backendServerId: s.serverId,
          kind: 'host',
          identity: `h-${i}`,
          lookup: [],
          state: 'owned',
          since: 0,
          updatedAt: 0,
        });
    });
    const removed = await insertPanelServer(s.t, { slug: 'panel-c' });
    await s.t.run(async (ctx) => {
      await ctx.db.insert('panelOwnership', {
        backendServerId: removed,
        kind: 'node',
        identity: 'legacy-z',
        lookup: ['legacy-z'],
        state: 'tombstoned',
        since: 0,
        updatedAt: 0,
      });
      await ctx.db.delete(removed);
    });
    expect(await s.t.action(internal.serverAdmin.removedBackends, {})).toEqual([removed]);
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
