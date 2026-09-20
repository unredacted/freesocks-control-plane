/// <reference types="vite/client" />
/**
 * The bootstrap contract on a fake backend: "Set up this backend" creates the
 * profile from the template (one POST, keys never stored) with one transport
 * per mode, binds each REALITY transport to its family, makes each mode's
 * group and placement; an existing backend is adopted only when the operator
 * says so, and a group an earlier setup named is renamed in place. Then a
 * direct node is enrolled by name, its row and its DISABLED addresses (one per
 * family name) are created, the bootstrap answer carries the secret, and the
 * applied report leads to machine_ready with revision-bound evidence.
 * Identical reruns perform no write. Fixtures use RFC 5737 addresses and
 * `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { addressRemark, addressesOf, ownsAddress } from './panelIntents';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

interface Panel {
  profiles: {
    uuid: string;
    name: string;
    config: any;
    inbounds: { uuid: string; tag: string }[];
  }[];
  squads: { uuid: string; name: string; inbounds: { uuid: string; tag: string }[] }[];
  hosts: any[];
  nodes: any[];
  writes: { call: string; body: any }[];
  seq: number;
}

function installPanel(): Panel {
  const panel: Panel = { profiles: [], squads: [], hosts: [], nodes: [], writes: [], seq: 10 };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body as string) : {};
      if (method === 'GET') {
        if (path === '/api/nodes')
          return json(panel.nodes.map((n) => ({ ...n, isConnected: true })));
        if (path === '/api/hosts') return json(panel.hosts);
        if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
        if (path === '/api/config-profiles') return json({ configProfiles: panel.profiles });
        if (path === '/api/keygen') return json({ pubKey: 'panel-node-secret-placeholder' });
        if (path === '/api/subscription-templates') return json([]);
        const p = panel.profiles.find((x) => path === `/api/config-profiles/${x.uuid}`);
        if (p) return json(p);
        return json({});
      }
      panel.writes.push({ call: `${method} ${path}`, body });
      if (path === '/api/config-profiles' && method === 'POST') {
        const uuid = UUID(++panel.seq);
        const inbounds = (body.config.inbounds as { tag: string }[]).map((i) => ({
          uuid: UUID(++panel.seq),
          tag: i.tag,
        }));
        panel.profiles.push({ uuid, name: body.name, config: body.config, inbounds });
        return json({ uuid }, 201);
      }
      if (path === '/api/internal-squads' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          inbounds: (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid })),
        };
        panel.squads.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/internal-squads' && method === 'PATCH') {
        const s = panel.squads.find((x) => x.uuid === body.uuid)!;
        if (typeof body.name === 'string') s.name = body.name;
        if (Array.isArray(body.inbounds))
          s.inbounds = (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid }));
        return json(s);
      }
      if (path === '/api/hosts' && method === 'POST') {
        const made = { uuid: UUID(++panel.seq), ...body, isDisabled: body.isDisabled === true };
        panel.hosts.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/nodes' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          address: body.address,
          port: body.port ?? 2222,
          countryCode: body.countryCode ?? 'XX',
          isDisabled: false,
          lastStatusChange: 't0',
          configProfile: {
            activeConfigProfileUuid: body.configProfile.activeConfigProfileUuid,
            activeInbounds: (body.configProfile.activeInbounds as string[]).map((uuid) => ({
              uuid,
              tag: uuid,
            })),
          },
        };
        panel.nodes.push(made);
        return json(made, 201);
      }
      return json({});
    }),
  );
  return panel;
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
      slug: 'freedom-reality',
      name: 'Freedom-Reality',
      shape: { transport: 'reality' as const, fronting: 'edge-l4' as const },
      familySlug: 'fam-fronted',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-xhttp',
      name: 'Freedom-XHTTP',
      shape: { transport: 'xhttp-reality' as const, fronting: 'edge-l4' as const },
      familySlug: 'fam-fronted',
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

/** Two families with qualified names, and families switched on (binding needs it). */
async function seedFamilies(t: T) {
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  for (const [slug, target, names] of [
    ['fam-direct', 'decoy-a.example', ['decoy-a.example', 'www.decoy-a.example']],
    ['fam-fronted', 'decoy-b.example', ['decoy-b.example']],
  ] as const) {
    await t.mutation(internal.sniFamilies.create, {
      slug,
      label: slug,
      targetAddress: target,
      targetPort: 443,
    });
    await t.mutation(internal.sniFamilies.importNames, { slug, lines: [...names] });
  }
  const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
  for (const n of due)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
}

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await seedFamilies(t);
  return { t, serverId, panel };
}

/** Poll until the workflow released its lease (real timers: the scheduled run starts on the next tick). */
async function settled<R extends { claim?: unknown }>(get: () => Promise<R | null>): Promise<R> {
  for (let i = 0; i < 500; i++) {
    await new Promise((r) => setTimeout(r, 5));
    const row = await get();
    if (row && !row.claim) return row;
  }
  throw new Error('workflow did not settle');
}

async function runSetup(t: T, serverId: Id<'backendServers'>, input = setupInput) {
  const started = await t.mutation(internal.panelSetup.start, {
    backendServerId: serverId,
    input,
  });
  // `start` scheduled the run; convex-test executes it on the next tick.
  return settled(() => t.run((ctx) => ctx.db.get(started.setupId)));
}

async function runIntent(t: T, intentId: Id<'panelNodeIntents'>) {
  return settled(() => t.run((ctx) => ctx.db.get(intentId)));
}

describe('setting up a fresh backend', () => {
  test('creates the profile once with a transport per mode, binds families, makes groups and placements', async () => {
    const { t, serverId, panel } = await seed();
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    expect(row.code).toBeUndefined();
    expect(row.adopted).toBe(false);
    expect(row.profileUuid).toBe(panel.profiles[0]!.uuid);
    expect(row.privacy).toBe('ok');
    expect(panel.writes.filter((w) => w.call === 'POST /api/config-profiles')).toHaveLength(1);
    const bySlug = Object.fromEntries(row.modes!.map((m) => [m.slug, m]));
    expect(bySlug['privacy-reality']).toMatchObject({
      tag: 'PRIVACY_REALITY',
      placement: 'bound',
      family: 'bound',
      transport: {
        port: 443,
        serverNames: ['decoy-a.example', 'www.decoy-a.example'],
        target: { address: 'decoy-a.example', port: 443 },
      },
    });
    expect(bySlug['freedom-xhttp']).toMatchObject({
      tag: 'FREEDOM_XHTTP',
      family: 'bound',
      transport: { path: '/', target: { address: 'decoy-b.example', port: 443 } },
    });
    expect(bySlug['freedom-ws']).toMatchObject({
      tag: 'FREEDOM_WEBSOCKET',
      family: 'none',
      transport: { port: 8443, path: '/ws' },
    });
    expect(row.modes!.every((m) => !!m.groupUuid)).toBe(true);
    expect(panel.squads.map((s) => s.name).sort()).toEqual([
      'Freedom-Reality',
      'Freedom-WebSocket',
      'Freedom-XHTTP',
      'Privacy-Reality',
    ]);
    const bindings = await t.run((ctx) => ctx.db.query('sniInboundBindings').collect());
    expect(bindings.map((b) => b.inboundTag).sort()).toEqual([
      'FREEDOM_REALITY',
      'FREEDOM_XHTTP',
      'PRIVACY_REALITY',
    ]);
    const obligations = await t.run((ctx) => ctx.db.query('panelObligations').collect());
    expect(obligations).toHaveLength(1);
    expect(obligations[0]).toMatchObject({
      kind: 'profile.create',
      state: 'confirmed',
      ownership: 'shared',
    });
    // No private key anywhere FCP keeps.
    const rows = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelSetups').collect(),
        await ctx.db.query('panelProfiles').collect(),
        await ctx.db.query('panelObligations').collect(),
        await ctx.db.query('auditLog').collect(),
      ]),
    );
    for (const ib of panel.profiles[0]!.config.inbounds) {
      const privateKey = ib.streamSettings?.realitySettings?.privateKey;
      if (!privateKey) continue;
      expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(rows).not.toContain(privateKey);
    }

    // An identical rerun performs no write.
    const before = panel.writes.length;
    const again = await t.mutation(internal.panelSetup.start, {
      backendServerId: serverId,
      input: setupInput,
    });
    expect(again.started).toBe(false);
    expect(panel.writes.length).toBe(before);
  });

  test('a mode without a usable family, or an unknown mode, is refused before anything is written', async () => {
    const { t, serverId, panel } = await seed();
    await expect(
      t.mutation(internal.panelSetup.start, {
        backendServerId: serverId,
        input: {
          ...setupInput,
          modes: [{ ...setupInput.modes[0]!, familySlug: 'nope' }],
        },
      }),
    ).rejects.toThrow(/family_missing/);
    await expect(
      t.mutation(internal.panelSetup.start, {
        backendServerId: serverId,
        input: { ...setupInput, modes: [{ ...setupInput.modes[0]!, slug: 'made-up-mode' }] },
      }),
    ).rejects.toThrow(/mode_unknown/);
    expect(panel.writes).toHaveLength(0);
  });

  test('an existing backend is adopted only on the typed say-so; a group an earlier setup named is renamed in place', async () => {
    const { t, serverId, panel } = await seed();
    panel.nodes.push({
      uuid: UUID(1),
      name: 'legacy',
      address: '192.0.2.5',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: UUID(2), activeInbounds: [] },
    });
    // The group also grants a transport of an older release: a mode grants one.
    const legacyGroup = {
      uuid: UUID(3),
      name: 'FreeSocks-Reality',
      inbounds: [{ uuid: UUID(9), tag: 'VLESS_OLD' }],
    };
    panel.squads.push(legacyGroup);
    await t.action(internal.panelObserve.refresh, { backendServerId: serverId });
    await expect(
      t.mutation(internal.panelSetup.start, { backendServerId: serverId, input: setupInput }),
    ).rejects.toThrow(/adopt_required/);
    expect(panel.writes).toHaveLength(0);
    const row = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(row.state).toBe('ready');
    expect(row.adopted).toBe(true);
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    expect(direct.groupUuid).toBe(legacyGroup.uuid);
    expect(direct.renamedFrom).toBe('FreeSocks-Reality');
    expect(panel.squads.find((s) => s.uuid === legacyGroup.uuid)!.name).toBe('Privacy-Reality');
    // Exactly the mode's transport, not the old one beside it.
    expect(
      panel.squads
        .find((x) => x.uuid === legacyGroup.uuid)!
        .inbounds.map((i: { uuid: string }) => i.uuid),
    ).toEqual([direct.transport!.uuid]);
    expect(panel.squads.filter((s) => s.name === 'FreeSocks-Reality')).toHaveLength(0);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'servers.setup.group_renamed')).toBe(true);
  });

  // A tag is unique per profile, never per backend: another profile reusing a
  // conventional tag must not make an unambiguous binding fail.
  test('a second profile reusing a transport tag does not stop the family binding', async () => {
    const { t, serverId, panel } = await seed();
    panel.profiles.push({
      uuid: UUID(90),
      name: 'Someone-Elses-Config',
      config: { inbounds: [{ tag: 'PRIVACY_REALITY' }] },
      inbounds: [{ uuid: UUID(91), tag: 'PRIVACY_REALITY' }],
    });
    await t.action(internal.panelObserve.refresh, { backendServerId: serverId });
    const row = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(row.state).toBe('ready');
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    expect(direct.family).toBe('bound');
    // The family is bound to THIS profile's transport, not the other one.
    const bindings = await t.run((ctx) => ctx.db.query('sniInboundBindings').collect());
    expect(bindings.map((b) => b.inboundUuid)).toContain(direct.transport!.uuid);
    expect(bindings.map((b) => b.inboundUuid)).not.toContain(UUID(91));
  });

  // A transport already bound to ANOTHER family answers to that family's
  // rollouts: setting up around it would leave two owners of one allowlist.
  test('a transport bound to another family stops the setup with that family', async () => {
    const { t, serverId } = await seed();
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-other',
      label: 'fam-other',
      targetAddress: 'decoy-a.example',
      targetPort: 443,
    });
    await t.run(async (ctx) => {
      const other = await ctx.db
        .query('sniFamilies')
        .withIndex('by_slug', (q) => q.eq('slug', 'fam-other'))
        .unique();
      const mine = (await ctx.db.query('sniInboundBindings').collect()).find(
        (x) => x.inboundUuid === direct.transport!.uuid,
      )!;
      await ctx.db.patch(mine._id, { familyId: other!._id });
      // The row asks to be looked at again (as a resumed or retried setup does).
      await ctx.db.patch(row._id, {
        modes: row.modes!.map((m) =>
          m.slug === 'privacy-reality' ? { ...m, family: 'unbound' as const } : m,
        ),
      });
    });
    const again = await runSetup(t, serverId);
    expect(again.state).toBe('failed');
    expect(again.code).toBe('servers.family_bound_elsewhere:fam-other');
    expect(again.modes!.find((m) => m.slug === 'privacy-reality')!.family).toBe('bound_elsewhere');
  });
});

describe('enrolling a direct node', () => {
  test('creates the row and DISABLED addresses (one per family name), serves the secret, and reaches machine_ready on the applied report', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    const observed = {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    };
    const { intentId } = await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed,
    });
    let intent = await runIntent(t, intentId);
    expect(intent.state).toBe('ready');
    expect(intent.activation.stage).toBe('registered');
    expect(panel.nodes).toHaveLength(1);
    expect(panel.nodes[0]).toMatchObject({ name: 'node-a', address: '192.0.2.10', port: 2222 });
    expect(panel.hosts.map((h) => h.remark).sort()).toEqual([
      'node-a | decoy-a.example',
      'node-a | www.decoy-a.example',
    ]);
    expect(panel.hosts[0]).toMatchObject({
      address: '203.0.113.10',
      port: 443,
      sni: 'decoy-a.example',
      isDisabled: true,
    });
    expect(intent.nodeUuid).toBe(panel.nodes[0]!.uuid);
    expect(intent.addressUuids?.sort()).toEqual(panel.hosts.map((h) => h.uuid).sort());
    expect(intent.configRevision).toMatch(/:/);
    expect(intent.authRevision).toBeTruthy();

    // The bootstrap answer carries the secret and the mode; nothing FCP keeps holds the secret.
    const boot = await t.action(internal.panelIntents.bootstrap, { intentId });
    expect(boot).toMatchObject({
      machineRevision: 1,
      secretKey: 'panel-node-secret-placeholder',
      node: {
        port: 2222,
        mode: { slug: 'privacy-reality', shape: { transport: 'reality', fronting: 'direct' } },
      },
      ingress: null,
    });
    const kept = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelNodeIntents').collect(),
        await ctx.db.query('auditLog').collect(),
        await ctx.db.query('panelOps').collect(),
      ]),
    );
    expect(kept).not.toContain('panel-node-secret-placeholder');
    intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.activation.stage).toBe('bootstrap_available');

    // Applied: idempotent, stale and unknown revisions refused, then machine_ready.
    await expect(
      t.mutation(internal.panelIntents.applied, {
        intentId,
        appliedRevision: 2,
        nodeStarted: true,
      }),
    ).rejects.toThrow(/revision_unknown/);
    const r1 = await t.mutation(internal.panelIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    expect(r1).toEqual({ stage: 'machine_applied', repeated: false });
    intent = await runIntent(t, intentId);
    expect(intent.activation.stage).toBe('machine_ready');
    expect(intent.activation.evidence.map((e) => e.kind).sort()).toEqual([
      'machine_applied',
      'machine_ready',
    ]);
    const r2 = await t.mutation(internal.panelIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    expect(r2).toEqual({ stage: 'machine_ready', repeated: true });

    // An identical observation rerun changes nothing on the backend.
    const before = panel.writes.length;
    await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed,
    });
    intent = await runIntent(t, intentId);
    expect(panel.writes.length).toBe(before);
    expect(intent.activation.stage).toBe('machine_ready');

    // The gate stays closed before any approval; the role view says so.
    const gate = await t.query(internal.panelIntents.nodeGate, {
      backendServerId: serverId,
      nodeName: 'node-a',
    });
    expect(gate.state).toBe('blocked');
    const view = await t.query(internal.panelIntents.roleViewByName, {
      backendServerId: serverId,
      name: 'node-a',
    });
    expect(view).toMatchObject({
      mode: { slug: 'privacy-reality', name: 'Privacy-Reality' },
      stage: 'machine_ready',
      delivery: 'staged',
    });
  });

  test('a mode change, an unknown mode, an unowned backend node and a stale contract are refused', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    const observed = {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: {},
      capabilities: { caddy: false, ipv6: false },
    };
    await expect(
      t.mutation(internal.panelIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'privacy-reality',
        contractVersion: 1,
        observed,
      }),
    ).rejects.toThrow(/contract_version/);
    await expect(
      t.mutation(internal.panelIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'no-such-mode',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/mode_unknown/);
    panel.nodes.push({
      uuid: UUID(99),
      name: 'stranger',
      address: '192.0.2.99',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: panel.profiles[0]!.uuid, activeInbounds: [] },
    });
    await t.action(internal.panelObserve.refresh, { backendServerId: serverId });
    await expect(
      t.mutation(internal.panelIntents.enroll, {
        backendServerId: serverId,
        name: 'stranger',
        mode: 'privacy-reality',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/node_exists_unowned/);
    await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'freedom-reality',
      contractVersion: 2,
      observed,
    });
    await expect(
      t.mutation(internal.panelIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'privacy-reality',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/mode_change_needs_admin/);
  });
});

describe('an address belongs to exactly one node', () => {
  test('a node whose name is the prefix of another never owns its addresses', () => {
    expect(addressRemark('node-a', 'decoy-a.example')).toBe('node-a | decoy-a.example');
    expect(ownsAddress('node-a', addressRemark('node-a', 'decoy-a.example'))).toBe(true);
    // The collision a name prefix used to cause: node-a would have taken
    // node-a-west's addresses for its own, and deleted them as extra.
    expect(ownsAddress('node-a', addressRemark('node-a-west', 'decoy-a.example'))).toBe(false);
    expect(ownsAddress('node-a-west', addressRemark('node-a', 'decoy-a.example'))).toBe(false);
    // Whatever remark it carries, an address the node has recorded is its own
    // (an adopted node's were named by whoever made them).
    const hosts = [
      { hostUuid: 'h1', remark: 'anything at all' },
      { hostUuid: 'h2', remark: addressRemark('node-a', 'www.decoy-a.example') },
      { hostUuid: 'h3', remark: addressRemark('node-a-west', 'decoy-a.example') },
    ];
    expect(
      addressesOf({ name: 'node-a', addressUuids: ['h1'] }, hosts).map((h) => h.hostUuid),
    ).toEqual(['h1', 'h2']);
  });
});

describe('moving off contract v1', () => {
  test('the migration clears the v1 rows and leaves a current setup alone', async () => {
    const { t, serverId, panel } = await seed();
    const current = await runSetup(t, serverId);
    expect(current.state).toBe('ready');
    expect(panel.profiles).toHaveLength(1);
    // A second backend carrying what the release before modes wrote.
    const legacy = await insertPanelServer(t, { slug: 'panel-b' });
    const legacyIds = await t.run(async (ctx) => {
      const setupId = await ctx.db.insert('panelSetups', {
        backendServerId: legacy,
        desired: '{}',
        desiredHash: 'h',
        generation: 1,
        state: 'ready',
        profileName: 'FreeSocks-Config',
        profileUuid: UUID(80),
        inbounds: { cdn: { uuid: UUID(81), tag: 'VLESS_WS_CDN' } },
        squads: { fronted: { name: 'FreeSocks-Fronted' } },
        placements: [{ mode: 'freedom-ws', state: 'bound' }],
        handoff: 'fresh',
        templates: [],
        gateVersion: 3,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      });
      const intentId = await ctx.db.insert('panelNodeIntents', {
        backendServerId: legacy,
        name: 'legacy-node',
        label: 'legacy-node',
        purpose: 'front',
        contractVersion: 1,
        generation: 1,
        desiredHash: 'h',
        state: 'ready',
        observed: {
          management: { address: '192.0.2.9', port: 2222 },
          publicIps: {},
          capabilities: { caddy: true, ipv6: false },
          at: Date.now(),
        },
        settings: { originHostnameSource: 'none', publishV6: false, nodePort: 2222 },
        machineRevision: 1,
        activation: { stage: 'live', evidence: [] },
        delivery: {
          disposition: 'live',
          acceptingAssignments: true,
          exposure: { everLive: true, hosts: [], mirrors: 0, testCredentials: 0, dns: 0 },
        },
        origin: { dns: 'none' },
        hostUuid: UUID(82),
        registeredAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('panelHandoff', {
        backendServerId: legacy,
        roleContractVersion: 1,
        reportedAt: Date.now(),
        reportedBy: 'role',
      });
      const ownershipId = await ctx.db.insert('panelOwnership', {
        backendServerId: legacy,
        kind: 'node',
        identity: 'legacy-node',
        lookup: ['legacy-node'],
        state: 'reserved',
        reservation: { roleOpId: 'op-1', at: Date.now() },
        since: Date.now(),
        updatedAt: Date.now(),
      });
      return { setupId, intentId, ownershipId };
    });

    const out = await t.mutation(internal.panelSetup.migrateContractV2, {});
    expect(out).toEqual({ handoffs: 1, reservations: 1, setups: 1, intents: 1 });
    await t.run(async (ctx) => {
      expect(await ctx.db.get(legacyIds.setupId)).toBeNull();
      expect(await ctx.db.get(legacyIds.intentId)).toBeNull();
      expect(await ctx.db.query('panelHandoff').collect()).toHaveLength(0);
      const own = (await ctx.db.get(legacyIds.ownershipId))!;
      expect(own.state).toBe('owned');
      expect(own.reservation).toBeUndefined();
      // The current backend is untouched, and nothing on a backend was called.
      expect((await ctx.db.get(current._id))!.state).toBe('ready');
    });
    expect(panel.writes.filter((w) => w.call.startsWith('DELETE'))).toHaveLength(0);
    // Idempotent.
    expect(await t.mutation(internal.panelSetup.migrateContractV2, {})).toEqual({
      handoffs: 0,
      reservations: 0,
      setups: 0,
      intents: 0,
    });
  });
});
