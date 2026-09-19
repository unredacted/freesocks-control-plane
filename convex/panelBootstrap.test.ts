/// <reference types="vite/client" />
/**
 * The bootstrap contract on a FRESH fake panel: "Set up this panel" creates
 * the profile from the template (one POST, keys never stored), the three
 * squads and their placements, and writes the handoff itself; then a direct
 * node is enrolled by name, its row and its DISABLED Host are created, the
 * bootstrap answer carries the secret, and the applied report leads to
 * machine_ready with revision-bound evidence. Identical reruns perform no
 * write. Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { BOOTSTRAP_TAGS } from './lib/panel/profileTemplate';

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
  cdn: { path: '/ws', port: 8443 },
  reality: { target: { address: 'decoy-a.example', port: 443 }, serverNames: ['decoy-a.example'] },
  relay: {
    target: { address: 'decoy-b.example', port: 443 },
    serverNames: ['decoy-b.example'],
    acceptProxyProtocol: false,
  },
  squads: { fronted: 'FreeSocks-Fronted', reality: 'FreeSocks-Reality', relay: 'FreeSocks-Relay' },
  originDns: null,
};

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
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

async function runSetup(t: T, serverId: Id<'backendServers'>) {
  const started = await t.mutation(internal.panelSetup.start, {
    backendServerId: serverId,
    input: setupInput,
  });
  // `start` scheduled the run; convex-test executes it on the next tick.
  return settled(() => t.run((ctx) => ctx.db.get(started.setupId)));
}

async function runIntent(t: T, intentId: Id<'panelNodeIntents'>) {
  return settled(() => t.run((ctx) => ctx.db.get(intentId)));
}

describe('setting up a fresh panel', () => {
  test('creates the profile once, the squads and placements, and hands the panel to FCP', async () => {
    const { t, serverId, panel } = await seed();
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    expect(row.handoff).toBe('fresh');
    expect(row.profileUuid).toBe(panel.profiles[0]!.uuid);
    expect(row.inbounds!.cdn).toMatchObject({ tag: BOOTSTRAP_TAGS.cdn, port: 8443, path: '/ws' });
    expect(row.inbounds!.reality.serverNames).toEqual(['decoy-a.example']);
    expect(row.privacy).toBe('ok');
    expect(panel.writes.filter((w) => w.call === 'POST /api/config-profiles')).toHaveLength(1);
    expect(panel.squads.map((s) => s.name).sort()).toEqual([
      'FreeSocks-Fronted',
      'FreeSocks-Reality',
      'FreeSocks-Relay',
    ]);
    expect(row.placements).toEqual([
      { mode: 'freedom-ws', state: 'bound' },
      { mode: 'privacy-reality', state: 'bound' },
      { mode: 'freedom-reality', state: 'bound' },
    ]);
    const handoff = await t.run((ctx) =>
      ctx.db
        .query('panelHandoff')
        .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
        .unique(),
    );
    expect(handoff).toMatchObject({ roleContractVersion: 2, reportedBy: 'fcp-setup' });
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
    const privateKey =
      panel.profiles[0]!.config.inbounds[1].streamSettings.realitySettings.privateKey;
    expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(rows).not.toContain(privateKey);

    // An identical rerun performs no write.
    const before = panel.writes.length;
    const again = await t.mutation(internal.panelSetup.start, {
      backendServerId: serverId,
      input: setupInput,
    });
    expect(again.started).toBe(false);
    expect(panel.writes.length).toBe(before);
  });

  test('an existing panel with nodes needs the typed takeover before FCP writes', async () => {
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
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('needs_takeover');
    expect(panel.writes).toHaveLength(0);
    await t.mutation(internal.panelSetup.takeover, { backendServerId: serverId });
    const after = await runSetup(t, serverId);
    expect(after.state).toBe('ready');
    expect(after.handoff).toBe('taken_over');
  });
});

describe('enrolling a direct node', () => {
  test('creates the row and a DISABLED Host, serves the secret, and reaches machine_ready on the applied report', async () => {
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
      purpose: 'direct',
      contractVersion: 2,
      observed,
    });
    let intent = await runIntent(t, intentId);
    expect(intent.state).toBe('ready');
    expect(intent.activation.stage).toBe('registered');
    expect(panel.nodes).toHaveLength(1);
    expect(panel.nodes[0]).toMatchObject({ name: 'node-a', address: '192.0.2.10', port: 2222 });
    expect(panel.hosts).toHaveLength(1);
    expect(panel.hosts[0]).toMatchObject({
      remark: 'node-a-reality',
      address: '203.0.113.10',
      port: 443,
      sni: 'decoy-a.example',
      isDisabled: true,
    });
    expect(intent.nodeUuid).toBe(panel.nodes[0]!.uuid);
    expect(intent.hostUuid).toBe(panel.hosts[0]!.uuid);
    expect(intent.configRevision).toMatch(/:/);
    expect(intent.authRevision).toBeTruthy();

    // The bootstrap answer carries the secret; nothing FCP keeps does.
    const boot = await t.action(internal.panelIntents.bootstrap, { intentId });
    expect(boot).toMatchObject({
      machineRevision: 1,
      secretKey: 'panel-node-secret-placeholder',
      node: { port: 2222, purpose: 'direct' },
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

    // An identical observation rerun changes nothing on the panel.
    const before = panel.writes.length;
    await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      purpose: 'direct',
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
    expect(view).toMatchObject({ purpose: 'direct', stage: 'machine_ready', delivery: 'staged' });
  });

  test('a purpose change, an unowned panel node and a stale contract are refused', async () => {
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
        purpose: 'direct',
        contractVersion: 1,
        observed,
      }),
    ).rejects.toThrow(/contract_version/);
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
        purpose: 'direct',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/node_exists_unowned/);
    await t.mutation(internal.panelIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      purpose: 'relay',
      contractVersion: 2,
      observed,
    });
    await expect(
      t.mutation(internal.panelIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        purpose: 'direct',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/purpose_change_needs_admin/);
  });
});
