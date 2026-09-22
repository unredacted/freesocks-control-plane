/// <reference types="vite/client" />
/**
 * Node writes through the operations ledger.
 *
 *  - a rename or a country change queues no node work; an address, port or
 *    profile change makes the backend restart the node, and holds the node's
 *    claim until the node's own clock moves;
 *  - a RESTART names no field of the row, so the row alone never settles it;
 *    it is sent as a forced restart, and refused on a node that is off;
 *  - enable / disable are refused when the node is already in that state (a
 *    repeat enqueues backend work for nothing);
 *  - deleting is two named things: "stop and remove" needs the node to be off
 *    already, "remove from backend" says the process may keep running;
 *  - a node an origin stands in front of is not moved, stopped or removed here,
 *    and a node whose NAME anything refers to is not renamed.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import {
  insertPanelServer,
  markBackendSetUp,
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
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

interface Node {
  uuid: string;
  name: string;
  address: string;
  port: number;
  countryCode: string;
  isDisabled: boolean;
  lastStatusChange: string;
  configProfile: {
    activeConfigProfileUuid: string;
    activeInbounds: { uuid: string; tag: string }[];
  };
}
interface Panel {
  nodes: Node[];
  writes: { call: string; body: any }[];
  seq: number;
}

function installPanel(): Panel {
  const inbounds = [
    { uuid: 'i-1', tag: 'in-1' },
    { uuid: 'i-2', tag: 'in-2' },
  ];
  const panel: Panel = {
    nodes: [
      {
        uuid: 'n-1',
        name: 'node-one',
        address: '192.0.2.10',
        port: 2222,
        countryCode: 'NL',
        isDisabled: false,
        lastStatusChange: 't0',
        configProfile: { activeConfigProfileUuid: 'p-1', activeInbounds: [inbounds[0]] },
      },
      {
        uuid: 'n-2',
        name: 'node-two',
        address: '192.0.2.20',
        port: 2222,
        countryCode: 'DE',
        isDisabled: false,
        lastStatusChange: 't0',
        configProfile: { activeConfigProfileUuid: 'p-1', activeInbounds: [inbounds[0]] },
      },
    ],
    writes: [],
    seq: 0,
  };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const profile = {
    uuid: 'p-1',
    name: 'Default',
    config: {
      inbounds: inbounds.map((i, k) => ({
        tag: i.tag,
        port: 443 + k,
        protocol: 'vless',
        streamSettings: { network: 'tcp', security: 'none' },
      })),
    },
    inbounds,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body as string) : {};
      if (method === 'GET') {
        if (path === '/api/nodes')
          return json(panel.nodes.map((n) => ({ ...n, isConnected: true })));
        if (path === '/api/hosts') return json([]);
        if (path === '/api/internal-squads') return json({ internalSquads: [] });
        if (path === '/api/config-profiles') return json({ configProfiles: [profile] });
        if (path === '/api/config-profiles/p-1') return json(profile);
        return json({});
      }
      panel.writes.push({ call: `${method} ${path}`, body });
      const byPath = panel.nodes.find((n) => path.includes(`/api/nodes/${n.uuid}`));
      if (path === '/api/nodes' && method === 'POST') {
        const made = {
          uuid: `n-new-${++panel.seq}`,
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
      if (path === '/api/nodes' && method === 'PATCH') {
        const n = panel.nodes.find((x) => x.uuid === body.uuid)!;
        const { configProfile, uuid: _u, ...rest } = body;
        Object.assign(n, rest);
        if (configProfile)
          n.configProfile = {
            activeConfigProfileUuid: configProfile.activeConfigProfileUuid,
            activeInbounds: (configProfile.activeInbounds as string[]).map((uuid) => ({
              uuid,
              tag: uuid,
            })),
          };
        return json(n);
      }
      if (byPath && path.endsWith('/actions/disable')) byPath.isDisabled = true;
      if (byPath && path.endsWith('/actions/enable')) byPath.isDisabled = false;
      if (byPath && method === 'DELETE') panel.nodes = panel.nodes.filter((n) => n !== byPath);
      return json({}, path.endsWith('/restart') ? 202 : 200);
    }),
  );
  return panel;
}

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
  const panel = installPanel();
  await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await markBackendSetUp(t, serverId);
  const call = async (method: string, path: string, body?: unknown) =>
    (
      await t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
        method,
        headers: { cookie, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    ).json();
  const observe = (id: string) => call('POST', `ops/${id}/observe`);
  const refresh = () => t.action(internal.backendObserve.refresh, { backendServerId: serverId });
  return { t, serverId, panel, call, observe, refresh };
}

const claims = (t: T) => t.run((ctx) => ctx.db.query('panelClaims').collect());

describe('node changes', () => {
  test('a rename and a country change queue no node work', async () => {
    const { t, panel, call } = await seed();
    const op = await call('PATCH', 'nodes/n-2', { name: 'node-two-b', countryCode: 'fr' });
    expect(op).toMatchObject({ kind: 'node', verb: 'update', state: 'done', asyncEffect: 'none' });
    expect(panel.nodes[1]).toMatchObject({
      name: 'node-two-b',
      countryCode: 'FR',
      address: '192.0.2.20',
    });
    expect(await claims(t)).toEqual([]);
  });

  test("an address change restarts the node: the claim holds until the node's own clock moves", async () => {
    const { t, panel, call, observe } = await seed();
    const op = await call('PATCH', 'nodes/n-2', { address: '192.0.2.21' });
    expect(op).toMatchObject({
      panelState: 'observed',
      asyncEffect: 'pending',
      state: 'waiting_for_nodes',
      open: true,
    });
    expect((await claims(t)).map((c) => c.key)).toEqual(['node:n-2']);
    // Another change to the same node waits.
    expect((await call('POST', 'nodes/n-2/restart')).error.code).toBe('servers.op_running');
    expect((await observe(op.id)).open).toBe(true);
    panel.nodes[1].lastStatusChange = 't1';
    expect(await observe(op.id)).toMatchObject({ state: 'done', asyncEffect: 'complete' });
  });

  test('profile and transports travel together, and must belong to each other', async () => {
    const { panel, call, observe } = await seed();
    const bad = await call('PATCH', 'nodes/n-2', { activeInboundUuids: ['i-nope'] });
    expect(bad.error.code).toBe('servers.unknown_inbound');
    const op = await call('PATCH', 'nodes/n-2', { activeInboundUuids: ['i-1', 'i-2'] });
    expect(panel.writes.at(-1)!.body.configProfile).toEqual({
      activeConfigProfileUuid: 'p-1',
      activeInbounds: ['i-1', 'i-2'],
    });
    panel.nodes[1].lastStatusChange = 't1';
    expect((await observe(op.id)).state).toBe('done');
  });
});

describe('enable, disable, restart', () => {
  test('a restart is FORCED, and the row alone never settles it', async () => {
    const { panel, call, observe } = await seed();
    const op = await call('POST', 'nodes/n-2/restart');
    expect(panel.writes.at(-1)).toEqual({
      call: 'POST /api/nodes/n-2/actions/restart',
      body: { forceRestart: true },
    });
    // The backend answered 202 (queued). The row looks exactly as before: not done.
    expect(op).toMatchObject({ verb: 'restart', asyncEffect: 'pending', open: true });
    expect((await observe(op.id)).open).toBe(true);
    panel.nodes[1].lastStatusChange = 't1';
    expect((await observe(op.id)).state).toBe('done');
  });

  test('a repeat is refused instead of sent; a node that is off is not restarted', async () => {
    const { panel, call, refresh } = await seed();
    expect((await call('POST', 'nodes/n-2/enable')).error.code).toBe('servers.already');
    const off = await call('POST', 'nodes/n-2/disable');
    // A disabled node has no application work left to wait for.
    expect(off).toMatchObject({ verb: 'disable', state: 'done' });
    await refresh();
    expect((await call('POST', 'nodes/n-2/disable')).error.code).toBe('servers.already');
    expect((await call('POST', 'nodes/n-2/restart')).error.code).toBe('servers.node_off');
    expect(panel.writes.filter((w) => w.call.includes('/actions/')).length).toBe(1);
  });
});

describe('create and delete', () => {
  test('create makes the backend ROW only, once, and never asks for the node secret', async () => {
    const { panel, call } = await seed();
    const spec = {
      name: 'node-three',
      address: '192.0.2.30',
      configProfileUuid: 'p-1',
      activeInboundUuids: ['i-1'],
    };
    const op = await call('POST', 'nodes', spec);
    expect(op).toMatchObject({ verb: 'create', state: 'done' });
    expect(panel.writes.map((w) => w.call)).toEqual(['POST /api/nodes']);
    expect(panel.nodes.map((n) => n.name)).toContain('node-three');
    expect((await call('POST', 'nodes', { ...spec, name: 'node-one' })).error.code).toBe(
      'servers.node_name_taken',
    );
    expect((await call('POST', 'nodes', { ...spec, name: 'x' })).error.code).toBe('validation');
  });

  test('"stop and remove" needs the node to be off already; "remove from backend" says what it is', async () => {
    const { panel, call, observe, refresh } = await seed();
    expect((await call('DELETE', 'nodes/n-2')).error.code).toBe('servers.node_still_on');
    await call('POST', 'nodes/n-2/disable');
    await refresh();
    const op = await call('DELETE', 'nodes/n-2');
    expect(op).toMatchObject({ verb: 'delete', open: true });
    expect((await observe(op.id)).state).toBe('done');
    expect(panel.nodes.map((n) => n.uuid)).toEqual(['n-1']);
    // Removed on purpose: not recreated by name, unless the operator says so.
    await refresh();
    const again = {
      name: 'node-two',
      address: '192.0.2.20',
      configProfileUuid: 'p-1',
      activeInboundUuids: ['i-1'],
    };
    expect((await call('POST', 'nodes', again)).error.code).toBe('servers.tombstoned');
    expect((await call('POST', 'nodes', { ...again, restore: true })).state).toBe('done');
  });

  test('"remove from backend" works on a running node', async () => {
    const { panel, call, observe } = await seed();
    const op = await call('DELETE', 'nodes/n-2?removeOnly=1');
    expect((await observe(op.id)).state).toBe('done');
    expect(panel.nodes.map((n) => n.uuid)).toEqual(['n-1']);
  });
});

describe('a node something depends on', () => {
  test('an origin stands in front of it: it is not moved, stopped, reassigned or removed here', async () => {
    const { t, panel, call } = await seed();
    await registerRelay(t, { listeners: [realityListener()] });
    for (const res of [
      await call('PATCH', 'nodes/n-1', { address: '192.0.2.99' }),
      await call('PATCH', 'nodes/n-1', { activeInboundUuids: ['i-2'] }),
      await call('POST', 'nodes/n-1/disable'),
      await call('DELETE', 'nodes/n-1?removeOnly=1'),
    ])
      expect(res.error.code).toBe('servers.node_relay_origin');
    // Its name is an identifier: origins, delivery requirements and pinned keys refer to it.
    expect((await call('PATCH', 'nodes/n-1', { name: 'renamed' })).error.code).toBe(
      'servers.node_rename_referenced',
    );
    // A restart is allowed: it changes nothing the origin depends on.
    expect((await call('POST', 'nodes/n-1/restart')).verb).toBe('restart');
    expect(panel.writes.map((w) => w.call)).toEqual(['POST /api/nodes/n-1/actions/restart']);
  });

  test('a node members are pinned to is not renamed', async () => {
    const { t, serverId, call } = await seed();
    await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        supportId: 'S',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'u',
        backendShortId: 's',
        backendServerId: serverId,
        subscriptionUrl: 'https://panel.example/sub/s',
        subscriptionMirrors: [],
        state: 'active',
        pinnedNode: 'node-two',
        updatedAt: Date.now(),
      });
    });
    expect((await call('PATCH', 'nodes/n-2', { name: 'other' })).error.code).toBe(
      'servers.node_rename_referenced',
    );
  });
});
