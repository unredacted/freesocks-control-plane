/// <reference types="vite/client" />
/**
 * Server-management WRITES through the operations ledger (Hosts, mode groups).
 * These are the cases the design exists for:
 *
 *  - nothing is written while dormant, without the role's handoff, or by a
 *    token that only holds `admin:servers:write`;
 *  - an op is sent AT MOST ONCE. A create whose answer is lost is settled by
 *    LOOKING (adopted, never repeated); a gateway error while upstream commits
 *    stays "unknown" until the result is seen;
 *  - the delayed-attempt sequence: while an attempt's outcome is unknown, a
 *    re-send does not happen, an opposing write is refused, and when the
 *    original finally lands the op resolves. No conflicting op was admitted;
 *  - reading a changed mode group row never releases the claims on the profiles and
 *    nodes the backend re-applies; the nodes' own clocks must move;
 *  - what belongs to the edges machinery is locked; a deliberate removal is
 *    not undone by name; a recovery needs every condition.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { sha256Hex } from './lib/crypto';
import {
  insertPanelServer,
  markBackendSetUp,
  registerRelay,
  realityListener,
} from './lib/edges/testing/fixtures';
import { claimKey } from './lib/panel/ops';
import { assertNoPanelClaim } from './panelLedger';
import { scopeFor } from './httpServers';

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

// --- a mutable fake backend that can lose answers and delay writes ---------------------------------

interface Host {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string;
  fingerprint?: string;
  viewPosition?: number;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
}
interface Squad {
  uuid: string;
  name: string;
  inbounds: { uuid: string; tag: string }[];
  info: { membersCount: number };
}
type Fault = null | { status?: number; timeout?: boolean; apply: 'now' | 'later' | 'never' };

interface Panel {
  hosts: Host[];
  squads: Squad[];
  nodes: { uuid: string; name: string; isDisabled: boolean; lastStatusChange: string | null }[];
  writes: string[];
  fault: Fault;
  /** Writes accepted by the backend but not applied yet (`apply: 'later'`). */
  delayed: (() => void)[];
  seq: number;
}

const newPanel = (): Panel => ({
  hosts: [
    {
      uuid: 'h-1',
      remark: 'node-one-direct',
      address: '192.0.2.10',
      port: 443,
      sni: 'a.example',
      viewPosition: 1,
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-1' },
    },
    {
      uuid: 'h-edge',
      remark: 'node-one-relay-a',
      address: '198.51.100.7',
      port: 443,
      viewPosition: 2,
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-1' },
    },
  ],
  squads: [
    {
      uuid: 's-1',
      name: 'free',
      inbounds: [{ uuid: 'i-1', tag: 'in-1' }],
      info: { membersCount: 0 },
    },
    {
      uuid: 's-busy',
      name: 'busy',
      inbounds: [{ uuid: 'i-1', tag: 'in-1' }],
      info: { membersCount: 4 },
    },
  ],
  nodes: [{ uuid: 'n-1', name: 'node-one', isDisabled: false, lastStatusChange: 't0' }],
  writes: [],
  fault: null,
  delayed: [],
  seq: 0,
});

function installPanel(panel: Panel) {
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const profile = {
    uuid: 'p-1',
    name: 'Default',
    config: {
      inbounds: [
        {
          tag: 'in-1',
          port: 443,
          protocol: 'vless',
          streamSettings: { network: 'tcp', security: 'none' },
        },
        {
          tag: 'in-2',
          port: 8443,
          protocol: 'vless',
          streamSettings: { network: 'tcp', security: 'none' },
        },
      ],
    },
    inbounds: [
      { uuid: 'i-1', tag: 'in-1' },
      { uuid: 'i-2', tag: 'in-2' },
    ],
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? (JSON.parse(init.body as string) as Record<string, any>) : {};
      if (method === 'GET') {
        if (path === '/api/hosts') return json(panel.hosts);
        if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
        if (path === '/api/nodes')
          return json(
            panel.nodes.map((n) => ({
              ...n,
              isConnected: true,
              configProfile: { activeConfigProfileUuid: 'p-1', activeInbounds: profile.inbounds },
            })),
          );
        if (path === '/api/config-profiles') return json({ configProfiles: [profile] });
        if (path === '/api/config-profiles/p-1') return json(profile);
        return json({});
      }
      panel.writes.push(`${method} ${path}`);
      let made: unknown = {};
      const apply = () => {
        if (path === '/api/hosts' && method === 'POST') {
          const h = { uuid: `h-new-${++panel.seq}`, ...body } as Host;
          panel.hosts.push(h);
          made = h;
        } else if (path === '/api/hosts' && method === 'PATCH') {
          const h = panel.hosts.find((x) => x.uuid === body.uuid);
          if (h) Object.assign(h, body);
        } else if (path.startsWith('/api/hosts/') && method === 'DELETE')
          panel.hosts = panel.hosts.filter((h) => h.uuid !== path.split('/').pop());
        else if (path === '/api/hosts/actions/reorder')
          for (const o of body.hosts as { uuid: string; viewPosition: number }[]) {
            const h = panel.hosts.find((x) => x.uuid === o.uuid);
            if (h) h.viewPosition = o.viewPosition;
          }
        else if (path === '/api/internal-squads' && method === 'POST') {
          const s = {
            uuid: `s-new-${++panel.seq}`,
            name: body.name,
            inbounds: (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid })),
            info: { membersCount: 0 },
          };
          panel.squads.push(s);
          made = s;
        } else if (path === '/api/internal-squads' && method === 'PATCH') {
          const s = panel.squads.find((x) => x.uuid === body.uuid);
          if (s && body.name) s.name = body.name;
          if (s && body.inbounds)
            s.inbounds = (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid }));
        } else if (path.startsWith('/api/internal-squads/') && method === 'DELETE')
          panel.squads = panel.squads.filter((s) => s.uuid !== path.split('/').pop());
      };
      const fault = panel.fault;
      if (!fault) {
        apply();
        return json(made, method === 'POST' ? 201 : 200);
      }
      if (fault.apply === 'now') apply();
      if (fault.apply === 'later') panel.delayed.push(apply);
      if (fault.timeout) throw new DOMException('The operation was aborted', 'AbortError');
      return new Response('gateway said no', { status: fault.status ?? 500 });
    }),
  );
}

async function adminCookie(t: T) {
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
  return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
}

async function token(t: T, scopes: string[]): Promise<string> {
  const plaintext = `fsv1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
  const tokenHash = await sha256Hex(plaintext);
  await t.run(async (ctx) => {
    const admin = await ctx.db.insert('adminUsers', {
      username: `tok-${plaintext.slice(-8)}`,
      displayName: 'T',
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('apiTokens', {
      name: 'test',
      tokenHash,
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: admin,
      scopes,
      subjectType: 'service',
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

async function seed(opts: { enabled?: boolean; handoff?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const cookie = await adminCookie(t);
  const panel = newPanel();
  installPanel(panel);
  await t.action(internal.panelObserve.refresh, { backendServerId: serverId });
  if (opts.enabled !== false)
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  if (opts.handoff !== false) await markBackendSetUp(t, serverId);
  const call = (
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    t.fetch(`/api/v1/admin/servers/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return { t, serverId, panel, call, cookie };
}

const NEW_HOST = {
  remark: 'node-one-alt',
  address: '192.0.2.11',
  port: 8443,
  inboundUuid: 'i-1',
  sni: 'b.example',
};
const claims = (t: T) => t.run((ctx) => ctx.db.query('panelClaims').collect());
const ops = (t: T) => t.run((ctx) => ctx.db.query('panelOps').collect());
const auditOf = (t: T, action: string) =>
  t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect())
      .filter((a) => a.action === action)
      .map((a) => a.payload),
  );

describe('gates', () => {
  test('dormant: no write is accepted and nothing is sent', async () => {
    const { call, panel } = await seed({ enabled: false });
    const res = await call('POST', 'panel-a/hosts', NEW_HOST);
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe('servers.manage_disabled');
    expect(panel.writes).toEqual([]);
  });

  test('a backend FCP has not set up or adopted refuses every write', async () => {
    const { call, panel, t } = await seed({ handoff: false });
    const res = await call('POST', 'panel-a/hosts', NEW_HOST);
    expect((await res.json()).error.code).toBe('servers.not_set_up');
    expect(panel.writes).toEqual([]);
    expect(await claims(t)).toEqual([]);
  });

  test('the node role token (admin:servers:write) cannot change a backend; a manager can once it is set up', async () => {
    const { t, panel, serverId } = await seed({ handoff: false });
    const role = await token(t, ['admin:servers:read', 'admin:servers:write']);
    const as = (tok: string, method: string, path: string, body?: unknown) =>
      t.fetch(`/api/v1/admin/servers/${path}`, {
        method,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    expect((await as(role, 'POST', 'panel-a/hosts', NEW_HOST)).status).toBe(401);
    expect((await as(role, 'DELETE', 'panel-a/hosts/h-1')).status).toBe(401);
    // The v1 handoff route is gone: a role token's PUT is refused by scope before any route.
    expect((await as(role, 'PUT', 'panel-a/handoff', { roleContractVersion: 1 })).status).toBe(401);
    expect(panel.writes).toEqual([]);
    await markBackendSetUp(t, serverId);
    const manager = await token(t, ['admin:servers:manage']);
    expect((await as(manager, 'POST', 'panel-a/hosts', NEW_HOST)).status).toBe(200);
    expect(scopeFor(['panel-a', 'hosts'], 'POST')).toBe('admin:servers:manage');
    expect(scopeFor(['panel-a', 'ops', 'x', 'observe'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['panel-a', 'ops', 'x', 'recover'], 'POST')).toBe('admin:servers:manage');
  });
});

describe('Hosts', () => {
  test('create: sent once, seen, owned, claims released, audited by name only', async () => {
    const { t, call, panel } = await seed();
    const op = await (await call('POST', 'panel-a/hosts', NEW_HOST)).json();
    expect(op).toMatchObject({ kind: 'host', verb: 'create', state: 'done', open: false });
    expect(panel.writes).toEqual(['POST /api/hosts']);
    expect(panel.hosts.at(-1)).toMatchObject({ remark: 'node-one-alt', sni: 'b.example' });
    expect(await claims(t)).toEqual([]);
    const cached = await t.run((ctx) => ctx.db.query('panelHosts').collect());
    expect(cached.map((h) => h.remark)).toContain('node-one-alt');
    const owned = await t.run((ctx) => ctx.db.query('panelOwnership').collect());
    expect(owned).toMatchObject([{ kind: 'host', state: 'owned' }]);
    expect(await auditOf(t, 'servers.host.create')).toEqual([
      { backendSlug: 'panel-a', label: 'node-one-alt', outcome: 'done' },
    ]);
  });

  test('a LOST create response is settled by looking: adopted, never sent twice', async () => {
    const { t, call, panel } = await seed();
    panel.fault = { status: 504, apply: 'now' };
    const op = await (await call('POST', 'panel-a/hosts', NEW_HOST)).json();
    // The gateway said 504, the backend had created it: the look right after finds it.
    expect(op).toMatchObject({ state: 'done', request: 'uncertain', panelState: 'observed' });
    expect(panel.writes).toEqual(['POST /api/hosts']);
    expect(panel.hosts.filter((h) => h.remark === 'node-one-alt')).toHaveLength(1);
    expect(await claims(t)).toEqual([]);
  });

  test('the delayed-attempt sequence: no re-send, no opposing write, resolves when the original lands', async () => {
    const { t, call, panel } = await seed();
    panel.fault = { timeout: true, apply: 'later' };
    const first = await (await call('PATCH', 'panel-a/hosts/h-1', { sni: 'x.example' })).json();
    expect(first).toMatchObject({ state: 'outcome_unknown', request: 'uncertain', open: true });
    panel.fault = null;

    // Running it again never sends a second attempt.
    await t.action(internal.panelWrites.run, { opId: first.id as Id<'panelOps'> });
    await t.action(internal.panelWrites.reconcile, {});
    expect(panel.writes).toEqual(['PATCH /api/hosts']);

    // An opposing write to the same Host is refused, however many quiet looks pass.
    const opposing = await call('PATCH', 'panel-a/hosts/h-1', { sni: 'y.example' });
    expect(opposing.status).toBe(409);
    expect((await opposing.json()).error.code).toBe('servers.op_uncertain');
    expect(panel.writes).toEqual(['PATCH /api/hosts']);
    expect(panel.hosts[0].sni).toBe('a.example');

    // The original finally lands. Nothing else was admitted, so it cannot overwrite anything.
    panel.delayed.splice(0).forEach((apply) => apply());
    const settled = await (await call('POST', `panel-a/ops/${first.id}/observe`)).json();
    expect(settled).toMatchObject({ state: 'done', open: false });
    expect(panel.hosts[0].sni).toBe('x.example');
    // Now the next change is welcome.
    expect(
      (await (await call('PATCH', 'panel-a/hosts/h-1', { sni: 'y.example' })).json()).state,
    ).toBe('done');
  });

  test('a gateway 502 while upstream commits stays unknown until the result is seen', async () => {
    const { call, panel } = await seed();
    panel.fault = { status: 502, apply: 'later' };
    const op = await (await call('PATCH', 'panel-a/hosts/h-1', { fingerprint: 'firefox' })).json();
    expect(op).toMatchObject({ state: 'outcome_unknown', open: true });
    panel.fault = null;
    panel.delayed.splice(0).forEach((apply) => apply());
    expect(await (await call('POST', `panel-a/ops/${op.id}/observe`)).json()).toMatchObject({
      state: 'done',
    });
  });

  test('an auth rejection is the one answer that releases at once', async () => {
    const { t, call, panel } = await seed();
    panel.fault = { status: 401, apply: 'never' };
    const op = await (await call('PATCH', 'panel-a/hosts/h-1', { sni: 'x.example' })).json();
    expect(op).toMatchObject({ state: 'refused', open: false, errorCode: 'servers.panel_refused' });
    expect(await claims(t)).toEqual([]);
  });

  test('a create whose identity already exists is adopted without sending; several are refused', async () => {
    const { call, panel } = await seed();
    panel.hosts.push({
      uuid: 'h-pre',
      ...NEW_HOST,
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-1' },
    } as never);
    const adopted = await (await call('POST', 'panel-a/hosts', NEW_HOST)).json();
    expect(adopted).toMatchObject({ state: 'done', errorCode: 'servers.adopted_existing' });
    expect(panel.writes).toEqual([]);
    panel.hosts.push({
      uuid: 'h-pre-2',
      ...NEW_HOST,
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-1' },
    } as never);
    const dup = await (await call('POST', 'panel-a/hosts', NEW_HOST)).json();
    expect(dup).toMatchObject({ state: 'refused', errorCode: 'servers.duplicate_object' });
    expect(panel.writes).toEqual([]);
  });

  test('what belongs to an edge is locked, and its remark pattern cannot be created', async () => {
    const { t, call, serverId, panel } = await seed();
    const { relayId } = await registerRelay(t, { listeners: [realityListener()] });
    void serverId;
    const listener = await t.run(
      async (ctx) =>
        (await ctx.db.query('relayListeners').collect()).find((l) => l.relayId === relayId)!,
    );
    await t.run((ctx) =>
      ctx.db.patch(listener._id, { host: { state: 'present', uuid: 'h-edge', ownership: 'fcp' } }),
    );
    for (const res of [
      await call('PATCH', 'panel-a/hosts/h-edge', { sni: 'x.example' }),
      await call('DELETE', 'panel-a/hosts/h-edge'),
    ])
      expect((await res.json()).error.code).toBe('servers.host_edge_owned');
    const spoof = await call('POST', 'panel-a/hosts', { ...NEW_HOST, remark: 'node-one-relay-zz' });
    expect((await spoof.json()).error.code).toBe('servers.relay_remark');
    expect(panel.writes).toEqual([]);
  });

  test('a delete needs two quiet looks, leaves a tombstone, and is not undone by name', async () => {
    const { t, call, panel } = await seed();
    const op = await (await call('DELETE', 'panel-a/hosts/h-1')).json();
    // One look right after the call is not enough to call something gone.
    expect(op).toMatchObject({ verb: 'delete', open: true, state: 'working' });
    const settled = await (await call('POST', `panel-a/ops/${op.id}/observe`)).json();
    expect(settled).toMatchObject({ state: 'done', open: false });
    expect(panel.hosts.map((h) => h.uuid)).not.toContain('h-1');
    expect(await t.run((ctx) => ctx.db.query('panelOwnership').collect())).toMatchObject([
      { kind: 'host', state: 'tombstoned', panelUuid: 'h-1' },
    ]);
    const again = {
      remark: 'node-one-direct',
      address: '192.0.2.10',
      port: 443,
      inboundUuid: 'i-1',
    };
    expect((await (await call('POST', 'panel-a/hosts', again)).json()).error.code).toBe(
      'servers.tombstoned',
    );
    expect(
      (await (await call('POST', 'panel-a/hosts', { ...again, restore: true })).json()).state,
    ).toBe('done');
  });

  test('clearing the security layer settles: the postcondition expects what the backend will SHOW', async () => {
    const { t, call, panel } = await seed();
    const op = await (await call('PATCH', 'panel-a/hosts/h-1', { securityLayer: null })).json();
    // The provider sends the backend's own default word for "cleared", and the
    // backend reads it back as that word: the op must not wait for a null that
    // will never be seen.
    expect((panel.hosts[0] as { securityLayer?: string }).securityLayer).toBe('DEFAULT');
    expect(op).toMatchObject({ state: 'done', panelState: 'observed', open: false });
    expect(await claims(t)).toEqual([]);
  });

  test('reorder, validation and unknown references', async () => {
    const { call, panel } = await seed();
    const op = await (
      await call('POST', 'panel-a/hosts/reorder', { hostUuids: ['h-edge', 'h-1'] })
    ).json();
    expect(op.state).toBe('done');
    expect(panel.hosts.find((h) => h.uuid === 'h-edge')!.viewPosition).toBe(1);
    expect((await call('POST', 'panel-a/hosts/reorder', { hostUuids: ['h-1'] })).status).toBe(400);
    expect((await call('POST', 'panel-a/hosts', { ...NEW_HOST, port: 70000 })).status).toBe(400);
    expect((await call('POST', 'panel-a/hosts', { ...NEW_HOST, alpn: 'spdy' })).status).toBe(400);
    const unknown = await call('POST', 'panel-a/hosts', { ...NEW_HOST, inboundUuid: 'i-nope' });
    expect((await unknown.json()).error.code).toBe('servers.unknown_inbound');
    expect((await call('PATCH', 'panel-a/hosts/h-nope', { sni: 'x.example' })).status).toBe(404);
  });
});

describe('squads', () => {
  test('create and rename queue no node work and take no profile claim', async () => {
    const { t, call } = await seed();
    const made = await (
      await call('POST', 'panel-a/squads', { name: 'paid', inboundUuids: ['i-1'] })
    ).json();
    expect(made).toMatchObject({ state: 'done', asyncEffect: 'none' });
    const renamed = await (await call('PATCH', 'panel-a/squads/s-1', { name: 'free-b' })).json();
    expect(renamed).toMatchObject({ state: 'done', asyncEffect: 'none' });
    const all = await ops(t);
    expect(all.flatMap((o) => o.claimKeys).some((k) => k.startsWith('profile:'))).toBe(false);
    expect(
      (await (await call('POST', 'panel-a/squads', { name: 'paid', inboundUuids: [] })).json())
        .error.code,
    ).toBe('servers.squad_name_taken');
  });

  test('changing transports claims the profile and its nodes; the mode group row alone never releases them', async () => {
    const { t, call, serverId, panel } = await seed();
    const op = await (
      await call('PATCH', 'panel-a/squads/s-1', { inboundUuids: ['i-1', 'i-2'] })
    ).json();
    // The backend row already shows the change, but the node has not applied yet.
    expect(panel.squads[0].inbounds.map((i) => i.uuid)).toEqual(['i-1', 'i-2']);
    expect(op).toMatchObject({
      panelState: 'observed',
      asyncEffect: 'pending',
      state: 'waiting_for_nodes',
      open: true,
    });
    const held = (await claims(t)).map((c) => c.key).sort();
    expect(held).toEqual(
      [claimKey.node('n-1'), claimKey.profile('p-1'), claimKey.squad('s-1')].sort(),
    );

    // A competing change on the same mode group is refused, and another workflow sees the node claim.
    expect(
      (await (await call('PATCH', 'panel-a/squads/s-1', { name: 'x-y' })).json()).error.code,
    ).toBe('servers.op_running');
    await expect(
      t.run((ctx) => assertNoPanelClaim(ctx.db, serverId, [claimKey.node('n-1')])),
    ).rejects.toThrow(/op_running/);

    // Looking again changes nothing while the node's clock has not moved...
    expect((await (await call('POST', `panel-a/ops/${op.id}/observe`)).json()).open).toBe(true);
    // ...and releases once it has.
    panel.nodes[0].lastStatusChange = 't1';
    expect(await (await call('POST', `panel-a/ops/${op.id}/observe`)).json()).toMatchObject({
      state: 'done',
      asyncEffect: 'complete',
      open: false,
    });
    expect(await claims(t)).toEqual([]);
  });

  test('a mode group members are issued into, or that has members, is not deleted', async () => {
    const { t, call, panel } = await seed();
    expect((await (await call('DELETE', 'panel-a/squads/s-busy')).json()).error.code).toBe(
      'servers.squad_has_members',
    );
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['s-1'] }),
        updatedAt: Date.now(),
      }),
    );
    expect((await (await call('DELETE', 'panel-a/squads/s-1')).json()).error.code).toBe(
      'servers.squad_in_placement',
    );
    expect(
      (await (await call('PATCH', 'panel-a/squads/s-1', { inboundUuids: [] })).json()).error.code,
    ).toBe('servers.squad_in_placement');
    expect(panel.writes).toEqual([]);
  });
});

describe('claims, interruption and recovery', () => {
  test('the owner path needs EXACT coverage: a missing required claim fails, it does not pass by vacuity', async () => {
    const { t, call, serverId, panel } = await seed();
    panel.fault = { timeout: true, apply: 'never' };
    const op = await (await call('PATCH', 'panel-a/hosts/h-1', { sni: 'x.example' })).json();
    const owner = { opId: op.id as Id<'panelOps'>, generation: 1 };
    const check = (keys: string[], o?: typeof owner) =>
      t.run((ctx) => assertNoPanelClaim(ctx.db, serverId, keys, o));
    await expect(check([claimKey.host('h-1')], owner)).resolves.toBeFalsy();
    await expect(check([claimKey.host('h-1'), claimKey.profile('p-1')], owner)).rejects.toThrow(
      /claim_not_held/,
    );
    await expect(check([claimKey.host('h-1')], { ...owner, generation: 2 })).rejects.toThrow(
      /claim_not_held/,
    );
    await expect(check([claimKey.host('h-1')])).rejects.toThrow(/op_running/);
    await expect(check([claimKey.host('h-other')])).resolves.toBeFalsy();
  });

  test('an op that never sent is released; one interrupted mid-call becomes unknown', async () => {
    const { t, serverId, panel } = await seed();
    const { opId: neverSent } = await t.mutation(internal.panelWrites.requestHostUpdate, {
      backendServerId: serverId,
      hostUuid: 'h-1',
      sni: 'x.example',
    });
    const { opId: midCall } = await t.mutation(internal.panelWrites.requestHostUpdate, {
      backendServerId: serverId,
      hostUuid: 'h-edge',
      sni: 'y.example',
    });
    await t.mutation(internal.panelLedger.markSent, { opId: midCall, attemptId: 'a-1' });
    await t.run(async (ctx) => {
      for (const id of [neverSent, midCall])
        await ctx.db.patch(id, { updatedAt: Date.now() - 10 * 60_000 });
    });
    await t.action(internal.panelWrites.reconcile, {});
    const byId = new Map((await ops(t)).map((o) => [o._id, o]));
    expect(byId.get(neverSent)).toMatchObject({
      open: false,
      request: 'rejected_pre_mutation',
      errorCode: 'servers.never_sent',
    });
    expect(byId.get(midCall)).toMatchObject({ open: true, request: 'uncertain' });
    expect(panel.writes).toEqual([]);
  });

  test('a recovery needs every condition, and a fresh look may settle it first', async () => {
    const { t, call, panel } = await seed();
    panel.fault = { timeout: true, apply: 'never' };
    const op = await (await call('PATCH', 'panel-a/hosts/h-1', { sni: 'x.example' })).json();
    panel.fault = null;
    const partial = await call('POST', `panel-a/ops/${op.id}/recover`, {
      credentialsRevoked: true,
      noInFlightExecutor: true,
      queueDrained: false,
    });
    expect((await partial.json()).error.code).toBe('servers.recovery_incomplete');
    expect((await claims(t)).length).toBe(1);
    const done = await (
      await call('POST', `panel-a/ops/${op.id}/recover`, {
        credentialsRevoked: true,
        noInFlightExecutor: true,
        queueDrained: true,
        note: 'token revoked in the backend, queue inspected',
      })
    ).json();
    expect(done).toMatchObject({ state: 'recovered', open: false, recovered: true });
    expect(await claims(t)).toEqual([]);
    expect((await auditOf(t, 'servers.host.update')).at(-1)).toMatchObject({
      outcome: 'recovered',
    });
    const list = await (await call('GET', 'panel-a/ops')).json();
    expect(list.ops[0]).toMatchObject({ id: op.id, state: 'recovered' });
  });
});
