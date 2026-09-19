/// <reference types="vite/client" />
/**
 * The node role's reservations.
 *
 *  - the role's own token (`admin:servers:write`) may reserve and settle, and
 *    nothing else here; releasing an unanswered reservation is an operator's;
 *  - a tombstoned identity is refused by name, an existing one is refused, a
 *    second run cannot reserve what another holds, the same call twice is the
 *    same answer;
 *  - while a reservation is open FCP does not create that identity, even with
 *    "I want it back";
 *  - a reservation never times out: it closes when the role settles it, when
 *    FCP SEES the object on the panel, or by the attested recovery.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { sha256Hex } from './lib/crypto';
import { scopeFor } from './httpServers';
import { insertPanelServer } from './lib/edges/testing/fixtures';

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

interface Panel {
  nodes: { uuid: string; name: string }[];
  squads: { uuid: string; name: string }[];
  writes: string[];
}

function installPanel(): Panel {
  const panel: Panel = { nodes: [{ uuid: 'n-1', name: 'node-one' }], squads: [], writes: [] };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const inbounds = [{ uuid: 'i-1', tag: 'in-1' }];
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
      ],
    },
    inbounds,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      if (method !== 'GET') {
        panel.writes.push(`${method} ${path}`);
        if (path === '/api/internal-squads') {
          const body = JSON.parse(init.body as string);
          const made = { uuid: `s-${panel.squads.length + 1}`, name: body.name };
          panel.squads.push(made);
          return json({ ...made, inbounds: [], info: { membersCount: 0 } }, 201);
        }
        return json({});
      }
      if (path === '/api/nodes')
        return json(
          panel.nodes.map((n) => ({
            ...n,
            address: '192.0.2.10',
            port: 2222,
            isConnected: true,
            isDisabled: false,
            configProfile: { activeConfigProfileUuid: 'p-1', activeInbounds: inbounds },
          })),
        );
      if (path === '/api/hosts') return json([]);
      if (path === '/api/internal-squads')
        return json({
          internalSquads: panel.squads.map((s) => ({
            ...s,
            inbounds: [],
            info: { membersCount: 0 },
          })),
        });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile] });
      if (path === '/api/config-profiles/p-1') return json(profile);
      return json({});
    }),
  );
  return panel;
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

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  const refresh = () => t.action(internal.panelObserve.refresh, { backendServerId: serverId });
  await refresh();
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await t.mutation(internal.panelLedger.reportHandoff, {
    backendServerId: serverId,
    roleContractVersion: 1,
  });
  const role = await token(t, ['admin:servers:read', 'admin:servers:write']);
  const manager = await token(t, ['admin:servers:read', 'admin:servers:manage']);
  const as = (tok: string) => async (method: string, path: string, body?: unknown) => {
    const res = await t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tok}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };
  return { t, serverId, panel, refresh, role: as(role), manager: as(manager) };
}

const ownership = (t: T) => t.run((ctx) => ctx.db.query('panelOwnership').collect());
const ATTESTED = {
  credentialsRevoked: true,
  noInFlightExecutor: true,
  queueDrained: true,
  freshReadAt: 1,
};

describe('reserving', () => {
  test('the role reserves an absent identity, once; a retry of the same call is the same answer', async () => {
    const { t, role } = await seed();
    const body = { roleOpId: 'run-0001:node', kind: 'node', identity: 'node-two' };
    expect((await role('POST', 'reservations', body)).body).toEqual({
      ok: true,
      roleOpId: 'run-0001:node',
      state: 'reserved',
    });
    expect((await role('POST', 'reservations', body)).body.state).toBe('reserved');
    expect((await ownership(t)).length).toBe(1);
    // The same id for something else is a bug in the caller.
    const other = await role('POST', 'reservations', { ...body, identity: 'node-three' });
    expect(other.body.error.code).toBe('servers.reservation_conflict');
    // Another run does not get what this one holds.
    const second = await role('POST', 'reservations', { ...body, roleOpId: 'run-0002:node' });
    expect(second.body.error.code).toBe('servers.reservation_open');
    expect((await role('GET', 'reservations')).body.reservations).toMatchObject([
      { roleOpId: 'run-0001:node', kind: 'node', label: 'node-two' },
    ]);
  });

  test('what exists is looked up, not created; an inbound is found by its tag on any profile', async () => {
    const { role } = await seed();
    const node = await role('POST', 'reservations', {
      roleOpId: 'run-0001:n',
      kind: 'node',
      identity: 'node-one',
    });
    expect(node.body.error.code).toBe('servers.exists');
    const inbound = await role('POST', 'reservations', {
      roleOpId: 'run-0001:i',
      kind: 'inbound',
      identity: 'in-1',
    });
    expect(inbound.body.error.code).toBe('servers.exists');
    const bad = await role('POST', 'reservations', { roleOpId: 'x', kind: 'node', identity: 'n' });
    expect(bad.body.error.code).toBe('validation');
  });

  test('a tombstone refuses the role by name, including a name the object used to have', async () => {
    const { t, serverId, role } = await seed();
    await t.run((ctx) =>
      ctx.db.insert('panelOwnership', {
        backendServerId: serverId,
        kind: 'squad',
        identity: 'pool-b',
        lookup: ['pool-a', 'pool-b'],
        panelUuid: 's-gone',
        state: 'tombstoned',
        since: 1,
        updatedAt: 1,
      }),
    );
    for (const identity of ['pool-a', 'pool-b']) {
      const res = await role('POST', 'reservations', {
        roleOpId: `run-0001:${identity}`,
        kind: 'squad',
        identity,
      });
      expect(res.body.error.code).toBe('servers.tombstoned');
    }
  });

  test('a Host is reserved by its parts, and listed by its remark only', async () => {
    const { role } = await seed();
    const host = { remark: 'node-one-alt', inboundUuid: 'i-1', address: '192.0.2.11', port: 8443 };
    const res = await role('POST', 'reservations', { roleOpId: 'run-0001:h', kind: 'host', host });
    expect(res.body.state).toBe('reserved');
    const listed = (await role('GET', 'reservations')).body.reservations;
    expect(listed[0].label).toBe('node-one-alt');
    expect(JSON.stringify(listed)).not.toContain('192.0.2.11');
  });
});

describe('FCP and an open reservation', () => {
  test('FCP does not create a reserved identity, even with "I want it back"', async () => {
    const { role, manager, panel } = await seed();
    await role('POST', 'reservations', {
      roleOpId: 'run-0001:sq',
      kind: 'squad',
      identity: 'pool-new',
    });
    for (const restore of [false, true]) {
      const res = await manager('POST', 'squads', {
        name: 'pool-new',
        inboundUuids: ['i-1'],
        restore,
      });
      expect(res.body.error.code).toBe('servers.reservation_open');
    }
    expect(panel.writes).toEqual([]);
  });

  test('the role does not get an identity FCP is creating right now', async () => {
    const { t, serverId, role } = await seed();
    // Claimed, not sent yet: exactly the window a role run could race into.
    await t.mutation(internal.panelWrites.requestSquadCreate, {
      backendServerId: serverId,
      name: 'pool-c',
      inboundUuids: ['i-1'],
    });
    const res = await role('POST', 'reservations', {
      roleOpId: 'run-0001:c',
      kind: 'squad',
      identity: 'Pool-C',
    });
    expect(res.body.error.code).toBe('servers.op_running');
  });
});

describe('closing a reservation', () => {
  test('settled as created: owned under the panel uuid; settled as refused: forgotten', async () => {
    const { t, role } = await seed();
    await role('POST', 'reservations', { roleOpId: 'run-0001:a', kind: 'squad', identity: 'a1' });
    await role('POST', 'reservations', { roleOpId: 'run-0001:b', kind: 'squad', identity: 'b1' });
    expect((await role('PUT', 'reservations/run-0001:a', { created: 's-9' })).body.state).toBe(
      'owned',
    );
    expect(
      (await role('PUT', 'reservations/run-0001:b', { rejected_pre_mutation: true })).body.state,
    ).toBe('released');
    expect((await role('PUT', 'reservations/run-0001:a', {})).status).toBe(400);
    const rows = await ownership(t);
    expect(rows.map((r) => [r.identity, r.state, r.panelUuid])).toEqual([['a1', 'owned', 's-9']]);
    expect(rows[0].reservation).toBeUndefined();
  });

  test('a lost answer never times out: the reservation closes when FCP sees the object', async () => {
    const { t, role, panel, refresh } = await seed();
    await role('POST', 'reservations', {
      roleOpId: 'run-0001:n2',
      kind: 'node',
      identity: 'node-two',
    });
    vi.useFakeTimers({ now: Date.now() + 90 * 24 * 3_600_000, toFake: ['Date'] });
    try {
      await refresh();
      expect((await ownership(t))[0].state).toBe('reserved');
      // The run did create it; its answer to FCP was lost.
      panel.nodes.push({ uuid: 'n-2', name: 'node-two' });
      await refresh();
    } finally {
      vi.useRealTimers();
    }
    expect((await ownership(t))[0]).toMatchObject({ state: 'owned', panelUuid: 'n-2' });
  });

  test('releasing an unanswered one is an operator attesting each condition, not the role', async () => {
    const { t, role, manager } = await seed();
    await role('POST', 'reservations', { roleOpId: 'run-0001:z', kind: 'squad', identity: 'z1' });
    expect((await role('POST', 'reservations/run-0001:z/recover', ATTESTED)).status).toBe(401);
    const partial = await manager('POST', 'reservations/run-0001:z/recover', {
      ...ATTESTED,
      queueDrained: false,
    });
    expect(partial.body.error.code).toBe('servers.recovery_incomplete');
    const undated = await manager('POST', 'reservations/run-0001:z/recover', {
      ...ATTESTED,
      freshReadAt: undefined,
    });
    expect(undated.status).toBe(400);
    expect((await manager('POST', 'reservations/run-0001:z/recover', ATTESTED)).body.ok).toBe(true);
    expect(await ownership(t)).toEqual([]);
    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'servers.reservation.recover'))
        .collect(),
    );
    expect(audit.map((r) => r.payload)).toEqual([{ backendSlug: 'panel-a', kind: 'squad' }]);
  });

  test('scopes', () => {
    const both = ['admin:servers:write', 'admin:servers:manage'];
    expect(scopeFor(['panel-a', 'reservations'], 'POST')).toEqual(both);
    expect(scopeFor(['panel-a', 'reservations', 'r'], 'PUT')).toEqual(both);
    expect(scopeFor(['panel-a', 'reservations', 'r', 'recover'], 'POST')).toBe(
      'admin:servers:manage',
    );
    expect(scopeFor(['panel-a', 'reservations'], 'GET')).toBe('admin:servers:read');
  });
});
