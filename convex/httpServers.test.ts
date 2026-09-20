/// <reference types="vite/client" />
/**
 * Server management, read half: backend observation (`backendObserve`) and the
 * admin surface over it (`/api/v1/admin/servers/*`).
 *
 *  - DORMANT by default: the healthcheck makes no observation call until
 *    `servers.manage.observe` is on, and a failing look never marks the
 *    instance unhealthy nor stores the provider's message.
 *  - The caches follow the backend: a row the backend stopped listing is deleted,
 *    a moved change token is stamped (a token made with another key is not).
 *  - NOTHING secret is stored or served: no private key, short id, client or
 *    certificate, in any `backend*` row, any response, or any audit row.
 *  - Auth: read scope for the tree, settings scope for the switches; the
 *    sealing policy covers every verb.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import { sha256Hex } from './lib/crypto';
import { routePolicy } from '../src/shared/crypto/envelope';
import {
  PlacementValidation,
  ServerConfigView,
  ServerSummary,
  ServerTree,
} from '../src/shared/contracts/servers';
import { scopeFor } from './httpServers';
import { insertPanelServer } from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;

const PRIVATE_KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)))
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');
const SECRETS = [PRIVATE_KEY, 'deadbeef00112233', 'client-uuid-1', 'CERT_PEM_BODY'];

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

// --- a mutable fake backend --------------------------------------------------------------------

interface FakePanel {
  names: string[];
  shortIds: string[];
  hosts: Record<string, unknown>[];
  nodes: Record<string, unknown>[];
  fail: boolean;
  calls: string[];
}

const newPanel = (): FakePanel => ({
  names: ['a.example', 'b.example'],
  shortIds: ['deadbeef00112233'],
  hosts: [
    {
      uuid: 'h-1',
      remark: 'node-one-reality',
      address: '192.0.2.10',
      port: 443,
      sni: 'a.example',
      fingerprint: 'chrome',
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-reality' },
    },
    {
      uuid: 'h-orphan',
      remark: 'points-nowhere',
      address: '192.0.2.99',
      port: 443,
      inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-unserved' },
    },
  ],
  nodes: [
    {
      uuid: 'n-1',
      name: 'node-one',
      address: '192.0.2.10',
      port: 2222,
      countryCode: 'NL',
      isConnected: true,
      isDisabled: false,
      usersOnline: 4,
      configProfile: {
        activeConfigProfileUuid: 'p-1',
        activeInbounds: [{ uuid: 'i-reality', tag: 'reality-in' }],
      },
    },
  ],
  fail: false,
  calls: [],
});

function installPanel(panel: FakePanel) {
  const profile = () => ({
    uuid: 'p-1',
    name: 'Default',
    config: {
      inbounds: [
        {
          tag: 'reality-in',
          port: 443,
          protocol: 'vless',
          settings: { clients: [{ id: 'client-uuid-1' }], decryption: 'none' },
          streamSettings: {
            network: 'tcp',
            security: 'reality',
            realitySettings: {
              target: 'target.example:443',
              serverNames: panel.names,
              privateKey: PRIVATE_KEY,
              shortIds: panel.shortIds,
            },
          },
        },
        {
          tag: 'unserved-in',
          port: 8443,
          protocol: 'trojan',
          settings: { clients: [] },
          streamSettings: {
            security: 'tls',
            tlsSettings: {
              serverName: 'c.example',
              certificates: [{ certificate: ['CERT_PEM_BODY'] }],
            },
          },
        },
      ],
    },
    inbounds: [
      { uuid: 'i-reality', tag: 'reality-in' },
      { uuid: 'i-unserved', tag: 'unserved-in' },
    ],
  });
  const json = (o: unknown) =>
    new Response(JSON.stringify({ response: o }), {
      headers: { 'content-type': 'application/json' },
    });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      panel.calls.push(path);
      if (panel.fail) return new Response(`boom ${PRIVATE_KEY}`, { status: 500 });
      if (path === '/api/nodes') return json(panel.nodes);
      if (path === '/api/hosts') return json(panel.hosts);
      if (path === '/api/internal-squads')
        return json({
          internalSquads: [
            {
              uuid: 's-1',
              name: 'free',
              inbounds: [{ uuid: 'i-reality', tag: 'reality-in' }],
              info: { membersCount: 3 },
            },
            { uuid: 's-empty', name: 'empty-squad', inbounds: [] },
          ],
        });
      if (path === '/api/config-profiles') return json({ configProfiles: [profile()] });
      if (path === '/api/config-profiles/p-1') return json(profile());
      // The healthcheck's own probes: healthy, nothing of interest.
      return json({});
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

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const cookie = await adminCookie(t);
  const panel = newPanel();
  installPanel(panel);
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
  return { t, serverId, cookie, panel, call };
}

const allPanelRows = (t: T) =>
  t.run(async (ctx) => ({
    nodes: await ctx.db.query('panelNodes').collect(),
    profiles: await ctx.db.query('panelProfiles').collect(),
    hosts: await ctx.db.query('panelHosts').collect(),
    squads: await ctx.db.query('panelSquads').collect(),
    state: await ctx.db.query('panelObserveState').collect(),
  }));

describe('backend observation', () => {
  test('dormant by default: the healthcheck makes no observation call', async () => {
    const { t, panel } = await seed();
    await t.action(internal.backendServers.healthcheck, {});
    expect(panel.calls).not.toContain('/api/config-profiles');
    expect(panel.calls).not.toContain('/api/hosts');
    expect((await allPanelRows(t)).state).toEqual([]);
  });

  test('switched on, the healthcheck fills the caches', async () => {
    const { t, panel } = await seed();
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.observe': true } });
    await t.action(internal.backendServers.healthcheck, {});
    expect(panel.calls).toContain('/api/config-profiles/p-1');
    const rows = await allPanelRows(t);
    expect(rows.nodes.map((n) => n.name)).toEqual(['node-one']);
    expect(rows.profiles[0].inbounds.map((i) => i.tag)).toEqual(['reality-in', 'unserved-in']);
    expect(rows.hosts).toHaveLength(2);
    expect(rows.squads.map((s) => s.name).sort()).toEqual(['empty-squad', 'free']);
    expect(rows.state[0]).toMatchObject({
      ok: true,
      counts: { nodes: 1, profiles: 1, hosts: 2, squads: 2 },
    });
  });

  test('no secret is stored', async () => {
    const { t, serverId } = await seed();
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const blob = JSON.stringify(await allPanelRows(t));
    for (const s of SECRETS) expect(blob).not.toContain(s);
    expect(blob).not.toContain('clients');
  });

  test('the caches follow the backend, and a moved change token is stamped', async () => {
    const { t, serverId, panel } = await seed();
    const look = () => t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    await look();
    let rows = await allPanelRows(t);
    const token0 = rows.profiles[0].changeToken;
    expect(rows.profiles[0].tokenChangedAt).toBeUndefined();

    // Nothing changed: nothing is stamped.
    await look();
    rows = await allPanelRows(t);
    expect(rows.profiles[0].changeToken).toBe(token0);
    expect(rows.profiles[0].tokenChangedAt).toBeUndefined();

    // A secret-only change (short ids) moves the token but not the shape hash.
    const shape0 = rows.profiles[0].shapeHash;
    panel.shortIds = ['ffffffff00000000'];
    panel.hosts = panel.hosts.slice(0, 1);
    await look();
    rows = await allPanelRows(t);
    expect(rows.profiles[0].changeToken).not.toBe(token0);
    expect(rows.profiles[0].shapeHash).toBe(shape0);
    expect(rows.profiles[0].tokenChangedAt).toBeGreaterThan(0);
    // The Host the backend stopped listing is gone.
    expect(rows.hosts.map((h) => h.hostUuid)).toEqual(['h-1']);
  });

  test('a token made with another key is a new baseline, not a change', async () => {
    const { t, serverId } = await seed();
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'another-deployment');
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const [p] = (await allPanelRows(t)).profiles;
    expect(p.tokenChangedAt).toBeUndefined();
  });

  test('a failing look keeps the last snapshot, stores a code word, and never the message', async () => {
    const { t, serverId, panel } = await seed();
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    panel.fail = true;
    await expect(
      t.action(internal.backendObserve.refresh, { backendServerId: serverId }),
    ).rejects.toThrow(/panel_read_failed/);
    const rows = await allPanelRows(t);
    expect(rows.nodes).toHaveLength(1);
    expect(rows.state[0]).toMatchObject({ ok: false, errorCode: 'servers.observe_failed' });
    expect(rows.state[0].observedAt).toBeGreaterThan(0);
    expect(JSON.stringify(rows.state)).not.toContain(PRIVATE_KEY);
  });

  test('a failing look inside the healthcheck does not mark the instance unhealthy', async () => {
    const { t, serverId, panel } = await seed();
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.observe': true } });
    const real = globalThis.fetch;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
        if (path.startsWith('/api/config-profiles')) return new Response('x', { status: 500 });
        return real(input as never);
      }),
    );
    void panel;
    const out = await t.action(internal.backendServers.healthcheck, {});
    expect(out).toEqual({ checked: 1, healthy: 1 });
    const server = await t.run((ctx) => ctx.db.get(serverId));
    expect(server!.lastHealthOkAt).toBeGreaterThan(0);
  });

  test('an Outline instance has nothing to observe', async () => {
    const { t } = await seed();
    const outline = await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    await expect(
      t.action(internal.backendObserve.refresh, { backendServerId: outline }),
    ).rejects.toThrow(/unsupported_backend/);
  });
});

describe('/api/v1/admin/servers', () => {
  test('the tree shows what already exists: node -> profile -> transports -> Hosts + mode groups', async () => {
    const { call } = await seed();
    const res = await call('POST', 'panel-a/refresh');
    expect(res.status).toBe(200);
    const tree = ServerTree.parse(await res.json());
    expect(tree.state.ok).toBe(true);
    const [node] = tree.nodes;
    expect(node).toMatchObject({ name: 'node-one', online: true, usersOnline: 4 });
    expect(node.profile).toMatchObject({ name: 'Default', transportCount: 2 });
    // Only the transports the node SERVES hang off it.
    expect(node.transports.map((i) => i.tag)).toEqual(['reality-in']);
    expect(node.transports[0]).toMatchObject({
      security: 'reality',
      serverNames: ['a.example', 'b.example'],
      realityTarget: 'target.example:443',
      realityPublicKeyMismatch: false,
    });
    expect(node.transports[0].realityPublicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(node.transports[0].addresses.map((h) => h.remark)).toEqual(['node-one-reality']);
    expect(node.transports[0].modeGroups).toEqual([{ groupUuid: 's-1', name: 'free' }]);
    // A Host on a transport no node serves is what an operator must notice.
    expect(tree.unattached).toEqual({ profiles: [], addresses: ['points-nowhere'] });
    // GET serves the same thing from the cache, with no backend call.
    const cached = ServerTree.parse(await (await call('GET', 'panel-a/tree')).json());
    expect(cached.nodes[0].transports[0].serverNames).toEqual(['a.example', 'b.example']);
  });

  test('no response carries a secret', async () => {
    const { call } = await seed();
    const bodies = [
      await (await call('POST', 'panel-a/refresh')).text(),
      await (await call('GET', 'panel-a/tree')).text(),
      await (await call('GET', 'summary')).text(),
    ].join('\n');
    for (const s of SECRETS) expect(bodies).not.toContain(s);
  });

  test('summary lists every instance and whether it can be observed', async () => {
    const { t, call } = await seed();
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    await call('POST', 'panel-a/refresh');
    const s = ServerSummary.parse(await (await call('GET', 'summary')).json());
    expect(s.config).toEqual({ 'manage.enabled': false, 'manage.observe': false });
    expect(s.instances.map((i) => [i.slug, i.observable, i.ok])).toEqual([
      ['outline-a', false, null],
      ['panel-a', true, true],
    ]);
  });

  test('a backend that cannot be read is a 502 with a code, never the backend text', async () => {
    const { call, panel } = await seed();
    panel.fail = true;
    const res = await call('POST', 'panel-a/refresh');
    expect(res.status).toBe(502);
    const text = await res.text();
    expect(text).toContain('backend.panel_read_failed');
    expect(text).not.toContain(PRIVATE_KEY);
  });

  test('the switches: settings scope, audited by name only', async () => {
    const { t, call } = await seed();
    const res = await call('PATCH', 'config', { 'manage.observe': true, bogus: 1 });
    expect(await res.json()).toEqual({ changedKeys: ['manage.observe'] });
    const view = ServerConfigView.parse(await (await call('GET', 'config')).json());
    expect(view.config['manage.observe']).toBe(true);
    const audit = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (a) => a.action === 'servers.config.update',
      ),
    );
    expect(audit.map((a) => a.payload)).toEqual([{ changedKeys: ['manage.observe'] }]);
  });

  test('placement validation answers in counts and names, never the pasted uuids', async () => {
    const { t, call } = await seed();
    await call('POST', 'panel-a/refresh');
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-reality',
        backend: 'remnawave',
        config: JSON.stringify({
          squadUuids: ['s-1', 's-empty', '99999999-9999-4999-8999-999999999999'],
        }),
        updatedAt: Date.now(),
      }),
    );
    const res = await call('POST', 'panel-a/placements/validate');
    const text = await res.text();
    expect(PlacementValidation.parse(JSON.parse(text)).modes).toEqual([
      {
        modeSlug: 'freedom-reality',
        modeGroups: 3,
        unknownHere: 1,
        withoutTransports: ['empty-squad'],
      },
    ]);
    expect(text).not.toContain('99999999');
  });

  test('auth: anonymous is refused; read scope reads; the switches need the settings scope', async () => {
    const { t } = await seed();
    const as = (tok: string | null, method: string, path: string, body?: unknown) =>
      t.fetch(`/api/v1/admin/servers/${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          ...(tok ? { authorization: `Bearer ${tok}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    expect((await as(null, 'GET', 'summary')).status).toBe(401);
    const reader = await token(t, ['admin:servers:read']);
    expect((await as(reader, 'GET', 'summary')).status).toBe(200);
    expect((await as(reader, 'GET', 'panel-a/tree')).status).toBe(200);
    expect((await as(reader, 'GET', 'config')).status).toBe(401);
    expect((await as(reader, 'PATCH', 'config', { 'manage.observe': true })).status).toBe(401);
    const settings = await token(t, ['admin:settings:write']);
    expect((await as(settings, 'PATCH', 'config', { 'manage.observe': true })).status).toBe(200);
    expect((await as(settings, 'GET', 'summary')).status).toBe(401);
    expect((await as(reader, 'GET', 'nope/nope/nope')).status).toBe(404);
    expect((await as(reader, 'GET', 'missing-slug/tree')).status).toBe(404);
  });

  test('scope map and sealing policy cover every verb', () => {
    expect(scopeFor(['config'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['config'], 'PATCH')).toBe('admin:settings:write');
    expect(scopeFor(['panel-a', 'tree'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['panel-a', 'refresh'], 'POST')).toBe('admin:servers:read');
    for (const m of ['GET', 'POST', 'PATCH'])
      expect(routePolicy('/api/v1/admin/servers/panel-a/tree', m)).toBeDefined();
  });
});
