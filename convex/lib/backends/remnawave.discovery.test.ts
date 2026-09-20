/**
 * The two Remnawave ops the edges autopilot rests on: the Host disable bit
 * (`PATCH /api/hosts { uuid, isDisabled }` and nothing else) and node inbound
 * discovery (`GET /api/nodes` + `GET /api/config-profiles/{uuid}`, joined by
 * tag, allowlisted fields only). The redaction assertions here are the guard
 * that a config profile's private key, short ids, clients and certificate
 * material can never leave the provider.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  projectXrayInbound,
  remnawaveListNodeInbounds,
  remnawaveSetHostDisabled,
  type RemnawaveConfig,
} from './remnawave';

const cfg: RemnawaveConfig = { baseUrl: 'https://panel.internal', apiToken: 'SECRET_TOKEN' };

interface Captured {
  path: string;
  method: string;
  body: Record<string, unknown> | undefined;
}
let calls: Captured[] = [];

function mockFetch(handler: (path: string, method: string) => Response): void {
  calls = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      const method = (init.method ?? 'GET').toUpperCase();
      calls.push({
        path: url.pathname,
        method,
        body: init.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : undefined,
      });
      return handler(url.pathname, method);
    }),
  );
}

function jsonRes(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('remnawaveSetHostDisabled', () => {
  test('PATCHes /api/hosts with ONLY { uuid, isDisabled }', async () => {
    mockFetch(() => jsonRes({ response: { uuid: 'h-1', isDisabled: true } }));
    await remnawaveSetHostDisabled(cfg, 'h-1', true);
    expect(calls[0]).toMatchObject({ path: '/api/hosts', method: 'PATCH' });
    // Nothing else travels: the backend omits absent fields, so the address,
    // port, names, inbound and fingerprint stay exactly as they were.
    expect(calls[0].body).toEqual({ uuid: 'h-1', isDisabled: true });
    mockFetch(() => jsonRes({ response: { uuid: 'h-1', isDisabled: false } }));
    await remnawaveSetHostDisabled(cfg, 'h-1', false);
    expect(calls[0].body).toEqual({ uuid: 'h-1', isDisabled: false });
  });

  test('surfaces a backend error without the URL host', async () => {
    mockFetch(() => new Response('nope', { status: 400 }));
    await expect(remnawaveSetHostDisabled(cfg, 'h-1', true)).rejects.toThrow(/400 on \/api\/hosts/);
    await expect(remnawaveSetHostDisabled(cfg, 'h-1', true)).rejects.not.toThrow(/panel\.internal/);
  });
});

// A profile as a 3.x backend returns it: the raw Xray config (with everything an
// operator would put there, secrets included) plus the derived inbound rows
// (`ConfigProfileInboundsSchema`, whose `rawInbound` repeats the whole inbound).
const PROFILE_UUID = '0f1e2d3c-4b5a-4968-8776-655443322110';
const IN_REALITY = '11111111-2222-4333-8444-555555555555';
const IN_WS = '22222222-3333-4444-8555-666666666666';
const IN_VMESS = '33333333-4444-4555-8666-777777777777';
const rawConfig = {
  log: { loglevel: 'none' },
  inbounds: [
    {
      tag: 'VLESS_REALITY',
      port: 443,
      protocol: 'vless',
      settings: {
        clients: [{ id: 'CLIENT_UUID_SECRET', flow: 'xtls-rprx-vision' }],
        decryption: 'none',
      },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          dest: 'decoy.example:443',
          serverNames: ['decoy.example'],
          privateKey: 'PRIVATE_KEY_SECRET',
          shortIds: ['SHORTID_SECRET'],
          fingerprint: 'chrome',
        },
      },
    },
    {
      tag: 'VLESS_WS',
      port: '8443',
      protocol: 'vless',
      settings: { clients: [] },
      streamSettings: {
        network: 'ws',
        security: 'tls',
        tlsSettings: {
          serverName: 'ws.example',
          certificates: [{ certificateFile: '/etc/cert.pem', keyFile: 'KEYFILE_SECRET' }],
        },
        wsSettings: { path: '/ws', headers: { Host: 'ws.example' } },
      },
    },
    {
      tag: 'VMESS_KCP',
      port: '1000-2000',
      protocol: 'vmess',
      settings: { clients: [{ id: 'VMESS_SECRET' }] },
      streamSettings: { network: 'kcp' },
    },
    // Not indexed by the backend (no derived row): nothing a Host could bind to.
    { tag: 'UNINDEXED', port: 9000, protocol: 'vless', settings: { clients: [] } },
    // No tag: skipped.
    { port: 9001, protocol: 'vless' },
  ],
  outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
};
const derived = [
  {
    uuid: IN_REALITY,
    profileUuid: PROFILE_UUID,
    tag: 'VLESS_REALITY',
    type: 'vless',
    network: 'tcp',
    security: 'reality',
    port: 443,
    rawInbound: rawConfig.inbounds[0],
  },
  {
    uuid: IN_WS,
    profileUuid: PROFILE_UUID,
    tag: 'VLESS_WS',
    type: 'vless',
    network: 'ws',
    security: 'tls',
    port: 8443,
    rawInbound: rawConfig.inbounds[1],
  },
  {
    uuid: IN_VMESS,
    profileUuid: PROFILE_UUID,
    tag: 'VMESS_KCP',
    type: 'vmess',
    network: 'kcp',
    security: null,
    port: null,
    rawInbound: rawConfig.inbounds[2],
  },
];
const NODE = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const nodesBody = (configProfile: unknown) => ({
  response: [
    {
      uuid: 'other-node',
      name: 'node-b',
      configProfile: { activeConfigProfileUuid: null, activeInbounds: [] },
    },
    { uuid: NODE, name: 'node-a', isConnected: true, usersOnline: 1, configProfile },
  ],
});
const SECRET_WORDS = [
  'PRIVATE_KEY_SECRET',
  'SHORTID_SECRET',
  'CLIENT_UUID_SECRET',
  'VMESS_SECRET',
  'KEYFILE_SECRET',
  'privateKey',
  'shortIds',
  'clients',
  'certificates',
  'rawInbound',
];
const profileRes = () =>
  jsonRes({ response: { uuid: PROFILE_UUID, name: 'p', config: rawConfig, inbounds: derived } });

describe('remnawaveListNodeInbounds', () => {
  test('joins the node profile with the config by tag; allowlisted fields only', async () => {
    mockFetch((path) => {
      if (path === '/api/nodes')
        return jsonRes(
          nodesBody({
            activeConfigProfileUuid: PROFILE_UUID,
            // Only the REALITY inbound is active on this node.
            activeInbounds: [derived[0]],
          }),
        );
      if (path === `/api/config-profiles/${PROFILE_UUID}`) return profileRes();
      return new Response('not found', { status: 404 });
    });
    const rows = await remnawaveListNodeInbounds(cfg, NODE);
    expect(calls.map((c) => c.path)).toEqual([
      '/api/nodes',
      `/api/config-profiles/${PROFILE_UUID}`,
    ]);
    expect(rows).toEqual([
      {
        tag: 'VLESS_REALITY',
        configProfileUuid: PROFILE_UUID,
        configProfileInboundUuid: IN_REALITY,
        protocol: 'vless',
        port: 443,
        network: 'tcp',
        security: 'reality',
        reality: { target: 'decoy.example:443', serverNames: ['decoy.example'] },
        active: true,
      },
      {
        tag: 'VLESS_WS',
        configProfileUuid: PROFILE_UUID,
        configProfileInboundUuid: IN_WS,
        protocol: 'vless',
        port: 8443,
        network: 'ws',
        security: 'tls',
        tls: { serverName: 'ws.example' },
        ws: { path: '/ws', host: 'ws.example' },
        active: false,
      },
      {
        tag: 'VMESS_KCP',
        configProfileUuid: PROFILE_UUID,
        configProfileInboundUuid: IN_VMESS,
        protocol: 'vmess',
        port: null,
        network: 'kcp',
        security: 'none',
        active: false,
      },
    ]);
    const json = JSON.stringify(rows);
    for (const w of SECRET_WORDS) expect(json).not.toContain(w);
  });

  test('tolerates the configProfileUuid spelling and tag-only active rows', async () => {
    mockFetch((path) =>
      path === '/api/nodes'
        ? jsonRes(
            nodesBody({
              configProfileUuid: PROFILE_UUID,
              activeInbounds: [{ uuid: 'stale', tag: 'VLESS_WS' }],
            }),
          )
        : profileRes(),
    );
    const rows = await remnawaveListNodeInbounds(cfg, NODE);
    expect(rows.map((r) => [r.tag, r.active])).toEqual([
      ['VLESS_REALITY', false],
      ['VLESS_WS', true],
      ['VMESS_KCP', false],
    ]);
  });

  test('no active profile -> [] without a profile fetch; an unknown node throws', async () => {
    mockFetch(() => jsonRes(nodesBody({ activeConfigProfileUuid: null, activeInbounds: [] })));
    expect(await remnawaveListNodeInbounds(cfg, NODE)).toEqual([]);
    expect(calls).toHaveLength(1);
    mockFetch(() => jsonRes(nodesBody(null)));
    expect(await remnawaveListNodeInbounds(cfg, NODE)).toEqual([]);
    mockFetch(() => jsonRes(nodesBody(null)));
    await expect(remnawaveListNodeInbounds(cfg, 'no-such-node')).rejects.toThrow(/node not found/);
  });
});

describe('projectXrayInbound', () => {
  const binding = {
    configProfileUuid: PROFILE_UUID,
    configProfileInboundUuid: IN_REALITY,
    active: true,
  };

  test('reads the allowlist only (the `target` alias, empty names dropped)', () => {
    const out = projectXrayInbound(
      {
        tag: 'R',
        port: 443,
        protocol: 'VLESS',
        settings: { clients: [{ id: 'CLIENT_UUID_SECRET' }] },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            target: 'd.example:443',
            serverNames: ['d.example', ''],
            privateKey: 'PRIVATE_KEY_SECRET',
            shortIds: ['SHORTID_SECRET'],
          },
        },
      },
      binding,
    );
    expect(out).toEqual({
      tag: 'R',
      configProfileUuid: PROFILE_UUID,
      configProfileInboundUuid: IN_REALITY,
      protocol: 'vless',
      port: 443,
      network: 'tcp',
      security: 'reality',
      reality: { target: 'd.example:443', serverNames: ['d.example'] },
      active: true,
    });
    const json = JSON.stringify(out);
    for (const w of SECRET_WORDS) expect(json).not.toContain(w);
  });

  test('carries the `listen` address (a loopback-bound inbound is not reachable from outside)', () => {
    const base = { tag: 'W', port: 8443, protocol: 'vless', streamSettings: { network: 'ws' } };
    expect(projectXrayInbound({ ...base, listen: '127.0.0.1' }, binding)).toMatchObject({
      listen: '127.0.0.1',
    });
    expect(projectXrayInbound(base, binding)).not.toHaveProperty('listen');
  });

  test('httpupgrade, grpc and the ws host field vs the legacy Host header', () => {
    expect(
      projectXrayInbound(
        {
          tag: 'H',
          port: 80,
          protocol: 'vless',
          streamSettings: {
            network: 'httpupgrade',
            httpupgradeSettings: { path: '/u', host: 'h.example' },
          },
        },
        binding,
      ),
    ).toMatchObject({ security: 'none', httpupgrade: { path: '/u', host: 'h.example' } });
    expect(
      projectXrayInbound(
        {
          tag: 'G',
          port: 2053,
          protocol: 'vless',
          streamSettings: {
            network: 'grpc',
            security: 'tls',
            tlsSettings: {},
            grpcSettings: { serviceName: 's' },
          },
        },
        binding,
      ),
    ).toMatchObject({ tls: { serverName: null }, grpc: { serviceName: 's' } });
    expect(
      projectXrayInbound(
        {
          tag: 'W',
          port: 443,
          protocol: 'vless',
          streamSettings: {
            network: 'ws',
            wsSettings: { host: 'w.example', headers: { Host: 'ignored.example' } },
          },
        },
        binding,
      ),
    ).toMatchObject({ ws: { path: null, host: 'w.example' } });
  });

  test('ports: a numeric string is a port; a list, a range and a bad number are not', () => {
    const p = (port: unknown) =>
      projectXrayInbound({ tag: 'P', port, protocol: 'vless' }, binding)?.port;
    expect(p(443)).toBe(443);
    expect(p('443')).toBe(443);
    expect(p(' 8443 ')).toBe(8443);
    expect(p('443,8443')).toBeNull();
    expect(p('1000-2000')).toBeNull();
    expect(p(70000)).toBeNull();
    expect(p(0)).toBeNull();
    expect(p(undefined)).toBeNull();
  });

  test('no tag or not an object: nothing', () => {
    expect(projectXrayInbound({ port: 443 }, binding)).toBeNull();
    expect(projectXrayInbound('nope', binding)).toBeNull();
    expect(projectXrayInbound(null, binding)).toBeNull();
  });
});
