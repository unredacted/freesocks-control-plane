/**
 * Backend observation (`remnawaveObservePanel`): what server management reads to
 * show an operator the nodes, config profiles, Hosts and mode groups that already
 * exist. It is READ-ONLY, and the guard here is the same one discovery has: a
 * config profile's private key, short ids, clients, certificate material and
 * the backend's derived `rawInbound` can never leave the provider, in a value or
 * in an error.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { realityPublicKey } from '../panel/digest';
import { remnawaveObservePanel, type RemnawaveConfig } from './remnawave';

const cfg: RemnawaveConfig = { baseUrl: 'https://panel.internal', apiToken: 'SECRET_TOKEN' };
const KEY = 'digest-key';

const PRIVATE_KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)))
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');
const SECRETS = [PRIVATE_KEY, 'deadbeef00112233', 'client-uuid-1', 'CERT_PEM_BODY', 'SECRET_TOKEN'];

const realityInbound = (names: string[], shortIds = ['deadbeef00112233']) => ({
  tag: 'reality-in',
  port: 443,
  protocol: 'vless',
  settings: { clients: [{ id: 'client-uuid-1', email: 'member' }], decryption: 'none' },
  streamSettings: {
    network: 'tcp',
    security: 'reality',
    realitySettings: {
      target: 'target.example:443',
      serverNames: names,
      privateKey: PRIVATE_KEY,
      shortIds,
    },
  },
});

const profile = (names: string[], shortIds?: string[]) => ({
  uuid: 'p-1',
  name: 'Default',
  config: {
    log: { loglevel: 'none' },
    inbounds: [
      realityInbound(names, shortIds),
      {
        tag: 'tls-in',
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
    // The backend's derived rows carry the COMPLETE inbound JSON, key included.
    { uuid: 'i-reality', tag: 'reality-in', rawInbound: realityInbound(names, shortIds) },
    { uuid: 'i-tls', tag: 'tls-in' },
  ],
});

const panel = (p: ReturnType<typeof profile>) => (path: string) => {
  if (path === '/api/nodes')
    return json([
      {
        uuid: 'n-1',
        name: 'node-one',
        address: '192.0.2.10',
        port: 2222,
        countryCode: 'NL',
        isConnected: true,
        isDisabled: false,
        usersOnline: 4,
        tags: ['FCP_MANAGED'],
        configProfile: {
          activeConfigProfileUuid: 'p-1',
          activeInbounds: [{ uuid: 'i-reality', tag: 'reality-in' }],
        },
      },
      { uuid: 'n-2', name: 'node-two', isConnected: true, isDisabled: true },
    ]);
  if (path === '/api/hosts')
    return json([
      {
        uuid: 'h-1',
        remark: 'node-one-reality',
        address: '192.0.2.10',
        port: 443,
        sni: 'a.example',
        host: '',
        fingerprint: 'chrome',
        alpn: 'h2',
        isDisabled: false,
        viewPosition: 2,
        inbound: { configProfileUuid: 'p-1', configProfileInboundUuid: 'i-reality' },
        nodes: ['n-1'],
      },
    ]);
  if (path === '/api/internal-squads')
    return json({
      internalSquads: [
        {
          uuid: 's-1',
          name: 'free',
          inbounds: [{ uuid: 'i-reality', tag: 'reality-in' }],
          info: { membersCount: 12 },
        },
      ],
    });
  if (path === '/api/config-profiles') return json({ configProfiles: [{ ...p, config: {} }] });
  if (path === '/api/config-profiles/p-1') return json(p);
  return new Response('nope', { status: 404 });
};

const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify({ response: o }), {
    status,
    headers: { 'content-type': 'application/json' },
  });

let calls: { path: string; method: string }[] = [];
function mockFetch(handler: (path: string) => Response) {
  calls = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      calls.push({ path: url.pathname, method: (init.method ?? 'GET').toUpperCase() });
      return handler(url.pathname);
    }),
  );
}
afterEach(() => vi.unstubAllGlobals());

describe('remnawaveObservePanel', () => {
  test('is read-only and reads each profile by uuid, never from the list row', async () => {
    mockFetch(panel(profile(['a.example', 'b.example'])));
    await remnawaveObservePanel(cfg, KEY);
    expect(calls.every((c) => c.method === 'GET')).toBe(true);
    expect(calls.map((c) => c.path).sort()).toEqual([
      '/api/config-profiles',
      '/api/config-profiles/p-1',
      '/api/hosts',
      '/api/internal-squads',
      '/api/nodes',
    ]);
  });

  test('nothing secret leaves the provider', async () => {
    mockFetch(panel(profile(['a.example', 'b.example'])));
    const blob = JSON.stringify(await remnawaveObservePanel(cfg, KEY));
    for (const s of SECRETS) expect(blob).not.toContain(s);
    expect(blob).not.toContain('rawInbound');
    expect(blob).not.toContain('clients');
    expect(blob).not.toContain('shortIds');
  });

  test('projects nodes, profiles, Hosts and mode groups', async () => {
    mockFetch(panel(profile(['a.example', 'b.example'])));
    const o = await remnawaveObservePanel(cfg, KEY);
    expect(o.nodes).toEqual([
      {
        nodeUuid: 'n-1',
        name: 'node-one',
        address: '192.0.2.10',
        port: 2222,
        countryCode: 'NL',
        online: true,
        isDisabled: false,
        usersOnline: 4,
        configProfileUuid: 'p-1',
        activeInboundUuids: ['i-reality'],
        tags: ['FCP_MANAGED'],
      },
      // Connected but disabled is not "online"; missing fields degrade to unknowns.
      expect.objectContaining({
        nodeUuid: 'n-2',
        online: false,
        isDisabled: true,
        configProfileUuid: null,
      }),
    ]);
    const [p] = o.profiles;
    expect(p).toMatchObject({ profileUuid: 'p-1', name: 'Default' });
    expect(p.shapeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(p.changeToken).toMatch(/^[0-9a-f]{64}$/);
    expect(p.inbounds.map((i) => [i.tag, i.configProfileInboundUuid, i.security, i.port])).toEqual([
      ['reality-in', 'i-reality', 'reality', 443],
      ['tls-in', 'i-tls', 'tls', 8443],
    ]);
    expect(p.inbounds[0].reality).toEqual({
      target: 'target.example:443',
      serverNames: ['a.example', 'b.example'],
    });
    // The public key is DERIVED from the private one (it is public: every share link carries it).
    expect(p.inbounds[0].realityAuth).toEqual({
      digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      publicKey: realityPublicKey(PRIVATE_KEY),
      publicKeyMismatch: false,
    });
    expect(p.inbounds[1].realityAuth).toBeUndefined();
    expect(o.hosts[0]).toMatchObject({
      hostUuid: 'h-1',
      sni: 'a.example',
      host: null,
      fingerprint: 'chrome',
      alpn: 'h2',
      viewPosition: 2,
      configProfileInboundUuid: 'i-reality',
      nodeUuids: ['n-1'],
    });
    expect(o.squads).toEqual([
      { squadUuid: 's-1', name: 'free', inboundUuids: ['i-reality'], membersCount: 12 },
    ]);
  });

  test('a name change moves both digests; a short-id change moves only the keyed ones', async () => {
    const read = async (p: ReturnType<typeof profile>) => {
      mockFetch(panel(p));
      return (await remnawaveObservePanel(cfg, KEY)).profiles[0];
    };
    const base = await read(profile(['a.example']));
    const renamed = await read(profile(['a.example', 'z.example']));
    expect(renamed.shapeHash).not.toBe(base.shapeHash);
    expect(renamed.changeToken).not.toBe(base.changeToken);
    expect(renamed.inbounds[0].realityAuth!.digest).toBe(base.inbounds[0].realityAuth!.digest);
    const rekeyed = await read(profile(['a.example'], ['ffffffff00000000']));
    expect(rekeyed.shapeHash).toBe(base.shapeHash);
    expect(rekeyed.changeToken).not.toBe(base.changeToken);
    expect(rekeyed.inbounds[0].realityAuth!.digest).not.toBe(base.inbounds[0].realityAuth!.digest);
  });

  test('a failing profile read names status and path only', async () => {
    const ok = panel(profile(['a.example']));
    mockFetch((path) =>
      path === '/api/config-profiles/p-1'
        ? new Response(`boom {"privateKey":"${PRIVATE_KEY}"}`, { status: 500 })
        : ok(path),
    );
    await expect(remnawaveObservePanel(cfg, KEY)).rejects.toThrow(
      /^Remnawave 500 on \/api\/config-profiles\/p-1$/,
    );
  });
});
