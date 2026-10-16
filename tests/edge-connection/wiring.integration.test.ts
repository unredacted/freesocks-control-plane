/**
 * The WIRING of the edge connection stack, with hand-written configs and no FCP:
 * a REALITY session through the fake L4 edge and a WebSocket session through
 * the fake L7 front each fetch the page only the nodes can reach, and the
 * member's network reaches no node directly. If this fails, the topology is
 * broken and nothing FCP does can be judged; if it passes and the lifecycle
 * test fails, the failure is FCP's.
 *
 * Leaves the panel as it found it: the lifecycle test sets the backend up
 * from scratch.
 */
import { generateKeyPairSync } from 'node:crypto';
import { afterAll, describe, expect, test } from 'vitest';
import {
  ADDR,
  ENABLED,
  NODE_ADDRESSES,
  accessLog,
  clientReachesDirectly,
  env,
  fetchThroughClientEventually,
  forwarderConnections,
  startClient,
  stopClient,
  until,
  wireForwarder,
} from './stack';

async function api(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(new URL(`/api/${path}`, env.panelUrl), {
    method,
    headers: { authorization: `Bearer ${env.panelToken}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`panel ${method} ${path.split('/')[0]}: HTTP ${res.status}`);
  const text = await res.text();
  return text ? JSON.parse(text).response : null;
}

describe.skipIf(!ENABLED)('edge connection stack wiring (hand-written configs)', () => {
  const created = {
    users: [] as string[],
    nodes: [] as string[],
    squads: [] as string[],
    profiles: [] as string[],
  };
  const keys = generateKeyPairSync('x25519');
  const raw = (k: { export: (o: object) => Buffer }, type: string) =>
    k.export({ type, format: 'der' }).subarray(-32).toString('base64url');
  const privateKey = raw(keys.privateKey as never, 'pkcs8');
  const publicKey = raw(keys.publicKey as never, 'spki');
  const sni = `www.${env?.realityTarget}`;
  const frontHost = `wiring.${env?.l7Zone}`;
  let vlessUuid = '';

  // Always: the member test sets the backend up from scratch on this panel.
  afterAll(async () => {
    stopClient();
    for (const u of created.users) await api('DELETE', `users/${u}`).catch(() => null);
    for (const u of created.nodes) await api('DELETE', `nodes/${u}`).catch(() => null);
    for (const u of created.squads) await api('DELETE', `internal-squads/${u}`).catch(() => null);
    for (const u of created.profiles) await api('DELETE', `config-profiles/${u}`).catch(() => null);
  });

  test('both nodes connect to the panel and run their transport', async () => {
    const profile = await api('POST', 'config-profiles', {
      name: 'EC wiring',
      config: {
        log: { loglevel: 'warning' },
        inbounds: [
          {
            tag: 'EC_REALITY',
            listen: '::',
            port: 443,
            protocol: 'vless',
            settings: { clients: [], decryption: 'none' },
            streamSettings: {
              network: 'raw',
              security: 'reality',
              realitySettings: {
                dest: `${env.realityTarget}:443`,
                serverNames: [sni],
                privateKey,
                shortIds: [''],
                // Xray 26 refuses clients older than itself by default, sing-box
                // included; FCP's profile template sets the same floor.
                minClientVer: '1.8.1',
              },
            },
          },
          {
            tag: 'EC_WS',
            listen: '127.0.0.1',
            port: env.wsPort,
            protocol: 'vless',
            settings: { clients: [], decryption: 'none' },
            streamSettings: { network: 'ws', security: 'none', wsSettings: { path: env.wsPath } },
          },
        ],
        outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
      },
    });
    created.profiles.push(profile.uuid);
    const inbound = (tag: string) => profile.inbounds.find((i: any) => i.tag === tag).uuid;
    const squad = await api('POST', 'internal-squads', {
      name: 'EC-wiring',
      inbounds: [inbound('EC_REALITY'), inbound('EC_WS')],
    });
    created.squads.push(squad.uuid);
    const user = await api('POST', 'users', {
      username: `ec_wiring_${Date.now()}`,
      expireAt: '2099-01-01T00:00:00.000Z',
      trafficLimitBytes: 0,
      trafficLimitStrategy: 'NO_RESET',
      activeInternalSquads: [squad.uuid],
    });
    created.users.push(user.uuid ?? String(user.id));
    vlessUuid = user.vlessUuid;
    for (const [name, address, tag] of [
      ['ec-wiring-reality', ADDR.realityNode.control, 'EC_REALITY'],
      ['ec-wiring-ws', ADDR.wsNode.control, 'EC_WS'],
    ] as const) {
      const node = await api('POST', 'nodes', {
        name,
        address,
        port: 2222,
        configProfile: { activeConfigProfileUuid: profile.uuid, activeInbounds: [inbound(tag)] },
      });
      created.nodes.push(node.uuid);
    }
    const connected = await until(
      async () => {
        const nodes = await Promise.all(created.nodes.map((u) => api('GET', `nodes/${u}`)));
        return nodes.every((n) => n.isConnected);
      },
      180_000,
      2000,
    );
    expect(connected, 'a node never connected to the panel').toBe(true);
  });

  test('the member network reaches no node, and no page, directly', () => {
    for (const address of NODE_ADDRESSES)
      for (const port of [443, 2222, env.wsPort])
        expect(clientReachesDirectly(address, port), `${address}:${port}`).toBe(false);
    expect(clientReachesDirectly(ADDR.originPage, 80)).toBe(false);
    // ...while the edges themselves are reachable.
    expect(clientReachesDirectly(ADDR.front.client, 443)).toBe(true);
  });

  test('REALITY through the L4 forwarder and WebSocket through the L7 front reach the page', async () => {
    await wireForwarder(443, `${ADDR.realityNode.edge}:443`);
    const before = await forwarderConnections(443);
    await startClient(
      JSON.stringify({
        log: { level: 'warn' },
        dns: { servers: [{ type: 'udp', tag: 'ec-dns', server: ADDR.dns }], final: 'ec-dns' },
        inbounds: [
          { type: 'mixed', tag: 'in-l4', listen: '127.0.0.1', listen_port: 1080 },
          { type: 'mixed', tag: 'in-l7', listen: '127.0.0.1', listen_port: 1081 },
        ],
        outbounds: [
          {
            type: 'vless',
            tag: 'l4',
            server: ADDR.forwarder.client,
            server_port: 443,
            uuid: vlessUuid,
            flow: 'xtls-rprx-vision',
            tls: {
              enabled: true,
              server_name: sni,
              utls: { enabled: true, fingerprint: 'chrome' },
              reality: { enabled: true, public_key: publicKey, short_id: '' },
            },
          },
          {
            type: 'vless',
            tag: 'l7',
            server: frontHost,
            server_port: 443,
            uuid: vlessUuid,
            tls: { enabled: true, server_name: frontHost },
            transport: { type: 'ws', path: env.wsPath, headers: { Host: frontHost } },
          },
        ],
        route: {
          rules: [
            { inbound: ['in-l4'], outbound: 'l4' },
            { inbound: ['in-l7'], outbound: 'l7' },
          ],
          final: 'l4',
          default_domain_resolver: 'ec-dns',
        },
      }),
      1081,
    );
    const l4 = await fetchThroughClientEventually(1080);
    expect(l4?.token, 'no page through the L4 edge').toBe(env.originToken);
    expect(await forwarderConnections(443)).toBeGreaterThan(before);
    const l7 = await fetchThroughClientEventually(1081);
    expect(l7?.token, 'no page through the L7 front').toBe(env.originToken);
    // The page saw a node, never the client.
    expect([ADDR.realityNode.origin, ADDR.wsNode.origin]).toContain(l4!.peer);
    expect(l7!.peer).toBe(ADDR.wsNode.origin);
    // The front logs a request when it finishes: close the tunnels first.
    stopClient();
    const viaFront = await until(
      async () =>
        accessLog('front').find(
          (e) => e.host === frontHost && e.uri === env.wsPath && e.status === 101,
        ),
      20_000,
      500,
    );
    expect(viaFront, 'the L7 front never logged the WebSocket session').toBeTruthy();
    // ...and the node's ingress saw the FRONT, not the member.
    expect(
      accessLog('ingress').some((e) => e.uri === env.wsPath && e.remoteIp === ADDR.front.edge),
    ).toBe(true);
  });
});
