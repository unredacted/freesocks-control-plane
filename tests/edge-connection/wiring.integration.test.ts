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
  routeFront,
  startClient,
  stopClient,
  until,
  wireForwarder,
} from './stack';
import { OPERATOR_INBOUNDS, OPERATOR_NODES, operatorProfile } from './cells';
import { configForEndpoint, type Endpoint } from './clients';

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
    // What a proxied CNAME to the origin hostname is.
    await routeFront(frontHost, { host: env.originHostname, port: 443 }, env.originHostname);
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

/**
 * The operator nodes' transports, each through its own edge, with hand-written
 * endpoints: a forwarder address per L4 transport, a front hostname per L7
 * one, every engine that speaks the transport. Proves the operator profile,
 * the edges and both engines before FCP takes any of them through the
 * lifecycle.
 */
describe.skipIf(!ENABLED)('operator transports through their edges (hand-written)', () => {
  const created = {
    users: [] as string[],
    nodes: [] as string[],
    squads: [] as string[],
    profiles: [] as string[],
  };
  let secrets: { vless: string; trojan: string; ss: string };

  afterAll(async () => {
    stopClient();
    for (const u of created.users) await api('DELETE', `users/${u}`).catch(() => null);
    for (const u of created.nodes) await api('DELETE', `nodes/${u}`).catch(() => null);
    for (const u of created.squads) await api('DELETE', `internal-squads/${u}`).catch(() => null);
    for (const u of created.profiles) await api('DELETE', `config-profiles/${u}`).catch(() => null);
  });

  test('both operator nodes connect to the panel at their public address', async () => {
    const profiles: Array<{ node: 'l4m' | 'l7m'; uuid: string; inbounds: string[] }> = [];
    for (const node of ['l4m', 'l7m'] as const) {
      const profile = await api('POST', 'config-profiles', {
        name: `EC wiring ${node}`,
        config: operatorProfile(node, env.tlsName),
      });
      created.profiles.push(profile.uuid);
      profiles.push({
        node,
        uuid: profile.uuid,
        inbounds: profile.inbounds.map((i: { uuid: string }) => i.uuid),
      });
    }
    const squad = await api('POST', 'internal-squads', {
      name: 'EC-wiring-ops',
      inbounds: profiles.flatMap((p) => p.inbounds),
    });
    created.squads.push(squad.uuid);
    // The user before the nodes: a node starts with the users it has then, and
    // a user created while a node is still starting can miss it (a panel race;
    // members of the lifecycle test are issued long after their node is up).
    const user = await api('POST', 'users', {
      username: `ec_wiring_ops_${Date.now()}`,
      expireAt: '2099-01-01T00:00:00.000Z',
      trafficLimitBytes: 0,
      trafficLimitStrategy: 'NO_RESET',
      activeInternalSquads: [squad.uuid],
    });
    created.users.push(user.uuid ?? String(user.id));
    secrets = { vless: user.vlessUuid, trojan: user.trojanPassword, ss: user.ssPassword };
    for (const p of profiles) {
      const n = await api('POST', 'nodes', {
        name: `ec-wiring-${p.node}`,
        address: OPERATOR_NODES[p.node].edge,
        port: 2222,
        configProfile: { activeConfigProfileUuid: p.uuid, activeInbounds: p.inbounds },
      });
      created.nodes.push(n.uuid);
    }
    const connected = await until(
      async () => {
        const nodes = await Promise.all(created.nodes.map((u) => api('GET', `nodes/${u}`)));
        return nodes.every((n) => n.isConnected);
      },
      180_000,
      2000,
    );
    expect(connected, 'an operator node never connected to the panel').toBe(true);
  });

  test('every operator transport reaches the page through its edge, with every engine that speaks it', async () => {
    const pool = [...ADDR.forwarderPool].reverse(); // the far end of the pool: the member test takes the near end
    const failures: string[] = [];
    for (const ib of OPERATOR_INBOUNDS) {
      const node = OPERATOR_NODES[ib.node];
      const l4 = ib.node === 'l4m';
      const address = l4
        ? pool.shift()!
        : `w-${ib.tag.toLowerCase().replace(/_/g, '-')}.${env.l7Zone}`;
      if (l4) await wireForwarder(443, `${node.edge}:${ib.port}`, address);
      else await routeFront(address, { host: node.edge, port: ib.port }, address);
      const e: Endpoint = {
        protocol: ib.protocol,
        server: address,
        port: 443,
        secret:
          ib.protocol === 'vless'
            ? secrets.vless
            : ib.protocol === 'trojan'
              ? secrets.trojan
              : secrets.ss,
        ...(ib.protocol === 'shadowsocks' ? { method: 'chacha20-ietf-poly1305' } : {}),
        ...(ib.protocol === 'vless' && ib.network === 'raw' ? { flow: 'xtls-rprx-vision' } : {}),
        security: ib.security,
        ...(ib.security === 'tls' ? { sni: l4 ? env.tlsName : address, alpn: ib.alpn } : {}),
        network: ib.network === 'raw' ? 'tcp' : ib.network,
        ...(ib.path ? { path: ib.path } : {}),
        ...(ib.serviceName ? { serviceName: ib.serviceName } : {}),
        ...(ib.mode ? { mode: ib.mode } : {}),
        ...(!l4 && ib.network !== 'grpc' ? { host: address } : {}),
      };
      const engines: Array<'singbox' | 'mihomo'> =
        ib.network === 'xhttp' ? ['mihomo'] : ['singbox', 'mihomo'];
      for (const engine of engines) {
        const { config } = configForEndpoint(e, 1080, engine);
        try {
          await startClient(config, 1080, engine);
          const page = await fetchThroughClientEventually(1080, 20_000);
          if (page?.token !== env.originToken) failures.push(`${ib.tag}/${engine}`);
          else if (page.peer !== node.origin) failures.push(`${ib.tag}/${engine}: wrong peer`);
        } catch (err) {
          failures.push(`${ib.tag}/${engine}: ${(err as Error).message}`);
        } finally {
          stopClient();
        }
      }
    }
    expect(failures).toEqual([]);
  });
});
