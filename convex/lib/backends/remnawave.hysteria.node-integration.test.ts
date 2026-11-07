// @vitest-environment node
/**
 * NODE-SIDE HYSTERIA: a live Remnawave backend WITH a backend-managed node
 * (remnawave/node 3.4.3, the Xray release the fleet runs) serving FCP's own
 * Hysteria transport beside a REALITY one, and the node image's Xray as the
 * client (docker-compose.remnawave-node-test.yml). What the backend and engine
 * jobs cannot show without a node:
 *
 *  - the node applies a profile carrying FCP's Hysteria transport (with its
 *    self-signed certificate) and serves it on UDP 443 beside REALITY on TCP
 *    443, both to one key placed in both groups (the Hysteria mode and its
 *    REALITY backup);
 *  - a key added while the node runs is served without an Xray restart;
 *  - the backend counts Hysteria bytes to the key;
 *  - a disabled key is refused on both on a new connection. A Hysteria
 *    connection the client opened before the disable is not cut by it at
 *    once (Hysteria authenticates once per QUIC connection): how long it goes
 *    on is recorded (`observed.openHysteriaCutAfterDisableMs`), not asserted;
 *  - regenerating (FCP deletes the key and issues a new one) retires the old
 *    password: it is refused, the new one is served.
 *
 * Run via `bun run test:integration:remnawave-node` (or one file:
 * `bun run test:integration:remnawave-node convex/lib/backends/remnawave.hysteria.node-integration.test.ts`).
 * Fixture names are `*.example` only.
 */
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { afterAll, describe, expect, test } from 'vitest';
import { buildTransport } from '../backend/profileTemplate';
import { generateHysteriaCertificate } from '../backend/hysteriaCert';
import {
  remnawaveDeleteUser,
  remnawaveGetUser,
  remnawaveIssueUser,
  remnawaveSetStatus,
  type RemnawaveConfig,
} from './remnawave';

const BASE_URL = process.env.REMNAWAVE_TEST_URL;
const API_TOKEN = process.env.REMNAWAVE_TEST_TOKEN;
const ENABLED = process.env.REMNAWAVE_TEST_NODE === '1' && !!BASE_URL && !!API_TOKEN;

const COMPOSE = [
  'compose',
  '-f',
  'docker-compose.remnawave-test.yml',
  '-f',
  'docker-compose.remnawave-node-test.yml',
];
const docker = (...args: string[]) =>
  execFileSync('docker', args, {
    encoding: 'utf8',
    timeout: 120_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

async function api(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(new URL(`/api/${path}`, BASE_URL), {
    method,
    headers: { authorization: `Bearer ${API_TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`backend ${method} ${path.split('/')[0]}: HTTP ${res.status}`);
  const text = await res.text();
  return text.trim() ? JSON.parse(text).response : undefined;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(read: () => Promise<boolean>, ms: number, every = 1500): Promise<boolean> {
  const end = Date.now() + ms;
  for (;;) {
    if (await read().catch(() => false)) return true;
    if (Date.now() > end) return false;
    await sleep(every);
  }
}

const RUN = randomUUID().slice(0, 8);
const HY_TAG = `PRIVACY_HYSTERIA_${RUN}`;
const R_TAG = `PRIVACY_REALITY_${RUN}`;
const SERVER_NAME = 'hy.example';
const REALITY_NAME = 'n0000.example';
const CERT = generateHysteriaCertificate(SERVER_NAME);
const keys = generateKeyPairSync('x25519');
const PRIVATE_KEY = keys.privateKey
  .export({ type: 'pkcs8', format: 'der' })
  .subarray(-32)
  .toString('base64url');
const PUBLIC_KEY = keys.publicKey
  .export({ type: 'spki', format: 'der' })
  .subarray(-32)
  .toString('base64url');
const SHORT_ID = '0123456789abcdef';

function profileConfig() {
  const hysteria = buildTransport(
    {
      slug: 'privacy-hysteria',
      name: `Privacy-Hysteria-${RUN}`,
      shape: { transport: 'hysteria', fronting: 'direct' },
      hysteria: { serverName: SERVER_NAME, salamander: false },
    },
    undefined,
    { certificate: CERT.certificate, key: CERT.key },
  );
  hysteria.tag = HY_TAG;
  return {
    log: { loglevel: process.env.RW_TEST_NODE_LOG ?? 'warning' },
    inbounds: [
      {
        tag: R_TAG,
        port: 443,
        protocol: 'vless',
        settings: { clients: [], decryption: 'none' },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            target: 'rw-test-origin:8443',
            serverNames: [REALITY_NAME],
            privateKey: PRIVATE_KEY,
            shortIds: [SHORT_ID],
          },
        },
      },
      hysteria,
    ],
    outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
  };
}

/** One client entry: a loopback port (18100 + index) whose fetch is a session through the node. */
type Leg = { kind: 'hysteria'; password: string } | { kind: 'reality'; vlessUuid: string };

function outboundOf(leg: Leg, tag: string): unknown {
  if (leg.kind === 'hysteria')
    return {
      tag,
      protocol: 'hysteria',
      settings: { version: 2, address: 'rw-test-node', port: 443 },
      streamSettings: {
        network: 'hysteria',
        security: 'tls',
        tlsSettings: {
          serverName: SERVER_NAME,
          alpn: ['h3'],
          pinnedPeerCertSha256: CERT.pinHex,
        },
        hysteriaSettings: { version: 2, auth: leg.password },
      },
    };
  return {
    tag,
    protocol: 'vless',
    settings: {
      vnext: [
        {
          address: 'rw-test-node',
          port: 443,
          users: [{ id: leg.vlessUuid, encryption: 'none', flow: 'xtls-rprx-vision' }],
        },
      ],
    },
    streamSettings: {
      network: 'tcp',
      security: 'reality',
      realitySettings: {
        serverName: REALITY_NAME,
        fingerprint: 'chrome',
        publicKey: PUBLIC_KEY,
        shortId: SHORT_ID,
      },
    },
  };
}

function startClient(legs: Leg[]) {
  writeFileSync(
    '.cache/remnawave-node-test/client.json',
    JSON.stringify({
      log: { loglevel: process.env.RW_TEST_CLIENT_LOG ?? 'warning' },
      inbounds: legs.map((_, i) => ({
        tag: `in-${i}`,
        listen: '0.0.0.0',
        port: 18100 + i,
        protocol: 'dokodemo-door',
        settings: { address: 'rw-test-origin', port: 80, network: 'tcp' },
      })),
      outbounds: legs.map((leg, i) => outboundOf(leg, `out-${i}`)),
      routing: {
        rules: legs.map((_, i) => ({
          type: 'field',
          inboundTag: [`in-${i}`],
          outboundTag: `out-${i}`,
        })),
      },
    }),
  );
  docker(...COMPOSE, '--profile', 'client', 'up', '-d', '--force-recreate', 'rw-test-client');
}

/** Whether leg #i gets the page through the tunnel. */
async function connects(i: number): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${18100 + i}/`, {
      signal: AbortSignal.timeout(8000),
    });
    return (await res.text()).includes('through-the-tunnel');
  } catch {
    return false;
  }
}
/** How long the disable test watches a connection opened before the disable. */
const OPEN_CONNECTION_WATCH_MS = Number(process.env.RW_TEST_OPEN_WATCH_MS ?? 300_000);
const servedSoon = (i: number) => until(() => connects(i), 90_000);
const refusedSoon = (i: number) => until(async () => !(await connects(i)), 120_000, 3000);

describe.skipIf(!ENABLED)('remnawave managed node: Hysteria beside REALITY (integration)', () => {
  const cfg: RemnawaveConfig = { baseUrl: BASE_URL!, apiToken: API_TOKEN!, timeoutMs: 30_000 };
  const created = {
    users: [] as string[],
    nodes: [] as string[],
    squads: [] as string[],
    profiles: [] as string[],
  };
  let nodeUuid = '';
  const observed: Record<string, unknown> = {};
  const squads = { reality: '', hysteria: '' };
  const member = { id: '', password: '' };

  afterAll(async () => {
    console.info(`[hysteria-node] observed ${JSON.stringify(observed)}`);
    writeFileSync(
      '.cache/remnawave-node-test/observed-hysteria.json',
      JSON.stringify(observed, null, 2),
    );
    if (process.env.RW_TEST_KEEP === '1') return;
    const quiet = (p: Promise<unknown>) => p.catch(() => undefined);
    for (const u of created.users) await quiet(api('DELETE', `users/${u}`));
    for (const u of created.nodes) await quiet(api('DELETE', `nodes/${u}`));
    for (const u of created.squads) await quiet(api('DELETE', `internal-squads/${u}`));
    for (const u of created.profiles) await quiet(api('DELETE', `config-profiles/${u}`));
  });

  const issue = async (inSquads: string[]) => {
    const issued = await remnawaveIssueUser(cfg, {
      username: `fcp_hy_${RUN}_${created.users.length}`,
      placement: inSquads[0]!,
      extraPlacements: inSquads.slice(1),
      tag: 'MEMBER',
      expireAt: null,
      trafficLimitBytes: 1024 ** 3,
    });
    created.users.push(issued.backendUserId);
    const raw = await api('GET', `users/${issued.backendUserId}`);
    // The backend hands the Hysteria inbound the key's VLESS id as its password.
    return { id: issued.backendUserId, password: raw.vlessUuid as string };
  };
  const nodeUptime = async (): Promise<number | null> => {
    const n = Number((await api('GET', `nodes/${nodeUuid}`))?.xrayUptime);
    return Number.isFinite(n) ? n : null;
  };

  test('the node serves FCP’s Hysteria transport and REALITY to one key in both groups', async () => {
    const profile = await api('POST', 'config-profiles', {
      name: `FCP hysteria node ${RUN}`,
      config: profileConfig(),
    });
    created.profiles.push(profile.uuid);
    const inbound = (tag: string) =>
      (profile.inbounds as Array<{ uuid: string; tag: string }>).find((i) => i.tag === tag)!.uuid;
    for (const [k, tag] of [
      ['reality', R_TAG],
      ['hysteria', HY_TAG],
    ] as const) {
      const squad = await api('POST', 'internal-squads', {
        name: `${k}-${RUN}`,
        inbounds: [inbound(tag)],
      });
      created.squads.push(squad.uuid);
      squads[k] = squad.uuid;
    }
    Object.assign(member, await issue([squads.hysteria, squads.reality]));

    const node = await api('POST', 'nodes', {
      name: `fcp-hy-${RUN}`,
      address: 'rw-test-node',
      port: 2222,
      configProfile: {
        activeConfigProfileUuid: profile.uuid,
        activeInbounds: [inbound(R_TAG), inbound(HY_TAG)],
      },
    });
    nodeUuid = node.uuid;
    created.nodes.push(nodeUuid);
    const up = await until(
      async () => !!(await api('GET', `nodes/${nodeUuid}`))?.isConnected,
      120_000,
      2000,
    );
    expect(up, 'the node never connected to the backend').toBe(true);

    startClient([
      { kind: 'hysteria', password: member.password },
      { kind: 'reality', vlessUuid: member.password },
    ]);
    expect(await servedSoon(0), 'Hysteria').toBe(true);
    expect(await servedSoon(1), 'REALITY backup').toBe(true);
  }, 300_000);

  test('a key added while the node runs is served without an Xray restart', async () => {
    const before = await nodeUptime();
    const late = await issue([squads.hysteria, squads.reality]);
    startClient([
      { kind: 'hysteria', password: member.password },
      { kind: 'hysteria', password: late.password },
    ]);
    expect(await servedSoon(1), 'the key added live').toBe(true);
    const after = await nodeUptime();
    // Xray's uptime only grows while it is never restarted (when the backend reports it).
    if (before !== null && after !== null) expect(after).toBeGreaterThanOrEqual(before);
  }, 300_000);

  test('the backend counts Hysteria bytes to the key', async () => {
    startClient([{ kind: 'hysteria', password: member.password }]);
    expect(await servedSoon(0)).toBe(true);
    for (let i = 0; i < 20; i++) await connects(0);
    const counted = await until(
      async () => ((await remnawaveGetUser(cfg, member.id)).usedTrafficBytes ?? 0) > 0,
      240_000,
      5000,
    );
    expect(counted, 'no bytes were ever counted to the key').toBe(true);
  }, 300_000);

  test('a disabled key is refused on a new connection, on both transports, and served again once enabled', async () => {
    startClient([
      { kind: 'hysteria', password: member.password },
      { kind: 'reality', vlessUuid: member.password },
    ]);
    expect(await servedSoon(0)).toBe(true);
    expect(await servedSoon(1)).toBe(true);
    const t0 = Date.now();
    await remnawaveSetStatus(cfg, member.id, false);
    // Recorded, not asserted: Hysteria authenticates once per QUIC connection,
    // so a client's connection opened before the disable may go on carrying
    // requests (REALITY authenticates every TCP connection).
    const cut = await until(async () => !(await connects(0)), OPEN_CONNECTION_WATCH_MS, 5000);
    observed.openHysteriaCutAfterDisableMs = cut ? Date.now() - t0 : null;
    observed.openHysteriaWatchedMs = OPEN_CONNECTION_WATCH_MS;
    // A new connection (the app reconnecting) is refused on both.
    startClient([
      { kind: 'hysteria', password: member.password },
      { kind: 'reality', vlessUuid: member.password },
    ]);
    expect(await refusedSoon(0), 'Hysteria served a disabled key on a new connection').toBe(true);
    expect(await refusedSoon(1), 'REALITY served a disabled key on a new connection').toBe(true);
    // Stay refused, not a passing hiccup.
    await sleep(10_000);
    expect(await connects(0)).toBe(false);
    await remnawaveSetStatus(cfg, member.id, true);
    expect(await servedSoon(0)).toBe(true);
  }, 900_000);

  test('regenerate retires the old password: refused, and the new key is served', async () => {
    const fresh = await issue([squads.hysteria, squads.reality]);
    await remnawaveDeleteUser(cfg, member.id);
    created.users.splice(created.users.indexOf(member.id), 1);
    startClient([
      { kind: 'hysteria', password: member.password },
      { kind: 'hysteria', password: fresh.password },
    ]);
    expect(await servedSoon(1), 'the new key').toBe(true);
    expect(await refusedSoon(0), 'the old password still works').toBe(true);
    expect(fresh.password).not.toBe(member.password);
  }, 400_000);
});
