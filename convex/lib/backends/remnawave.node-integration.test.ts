// @vitest-environment node
/**
 * NODE-SIDE CONTRACT: a live Remnawave backend WITH a backend-managed node, a
 * TLS 1.3 target and a pinned Xray client
 * (docker-compose.remnawave-node-test.yml). It establishes what the backend-only
 * probe cannot, by opening AUTHENTICATED REALITY sessions through the node:
 *
 *  - a server name works for members only once the NODE runs the config that
 *    lists it: with the node held off the backend, the backend says the name is
 *    there, a plain TLS handshake with that name SUCCEEDS (REALITY forwards it
 *    to the target), and yet no member can connect with it. A TLS probe is
 *    therefore never evidence that a node accepts a name;
 *  - an unlisted name falls through to the target (the client's REALITY
 *    verification fails), a listed one is authenticated;
 *  - how many server names production Xray takes, and how long a profile
 *    change takes to reach a connected node (recorded, docs/servers.md);
 *  - what the backend's node row says before, during and after (recorded): which
 *    of its fields could ever count as evidence that a node applied a change.
 *
 * Run via `bun run test:integration:remnawave-node`. Fixture names are
 * `*.example` only.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { afterAll, describe, expect, test } from 'vitest';

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

async function api(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; data: any }> {
  const res = await fetch(new URL(`/api/${path}`, BASE_URL), {
    method,
    headers: { authorization: `Bearer ${API_TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await res.text();
  let json: any;
  try {
    json = text.trim() ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, data: json && 'response' in json ? json.response : json };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until<T>(
  read: () => Promise<T | null | false>,
  ms: number,
  every = 1000,
): Promise<T | null> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await read().catch(() => null);
    if (v) return v;
    if (Date.now() > end) return null;
    await sleep(every);
  }
}

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
const TAG = `fcp-node-${randomUUID().slice(0, 8)}`;
const name = (i: number) => `n${String(i).padStart(4, '0')}.example`;
const names = (n: number) => Array.from({ length: n }, (_, i) => name(i));

const profileConfig = (serverNames: string[]) => ({
  log: { loglevel: process.env.RW_TEST_NODE_LOG ?? 'warning' },
  inbounds: [
    {
      tag: TAG,
      port: 443,
      protocol: 'vless',
      settings: { clients: [], decryption: 'none' },
      streamSettings: {
        network: 'tcp',
        security: 'reality',
        realitySettings: {
          target: 'rw-test-origin:8443',
          serverNames,
          privateKey: PRIVATE_KEY,
          shortIds: [SHORT_ID],
        },
      },
    },
  ],
  outbounds: [{ protocol: 'freedom', tag: 'DIRECT' }],
});

/**
 * (Re)start the client with one loopback port per server name: a plain HTTP
 * fetch of port 18100+i is a VLESS+REALITY session to the node presenting
 * `sni[i]`, asking for the target's plain page.
 */
function startClient(vlessUuid: string, snis: string[]) {
  writeFileSync(
    '.cache/remnawave-node-test/client.json',
    JSON.stringify({
      log: { loglevel: process.env.RW_TEST_CLIENT_LOG ?? 'warning' },
      inbounds: snis.map((_, i) => ({
        tag: `in-${i}`,
        listen: '0.0.0.0',
        port: 18100 + i,
        protocol: 'dokodemo-door',
        settings: { address: 'rw-test-origin', port: 80, network: 'tcp' },
      })),
      outbounds: snis.map((sni, i) => ({
        tag: `out-${i}`,
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: 'rw-test-node',
              port: 443,
              users: [
                {
                  id: vlessUuid,
                  encryption: 'none',
                  flow: process.env.RW_TEST_FLOW ?? 'xtls-rprx-vision',
                },
              ],
            },
          ],
        },
        streamSettings: {
          network: 'tcp',
          security: 'reality',
          realitySettings: {
            serverName: sni,
            fingerprint: 'chrome',
            publicKey: PUBLIC_KEY,
            shortId: SHORT_ID,
          },
        },
      })),
      routing: {
        rules: snis.map((_, i) => ({
          type: 'field',
          inboundTag: [`in-${i}`],
          outboundTag: `out-${i}`,
        })),
      },
    }),
  );
  docker(...COMPOSE, '--profile', 'client', 'up', '-d', '--force-recreate', 'rw-test-client');
}

/** Whether a member holding server name #i gets the page through the tunnel. */
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

/**
 * A plain TLS 1.3 handshake to the NODE presenting `sni`, run from inside the
 * data network (the node publishes nothing). True when the handshake completes.
 */
function tlsHandshakeCompletes(sni: string): boolean {
  // `-brief` reports on stderr, so both streams are read.
  const r = spawnSync(
    'docker',
    [
      'run',
      '--rm',
      '--network',
      'rw-node-test_rw-node-data',
      'alpine/openssl',
      's_client',
      '-connect',
      'rw-test-node:443',
      '-servername',
      sni,
      '-tls1_3',
      '-brief',
    ],
    { encoding: 'utf8', timeout: 60_000, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return /Protocol version: TLSv1\.3/.test(`${r.stdout ?? ''}${r.stderr ?? ''}`);
}

describe.skipIf(!ENABLED)('remnawave managed node (integration)', () => {
  const created = {
    users: [] as string[],
    nodes: [] as string[],
    squads: [] as string[],
    profiles: [] as string[],
  };
  const observed: Record<string, unknown> = {};
  let profileUuid = '';
  let inboundUuid = '';
  let nodeUuid = '';
  let vlessUuid = '';

  afterAll(async () => {
    try {
      docker('network', 'connect', 'rw-node-test_rw-node-control', 'rw-test-node');
    } catch {
      /* already connected */
    }
    console.info(`[managed-node] observed ${JSON.stringify(observed)}`);
    writeFileSync('.cache/remnawave-node-test/observed.json', JSON.stringify(observed, null, 2));
    // Debugging aid: leave the fixtures on the backend to poke at a live session.
    if (process.env.RW_TEST_KEEP === '1') return;
    for (const u of created.users) await api('DELETE', `users/${u}`);
    for (const u of created.nodes) await api('DELETE', `nodes/${u}`);
    for (const u of created.squads) await api('DELETE', `internal-squads/${u}`);
    for (const u of created.profiles) await api('DELETE', `config-profiles/${u}`);
  });

  const nodeRow = async () => (await api('GET', `nodes/${nodeUuid}`)).data;
  const pickStatus = (n: any) => ({
    isConnected: n?.isConnected,
    isConnecting: n?.isConnecting,
    isDisabled: n?.isDisabled,
    xrayUptime: n?.xrayUptime,
    lastStatusChange: n?.lastStatusChange,
    lastStatusMessage: n?.lastStatusMessage,
  });

  test('a backend-managed node connects and serves the profile', async () => {
    const profile = await api('POST', 'config-profiles', {
      name: `FCP node ${TAG}`,
      config: profileConfig(names(3)),
    });
    expect(profile.status).toBe(201);
    profileUuid = profile.data.uuid;
    created.profiles.push(profileUuid);
    inboundUuid = profile.data.inbounds[0].uuid;

    const squad = await api('POST', 'internal-squads', { name: TAG, inbounds: [inboundUuid] });
    expect(squad.status).toBe(201);
    created.squads.push(squad.data.uuid);

    const user = await api('POST', 'users', {
      username: `fcp_node_${Date.now()}`,
      expireAt: '2099-01-01T00:00:00.000Z',
      trafficLimitBytes: 0,
      trafficLimitStrategy: 'NO_RESET',
      activeInternalSquads: [squad.data.uuid],
    });
    expect(user.status).toBe(201);
    created.users.push(user.data.uuid ?? String(user.data.id));
    vlessUuid = user.data.vlessUuid;
    expect(vlessUuid).toMatch(/^[0-9a-f-]{36}$/);

    const node = await api('POST', 'nodes', {
      name: TAG,
      address: 'rw-test-node',
      port: 2222,
      configProfile: { activeConfigProfileUuid: profileUuid, activeInbounds: [inboundUuid] },
    });
    expect(node.status).toBe(201);
    nodeUuid = node.data.uuid;
    created.nodes.push(nodeUuid);
    observed.rowAtCreate = pickStatus(node.data);

    const up = await until(
      async () => ((await nodeRow())?.isConnected ? true : null),
      120_000,
      2000,
    );
    expect(up, 'the node never connected to the backend').toBe(true);
    observed.rowConnected = pickStatus(await nodeRow());
  });

  test('a listed name authenticates; an unlisted one falls through to the target', async () => {
    startClient(vlessUuid, [name(0), name(2), 'not-listed.example']);
    const ok = await until(async () => ((await connects(0)) ? true : null), 60_000, 1500);
    expect(ok, 'a member holding a listed name never connected').toBe(true);
    expect(await connects(1)).toBe(true);
    // Unlisted: REALITY forwards the handshake to the target, the client's own
    // verification then fails, and nothing comes back through the tunnel.
    expect(await connects(2)).toBe(false);
    // ...while a plain TLS handshake with that same name COMPLETES.
    expect(tlsHandshakeCompletes('not-listed.example')).toBe(true);
  });

  test('a name the PANEL holds but the NODE has not applied does not work, though TLS passes', async () => {
    // Hold the node on its current config: cut the control network only.
    docker('network', 'disconnect', 'rw-node-test_rw-node-control', 'rw-test-node');
    const held = [...names(3), 'late.example'];
    const patched = await api('PATCH', 'config-profiles', {
      uuid: profileUuid,
      config: profileConfig(held),
    });
    expect(patched.status).toBe(200);
    // The backend has it (this is all a read-back proves)...
    const stored = (await api('GET', `config-profiles/${profileUuid}`)).data.config.inbounds[0];
    expect(stored.streamSettings.realitySettings.serverNames).toContain('late.example');
    observed.rowWhileHeld = pickStatus(await nodeRow());

    startClient(vlessUuid, [name(0), 'late.example']);
    expect(await until(async () => ((await connects(0)) ? true : null), 60_000, 1500)).toBe(true);
    // ...a TLS probe passes...
    expect(tlsHandshakeCompletes('late.example')).toBe(true);
    // ...and no member can connect with it.
    expect(await connects(1)).toBe(false);

    // Give the node back: the name starts working only once the node applies the profile.
    const t0 = Date.now();
    docker('network', 'connect', 'rw-node-test_rw-node-control', 'rw-test-node');
    const works = await until(async () => ((await connects(1)) ? true : null), 240_000, 2000);
    observed.reconnectToWorkingMs = works ? Date.now() - t0 : null;
    observed.rowAfterApply = pickStatus(await nodeRow());
    if (!works) {
      // The backend does not re-push on reconnect by itself: record it, then
      // show that an explicit restart does deliver the config.
      const restarted = await api('POST', `nodes/${nodeUuid}/actions/restart`, {
        forceRestart: true,
      });
      observed.restartAfterReconnect = restarted.status;
      const later = await until(async () => ((await connects(1)) ? true : null), 180_000, 2000);
      observed.neededExplicitRestart = true;
      expect(later, 'the name never worked, even after a restart').toBe(true);
    }
  });

  for (const count of [64, 256, 512, 1024]) {
    test(`production Xray takes ${count} server names; first, middle and last all work`, async () => {
      const list = names(count);
      const t0 = Date.now();
      const patched = await api('PATCH', 'config-profiles', {
        uuid: profileUuid,
        config: profileConfig(list),
      });
      observed[`patchStatus${count}`] = patched.status;
      observed[`patchMs${count}`] = Date.now() - t0;
      expect(patched.status).toBe(200);
      const picks = [
        list[0],
        list[Math.floor(count / 2)],
        list[count - 1],
        `beyond-${count}.example`,
      ];
      startClient(vlessUuid, picks);
      // The LAST name is new in this list: it works only once the node applied it.
      const applied = await until(async () => ((await connects(2)) ? true : null), 240_000, 2000);
      observed[`applyMs${count}`] = applied ? Date.now() - t0 : null;
      expect(applied, `the node never accepted name #${count - 1}`).toBe(true);
      expect(await connects(0)).toBe(true);
      expect(await connects(1)).toBe(true);
      expect(await connects(3)).toBe(false);
      observed[`row${count}`] = pickStatus(await nodeRow());
    });
  }
});
