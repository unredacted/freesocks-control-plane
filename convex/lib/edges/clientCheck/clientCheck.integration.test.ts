/**
 * FCP's own client check against REAL Xray-cores (docs/edges.md § "FCP's own
 * client check"): the edge-client-check service, built as the stack builds it,
 * is called the way FCP calls it (signed, with outbounds converted from share
 * links by `outboundsForLink`).
 *
 * Two cores of the fleet release (v26.7.28): one whose REALITY transports set
 * `minClientVer` 1.8.1 (as FCP's profile template does) and one that leaves it
 * unset, which that release turns into a minimum of 26.3.27, refusing sing-box
 * (it reports 1.8.1) while an Xray client gets in. The check must pass the first
 * with both engines and name sing-box refused on the second: exactly the
 * transport a human tick with an Xray client passed on 2026-10-25.
 *
 * Runs only under scripts/compat/client-check.sh (the `client-check` job in
 * .github/workflows/client-compatibility.yml); without FCP_CLIENT_CHECK_IT the
 * suite skips. Never prints a config, a link or the service's answers beyond
 * codes: they carry the per-run client id.
 */
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { beforeAll, describe, expect, test } from 'vitest';
import type { ClientCheckEngine } from '../../../../src/shared/contracts/edgeCodes';
import { outboundsForLink } from './outbound';
import {
  CLIENT_CHECK_PATHS,
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
  type ClientCheckResponse,
} from './protocol';
import { signRequest } from './signing';

const ENABLED = process.env.FCP_CLIENT_CHECK_IT === '1';
const WORK = '.cache/compat/client-check';
const COMPOSE = ['compose', '-f', 'docker-compose.compat.yml'];
const SERVICES = [
  'compat-reality-target',
  'compat-check-xray-min',
  'compat-check-xray-nomin',
  'compat-client-check',
];
const SERVICE = 'http://127.0.0.1:18090';
const SECRET = 'compat-client-check-secret';

/** Fixed in docker-compose.compat.yml. */
const CORES = {
  min: { edge: '10.89.72.21', origin: '10.89.73.21' },
  nomin: { edge: '10.89.72.22', origin: '10.89.73.22' },
} as const;
const TARGET = '10.89.73.20';
/** An example name only (docs/edges.md: never a real target). */
const SERVER_NAME = 'decoy.example';
const PORTS = { raw: 443, xhttp: 8443 } as const;
const XHTTP_PATH = '/kx';

// Per run: nothing here authenticates anything once the containers are gone.
const ID = randomUUID();
const SHORT_ID = randomBytes(4).toString('hex');
const KEYS = (() => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    public: publicKey.export({ format: 'jwk' }).x!,
    private: privateKey.export({ format: 'jwk' }).d!,
  };
})();

function xrayConfig(minClientVer: string | null): unknown {
  const realitySettings = {
    target: `${TARGET}:443`,
    serverNames: [SERVER_NAME],
    privateKey: KEYS.private,
    shortIds: [SHORT_ID],
    ...(minClientVer ? { minClientVer } : {}),
  };
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'reality-raw',
        listen: '0.0.0.0',
        port: PORTS.raw,
        protocol: 'vless',
        settings: { clients: [{ id: ID, flow: 'xtls-rprx-vision' }], decryption: 'none' },
        streamSettings: { network: 'raw', security: 'reality', realitySettings },
      },
      {
        tag: 'reality-xhttp',
        listen: '0.0.0.0',
        port: PORTS.xhttp,
        protocol: 'vless',
        settings: { clients: [{ id: ID }], decryption: 'none' },
        streamSettings: {
          network: 'xhttp',
          security: 'reality',
          realitySettings,
          xhttpSettings: { path: XHTTP_PATH },
        },
      },
    ],
    // Every tunnel ends at the echo page, whatever the client asked for.
    outbounds: [
      {
        tag: 'to-echo',
        protocol: 'freedom',
        settings: {
          redirect: `${TARGET}:8081`,
          finalRules: [{ action: 'allow', ip: [`${TARGET}/32`] }],
        },
      },
    ],
  };
}

/** The share link a test link carries for a core's transport. */
function link(core: keyof typeof CORES, transport: keyof typeof PORTS): string {
  const q = new URLSearchParams({
    security: 'reality',
    type: transport === 'raw' ? 'tcp' : 'xhttp',
    sni: SERVER_NAME,
    fp: 'chrome',
    pbk: KEYS.public,
    sid: SHORT_ID,
    ...(transport === 'raw' ? { flow: 'xtls-rprx-vision' } : { path: XHTTP_PATH, mode: 'auto' }),
  });
  return `vless://${ID}@${CORES[core].edge}:${PORTS[transport]}?${q.toString()}#FCP%20test`;
}

async function signed(method: 'GET' | 'POST', path: string, body: string): Promise<Response> {
  const time = String(Date.now());
  return fetch(`${SERVICE}${path}`, {
    method,
    ...(method === 'POST' ? { body } : {}),
    headers: {
      [CLIENT_CHECK_TIME_HEADER]: time,
      [CLIENT_CHECK_SIGNATURE_HEADER]: await signRequest(SECRET, method, path, time, body),
    },
  });
}

async function check(
  core: keyof typeof CORES,
  transport: keyof typeof PORTS,
  engine: ClientCheckEngine,
): Promise<ClientCheckResponse> {
  const conv = outboundsForLink(link(core, transport));
  const outbound = conv?.outbounds[engine];
  if (!conv || !outbound) throw new Error(`no ${engine} outbound for ${transport}`);
  const res = await signed(
    'POST',
    CLIENT_CHECK_PATHS.check,
    JSON.stringify({ engine, outbound, reality: conv.reality }),
  );
  if (!res.ok) throw new Error(`service answered ${res.status}`);
  return (await res.json()) as ClientCheckResponse;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A check that passes once the core is up (they start in a few seconds, emulated slower). */
async function checkSettled(
  core: keyof typeof CORES,
  transport: keyof typeof PORTS,
  engine: ClientCheckEngine,
): Promise<ClientCheckResponse> {
  let last: ClientCheckResponse | null = null;
  for (let i = 0; i < 6; i++) {
    last = await check(core, transport, engine);
    if (last.ok || last.code === 'reality_refused') return last;
    await sleep(5_000);
  }
  return last!;
}

describe.skipIf(!ENABLED)('FCP client check against real Xray-cores', () => {
  beforeAll(async () => {
    rmSync(WORK, { recursive: true, force: true });
    mkdirSync(WORK, { recursive: true });
    writeFileSync(`${WORK}/min.json`, JSON.stringify(xrayConfig('1.8.1')));
    writeFileSync(`${WORK}/nomin.json`, JSON.stringify(xrayConfig(null)));
    execFileSync('docker', [...COMPOSE, 'up', '-d', ...SERVICES], {
      stdio: ['ignore', 'ignore', 'pipe'],
      timeout: 240_000,
    });
    for (let i = 0; i < 60; i++) {
      try {
        if ((await fetch(`${SERVICE}/healthz`)).ok) return;
      } catch {
        // not up yet
      }
      await sleep(1_000);
    }
    throw new Error('the client check service never answered');
  }, 300_000);

  test('health names both engines; unsigned and replayed requests are refused', async () => {
    const h = await signed('GET', CLIENT_CHECK_PATHS.health, '');
    expect(h.status).toBe(200);
    const body = (await h.json()) as { engines: Array<{ engine: string; version: string | null }> };
    expect(body.engines.map((e) => e.engine)).toEqual(['sing-box', 'xray']);
    expect(body.engines.every((e) => !!e.version)).toBe(true);
    expect((await fetch(`${SERVICE}${CLIENT_CHECK_PATHS.health}`)).status).toBe(401);
    const time = String(Date.now());
    const headers = {
      [CLIENT_CHECK_TIME_HEADER]: time,
      [CLIENT_CHECK_SIGNATURE_HEADER]: await signRequest(
        SECRET,
        'GET',
        CLIENT_CHECK_PATHS.health,
        time,
        '',
      ),
    };
    expect((await fetch(`${SERVICE}${CLIENT_CHECK_PATHS.health}`, { headers })).status).toBe(200);
    expect((await fetch(`${SERVICE}${CLIENT_CHECK_PATHS.health}`, { headers })).status).toBe(401);
    // A body with no length (chunked) is refused at the limit, never buffered whole.
    const big = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < 64; i++) c.enqueue(new Uint8Array(1024).fill(65));
        c.close();
      },
    });
    const res = await fetch(`${SERVICE}${CLIENT_CHECK_PATHS.check}`, {
      method: 'POST',
      body: big,
      duplex: 'half',
    } as RequestInit);
    expect(res.status).toBe(413);
  });

  test('minClientVer 1.8.1: both engines connect and come out of the core', async () => {
    for (const engine of ['sing-box', 'xray'] as const) {
      const r = await checkSettled('min', 'raw', engine);
      expect({ engine, code: r.code }).toEqual({ engine, code: 'ok' });
      expect(r.egressIp).toBe(CORES.min.origin);
      expect(r.engineVersion).toBeTruthy();
    }
  }, 240_000);

  test('minClientVer unset on the fleet release: sing-box refused, Xray connects', async () => {
    const xray = await checkSettled('nomin', 'raw', 'xray');
    expect(xray.code).toBe('ok');
    expect(xray.egressIp).toBe(CORES.nomin.origin);
    const singbox = await checkSettled('nomin', 'raw', 'sing-box');
    expect(singbox.code).toBe('reality_refused');
    expect(singbox.egressIp).toBeNull();
  }, 240_000);

  test('XHTTP under REALITY: Xray only (sing-box has no XHTTP)', async () => {
    expect(outboundsForLink(link('min', 'xhttp'))?.skipped['sing-box']).toBe('no_xhttp');
    const r = await checkSettled('min', 'xhttp', 'xray');
    expect(r.code).toBe('ok');
    expect(r.egressIp).toBe(CORES.min.origin);
  }, 240_000);
});
