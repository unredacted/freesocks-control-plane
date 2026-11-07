/**
 * Hysteria 2 against a REAL Xray-core (docs/client-compatibility.md
 * § "Hysteria engines"): the core the node image runs (v26.7.28) serves FCP's
 * own Hysteria transport (`buildTransport`, with a certificate from
 * `generateHysteriaCertificate`), and the pinned engines connect through it
 * from the entry a member receives: the backend's entry for a pinned Host,
 * with FCP's Host rewrites applied (`hysteriaHostMapper`), through FCP's
 * delivery guard (`guardHysteria`) unchanged.
 *
 *  - Xray-core reads the `hysteria2://` link (the Privacy raw config) the way
 *    the Xray apps map it: `pinSHA256` becomes `pinnedPeerCertSha256`;
 *    sing-box runs its outbound (`certificate_public_key_sha256`, the SPKI
 *    pin) and Mihomo its proxy (`fingerprint`, the certificate pin).
 *  - Each carries a page fetch and a UDP datagram round trip (a DNS question
 *    to an echo service behind the server, through the engine's SOCKS UDP
 *    association), so the tunnel is proved to carry UDP, not only TCP.
 *  - A rogue Xray-core with another certificate for the same name, which
 *    accepts the member's password, answers in the node's place (the entry's
 *    server pointed at it, as a hijacked route would). Every engine refuses it
 *    and the rogue's access log stays empty, so no engine handed it the
 *    password: had one, the rogue would have accepted it and carried the
 *    request. A control run with the rogue's own pins then connects and is
 *    logged, so the refusal is the pin and the log would have shown it.
 *
 * It runs only under scripts/compat/hysteria.sh (the `hysteria-engines` job in
 * .github/workflows/client-compatibility.yml), which downloads the engines,
 * builds their image and always tears the containers down; without
 * FCP_HYSTERIA_ENGINES the suite skips. Never prints a config or a log: they
 * carry the per-run password.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { buildTransport, type ModeTemplateInput } from './backend/profileTemplate';
import { generateHysteriaCertificate, type HysteriaCertificate } from './backend/hysteriaCert';
import { hysteriaHostMapper } from './backend/hostMapper';
import { guardHysteria } from './hysteriaGuard';
import { applyMapper } from './edges/testing/fakeBackend';

const ENABLED = process.env.FCP_HYSTERIA_ENGINES === '1';
const WORK = '.cache/compat/hysteria';
// The project name comes from COMPOSE_PROJECT_NAME (set by the run script).
const COMPOSE = ['compose', '-f', 'docker-compose.compat.yml'];
/** Fixed in docker-compose.compat.yml. */
const NODE = { service: 'compat-hysteria-node', address: '10.89.72.41', version: '26.7.28' };
const ROGUE = { service: 'compat-hysteria-rogue', address: '10.89.72.42' };
const XRAY_CLIENT = { service: 'compat-hysteria-xray-client', address: '10.89.72.43' };
const ENGINE_CLIENT = 'compat-hysteria-client';
const SERVICES = [
  'compat-reality-target',
  'compat-hysteria-echo',
  NODE.service,
  ROGUE.service,
  ENGINE_CLIENT,
];
/** The page (compat-reality-target :8080) and the DNS echo, behind the servers only. */
const PAGE = '10.89.73.20:8080';
const ECHO = '10.89.73.30';
/** An example name only (docs/privacy.md: never a real node's name). */
const SERVER_NAME = 'hy.example';
const PORT = 443;
const LISTEN = 1080;
/** The email the backend gives a user on the node; every request it carries is logged with it. */
const EMAIL = 'compat-member';

type Engine = 'xray' | 'singbox' | 'mihomo';
const ENGINES: readonly Engine[] = ['xray', 'singbox', 'mihomo'];

// Per run: nothing here authenticates anything once the containers are gone.
const PASSWORD = randomUUID();
const NODE_CERT = generateHysteriaCertificate(SERVER_NAME);
const ROGUE_CERT = generateHysteriaCertificate(SERVER_NAME);

const MODE: ModeTemplateInput = {
  slug: 'privacy-hysteria',
  name: 'Privacy-Hysteria',
  shape: { transport: 'hysteria', fronting: 'direct' },
  hysteria: { serverName: SERVER_NAME, salamander: false },
};

/** One Xray-core serving FCP's Hysteria transport with `cert`, the member added as the backend adds users. */
function serverConfig(cert: HysteriaCertificate): unknown {
  const inbound = buildTransport(MODE, undefined, { certificate: cert.certificate, key: cert.key });
  const settings = inbound.settings as { clients: unknown[] };
  settings.clients = [{ auth: PASSWORD, email: EMAIL }];
  return {
    // The access log (stdout) names the user of every request it carries.
    log: { loglevel: 'warning', access: '' },
    inbounds: [inbound],
    outbounds: [
      {
        tag: 'out',
        protocol: 'freedom',
        settings: { finalRules: [{ action: 'allow', ip: ['10.89.73.0/24'] }] },
      },
    ],
  };
}

// --- the entries a member receives -----------------------------------------------------------------

type Pins = { pinHex: string; spkiB64: string };
const mapper = (pins: Pins) => hysteriaHostMapper(pins);

/**
 * The link the backend writes for a pinned Host (its own pin, the Xray-only
 * `fm` finalmask and, for older apps, `insecure`), with FCP's rewrites.
 */
function link(server: string, pins: Pins): string {
  const q: Record<string, string> = {
    sni: SERVER_NAME,
    alpn: 'h3',
    insecure: '1',
    pinSHA256: pins.pinHex,
    fm: JSON.stringify({ quicParams: { congestion: 'bbr' } }),
  };
  applyMapper(q, mapper(pins).base64, true);
  return `hysteria2://${PASSWORD}@${server}:${PORT}/?${new URLSearchParams(q).toString()}#${encodeURIComponent('🇺🇸 Example Port · UDP')}`;
}

/** The backend's sing-box outbound (its pin turned into `insecure`), with FCP's rewrites. */
function singboxOutbound(server: string, pins: Pins): Record<string, unknown> {
  const o = {
    type: 'hysteria2',
    tag: 'proxy',
    server,
    server_port: PORT,
    password: PASSWORD,
    tls: { enabled: true, server_name: SERVER_NAME, insecure: true, alpn: ['h3'] },
  };
  return applyMapper(o, mapper(pins).singbox);
}

/** The backend's Mihomo proxy (its pin turned into `skip-cert-verify`), with FCP's rewrites. */
function mihomoProxy(server: string, pins: Pins): Record<string, unknown> {
  const o = {
    name: 'proxy',
    type: 'hysteria2',
    server,
    port: PORT,
    password: PASSWORD,
    sni: SERVER_NAME,
    'skip-cert-verify': true,
    alpn: ['h3'],
  };
  return applyMapper(o, mapper(pins).mihomo);
}

/** A whole member body around one entry, for the guard. */
function bodyOf(engine: Engine, server: string, pins: Pins): string {
  if (engine === 'xray') return Buffer.from(link(server, pins)).toString('base64');
  if (engine === 'singbox')
    return JSON.stringify({
      outbounds: [
        { type: 'selector', tag: 'FreeSocks', outbounds: ['proxy'] },
        singboxOutbound(server, pins),
      ],
      route: { final: 'FreeSocks' },
    });
  return YAML.stringify({
    proxies: [mihomoProxy(server, pins)],
    'proxy-groups': [{ name: 'FreeSocks', type: 'select', proxies: ['proxy'] }],
    rules: ['MATCH,FreeSocks'],
  });
}

// --- engine configs: a local listener in front of the entry ----------------------------------------

/** The Xray outbound for a link, as the Xray apps map one (pinSHA256 → pinnedPeerCertSha256). */
function xrayClientConfig(l: string): unknown {
  const u = new URL(l);
  const pin = u.searchParams.get('pinSHA256');
  if (!pin || u.searchParams.has('insecure')) throw new Error('the link lost its pin');
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'in',
        listen: '0.0.0.0',
        port: LISTEN,
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true, ip: XRAY_CLIENT.address },
      },
    ],
    outbounds: [
      {
        tag: 'proxy',
        protocol: 'hysteria',
        settings: { version: 2, address: u.hostname, port: Number(u.port) },
        streamSettings: {
          network: 'hysteria',
          security: 'tls',
          tlsSettings: {
            serverName: u.searchParams.get('sni'),
            alpn: (u.searchParams.get('alpn') ?? 'h3').split(','),
            pinnedPeerCertSha256: pin,
          },
          hysteriaSettings: { version: 2, auth: decodeURIComponent(u.username) },
        },
      },
    ],
  };
}

function singboxClientConfig(outbound: Record<string, unknown>): string {
  return JSON.stringify({
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: LISTEN }],
    outbounds: [outbound],
    route: { final: 'proxy' },
  });
}

function mihomoClientConfig(proxy: Record<string, unknown>): string {
  return YAML.stringify({
    'mixed-port': LISTEN,
    'allow-lan': false,
    'bind-address': '127.0.0.1',
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    'geodata-mode': false,
    'geo-auto-update': false,
    dns: { enable: false },
    proxies: [proxy],
    rules: ['MATCH,proxy'],
  });
}

// --- running them ----------------------------------------------------------------------------------

let client = '';
const compose = (...args: string[]) =>
  execFileSync('docker', [...COMPOSE, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const inClient = (...args: string[]) =>
  spawnSync('docker', ['exec', client, ...args], { encoding: 'utf8', timeout: 60_000 });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until(check: () => boolean, ms: number, every = 500): Promise<boolean> {
  const end = Date.now() + ms;
  for (;;) {
    if (check()) return true;
    if (Date.now() > end) return false;
    await sleep(every);
  }
}

const reaches = (address: string, port: number) =>
  inClient(
    'python3',
    '-c',
    `import socket; socket.create_connection(("${address}",${port}),2).close()`,
  ).status === 0;

/** Where the engine's SOCKS listener is, seen from the engine container. */
const listenerOf = (engine: Engine) => (engine === 'xray' ? XRAY_CLIENT.address : '127.0.0.1');

function stopEngines(): void {
  for (const binary of ['sing-box', 'mihomo']) inClient('pkill', '-x', binary);
  spawnSync('docker', [...COMPOSE, 'rm', '-sf', XRAY_CLIENT.service], { timeout: 60_000 });
}

/**
 * Start one engine with the entry for `server`. sing-box and Mihomo run in
 * the engine container (their home and log stay in its /tmp); Xray-core runs
 * as its own container from the node image's release. Nothing is printed.
 */
async function startEngine(engine: Engine, server: string, pins: Pins): Promise<void> {
  stopEngines();
  await until(() => !reaches('127.0.0.1', LISTEN), 10_000, 200);
  if (engine === 'xray') {
    writeFileSync(`${WORK}/xray-client.json`, JSON.stringify(xrayClientConfig(link(server, pins))));
    compose('up', '-d', XRAY_CLIENT.service);
  } else {
    const file = engine === 'singbox' ? 'client.json' : 'client.yaml';
    writeFileSync(
      `${WORK}/client/${file}`,
      engine === 'singbox'
        ? singboxClientConfig(singboxOutbound(server, pins))
        : mihomoClientConfig(mihomoProxy(server, pins)),
    );
    const [check, run] =
      engine === 'singbox'
        ? [`sing-box check -c /work/${file}`, `sing-box run -c /work/${file}`]
        : [
            `mkdir -p /tmp/mihomo && mihomo -t -d /tmp/mihomo -f /work/${file}`,
            `mihomo -d /tmp/mihomo -f /work/${file}`,
          ];
    if (inClient('sh', '-c', `${check} >/dev/null 2>&1`).status !== 0)
      throw new Error(`${engine} refused the configuration`);
    execFileSync('docker', ['exec', '-d', client, 'sh', '-c', `${run} >/tmp/${engine}.log 2>&1`]);
  }
  if (!(await until(() => reaches(listenerOf(engine), LISTEN), 30_000, 250)))
    throw new Error(`${engine} never listened`);
}

/** One fetch of the page through the engine; true when the page answered through the tunnel. */
function fetchesPage(engine: Engine): boolean {
  const nonce = randomUUID();
  const r = inClient(
    'curl',
    '--silent',
    '--fail',
    '--max-time',
    '10',
    '--noproxy',
    '',
    '--socks5-hostname',
    `${listenerOf(engine)}:${LISTEN}`,
    `http://${PAGE}/${nonce}`,
  );
  return r.status === 0 && r.stdout.trim() === `reality-page /${nonce}`;
}

/** One DNS question to the echo through the engine's SOCKS UDP association (scripts/compat/probe.py). */
function udpRoundTrip(engine: Engine): boolean {
  const r = inClient('python3', '/probe.py', ECHO, listenerOf(engine));
  return r.status === 0 && r.stdout.includes('UDP_DNS_OK');
}

/** How many requests the server's access log carried for the member (read here, never printed). */
function carriedFor(service: string): number {
  const id = compose('ps', '-q', service).trim();
  const r = spawnSync('docker', ['logs', id], { encoding: 'utf8', timeout: 60_000 });
  return `${r.stdout}\n${r.stderr}`.split('\n').filter((l) => l.includes(`email: ${EMAIL}`)).length;
}

const nodePins: Pins = { pinHex: NODE_CERT.pinHex, spkiB64: NODE_CERT.spkiB64 };
const roguePins: Pins = { pinHex: ROGUE_CERT.pinHex, spkiB64: ROGUE_CERT.spkiB64 };

describe.skipIf(!ENABLED)('Hysteria 2 through a real Xray-core', () => {
  beforeAll(async () => {
    rmSync(WORK, { recursive: true, force: true });
    mkdirSync(`${WORK}/client`, { recursive: true });
    writeFileSync(`${WORK}/node.json`, JSON.stringify(serverConfig(NODE_CERT)));
    writeFileSync(`${WORK}/rogue.json`, JSON.stringify(serverConfig(ROGUE_CERT)));
    compose('up', '-d', ...SERVICES);
    client = compose('ps', '-q', ENGINE_CLIENT).trim();
    if (!client) throw new Error('the engine container did not start');
    // UDP has no connect to wait on: each test's first fetch, retried, is the readiness check.
  }, 300_000);

  afterAll(() => {
    if (client) stopEngines();
  });

  test("the node's core is the release the node image runs", () => {
    const running = compose('ps', '-q', NODE.service).trim();
    const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', running], {
      encoding: 'utf8',
    }).trim();
    const out = execFileSync(
      'docker',
      ['run', '--rm', '--network', 'none', '--platform', 'linux/amd64', image, 'version'],
      { encoding: 'utf8', timeout: 60_000 },
    );
    expect(out.split('\n')[0]).toContain(`Xray ${NODE.version} `);
  });

  test('every entry, rewritten by FCP, passes the delivery guard untouched and verifies by pin only', () => {
    const expected = { pinHex: [NODE_CERT.pinHex], spkiB64: [NODE_CERT.spkiB64] };
    for (const engine of ENGINES) {
      const body = bodyOf(engine, NODE.address, nodePins);
      expect(guardHysteria(body, expected), engine).toEqual({
        kind: 'kept',
        content: body,
        dropped: 0,
      });
    }
    // Booleans only: an entry carries the per-run password.
    const l = new URL(link(NODE.address, nodePins));
    expect(l.searchParams.get('pinSHA256')).toBe(NODE_CERT.pinHex);
    expect(l.searchParams.has('insecure') || l.searchParams.has('fm')).toBe(false);
    const sb = singboxOutbound(NODE.address, nodePins).tls as Record<string, unknown>;
    expect(sb.certificate_public_key_sha256).toEqual([NODE_CERT.spkiB64]);
    expect('insecure' in sb).toBe(false);
    const mh = mihomoProxy(NODE.address, nodePins);
    expect(mh.fingerprint).toBe(NODE_CERT.pinHex);
    expect('skip-cert-verify' in mh).toBe(false);
  });

  for (const engine of ENGINES)
    test(`${engine}: connects to the node and carries a page and a UDP round trip`, async () => {
      await startEngine(engine, NODE.address, nodePins);
      expect(await until(() => fetchesPage(engine), 45_000, 1500), 'page').toBe(true);
      expect(await until(() => udpRoundTrip(engine), 30_000, 1500), 'UDP').toBe(true);
    }, 180_000);

  test('the node carried those requests for the member', () => {
    expect(carriedFor(NODE.service)).toBeGreaterThan(0);
  });

  for (const engine of ENGINES)
    test(`${engine}: refuses a rogue with another certificate, and hands it nothing`, async () => {
      await startEngine(engine, ROGUE.address, nodePins);
      for (let i = 0; i < 3; i++) {
        expect(fetchesPage(engine), 'page').toBe(false);
        expect(udpRoundTrip(engine), 'UDP').toBe(false);
      }
      expect(carriedFor(ROGUE.service)).toBe(0);
    }, 180_000);

  test("control: with the rogue's own pins every engine gets through it, and it logs that", async () => {
    for (const engine of ENGINES) {
      await startEngine(engine, ROGUE.address, roguePins);
      expect(await until(() => fetchesPage(engine), 45_000, 1500), engine).toBe(true);
    }
    expect(carriedFor(ROGUE.service)).toBeGreaterThan(0);
  }, 300_000);
});
