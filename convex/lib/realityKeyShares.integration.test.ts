/**
 * The REALITY key share against REAL Xray-cores (docs/client-compatibility.md
 * § "REALITY client versions"): the pinned Mihomo and sing-box connect, or do
 * not, through the core the node image runs (v26.7.28) and a release from
 * v26.9.8 on, which refuses a Client Hello that does not offer X25519MLKEM768
 * ahead of X25519.
 *
 * Mihomo runs a body as the backend writes it for a Host without its Mihomo
 * override, and the same body as FCP serves it (`finishMemberBody`), over raw
 * TCP with Vision and over XHTTP. sing-box runs the entry the backend writes
 * for it; it removes X25519MLKEM768 itself, so no body lets it into the newer
 * core. Each transport sets `minClientVer` 1.8.1, as FCP's profile template
 * does, so the older core's default minimum is not what is tested.
 *
 * It runs only under scripts/compat/reality-keyshare.sh (the `reality-key-share`
 * job in .github/workflows/client-compatibility.yml), which downloads the
 * engines, builds their image and always tears the containers down; without
 * FCP_REALITY_KEYSHARE the suite skips. Never prints a config or an engine log:
 * they carry the per-run client id. A refusal is asserted by what the engine
 * logs when the server hands it to the target, read in the container and never
 * echoed.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import YAML from 'yaml';
import { MIHOMO_YAML } from './backend/subscriptionTemplates/MIHOMO';
import { finishMemberBody } from './subscriptionDelivery';

const ENABLED = process.env.FCP_REALITY_KEYSHARE === '1';
const WORK = '.cache/compat/reality';
// The project name comes from COMPOSE_PROJECT_NAME (set by the run script).
const COMPOSE = ['compose', '-f', 'docker-compose.compat.yml'];
const SERVICES = [
  'compat-reality-target',
  'compat-reality-xray-fleet',
  'compat-reality-xray-latest',
  'compat-reality-client',
];

/** Fixed in docker-compose.compat.yml. */
const CORES = {
  fleet: { service: 'compat-reality-xray-fleet', address: '10.89.72.11', version: '26.7.28' },
  latest: { service: 'compat-reality-xray-latest', address: '10.89.72.12', version: '26.10.21' },
} as const;
type Core = keyof typeof CORES;
const TARGET = '10.89.73.20';
/** An example name only (docs/edges.md: never a real target). */
const SERVER_NAME = 'decoy.example';
const PORTS = { raw: 443, xhttp: 8443 } as const;
type Transport = keyof typeof PORTS;
const XHTTP_PATH = '/kx';
const LISTEN = 1080;

/**
 * What an engine says when the server hands it to the target, as it does a
 * Client Hello it refuses: the engine then checks the target's certificate
 * like any TLS client, and the test target's (Caddy's internal CA) is one no
 * client trusts. The certificate of a client the server lets in is checked
 * against the REALITY key instead, never against a CA. (Against a public
 * target the same refusal reads `REALITY authentication failed` in Mihomo and
 * `reality verification failed` in sing-box.)
 */
const HANDED_TO_TARGET = 'x509: certificate signed by unknown authority';
type Engine = 'mihomo' | 'singbox';

// Per run: nothing here authenticates anything once the containers are gone.
const ID = randomUUID();
const SHORT_ID = randomBytes(4).toString('hex');
const KEYS = (() => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  // JWK `x` / `d` are unpadded base64url, the encoding Xray reads.
  return {
    public: publicKey.export({ format: 'jwk' }).x!,
    private: privateKey.export({ format: 'jwk' }).d!,
  };
})();

function xrayConfig(): unknown {
  const realitySettings = {
    target: `${TARGET}:443`,
    serverNames: [SERVER_NAME],
    privateKey: KEYS.private,
    shortIds: [SHORT_ID],
    minClientVer: '1.8.1',
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
    // Every tunnel ends at the page, whatever the client asked for.
    outbounds: [
      {
        tag: 'to-page',
        protocol: 'freedom',
        settings: {
          redirect: `${TARGET}:8080`,
          finalRules: [{ action: 'allow', ip: [`${TARGET}/32`] }],
        },
      },
    ],
  };
}

/**
 * The backend's Mihomo body for one core, as its Mihomo generator writes it for
 * a Host whose Mihomo override is not ticked (no `support-x25519mlkem768`).
 */
function backendBody(core: Core): string {
  const server = CORES[core].address;
  const common = {
    type: 'vless',
    server,
    uuid: ID,
    udp: true,
    tls: true,
    servername: SERVER_NAME,
    'client-fingerprint': 'chrome',
    'reality-opts': { 'public-key': KEYS.public, 'short-id': SHORT_ID },
  };
  const proxies = [
    {
      name: 'raw',
      ...common,
      port: PORTS.raw,
      network: 'tcp',
      flow: 'xtls-rprx-vision',
      'packet-encoding': 'xudp',
    },
    {
      name: 'xhttp',
      ...common,
      port: PORTS.xhttp,
      network: 'xhttp',
      'xhttp-opts': { path: XHTTP_PATH },
    },
  ];
  const doc = YAML.parse(MIHOMO_YAML) as Record<string, unknown> & {
    'proxy-groups': Array<Record<string, unknown>>;
  };
  doc.proxies = proxies;
  doc['proxy-groups'][0]!.proxies = proxies.map((p) => p.name);
  return YAML.stringify(doc);
}

/** A body's proxies in a sandbox config: a local listener, `pick` carrying every request. */
function mihomoConfig(body: string, pick: Transport): string {
  const doc = YAML.parse(body) as { proxies: unknown[] };
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
    proxies: doc.proxies,
    rules: [`MATCH,${pick}`],
  });
}

/** The entry the backend's sing-box generator writes for the raw transport. */
function singboxConfig(core: Core): string {
  return JSON.stringify({
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: LISTEN }],
    outbounds: [
      {
        type: 'vless',
        tag: 'raw',
        server: CORES[core].address,
        server_port: PORTS.raw,
        uuid: ID,
        flow: 'xtls-rprx-vision',
        tls: {
          enabled: true,
          server_name: SERVER_NAME,
          utls: { enabled: true, fingerprint: 'chrome' },
          reality: { enabled: true, public_key: KEYS.public, short_id: SHORT_ID },
        },
      },
    ],
    route: { final: 'raw' },
  });
}

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

function stopEngines(): void {
  for (const binary of ['sing-box', 'mihomo']) inClient('pkill', '-x', binary);
}

/**
 * Start one engine with `config`. Its home and log stay inside the container
 * (/tmp), so nothing it writes lands in the checkout, and the log is never
 * printed.
 */
async function startEngine(engine: Engine, config: string): Promise<void> {
  stopEngines();
  await until(() => !reaches('127.0.0.1', LISTEN), 10_000, 200);
  const file = engine === 'singbox' ? 'client.json' : 'client.yaml';
  writeFileSync(`${WORK}/client/${file}`, config);
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
  if (!(await until(() => reaches('127.0.0.1', LISTEN), 30_000, 250)))
    throw new Error(`${engine} never listened`);
}

/** One fetch of the page through the engine; true when the page answered through the tunnel. */
function fetchesPage(): boolean {
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
    `127.0.0.1:${LISTEN}`,
    `http://page.example/${nonce}`,
  );
  return r.status === 0 && r.stdout.trim() === `reality-page /${nonce}`;
}

/** Whether the engine's log has these words (read in the container, never printed). */
function engineSaid(engine: Engine, words: string): boolean {
  return inClient('grep', '-qF', words, `/tmp/${engine}.log`).status === 0;
}

/** Whether `engine` with `config` reaches the page (retried while it settles). */
async function connects(engine: Engine, config: string): Promise<boolean> {
  await startEngine(engine, config);
  return until(fetchesPage, 30_000, 1500);
}

/**
 * How `engine` with `config` fares when the server should refuse it: `refused`
 * (no fetch got through and the engine was handed the target), `connected`, or
 * `failed` (no fetch got through, for another reason).
 */
async function refusal(engine: Engine, config: string): Promise<string> {
  await startEngine(engine, config);
  for (let i = 0; i < 2; i++) if (fetchesPage()) return 'connected';
  return (await until(() => engineSaid(engine, HANDED_TO_TARGET), 10_000, 500))
    ? 'refused'
    : 'failed';
}

describe.skipIf(!ENABLED)('REALITY key shares against real Xray-cores', () => {
  beforeAll(async () => {
    rmSync(WORK, { recursive: true, force: true });
    mkdirSync(`${WORK}/client`, { recursive: true });
    writeFileSync(`${WORK}/xray.json`, JSON.stringify(xrayConfig()));
    compose('up', '-d', ...SERVICES);
    client = compose('ps', '-q', 'compat-reality-client').trim();
    if (!client) throw new Error('the client container did not start');
    for (const core of Object.values(CORES))
      for (const port of Object.values(PORTS))
        if (!(await until(() => reaches(core.address, port), 60_000)))
          throw new Error(`${core.service} never accepted a connection on ${port}`);
  }, 300_000);

  afterAll(() => {
    if (client) stopEngines();
  });

  test('the two cores are the releases this test is about', () => {
    for (const core of Object.values(CORES)) {
      const running = compose('ps', '-q', core.service).trim();
      const image = execFileSync('docker', ['inspect', '-f', '{{.Config.Image}}', running], {
        encoding: 'utf8',
      }).trim();
      const out = execFileSync(
        'docker',
        ['run', '--rm', '--network', 'none', '--platform', 'linux/amd64', image, 'version'],
        { encoding: 'utf8', timeout: 60_000 },
      );
      expect(out.split('\n')[0]).toContain(`Xray ${core.version} `);
    }
  });

  test("the node image's core (v26.7.28) lets every client in", async () => {
    const backend = backendBody('fleet');
    const served = finishMemberBody(backend, null);
    // Booleans only: a body carries the per-run client id.
    expect(backend.includes('support-x25519mlkem768'), 'the backend body asks').toBe(false);
    expect(served.includes('support-x25519mlkem768: true'), 'the served body asks').toBe(true);
    for (const pick of ['raw', 'xhttp'] as const) {
      expect(await connects('mihomo', mihomoConfig(backend, pick)), `backend body, ${pick}`).toBe(
        true,
      );
      expect(await connects('mihomo', mihomoConfig(served, pick)), `served body, ${pick}`).toBe(
        true,
      );
    }
    expect(await connects('singbox', singboxConfig('fleet')), 'sing-box').toBe(true);
  }, 300_000);

  test('from v26.9.8 on, Mihomo gets in only with the body FCP serves', async () => {
    const backend = backendBody('latest');
    const served = finishMemberBody(backend, null);
    for (const pick of ['raw', 'xhttp'] as const) {
      expect(await refusal('mihomo', mihomoConfig(backend, pick)), `backend body, ${pick}`).toBe(
        'refused',
      );
      expect(await connects('mihomo', mihomoConfig(served, pick)), `served body, ${pick}`).toBe(
        true,
      );
    }
  }, 300_000);

  test('from v26.9.8 on, sing-box never gets in', async () => {
    expect(await refusal('singbox', singboxConfig('latest'))).toBe('refused');
  }, 120_000);
});
