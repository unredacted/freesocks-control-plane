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
 * It also proves the post-quantum key exchange each engine ends up with
 * (docs/client-compatibility.md § "Post-quantum key exchange",
 * tests/compat/pqMatrix.ts): through a tap in front of the cores
 * (docker/compat/hello-tap.ts) that reads the TLS 1.3 Client and Server Hello
 * of every connection, Mihomo with FCP's body and Xray-core from the backend's
 * share link must end on X25519MLKEM768 and sing-box on X25519; and through a
 * VLESS Encryption inbound, Xray-core and Mihomo connect on the encrypted
 * entry and are refused without it, while sing-box cannot hold the entry.
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
import { CLASSIC_GROUP, PQ_ENGINES, PQ_GROUP } from '../../tests/compat/pqMatrix';
import { clientEncryption, generateVlessEncryption } from './backend/vlessEncryption';
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
  'compat-pq-tap',
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
 * The tap in front of both cores (docker/compat/hello-tap.ts) and its ports,
 * fixed in docker-compose.compat.yml: an engine dialling the tap reaches the
 * core behind the port, and the tap answers which groups each connection's
 * handshake offered and picked.
 */
const TAP = {
  address: '10.89.72.13',
  ports: { fleet: { raw: 443, xhttp: 8443 }, latest: { raw: 9443, xhttp: 9843 } },
} as const;
/** Xray-core as a client, one container per release (started per test). */
const XRAY_CLIENTS = {
  fleet: { service: 'compat-pq-xray-client-fleet', address: '10.89.72.14' },
  latest: { service: 'compat-pq-xray-client-latest', address: '10.89.72.15' },
} as const;
/**
 * A VLESS Encryption inbound on both cores, over a plain WebSocket: the layer
 * is what a CDN-fronted member's traffic relies on, whatever carries it. A
 * fresh ML-KEM-768 seed per run; the client string is the one the backend
 * derives for the entries it writes.
 */
const ENC = { port: 8090, path: '/wse', server: generateVlessEncryption().decryption };
const ENC_CLIENT = clientEncryption(ENC.server)!;

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
      {
        tag: 'vless-encryption',
        listen: '0.0.0.0',
        port: ENC.port,
        protocol: 'vless',
        settings: { clients: [{ id: ID }], decryption: ENC.server },
        streamSettings: { network: 'ws', wsSettings: { path: ENC.path } },
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
function backendBody(core: Core, via: 'direct' | 'tap' = 'direct'): string {
  const server = via === 'tap' ? TAP.address : CORES[core].address;
  const ports = via === 'tap' ? TAP.ports[core] : PORTS;
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
      port: ports.raw,
      network: 'tcp',
      flow: 'xtls-rprx-vision',
      'packet-encoding': 'xudp',
    },
    {
      name: 'xhttp',
      ...common,
      port: ports.xhttp,
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
function mihomoConfig(body: string, pick: string): string {
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
function singboxConfig(core: Core, via: 'direct' | 'tap' = 'direct'): string {
  return JSON.stringify({
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: LISTEN }],
    outbounds: [
      {
        type: 'vless',
        tag: 'raw',
        server: via === 'tap' ? TAP.address : CORES[core].address,
        server_port: via === 'tap' ? TAP.ports[core].raw : PORTS.raw,
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

/**
 * The share links the backend writes for the two REALITY transports (the
 * Host's `chrome` fingerprint, as FCP makes its Hosts), as FCP serves them: a
 * base64 link list through `finishMemberBody`.
 */
function servedLinks(core: Core, via: 'direct' | 'tap'): Record<Transport, string> {
  const server = via === 'tap' ? TAP.address : CORES[core].address;
  const ports = via === 'tap' ? TAP.ports[core] : PORTS;
  const query = (extra: Record<string, string>) =>
    new URLSearchParams({
      encryption: 'none',
      security: 'reality',
      sni: SERVER_NAME,
      fp: 'chrome',
      pbk: KEYS.public,
      sid: SHORT_ID,
      ...extra,
    }).toString();
  const links = [
    `vless://${ID}@${server}:${ports.raw}?${query({ type: 'tcp', flow: 'xtls-rprx-vision', headerType: 'none' })}#raw`,
    `vless://${ID}@${server}:${ports.xhttp}?${query({ type: 'xhttp', path: XHTTP_PATH, mode: 'auto' })}#xhttp`,
  ];
  const body = finishMemberBody(Buffer.from(links.join('\n')).toString('base64'), null);
  const served = Buffer.from(body, 'base64').toString('utf8').split('\n').filter(Boolean);
  const byName = (name: Transport) => served.find((l) => l.endsWith(`#${name}`));
  const raw = byName('raw');
  const xhttp = byName('xhttp');
  if (!raw || !xhttp) throw new Error('the served link list lost an entry');
  return { raw, xhttp };
}

/** A VLESS Encryption entry's share link (the twin), with the client string or without (plain). */
function encryptedLink(encryption: string): string {
  const q = new URLSearchParams({ encryption, security: 'none', type: 'ws', path: ENC.path });
  return `vless://${ID}@${CORES.fleet.address}:${ENC.port}?${q.toString()}#twin`;
}

/** A share link's VLESS outbound, mapped the way the Xray apps (v2rayNG, v2rayN, Happ) map one. */
function xrayOutbound(link: string): Record<string, unknown> {
  const u = new URL(link);
  const p = u.searchParams;
  const network = p.get('type') === 'tcp' ? 'raw' : p.get('type')!;
  const security = p.get('security') ?? 'none';
  const stream: Record<string, unknown> = { network, security };
  if (security === 'reality')
    stream.realitySettings = {
      serverName: p.get('sni'),
      fingerprint: p.get('fp'),
      publicKey: p.get('pbk'),
      shortId: p.get('sid') ?? '',
    };
  if (network === 'xhttp')
    stream.xhttpSettings = { path: p.get('path'), mode: p.get('mode') ?? 'auto' };
  if (network === 'ws') stream.wsSettings = { path: p.get('path') };
  const user: Record<string, unknown> = {
    id: decodeURIComponent(u.username),
    encryption: p.get('encryption') ?? 'none',
  };
  if (p.get('flow')) user.flow = p.get('flow');
  return {
    tag: 'proxy',
    protocol: 'vless',
    settings: { vnext: [{ address: u.hostname, port: Number(u.port), users: [user] }] },
    streamSettings: stream,
  };
}

function xrayClientConfig(link: string): string {
  return JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'in',
        listen: '0.0.0.0',
        port: LISTEN,
        protocol: 'socks',
        settings: { auth: 'noauth' },
      },
    ],
    outbounds: [xrayOutbound(link)],
  });
}

/** Mihomo's proxy for the encrypted entry (`encryption` set) or the plain one. */
function mihomoEncryptedConfig(encryption: string | null): string {
  const proxy: Record<string, unknown> = {
    name: 'twin',
    type: 'vless',
    server: CORES.fleet.address,
    port: ENC.port,
    uuid: ID,
    udp: true,
    network: 'ws',
    'ws-opts': { path: ENC.path },
  };
  if (encryption) proxy.encryption = encryption;
  return mihomoConfig(YAML.stringify({ proxies: [proxy] }), 'twin');
}

/** sing-box's VLESS outbound carrying the encrypted entry's `encryption`. */
function singboxEncryptedConfig(): string {
  return JSON.stringify({
    log: { level: 'info' },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: LISTEN }],
    outbounds: [
      {
        type: 'vless',
        tag: 'twin',
        server: CORES.fleet.address,
        server_port: ENC.port,
        uuid: ID,
        encryption: ENC_CLIENT,
        transport: { type: 'ws', path: ENC.path },
      },
    ],
    route: { final: 'twin' },
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

let xrayRunning = false;
function stopEngines(): void {
  for (const binary of ['sing-box', 'mihomo']) inClient('pkill', '-x', binary);
  if (xrayRunning)
    for (const x of Object.values(XRAY_CLIENTS))
      spawnSync('docker', [...COMPOSE, 'rm', '-sf', x.service], { timeout: 60_000 });
  xrayRunning = false;
}

/** Start Xray-core `release` as a client of `link`, its SOCKS listener on its own address. */
async function startXray(release: Core, link: string): Promise<void> {
  stopEngines();
  writeFileSync(`${WORK}/xray-client.json`, xrayClientConfig(link));
  xrayRunning = true;
  compose('up', '-d', '--force-recreate', XRAY_CLIENTS[release].service);
  if (!(await until(() => reaches(XRAY_CLIENTS[release].address, LISTEN), 30_000, 250)))
    throw new Error(`Xray-core ${release} never listened`);
}

/** Whether Xray-core `release` with `link` reaches the page (retried while it settles). */
async function xrayConnects(release: Core, link: string): Promise<boolean> {
  await startXray(release, link);
  return until(() => fetchesPage(XRAY_CLIENTS[release].address), 30_000, 1500);
}

// --- the tap ---------------------------------------------------------------------------------------

/** One connection's key exchange as the tap read it (docker/compat/tlsHello.ts `describeObservation`). */
interface Hello {
  port: number;
  offered: string[];
  shares: string[];
  negotiated: string | null;
  helloRetry: boolean;
  tls13: boolean;
}

function tapHellos(): Hello[] {
  const r = inClient(
    'curl',
    '--silent',
    '--fail',
    '--max-time',
    '5',
    `http://${TAP.address}:9000/hellos`,
  );
  if (r.status !== 0) throw new Error('the tap did not answer');
  return JSON.parse(r.stdout) as Hello[];
}
function tapReset(): void {
  const r = inClient(
    'curl',
    '--silent',
    '--fail',
    '-X',
    'POST',
    `http://${TAP.address}:9000/reset`,
  );
  if (r.status !== 0) throw new Error('the tap did not reset');
}

/**
 * The key exchange of every connection an engine made to the tap's `port`
 * while it fetched the page (`start` brings the engine up; nothing it says is
 * printed). Throws when it never reached the page.
 */
async function keyExchanges(
  start: () => Promise<void>,
  listener: string,
  port: number,
): Promise<Hello[]> {
  await start();
  tapReset();
  if (!(await until(() => fetchesPage(listener), 30_000, 1500)))
    throw new Error('no page through the tap');
  stopEngines();
  const mine = tapHellos().filter((h) => h.port === port);
  if (mine.length === 0) throw new Error('the tap saw no handshake');
  return mine;
}

/** Every connection ended on `group`, and over TLS 1.3. */
function expectAllNegotiated(hellos: Hello[], group: string, what: string): void {
  for (const h of hellos) {
    expect(h.tls13, `${what}: TLS 1.3`).toBe(true);
    expect(h.negotiated, `${what}: picked`).toBe(group);
  }
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
function fetchesPage(listener = '127.0.0.1'): boolean {
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
    `${listener}:${LISTEN}`,
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
  return until(() => fetchesPage(), 30_000, 1500);
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
      for (const port of [...Object.values(PORTS), ENC.port])
        if (!(await until(() => reaches(core.address, port), 60_000)))
          throw new Error(`${core.service} never accepted a connection on ${port}`);
    for (const port of [9000, ...Object.values(TAP.ports).flatMap((p) => Object.values(p))])
      if (!(await until(() => reaches(TAP.address, port), 60_000)))
        throw new Error(`the tap never accepted a connection on ${port}`);
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

  // --- the post-quantum key exchange (tests/compat/pqMatrix.ts) ------------------------------------
  // Read off the wire by the tap: the group the core's Server Hello picked, for
  // every connection the engine made while it fetched the page.

  test('post-quantum: Mihomo with the body FCP serves ends on X25519MLKEM768, with the backend body on X25519', async () => {
    for (const core of ['fleet', 'latest'] as const)
      for (const pick of ['raw', 'xhttp'] as const) {
        const served = finishMemberBody(backendBody(core, 'tap'), null);
        const hellos = await keyExchanges(
          () => startEngine('mihomo', mihomoConfig(served, pick)),
          '127.0.0.1',
          TAP.ports[core][pick],
        );
        expectAllNegotiated(hellos, PQ_ENGINES.mihomo.reality!, `Mihomo, ${core}, ${pick}`);
        for (const h of hellos) expect(h.shares, `Mihomo, ${core}, ${pick}`).toContain(PQ_GROUP);
      }
    // Why FCP adds the key: the backend's own body (only the node image's
    // core still lets it in) removes the share, and the key exchange is classic.
    for (const pick of ['raw', 'xhttp'] as const) {
      const hellos = await keyExchanges(
        () => startEngine('mihomo', mihomoConfig(backendBody('fleet', 'tap'), pick)),
        '127.0.0.1',
        TAP.ports.fleet[pick],
      );
      expectAllNegotiated(hellos, CLASSIC_GROUP, `Mihomo, backend body, ${pick}`);
      for (const h of hellos) expect(h.shares).not.toContain(PQ_GROUP);
    }
  }, 600_000);

  test('post-quantum: Xray-core of both releases, from the share link, ends on X25519MLKEM768 on both cores', async () => {
    for (const release of ['fleet', 'latest'] as const)
      for (const core of ['fleet', 'latest'] as const)
        for (const pick of ['raw', 'xhttp'] as const) {
          const what = `Xray-core ${CORES[release].version} to ${CORES[core].version}, ${pick}`;
          const hellos = await keyExchanges(
            () => startXray(release, servedLinks(core, 'tap')[pick]),
            XRAY_CLIENTS[release].address,
            TAP.ports[core][pick],
          );
          expectAllNegotiated(hellos, PQ_ENGINES.xray.reality!, what);
          for (const h of hellos) expect(h.shares, what).toContain(PQ_GROUP);
        }
  }, 900_000);

  // The pinned no: when a sing-box release offers X25519MLKEM768 this fails,
  // and the matrix, the docs and the hold on the node image's Xray move with it.
  test("pinned: sing-box offers no post-quantum key share and ends on X25519 on the node image's core", async () => {
    const hellos = await keyExchanges(
      () => startEngine('singbox', singboxConfig('fleet', 'tap')),
      '127.0.0.1',
      TAP.ports.fleet.raw,
    );
    expectAllNegotiated(hellos, PQ_ENGINES.singbox.reality!, 'sing-box');
    for (const h of hellos) expect(h.shares, 'sing-box').not.toContain(PQ_GROUP);
  }, 120_000);

  test('VLESS Encryption: Xray-core and Mihomo connect on the encrypted entry and are refused without it; sing-box cannot hold it', async () => {
    /** No fetch gets through (two tries), the engine running. */
    const refusedWith = async (start: () => Promise<void>, listener: string) => {
      await start();
      for (let i = 0; i < 2; i++) if (fetchesPage(listener)) return false;
      return true;
    };
    expect(ENC_CLIENT.startsWith('mlkem768x25519plus.')).toBe(true);
    for (const release of ['fleet', 'latest'] as const) {
      const what = `Xray-core ${CORES[release].version}`;
      expect(await xrayConnects(release, encryptedLink(ENC_CLIENT)), `${what}, encrypted`).toBe(
        PQ_ENGINES.xray.vlessEncryption,
      );
      // The inbound refuses a client that does not speak the layer: the
      // connection above went over it.
      expect(
        await refusedWith(
          () => startXray(release, encryptedLink('none')),
          XRAY_CLIENTS[release].address,
        ),
        `${what}, plain`,
      ).toBe(true);
    }
    expect(await connects('mihomo', mihomoEncryptedConfig(ENC_CLIENT)), 'Mihomo, encrypted').toBe(
      PQ_ENGINES.mihomo.vlessEncryption,
    );
    expect(
      await refusedWith(() => startEngine('mihomo', mihomoEncryptedConfig(null)), '127.0.0.1'),
      'Mihomo, plain',
    ).toBe(true);
    // The pinned no: sing-box's VLESS outbound has no `encryption`.
    expect(PQ_ENGINES.singbox.vlessEncryption).toBe(false);
    await expect(startEngine('singbox', singboxEncryptedConfig())).rejects.toThrow(
      'singbox refused the configuration',
    );
  }, 600_000);
});
