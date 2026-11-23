/**
 * The local target for the Hysteria app checks (docs/client-compatibility.md
 * § "Hysteria in real apps"): the node image's Xray-core serving FCP's own
 * Hysteria transport and a rogue with another certificate for the same name,
 * both published on the runner's loopback (docker-compose.compat-apps.yml),
 * and the raw configs a real application imports, served over HTTP.
 *
 *   bun --no-env-file scripts/compat/hysteria-apps/fixture.ts up <entry host>
 *   bun --no-env-file scripts/compat/hysteria-apps/fixture.ts carried <node|rogue>
 *
 * `up` writes a fresh certificate pair and password, starts the containers and
 * writes three raw configs (base64 link lists, as Privacy delivers them) under
 * .cache/compat/hysteria-apps/www, for `scripts/compat/hysteria-apps/serve.py`:
 *
 *  - `good`: a `· Direct` REALITY entry and the `· UDP` Hysteria entry for the
 *    node, the Hysteria one as the backend writes it for a pinned Host with
 *    FCP's rewrites applied, through FCP's delivery guard unchanged;
 *  - `wrongpin`: the same `· UDP` entry with one character of its pin changed;
 *  - `rogue`: the `· UDP` entry with the node's pin, pointed at the rogue
 *    (as a hijacked route would), which would accept the member's password.
 *
 * `carried` prints how many requests that server carried for the member (its
 * access log; nothing else is read or printed). The page behind the servers
 * (http://10.89.73.20:8080/<nonce>) is reachable only through them.
 *
 * Every value here is per run and dies with the containers.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import {
  buildTransport,
  type ModeTemplateInput,
} from '../../../convex/lib/backend/profileTemplate';
import { generateHysteriaCertificate } from '../../../convex/lib/backend/hysteriaCert';
import { hysteriaHostMapper } from '../../../convex/lib/backend/hostMapper';
import { guardHysteria } from '../../../convex/lib/hysteriaGuard';
import { applyMapper } from '../../../convex/lib/edges/testing/fakeBackend';
import { hysteriaApps, type HysteriaApp } from '../../../tests/compat/hysteriaApps';

const WORK = '.cache/compat/hysteria-apps';
const ENGINES_WORK = '.cache/compat/hysteria';
const COMPOSE = [
  'compose',
  '-f',
  'docker-compose.compat.yml',
  '-f',
  'docker-compose.compat-apps.yml',
];
const SERVICES = [
  'compat-reality-target',
  'compat-hysteria-echo',
  'compat-hysteria-node',
  'compat-hysteria-rogue',
];
/** Published by docker-compose.compat-apps.yml. */
const NODE_PORT = 8443;
const ROGUE_PORT = 8444;
/** Nothing listens here: the `· Direct` entry only has to be imported. */
const DIRECT_PORT = 8445;
/** An example name only (docs/privacy.md: never a real node's name). */
const SERVER_NAME = 'hy.example';
const EMAIL = 'compat-member';
const PLACE = '🇺🇸 Example Port';

const MODE: ModeTemplateInput = {
  slug: 'privacy-hysteria',
  name: 'Privacy-Hysteria',
  shape: { transport: 'hysteria', fronting: 'direct' },
  hysteria: { serverName: SERVER_NAME, salamander: false },
};

// Same project and Bun as scripts/compat/hysteria.sh (the echo service reads it).
process.env.COMPOSE_PROJECT_NAME = 'fcp-hysteria-apps';
const bun = /"packageManager":\s*"bun@([^"]+)"/.exec(readFileSync('package.json', 'utf8'))?.[1];
if (!bun) throw new Error('could not read the bun version from package.json');
process.env.FCP_COMPAT_BUN_VERSION = bun;

const compose = (...args: string[]) =>
  execFileSync('docker', [...COMPOSE, ...args], {
    encoding: 'utf8',
    timeout: 300_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

function serverConfig(cert: { certificate: string; key: string }, password: string): unknown {
  const inbound = buildTransport(MODE, undefined, { certificate: cert.certificate, key: cert.key });
  (inbound.settings as { clients: unknown[] }).clients = [{ auth: password, email: EMAIL }];
  return {
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

type Pins = { pinHex: string; spkiB64: string };

/** The backend's link for a pinned Host (its own pin, `fm` and `insecure`), with FCP's rewrites. */
function hysteriaLink(password: string, host: string, port: number, pins: Pins): string {
  const q: Record<string, string> = {
    sni: SERVER_NAME,
    alpn: 'h3',
    insecure: '1',
    pinSHA256: pins.pinHex,
    fm: JSON.stringify({ quicParams: { congestion: 'bbr' } }),
  };
  applyMapper(q, hysteriaHostMapper(pins).base64, true);
  return `hysteria2://${password}@${host}:${port}/?${new URLSearchParams(q).toString()}#${encodeURIComponent(`${PLACE} · UDP`)}`;
}

/** A REALITY entry of the shape Privacy delivers (a real X25519 key, nothing listening). */
function directLink(id: string, host: string): string {
  const { publicKey } = generateKeyPairSync('x25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const q = new URLSearchParams({
    encryption: 'none',
    flow: 'xtls-rprx-vision',
    security: 'reality',
    sni: 'dl.example',
    fp: 'chrome',
    pbk: raw.toString('base64url'),
    sid: randomBytes(4).toString('hex'),
    type: 'tcp',
  });
  return `vless://${id}@${host}:${DIRECT_PORT}?${q.toString()}#${encodeURIComponent(`${PLACE} · Direct`)}`;
}

const raw = (...lines: string[]) => Buffer.from(lines.join('\n') + '\n').toString('base64');

function up(host: string): void {
  const password = randomUUID();
  const node = generateHysteriaCertificate(SERVER_NAME);
  const rogue = generateHysteriaCertificate(SERVER_NAME);
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(`${WORK}/www`, { recursive: true });
  // The engines' compose services read their configs from here.
  rmSync(ENGINES_WORK, { recursive: true, force: true });
  mkdirSync(`${ENGINES_WORK}/client`, { recursive: true });
  writeFileSync(`${ENGINES_WORK}/node.json`, JSON.stringify(serverConfig(node, password)));
  writeFileSync(`${ENGINES_WORK}/rogue.json`, JSON.stringify(serverConfig(rogue, password)));

  const good = hysteriaLink(password, host, NODE_PORT, node);
  const body = raw(directLink(password, host), good);
  // The body a member gets, through the delivery guard unchanged.
  const guarded = guardHysteria(body, { pinHex: [node.pinHex], spkiB64: [node.spkiB64] });
  if (guarded.kind !== 'kept' || guarded.content !== body || guarded.dropped !== 0)
    throw new Error('the delivery guard changed the body');
  const flip = (hex: string) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
  writeFileSync(`${WORK}/www/good`, body);
  writeFileSync(
    `${WORK}/www/wrongpin`,
    raw(hysteriaLink(password, host, NODE_PORT, { ...node, pinHex: flip(node.pinHex) })),
  );
  writeFileSync(`${WORK}/www/rogue`, raw(hysteriaLink(password, host, ROGUE_PORT, node)));
  compose('up', '-d', ...SERVICES);
  console.log(`fixture up: entries at ${host}, node :${NODE_PORT}/udp, rogue :${ROGUE_PORT}/udp`);
}

function carried(which: string): void {
  const service = which === 'rogue' ? 'compat-hysteria-rogue' : 'compat-hysteria-node';
  const id = compose('ps', '-q', service).trim();
  const r = spawnSync('docker', ['logs', id], { encoding: 'utf8', timeout: 60_000 });
  const n = `${r.stdout}\n${r.stderr}`
    .split('\n')
    .filter((l) => l.includes(`email: ${EMAIL}`)).length;
  console.log(n);
}

/** Download one pinned release (tests/compat/hysteriaApps.ts) and print its path. */
async function download(app: string): Promise<void> {
  if (!(app in hysteriaApps)) throw new Error(`unknown app ${app}`);
  const pin = hysteriaApps[app as HysteriaApp];
  const dest = `.cache/compat/apps/${pin.url.split('/').pop()}`;
  mkdirSync('.cache/compat/apps', { recursive: true });
  const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
  let bytes: Buffer;
  try {
    bytes = readFileSync(dest);
  } catch {
    bytes = Buffer.alloc(0);
  }
  if (sha(bytes) !== pin.sha256) {
    const r = await fetch(pin.url, { signal: AbortSignal.timeout(180_000) });
    if (!r.ok) throw new Error(`${app}: download HTTP ${r.status}`);
    bytes = Buffer.from(await r.arrayBuffer());
    if (sha(bytes) !== pin.sha256) throw new Error(`${app}: checksum mismatch`);
    writeFileSync(dest, bytes);
  }
  console.log(dest);
}

const [command, arg] = process.argv.slice(2);
if (command === 'up' && arg) up(arg);
else if (command === 'download' && arg) await download(arg);
else if (command === 'carried' && arg) carried(arg);
else if (command === 'down') {
  spawnSync('docker', [...COMPOSE, 'down', '-v', '--remove-orphans'], { timeout: 120_000 });
  rmSync(WORK, { recursive: true, force: true });
  rmSync(ENGINES_WORK, { recursive: true, force: true });
} else {
  console.error('usage: fixture.ts up <entry host> | carried <node|rogue> | download <app> | down');
  process.exit(2);
}
