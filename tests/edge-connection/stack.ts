/**
 * The edge connection stack as the test sees it (docker-compose.edge-connection-test.yml):
 * fixed addresses, the per-run values the run script exports, and the few
 * things the test does to the containers (start sing-box in the client, fetch
 * through it, read what the fake edges saw).
 *
 * Never print a subscription body, a client config or a node log: they carry
 * credentials. Failures name what was expected, not what was received.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

export const ENABLED = process.env.EC_ENABLED === '1';

/**
 * The network's own fetch, taken before the lifecycle test routes the global
 * one through its provider fakes: the stack's control endpoints are the
 * test's, never FCP's.
 */
const realFetch: typeof fetch = globalThis.fetch.bind(globalThis);

const need = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set: run bun run test:integration:edge-connection`);
  return v;
};

export const env = ENABLED
  ? {
      panelUrl: need('REMNAWAVE_TEST_URL'),
      panelToken: need('REMNAWAVE_TEST_TOKEN'),
      originToken: need('EC_ORIGIN_TOKEN'),
      originHostname: need('EC_ORIGIN_HOSTNAME'),
      originPage: need('EC_ORIGIN_PAGE'),
      realityTarget: need('EC_REALITY_TARGET'),
      l7Zone: need('EC_L7_ZONE'),
      wsPath: need('EC_WS_PATH'),
      wsPort: Number(need('EC_WS_PORT')),
    }
  : (null as never);

/** Fixed addresses of the compose file. */
export const ADDR = {
  realityNode: { control: '192.0.2.11', edge: '198.51.100.11', origin: '11.11.11.11' },
  wsNode: { control: '192.0.2.12', edge: '198.51.100.12', origin: '11.11.11.12' },
  forwarder: { client: '203.0.113.21', edge: '198.51.100.21', api: 'http://198.51.100.21:9000' },
  front: { client: '203.0.113.22', edge: '198.51.100.22' },
  dns: '203.0.113.53',
  client: '203.0.113.100',
  originPage: '11.11.11.200',
} as const;

/** Every address of a relay node: none of them may reach a member. */
export const NODE_ADDRESSES: readonly string[] = [
  ...Object.values(ADDR.realityNode),
  ...Object.values(ADDR.wsNode),
];

const WORK = '.cache/edge-connection-test';

export function docker(...args: string[]): string {
  return execFileSync('docker', args, {
    encoding: 'utf8',
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function until<T>(
  read: () => Promise<T | null | false | undefined>,
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

// --- the fake edges ---------------------------------------------------------------------------

/** Wire the forwarder's frontend port to a backend (what a provider's LB create does). */
export async function wireForwarder(port: number, target: string): Promise<void> {
  const res = await realFetch(`${ADDR.forwarder.api}/forwards`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ port, target }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`forwarder refused ${port} -> ${target}: HTTP ${res.status}`);
}

export async function forwarderStats(): Promise<
  Record<string, { target: string; connections: number; failed: number }>
> {
  const res = await realFetch(`${ADDR.forwarder.api}/stats`, {
    signal: AbortSignal.timeout(10_000),
  });
  return res.json();
}

/** Connections the forwarder carried on one frontend port so far. */
export async function forwarderConnections(port: number): Promise<number> {
  return (await forwarderStats())[String(port)]?.connections ?? 0;
}

interface AccessEntry {
  host: string;
  uri: string;
  status: number;
  remoteIp: string;
}

/** The front's (or the ingress's) access log: one JSON object per finished request. */
export function accessLog(which: 'front' | 'ingress'): AccessEntry[] {
  const file = `${WORK}/logs/${which}-access.log`;
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim().startsWith('{'))
    .map((l) => JSON.parse(l))
    .filter((e) => e.request)
    .map((e) => ({
      host: String(e.request.host ?? ''),
      uri: String(e.request.uri ?? ''),
      status: Number(e.status ?? 0),
      remoteIp: String(e.request.remote_ip ?? ''),
    }));
}

// --- the member's client ----------------------------------------------------------------------

export function stopClient(): void {
  spawnSync('docker', ['exec', 'ec-client', 'pkill', '-x', 'sing-box'], { stdio: 'ignore' });
}

/** Validate and start sing-box with `config` (verbatim) in the client container. */
export async function startClient(config: string, port = 1080): Promise<void> {
  stopClient();
  writeFileSync(`${WORK}/client/client.json`, config);
  const check = spawnSync(
    'docker',
    ['exec', 'ec-client', 'sing-box', 'check', '-c', '/work/client.json'],
    {
      encoding: 'utf8',
    },
  );
  if (check.status !== 0) throw new Error('sing-box refused the configuration (check failed)');
  docker('exec', '-d', 'ec-client', 'sing-box', 'run', '-c', '/work/client.json');
  const ready = await until(
    async () => {
      const r = spawnSync(
        'docker',
        [
          'exec',
          'ec-client',
          'python3',
          '-c',
          `import socket; socket.create_connection(("127.0.0.1",${port}),1).close()`,
        ],
        { stdio: 'ignore' },
      );
      return r.status === 0;
    },
    20_000,
    250,
  );
  if (!ready) throw new Error(`sing-box never listened on ${port}`);
}

/**
 * Fetch the origin page through the client's local proxy listener. The name is
 * resolved at the far end (socks5-hostname): the client network resolves
 * nothing but the edges. Returns the page or null (never the error text).
 */
export function fetchThroughClient(
  port = 1080,
): { token: string; path: string; peer: string | null; nonce: string } | null {
  const nonce = randomUUID();
  const r = spawnSync(
    'docker',
    [
      'exec',
      'ec-client',
      'curl',
      '--silent',
      '--fail',
      '--max-time',
      '15',
      '--noproxy',
      '',
      '--socks5-hostname',
      `127.0.0.1:${port}`,
      `http://${env.originPage}/${nonce}`,
    ],
    { encoding: 'utf8', timeout: 30_000 },
  );
  if (r.status !== 0) return null;
  try {
    const page = JSON.parse(r.stdout);
    return { ...page, nonce };
  } catch {
    return null;
  }
}

/** Retry a tunnel fetch through transient failures (a listener up before the engine is ready). */
export async function fetchThroughClientEventually(port = 1080, ms = 30_000) {
  return until(
    async () => {
      const page = fetchThroughClient(port);
      return page && page.path === `/${page.nonce}` ? page : null;
    },
    ms,
    1500,
  );
}

/** Whether the client container can open a TCP connection to `address:port` WITHOUT the proxy. */
export function clientReachesDirectly(address: string, port: number): boolean {
  const r = spawnSync(
    'docker',
    [
      'exec',
      'ec-client',
      'python3',
      '-c',
      `import socket; socket.create_connection(("${address}",${port}),3).close()`,
    ],
    { stdio: 'ignore', timeout: 20_000 },
  );
  return r.status === 0;
}

/**
 * A served sing-box body, adapted to the sandbox and NOTHING else: the test
 * container has no TUN device (the mixed listener the template also declares
 * carries the test's requests instead) and the client network has no public
 * resolver (every plain DNS server of the template points at the network's
 * own resolver, tags kept so the template's rules still apply). The outbounds,
 * where everything FCP rendered lives, are untouched; the caller asserts it.
 */
export function sandboxSingbox(body: string): { config: string; port: number } {
  const c = JSON.parse(body);
  c.inbounds = (c.inbounds ?? []).filter((i: { type: string }) => i.type !== 'tun');
  const mixed = c.inbounds.find((i: { type: string }) => i.type === 'mixed');
  if (!mixed) throw new Error('the served sing-box body has no mixed listener');
  if (c.dns?.servers)
    c.dns.servers = c.dns.servers.map((s: { type: string; tag: string }) =>
      ['udp', 'tcp', 'tls', 'https', 'quic', 'h3'].includes(s.type)
        ? { type: 'udp', tag: s.tag, server: ADDR.dns }
        : s,
    );
  return { config: JSON.stringify(c), port: Number(mixed.listen_port) };
}

/**
 * A sing-box client config for ONE `vless://` share link (the try_it card's
 * isolated test link): what an operator's client does when it imports the
 * link. A mixed listener on `port`, the network's resolver, everything else
 * from the link.
 */
export function singboxForLink(link: string, port = 1080): string {
  const u = new URL(link);
  if (u.protocol !== 'vless:') throw new Error('the test link is not a VLESS link');
  const q = u.searchParams;
  const security = q.get('security') ?? 'none';
  const sni = q.get('sni') ?? undefined;
  const outbound: Record<string, unknown> = {
    type: 'vless',
    tag: 'test-link',
    server: u.hostname.replace(/^\[|\]$/g, ''),
    server_port: Number(u.port || 443),
    uuid: decodeURIComponent(u.username),
  };
  if (q.get('flow')) outbound.flow = q.get('flow');
  if (security === 'reality')
    outbound.tls = {
      enabled: true,
      server_name: sni,
      utls: { enabled: true, fingerprint: q.get('fp') || 'chrome' },
      reality: { enabled: true, public_key: q.get('pbk'), short_id: q.get('sid') ?? '' },
    };
  else if (security === 'tls') outbound.tls = { enabled: true, server_name: sni };
  const type = q.get('type') ?? 'tcp';
  if (type === 'ws')
    outbound.transport = {
      type: 'ws',
      path: q.get('path') ?? '/',
      ...(q.get('host') ? { headers: { Host: q.get('host') } } : {}),
    };
  return JSON.stringify({
    log: { level: 'warn' },
    dns: { servers: [{ type: 'udp', tag: 'ec-dns', server: ADDR.dns }], final: 'ec-dns' },
    inbounds: [{ type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: port }],
    outbounds: [outbound],
    route: { final: 'test-link', default_domain_resolver: 'ec-dns' },
  });
}
