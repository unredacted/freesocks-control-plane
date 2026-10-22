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
      tlsName: need('EC_TLS_NAME'),
      outlinePassword: need('EC_OUTLINE_PASSWORD'),
    }
  : (null as never);

/** Fixed addresses of the compose file. */
export const ADDR = {
  realityNode: { control: '192.0.2.11', edge: '198.51.100.11', origin: '11.11.11.11' },
  xhttpRealityNode: { control: '192.0.2.15', edge: '198.51.100.15', origin: '11.11.11.15' },
  wsNode: { control: '192.0.2.12', edge: '198.51.100.12', origin: '11.11.11.12' },
  // The operator nodes: managed at their public address.
  l4Matrix: { edge: '198.51.100.13', origin: '11.11.11.13' },
  l7Matrix: { edge: '198.51.100.14', origin: '11.11.11.14' },
  /** The Outline server's data plane (its management API is faked in the test). */
  outline: { edge: '198.51.100.16', origin: '11.11.11.16' },
  forwarder: { client: '203.0.113.21', edge: '198.51.100.21', api: 'http://198.51.100.21:9000' },
  /** The forwarder's address pool: one per load balancer the fake provider creates. */
  forwarderPool: Array.from({ length: 20 }, (_, i) => `203.0.113.${141 + i}`),
  front: {
    client: '203.0.113.22',
    edge: '198.51.100.22',
    admin: 'http://198.51.100.22:2019',
  },
  dns: '203.0.113.53',
  client: '203.0.113.100',
  originPage: '11.11.11.200',
} as const;

/** Every address of a relay node: none of them may reach a member. */
export const NODE_ADDRESSES: readonly string[] = [
  ...Object.values(ADDR.realityNode),
  ...Object.values(ADDR.xhttpRealityNode),
  ...Object.values(ADDR.wsNode),
  ...Object.values(ADDR.l4Matrix),
  ...Object.values(ADDR.l7Matrix),
  ...Object.values(ADDR.outline),
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

/**
 * Wire one forwarder frontend (`address:port`, the forwarder's own address when
 * none is named) to a backend: what a provider's load balancer does once its
 * public address is attached.
 */
export async function wireForwarder(
  port: number,
  target: string,
  address: string = ADDR.forwarder.client,
): Promise<void> {
  const res = await realFetch(`${ADDR.forwarder.api}/forwards`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ address, port, target }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok)
    throw new Error(`forwarder refused ${address}:${port} -> ${target}: HTTP ${res.status}`);
}

/** Per frontend (`address:port`): where it forwards and how many connections it carried. */
export async function forwarderStats(): Promise<
  Record<string, { target: string; connections: number; failed: number }>
> {
  const res = await realFetch(`${ADDR.forwarder.api}/stats`, {
    signal: AbortSignal.timeout(10_000),
  });
  return res.json();
}

/** Connections the forwarder carried on one frontend so far. */
export async function forwarderConnections(
  port: number,
  address: string = ADDR.forwarder.client,
): Promise<number> {
  return (await forwarderStats())[`${address}:${port}`]?.connections ?? 0;
}

/**
 * Route one hostname of the fake CDN to an origin, as a proxied record does:
 * TLS to `dial` (verified against the per-run CA, `serverName` as the SNI),
 * the front's hostname as the Host. Replaces the hostname's route when it has
 * one (a record's Origin Rule changes the port of an existing record, its
 * header rule what it sends).
 *
 * What it sends the origin is what Cloudflare sends: the client's address in
 * `CF-Connecting-IP` unless a Transform Rule for the hostname removes it
 * (`clientAddress: false`), and in `X-Forwarded-For` always (Caddy adds it, as
 * Cloudflare's proxy adds it back after every rule).
 */
export async function routeFront(
  hostname: string,
  dial: { host: string; port: number },
  serverName: string,
  opts: { clientAddress?: boolean } = {},
): Promise<void> {
  const id = `ec-route-${hostname.replace(/[^a-z0-9]/gi, '-')}`;
  const set: Record<string, string[]> = { Host: ['{http.request.host}'] };
  if (opts.clientAddress !== false) set['Cf-Connecting-Ip'] = ['{http.request.remote.host}'];
  const route = {
    '@id': id,
    match: [{ host: [hostname] }],
    handle: [
      {
        handler: 'reverse_proxy',
        upstreams: [{ dial: `${dial.host}:${dial.port}` }],
        headers: { request: { set } },
        // A CDN streams: an XHTTP download or a gRPC stream is never buffered.
        flush_interval: -1,
        transport: {
          protocol: 'http',
          tls: { server_name: serverName, root_ca_pem_files: ['/pki/ca.pem'] },
        },
      },
    ],
    terminal: true,
  };
  const admin = (method: string, path: string, body?: unknown) =>
    realFetch(`${ADDR.front.admin}${path}`, {
      method,
      // Node's fetch marks itself a browser-style request (`sec-fetch-mode`),
      // which Caddy's admin answers only for a named Origin.
      headers: { 'content-type': 'application/json', origin: ADDR.front.admin },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
  // Drop the hostname's previous route (absent the first time: a 404, ignored).
  await admin('DELETE', `/id/${id}`);
  const res = await admin('PUT', '/config/apps/http/servers/srv0/routes/0', route);
  if (!res.ok) throw new Error(`the front refused the route for a record: HTTP ${res.status}`);
}

interface AccessEntry {
  host: string;
  uri: string;
  status: number;
  remoteIp: string;
  /** The request's headers as Caddy logs them (canonical names; credentials redacted). */
  headers: Record<string, string[]>;
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
      // The request's host without a port: sing-box's gRPC sends `:authority`
      // as `name:443`, every other client the bare name.
      host: String(e.request.host ?? '').replace(/:\d+$/, ''),
      uri: String(e.request.uri ?? ''),
      status: Number(e.status ?? 0),
      remoteIp: String(e.request.remote_ip ?? ''),
      headers: (e.request.headers ?? {}) as Record<string, string[]>,
    }));
}

// --- the member's client ----------------------------------------------------------------------

export function stopClient(): void {
  for (const binary of ['sing-box', 'mihomo'])
    spawnSync('docker', ['exec', 'ec-client', 'pkill', '-x', binary], { stdio: 'ignore' });
}

/**
 * Validate and start one reference engine with `config` (verbatim) in the
 * client container: sing-box (JSON) or Mihomo (YAML).
 */
export async function startClient(
  config: string,
  port = 1080,
  engine: 'singbox' | 'mihomo' = 'singbox',
): Promise<void> {
  stopClient();
  const file = engine === 'singbox' ? 'client.json' : 'client.yaml';
  writeFileSync(`${WORK}/client/${file}`, config);
  const [binary, check, run] =
    engine === 'singbox'
      ? ['sing-box', ['check', '-c', `/work/${file}`], ['run', '-c', `/work/${file}`]]
      : // Its own home directory: Mihomo writes its cache there and never downloads
        // anything for a config without geo rules.
        [
          'mihomo',
          ['-t', '-d', '/work/mihomo', '-f', `/work/${file}`],
          ['-d', '/work/mihomo', '-f', `/work/${file}`],
        ];
  const checked = spawnSync('docker', ['exec', 'ec-client', binary, ...check], {
    encoding: 'utf8',
  });
  if (checked.status !== 0) throw new Error(`${binary} refused the configuration (check failed)`);
  docker('exec', '-d', 'ec-client', binary, ...run);
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
