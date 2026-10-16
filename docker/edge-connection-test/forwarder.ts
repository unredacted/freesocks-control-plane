/**
 * The fake L4 edge of the edge connection test (docker-compose.edge-connection-test.yml):
 * a plain TCP forwarder, which is all a provider's L4 load balancer is from a
 * member's point of view. It knows nothing about VLESS, REALITY, Trojan or
 * Shadowsocks; the bytes pass through untouched.
 *
 * One forwarder plays every load balancer of a run. Each one has its own
 * public address (the run's address pool, added to the client-network
 * interface by the `ec-l4-addresses` sidecar) and every edge FCP creates
 * listens on 443, so a frontend is keyed by the ADDRESS the member dialled
 * and the port: one socket per port, dispatched by the connection's local
 * address.
 *
 * Nothing forwards until it is told to. The test's fake provider API, answering
 * FCP's "attach the floating address" call, asks for exactly the frontend and
 * backend FCP named (`POST /forwards {"address": "203.0.113.141", "port": 443,
 * "target": "198.51.100.11:443"}`; no address = the forwarder's own), so what
 * is wired is what FCP asked for, not a fixture's guess. `GET /stats` answers
 * the connection count per `address:port`: the proof that a member's session
 * came through THIS edge. The control port is reachable from the test runner
 * (edge network); members only ever dial a frontend.
 */
import { createServer as createHttpServer } from 'node:http';
import { createServer, connect, type Server, type Socket } from 'node:net';

/** The forwarder's own client-network address: the frontend of a forward that names none. */
const OWN_ADDRESS = process.env.EC_FORWARDER_ADDRESS ?? '203.0.113.21';
const CONTROL_PORT = 9000;

interface Forward {
  target: { host: string; port: number };
  connections: number;
  failed: number;
}

/** `address:port` -> what it forwards to. */
const forwards = new Map<string, Forward>();
/** One listening socket per frontend port, whatever the address. */
const servers = new Map<number, Server>();

const V4 = /^(\d{1,3}(?:\.\d{1,3}){3})$/;

function parseTarget(target: string): { host: string; port: number } | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(target);
  if (!m) return null;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { host: m[1]!, port } : null;
}

const localV4 = (s: Socket) => (s.localAddress ?? '').replace(/^::ffff:/, '');

function pipe(client: Socket, port: number) {
  const f = forwards.get(`${localV4(client)}:${port}`);
  // A frontend nobody provisioned answers nothing, like an unallocated address.
  if (!f) return void client.destroy();
  f.connections++;
  const upstream = connect(f.target.port, f.target.host);
  const close = () => {
    client.destroy();
    upstream.destroy();
  };
  upstream.on('error', () => {
    f.failed++;
    close();
  });
  client.on('error', close);
  client.pipe(upstream);
  upstream.pipe(client);
}

async function listen(address: string, port: number, target: { host: string; port: number }) {
  const key = `${address}:${port}`;
  const existing = forwards.get(key);
  // Re-pointing a frontend (a fresh "provision" of the same address) keeps its counters.
  if (existing) existing.target = target;
  else forwards.set(key, { target, connections: 0, failed: 0 });
  if (servers.has(port)) return;
  const server = createServer();
  server.on('connection', (socket) => pipe(socket, port));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', () => resolve());
  });
  servers.set(port, server);
}

const json = (res: import('node:http').ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

createHttpServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/stats') {
    const out: Record<string, { target: string; connections: number; failed: number }> = {};
    for (const [key, f] of forwards)
      out[key] = {
        target: `${f.target.host}:${f.target.port}`,
        connections: f.connections,
        failed: f.failed,
      };
    return json(res, 200, out);
  }
  if (req.method === 'POST' && req.url === '/forwards') {
    let body = '';
    for await (const chunk of req) body += chunk;
    let parsed: { address?: unknown; port?: unknown; target?: unknown };
    try {
      parsed = JSON.parse(body);
    } catch {
      return json(res, 400, { error: 'json' });
    }
    const address = parsed.address === undefined ? OWN_ADDRESS : String(parsed.address);
    const port = Number(parsed.port);
    const target = typeof parsed.target === 'string' ? parseTarget(parsed.target) : null;
    if (
      !V4.test(address) ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535 ||
      port === CONTROL_PORT ||
      !target
    )
      return json(res, 400, { error: 'address, port or target' });
    try {
      await listen(address, port, target);
    } catch {
      return json(res, 409, { error: 'listen' });
    }
    return json(res, 200, { address, port, target: `${target.host}:${target.port}` });
  }
  json(res, 404, { error: 'not found' });
}).listen(CONTROL_PORT, '0.0.0.0');
