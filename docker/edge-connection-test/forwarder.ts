/**
 * The fake L4 edge of the edge connection test (docker-compose.edge-connection-test.yml):
 * a plain TCP forwarder, which is all a provider's L4 load balancer is from a
 * member's point of view. It knows nothing about VLESS or REALITY; the bytes
 * pass through untouched.
 *
 * Nothing forwards until it is told to. The test's fake provider API, answering
 * FCP's "create a load balancer" call, asks for one frontend port and the
 * backend FCP named (`POST /forwards {"port": 443, "target": "198.51.100.11:443"}`),
 * so what is wired is what FCP asked for, not a fixture's guess. `GET /stats`
 * answers the connection count per frontend port: the proof that a member's
 * session came through THIS edge. The control port is reachable from the test
 * runner (edge network); members only ever dial a frontend port.
 */
import { createServer as createHttpServer } from 'node:http';
import { createServer, connect, type Server, type Socket } from 'node:net';

interface Forward {
  target: { host: string; port: number };
  server: Server;
  connections: number;
  failed: number;
}

const forwards = new Map<number, Forward>();

function parseTarget(target: string): { host: string; port: number } | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(target);
  if (!m) return null;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { host: m[1]!, port } : null;
}

function pipe(client: Socket, f: Forward) {
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

async function listen(port: number, target: { host: string; port: number }) {
  const existing = forwards.get(port);
  if (existing) {
    // Re-pointing a frontend (a fresh "provision" of the same port) keeps the socket.
    existing.target = target;
    return;
  }
  const f: Forward = { target, server: createServer(), connections: 0, failed: 0 };
  f.server.on('connection', (socket) => pipe(socket, f));
  await new Promise<void>((resolve, reject) => {
    f.server.once('error', reject);
    f.server.listen(port, '0.0.0.0', () => resolve());
  });
  forwards.set(port, f);
}

const json = (res: import('node:http').ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

createHttpServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/stats') {
    const out: Record<string, { target: string; connections: number; failed: number }> = {};
    for (const [port, f] of forwards)
      out[port] = {
        target: `${f.target.host}:${f.target.port}`,
        connections: f.connections,
        failed: f.failed,
      };
    return json(res, 200, out);
  }
  if (req.method === 'POST' && req.url === '/forwards') {
    let body = '';
    for await (const chunk of req) body += chunk;
    let parsed: { port?: unknown; target?: unknown };
    try {
      parsed = JSON.parse(body);
    } catch {
      return json(res, 400, { error: 'json' });
    }
    const port = Number(parsed.port);
    const target = typeof parsed.target === 'string' ? parseTarget(parsed.target) : null;
    if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 9000 || !target)
      return json(res, 400, { error: 'port or target' });
    try {
      await listen(port, target);
    } catch {
      return json(res, 409, { error: 'listen' });
    }
    return json(res, 200, { port, target: `${target.host}:${target.port}` });
  }
  json(res, 404, { error: 'not found' });
}).listen(9000, '0.0.0.0');
