/**
 * A plain TCP forwarder that notes each connection's TLS key exchange
 * (docker-compose.compat.yml `compat-pq-tap`, docs/client-compatibility.md
 * § "Post-quantum key exchange"). The bytes pass through untouched; on the
 * way it reads the Client Hello and Server Hello (cleartext in TLS 1.3, and
 * REALITY's included) with ./tlsHello.ts and keeps the group numbers only.
 *
 *   TAP_FORWARDS="443=10.89.72.11:443,8443=10.89.72.11:8443"   listen port = target
 *   GET  :9000/hellos   [{port, groups...}] of every connection that said hello, oldest first
 *   POST :9000/reset    forget them
 *
 * Nothing is logged: the hellos carry nothing but the groups it keeps.
 */
import { createServer as createHttpServer } from 'node:http';
import { connect, createServer } from 'node:net';
import { describeObservation, observeConnection, type HelloObservation } from './tlsHello';

const CONTROL_PORT = 9000;
/** Plenty for a test; the oldest go first past it. */
const KEEP = 500;

/** Live: a connection's entry fills in as its hellos pass, and is read when asked. */
let seen: Array<{ port: number; observation: HelloObservation }> = [];

const forwards = (process.env.TAP_FORWARDS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => {
    const m = /^(\d{1,5})=([\d.]+):(\d{1,5})$/.exec(s);
    if (!m) throw new Error(`TAP_FORWARDS: cannot read ${s}`);
    return { port: Number(m[1]), host: m[2]!, targetPort: Number(m[3]) };
  });

for (const f of forwards)
  createServer((client) => {
    const { observation, fromClient, fromServer } = observeConnection();
    const upstream = connect(f.targetPort, f.host);
    let noted = false;
    const close = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('data', (d) => {
      fromClient.push(d);
      // A connection that never says hello (a port check) is not a handshake.
      if (!noted && observation.clientHellos.length > 0) {
        noted = true;
        seen.push({ port: f.port, observation });
        if (seen.length > KEEP) seen = seen.slice(-KEEP);
      }
      upstream.write(d);
    });
    upstream.on('data', (d) => {
      fromServer.push(d);
      client.write(d);
    });
    client.on('end', () => upstream.end());
    upstream.on('end', () => client.end());
    client.on('close', close);
    upstream.on('close', close);
    client.on('error', close);
    upstream.on('error', close);
  }).listen(f.port, '0.0.0.0');

createHttpServer((req, res) => {
  const reply = (status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  if (req.method === 'GET' && req.url === '/hellos')
    return reply(
      200,
      seen.map((s) => ({ port: s.port, ...describeObservation(s.observation) })),
    );
  if (req.method === 'POST' && req.url === '/reset') {
    seen = [];
    return reply(200, { ok: true });
  }
  reply(404, { error: 'not found' });
}).listen(CONTROL_PORT, '0.0.0.0');
