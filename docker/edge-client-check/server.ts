/**
 * FCP's client-check service (docs/edges.md § "FCP's own client check").
 *
 * FCP asks it to connect through one address with a REAL client engine (sing-box
 * or Xray), using FCP's own check credential, and to fetch an egress-IP page
 * through that tunnel. It answers whether the session worked, the address the
 * page saw and a short code; FCP judges the rest.
 *
 *   POST /v1/check   {engine, outbound, reality}   signed
 *   GET  /v1/health                                signed
 *   GET  /healthz                                  liveness only (no detail)
 *
 * Only FCP can call it: every request is signed with EDGE_CLIENT_CHECK_SECRET
 * (lib/edges/clientCheck/signing.ts) and a signature is accepted once. The
 * outbound is rebuilt from an allowlist and must dial a public IP literal
 * (sanitize.ts); the egress page is this service's own setting, never the
 * caller's. Nothing is logged per request: configurations, credentials,
 * addresses and engine output stay in memory and are dropped.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLIENT_CHECK_ENGINES,
  type ClientCheckEngine,
  type ClientCheckSessionCode,
} from '../../src/shared/contracts/edgeCodes';
import { canonicalIp } from '../../convex/lib/edges/ip';
import {
  CLIENT_CHECK_FETCH_MS,
  CLIENT_CHECK_MAX_BODY_BYTES,
  CLIENT_CHECK_PATHS,
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_START_MS,
  CLIENT_CHECK_TIME_HEADER,
  type ClientCheckHealth,
  type ClientCheckRefusal,
  type ClientCheckResponse,
} from '../../convex/lib/edges/clientCheck/protocol';
import { ReplayGuard, verifyRequest } from '../../convex/lib/edges/clientCheck/signing';
import { sanitizeOutbound } from '../../convex/lib/edges/clientCheck/sanitize';
import {
  engineConfig,
  engineRunArgs,
  parseEngineVersion,
  sessionCodeOf,
} from '../../convex/lib/edges/clientCheck/engine';

const SECRET = process.env.EDGE_CLIENT_CHECK_SECRET ?? '';
const EGRESS_URL = process.env.EDGE_CLIENT_CHECK_EGRESS_URL || 'https://api.ipify.org';
// The CI harness's nodes sit on private addresses; never set in a deployment.
const ALLOW_PRIVATE = process.env.EDGE_CLIENT_CHECK_ALLOW_PRIVATE === 'true';
const PORT = Number(process.env.PORT || 8080);
const BINARIES: Record<ClientCheckEngine, string> = {
  'sing-box': process.env.EDGE_CLIENT_CHECK_SINGBOX || '/usr/local/bin/sing-box',
  xray: process.env.EDGE_CLIENT_CHECK_XRAY || '/usr/local/bin/xray',
};
/** Engine output kept for the failure code (it is read, never echoed). */
const OUTPUT_CAP = 64 * 1024;

const guard = new ReplayGuard();
let running = false;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

function refuse(code: ClientCheckRefusal, status: number, message: string): Response {
  return json({ error: { code, message } }, status);
}

async function versionOf(engine: ClientCheckEngine): Promise<string | null> {
  try {
    const p = Bun.spawn([BINARIES[engine], 'version'], { stdout: 'pipe', stderr: 'pipe' });
    const text = await new Response(p.stdout).text();
    await p.exited;
    return parseEngineVersion(engine, text);
  } catch {
    return null;
  }
}

const versions: Record<ClientCheckEngine, string | null> = { 'sing-box': null, xray: null };

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const addr = s.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      s.close(() => resolve(port));
    });
  });
}

function portOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const c = connect({ host: '127.0.0.1', port }, () => {
      c.destroy();
      resolve(true);
    });
    c.once('error', () => resolve(false));
  });
}

/** Reads a stream into `sink` (capped) until it ends. */
async function drain(stream: ReadableStream<Uint8Array>, sink: { text: string }): Promise<void> {
  const dec = new TextDecoder();
  for await (const chunk of stream) {
    if (sink.text.length < OUTPUT_CAP) sink.text += dec.decode(chunk, { stream: true });
  }
}

async function runCheck(
  engine: ClientCheckEngine,
  outbound: Record<string, unknown>,
  reality: boolean,
): Promise<ClientCheckResponse> {
  const started = Date.now();
  const done = (code: ClientCheckSessionCode, egressIp: string | null = null) => ({
    ok: code === 'ok',
    engine,
    engineVersion: versions[engine],
    egressIp,
    ms: Date.now() - started,
    code,
  });
  const dir = mkdtempSync(join(tmpdir(), 'check-'));
  const port = await freePort();
  const configPath = join(dir, 'config.json');
  writeFileSync(configPath, JSON.stringify(engineConfig(engine, outbound, port)), { mode: 0o600 });
  const output = { text: '' };
  const proc = Bun.spawn([BINARIES[engine], ...engineRunArgs(configPath)], {
    stdout: 'pipe',
    stderr: 'pipe',
    env: {},
  });
  const reading = Promise.all([drain(proc.stdout, output), drain(proc.stderr, output)]);
  try {
    let listening = false;
    while (Date.now() - started < CLIENT_CHECK_START_MS && proc.exitCode === null) {
      if (await portOpen(port)) {
        listening = true;
        break;
      }
      await Bun.sleep(100);
    }
    if (!listening) return done(sessionCodeOf(output.text, { reality, started: false }));
    let res: Response;
    try {
      res = await fetch(EGRESS_URL, {
        proxy: `http://127.0.0.1:${port}`,
        redirect: 'error',
        signal: AbortSignal.timeout(CLIENT_CHECK_FETCH_MS),
      } as RequestInit);
    } catch (err) {
      // Give the engine a moment to log why the tunnel failed.
      await Bun.sleep(200);
      const thrown = err instanceof Error ? `${err.name} ${err.message}` : '';
      return done(sessionCodeOf(`${output.text}\n${thrown}`, { reality, started: true }));
    }
    if (!res.ok) {
      // The engine's proxy answers a tunnel that failed with an error status
      // (a plain-HTTP page) instead of dropping the connection: its log says why.
      await Bun.sleep(200);
      const code = sessionCodeOf(output.text, { reality, started: true });
      return done(code === 'session_failed' ? 'egress_unreadable' : code);
    }
    const text = (await res.text()).slice(0, 256).trim();
    const ip = canonicalIp(text.split(/\s/)[0] ?? '');
    return ip ? done('ok', ip) : done('egress_unreadable');
  } finally {
    proc.kill(9);
    await proc.exited;
    await reading.catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  }
}

async function authorized(req: Request, path: string, body: string): Promise<boolean> {
  return (
    (await verifyRequest(
      SECRET,
      {
        method: req.method,
        path,
        time: req.headers.get(CLIENT_CHECK_TIME_HEADER),
        signature: req.headers.get(CLIENT_CHECK_SIGNATURE_HEADER),
        body,
      },
      Date.now(),
      guard,
    )) === 'ok'
  );
}

async function handle(req: Request): Promise<Response> {
  const path = new URL(req.url).pathname;
  if (req.method === 'GET' && path === '/healthz') return new Response('ok');
  if (!SECRET) return refuse('not_configured', 503, 'No EDGE_CLIENT_CHECK_SECRET is set');
  if (req.method === 'GET' && path === CLIENT_CHECK_PATHS.health) {
    if (!(await authorized(req, path, ''))) return refuse('unauthorized', 401, 'Unauthorized');
    const health: ClientCheckHealth = {
      ok: true,
      engines: CLIENT_CHECK_ENGINES.map((engine) => ({ engine, version: versions[engine] })),
      egressHost: new URL(EGRESS_URL).host,
    };
    return json(health);
  }
  if (req.method !== 'POST' || path !== CLIENT_CHECK_PATHS.check)
    return refuse('invalid_request', 404, 'Not found');
  if (Number(req.headers.get('content-length') ?? 0) > CLIENT_CHECK_MAX_BODY_BYTES)
    return refuse('too_large', 413, 'Request too large');
  const body = await req.text();
  if (body.length > CLIENT_CHECK_MAX_BODY_BYTES)
    return refuse('too_large', 413, 'Request too large');
  if (!(await authorized(req, path, body))) return refuse('unauthorized', 401, 'Unauthorized');
  let parsed: { engine?: unknown; outbound?: unknown; reality?: unknown };
  try {
    parsed = JSON.parse(body);
  } catch {
    return refuse('invalid_request', 400, 'Body is not JSON');
  }
  const engine = parsed.engine as ClientCheckEngine;
  if (!CLIENT_CHECK_ENGINES.includes(engine))
    return refuse('invalid_request', 400, 'Unknown engine');
  const clean = sanitizeOutbound(engine, parsed.outbound, { allowPrivate: ALLOW_PRIVATE });
  if (!clean.ok) {
    const code = clean.code === 'invalid_outbound' ? 'invalid_request' : clean.code;
    return refuse(code, 400, `Outbound refused: ${clean.code}`);
  }
  if (running) return refuse('busy', 429, 'A check is running');
  running = true;
  try {
    return json(await runCheck(engine, clean.outbound, parsed.reality === true));
  } finally {
    running = false;
  }
}

for (const engine of CLIENT_CHECK_ENGINES) versions[engine] = await versionOf(engine);

Bun.serve({
  port: PORT,
  hostname: '0.0.0.0',
  fetch: (req) =>
    handle(req).catch(() => json({ error: { code: 'error', message: 'Check failed' } }, 500)),
});

console.log(
  `edge-client-check: listening on ${PORT}; ${CLIENT_CHECK_ENGINES.map((e) => `${e} ${versions[e] ?? 'missing'}`).join(', ')}${SECRET ? '' : '; NO SECRET SET, every call is refused'}`,
);
