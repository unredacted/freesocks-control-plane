'use node';
/**
 * The internal probe: FCP's own host connects to the target. This is NOT a
 * country signal (FCP is not in a censored network); it distinguishes "the edge
 * is down / blackholed for everyone" from "blocked in country X" so the
 * detector never rotates away from an outage as if it were a block.
 *
 * Per protocol:
 *  - `tcp`: any answer at all counts as reachable, INCLUDING a TLS handshake
 *    error (a REALITY edge will not present a certificate for a random SNI);
 *    only connection-level failures count as unreachable.
 *  - `tls`: a real handshake with SNI = the target name and full verification.
 *    A certificate or handshake failure IS unreachable: an L7 front that
 *    cannot complete a handshake for its own name is not serving anyone.
 *  - `https`: a request on top of that handshake; any HTTP status is reachable.
 *  - `tls-sni`: the protocol-SHAPE check of an L4 edge in front of a REALITY /
 *    TLS listener: a full handshake to the edge ADDRESS with SNI =
 *    `target.servername` (one of the listener's active names), the chain
 *    verified for that name against the system store, no HTTP. This is shape
 *    evidence only and never authentication: a forwarder aimed straight at the
 *    camouflage site presents that site's own certificate and PASSES it while
 *    every real REALITY session through it would fail (lib/edges/verifyRung.ts
 *    caps it at the `partial` rung for that reason).
 *
 * A NAME is resolved first and every answer must be a public literal: the probe
 * runs from the control plane's own network, so a name pointing at a private
 * range would turn it into an internal port scanner. The connection is then
 * made to ONE OF THOSE VERIFIED LITERALS, never to the name again: a second
 * resolution could answer differently (DNS rebinding) and reach an address the
 * check never saw. The name survives only as the SNI and the HTTP Host header.
 */
import { isPublicIpLiteral } from '../ip';
import { shortError, targetHost, type ProbeResult, type ProbeTarget } from './types';
import type { FetchLike } from './checkhost';

const CONNECT_FAILURE_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN',
  'ENOTFOUND',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
  'ABORT_ERR',
]);

const TLS_CODE_RE =
  /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO|SELF_SIGNED|EPROTO|HOSTNAME_MISMATCH)/;

function codeOf(err: unknown): string {
  const e = err as { name?: string; code?: string; cause?: { code?: string; message?: string } };
  return String(e?.cause?.code ?? e?.code ?? e?.name ?? '');
}

function looksTls(err: unknown): boolean {
  const e = err as { cause?: { message?: string }; message?: string };
  return (
    TLS_CODE_RE.test(codeOf(err)) ||
    /certificate|tls|ssl|handshake/i.test(e?.cause?.message ?? e?.message ?? '')
  );
}

function isTimeout(err: unknown): boolean {
  const name = (err as { name?: string })?.name;
  return name === 'TimeoutError' || name === 'AbortError';
}

/** Classify a fetch failure for the `tcp` probe: connection-level → unreachable; TLS-level → reachable. */
export function classifyInternalError(err: unknown): { ok: boolean; error: string } {
  const code = codeOf(err);
  if (isTimeout(err)) return { ok: false, error: 'timeout' };
  if (CONNECT_FAILURE_CODES.has(code)) return { ok: false, error: code };
  // Anything TLS/protocol-shaped means a peer answered on the port.
  if (looksTls(err)) return { ok: true, error: shortError(code || 'tls') };
  return { ok: false, error: shortError(code || (err instanceof Error ? err.message : 'error')) };
}

/**
 * Classify a failure for the `tls` / `https` probes: the handshake is the
 * measurement, so a certificate error is a FAILURE here (the opposite of the
 * `tcp` rule above, which is about bare reachability).
 */
export function classifyHandshakeError(err: unknown): { ok: false; error: string } {
  if (isTimeout(err)) return { ok: false, error: 'timeout' };
  const code = codeOf(err);
  if (code) return { ok: false, error: shortError(code) };
  return { ok: false, error: shortError(err instanceof Error ? err.message : 'error') };
}

export interface TlsHandshake {
  (opts: {
    host: string;
    port: number;
    servername?: string;
    timeoutMs: number;
  }): Promise<{ ok: boolean; error?: string }>;
}

/** A bare TCP connect to a verified literal (the `tcp` probe of a NAME target). */
export interface TcpConnect {
  (opts: {
    host: string;
    port: number;
    timeoutMs: number;
  }): Promise<{ ok: boolean; error?: string }>;
}

/**
 * The `https` probe of a NAME target: a TLS handshake to a verified literal
 * with SNI = the name, then one request carrying the name as Host; any HTTP
 * status line counts as an answer.
 */
export interface HttpsRequest {
  (opts: {
    host: string;
    port: number;
    servername: string;
    timeoutMs: number;
  }): Promise<{ ok: boolean; error?: string }>;
}

export interface InternalProbeDeps {
  fetchFn: FetchLike;
  /** name → IP literals. Injected in tests; defaults to the platform resolver. */
  lookup?: (name: string) => Promise<string[]>;
  /** TLS handshake. Injected in tests; defaults to `node:tls`. */
  tlsConnect?: TlsHandshake;
  /** TCP connect for a NAME target's `tcp` probe. Injected in tests; defaults to `node:net`. */
  tcpConnect?: TcpConnect;
  /** HTTPS request for a NAME target's `https` probe. Injected in tests; defaults to `node:tls`. */
  httpsRequest?: HttpsRequest;
}

async function defaultLookup(name: string): Promise<string[]> {
  const dns = await import('node:dns/promises');
  const answers = await dns.lookup(name, { all: true, verbatim: true });
  return answers.map((a) => a.address);
}

const defaultTlsConnect: TlsHandshake = async ({ host, port, servername, timeoutMs }) => {
  const tls = await import('node:tls');
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: { ok: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    const socket = tls.connect(
      { host, port, servername, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] },
      () => done({ ok: socket.authorized, error: socket.authorized ? undefined : 'cert_invalid' }),
    );
    socket.setTimeout(timeoutMs, () => done({ ok: false, error: 'timeout' }));
    socket.on('error', (err) => done(classifyHandshakeError(err)));
  });
};

const defaultTcpConnect: TcpConnect = async ({ host, port, timeoutMs }) => {
  const net = await import('node:net');
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: { ok: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    const socket = net.connect({ host, port }, () => done({ ok: true }));
    socket.setTimeout(timeoutMs, () => done({ ok: false, error: 'timeout' }));
    socket.on('error', (err) => {
      const c = classifyInternalError(err);
      done({ ok: c.ok, error: c.error });
    });
  });
};

const defaultHttpsRequest: HttpsRequest = async ({ host, port, servername, timeoutMs }) => {
  const tls = await import('node:tls');
  return new Promise((resolve) => {
    let settled = false;
    let buffered = '';
    const done = (r: { ok: boolean; error?: string }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    const socket = tls.connect(
      { host, port, servername, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] },
      () => {
        if (!socket.authorized) return done({ ok: false, error: 'cert_invalid' });
        socket.write(
          `GET / HTTP/1.1\r\nHost: ${servername}\r\nUser-Agent: fcp-probe/1\r\nConnection: close\r\n\r\n`,
        );
      },
    );
    socket.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('latin1');
      if (buffered.length >= 12 || buffered.includes('\n')) {
        done(/^HTTP\/\d/.test(buffered) ? { ok: true } : { ok: false, error: 'not_http' });
      }
    });
    socket.on('end', () => done({ ok: false, error: 'no_response' }));
    socket.setTimeout(timeoutMs, () => done({ ok: false, error: 'timeout' }));
    socket.on('error', (err) => done(classifyHandshakeError(err)));
  });
};

/** The verified literal to dial: the requested family when one of the answers has it, else the first answer. */
export function pickDialAddress(addresses: string[], requestedFamily: 4 | 6 | 'any'): string {
  if (requestedFamily !== 'any') {
    const wantV6 = requestedFamily === 6;
    const hit = addresses.find((a) => a.includes(':') === wantV6);
    if (hit) return hit;
  }
  return addresses[0]!;
}

const vantage = { country: 'XX', vantageClass: 'datacenter' as const };

/**
 * Resolve a name and refuse any answer outside public address space. Returns
 * the literals (so the caller can dial an address it has verified) or an error.
 */
export async function resolvePublic(
  name: string,
  lookup: (n: string) => Promise<string[]>,
): Promise<{ ok: true; addresses: string[] } | { ok: false; error: string }> {
  let addresses: string[];
  try {
    addresses = await lookup(name);
  } catch (err) {
    const code = codeOf(err);
    return { ok: false, error: shortError(code || 'resolve_failed', 60, [name]) };
  }
  if (addresses.length === 0) return { ok: false, error: 'no_address' };
  // EVERY answer must be public: one private answer is enough for a
  // round-robin name to reach the control plane's own network.
  if (!addresses.every((a) => isPublicIpLiteral(a))) return { ok: false, error: 'private_address' };
  return { ok: true, addresses };
}

export async function internalProbe(
  deps: InternalProbeDeps,
  target: ProbeTarget,
  timeoutMs = 6000,
): Promise<ProbeResult> {
  const lookup = deps.lookup ?? defaultLookup;
  const redact = target.addressKind === 'name' ? [target.address] : [];
  const started = Date.now();
  const finish = (r: { ok: boolean; error?: string }): ProbeResult => ({
    ...vantage,
    ok: r.ok,
    rttMs: r.ok ? Date.now() - started : undefined,
    ...(r.error ? { error: shortError(r.error, 60, redact) } : {}),
  });
  if (target.addressKind === 'name') {
    const resolved = await resolvePublic(target.address, lookup);
    if (!resolved.ok) return { ...vantage, ok: false, error: resolved.error };
    // Dial the literal the check verified; the name is only SNI / Host from here.
    const dial = pickDialAddress(resolved.addresses, target.requestedFamily);
    if (target.protocol === 'tls' || target.protocol === 'tls-sni') {
      return finish(
        await (deps.tlsConnect ?? defaultTlsConnect)({
          host: dial,
          port: target.port,
          servername:
            target.protocol === 'tls-sni' ? (target.servername ?? target.address) : target.address,
          timeoutMs,
        }),
      );
    }
    if (target.protocol === 'https') {
      return finish(
        await (deps.httpsRequest ?? defaultHttpsRequest)({
          host: dial,
          port: target.port,
          servername: target.address,
          timeoutMs,
        }),
      );
    }
    return finish(
      await (deps.tcpConnect ?? defaultTcpConnect)({ host: dial, port: target.port, timeoutMs }),
    );
  }
  const host = targetHost(target);
  if (target.protocol === 'tls-sni') {
    // Shape check: dial the literal, present the listener's name, verify the
    // chain for that name. No servername = nothing to verify against = not run.
    if (!target.servername) return { ...vantage, ok: false, error: 'no_servername' };
    return finish(
      await (deps.tlsConnect ?? defaultTlsConnect)({
        host: target.address,
        port: target.port,
        servername: target.servername,
        timeoutMs,
      }),
    );
  }
  if (target.protocol === 'tls') {
    return finish(
      await (deps.tlsConnect ?? defaultTlsConnect)({
        host: target.address,
        port: target.port,
        servername: undefined,
        timeoutMs,
      }),
    );
  }
  try {
    await deps.fetchFn(`https://${host}:${target.port}/`, {
      method: target.protocol === 'https' ? 'GET' : 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { ...vantage, ok: true, rttMs: Date.now() - started };
  } catch (err) {
    // `https` measures the handshake plus a request, so a TLS failure is a
    // failure; `tcp` only asks whether anything answered on the port.
    const c =
      target.protocol === 'https' ? classifyHandshakeError(err) : classifyInternalError(err);
    return {
      ...vantage,
      ok: c.ok,
      rttMs: c.ok ? Date.now() - started : undefined,
      error: shortError(c.error, 60, redact),
    };
  }
}
