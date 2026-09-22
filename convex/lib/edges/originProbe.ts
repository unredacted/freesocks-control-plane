/**
 * The origin probe (docs/edges.md § "Listener catalogue", discovery): how an
 * L7 front may dial a node's HTTP-transport transport, measured from the control
 * plane. Pure: every socket is injected (`OriginProbeDeps`); the `"use node"`
 * half (convex/edgeOriginProbeOps.ts) supplies the real ones.
 *
 * Per listener security:
 *  - `none`: the transport speaks plaintext HTTP; a TCP answer on the port is
 *    enough -> `{ scheme: 'http' }` (L7-only: a forwarder cannot add the TLS
 *    the CDN terminated).
 *  - `tls`: a handshake with SNI = the first server name. `certPublic` = the
 *    chain verifies against the system store; `certNames` = the leaf's names;
 *    `acceptsHostHeader` = `'names'` (conservative) unless one request with a
 *    FOREIGN Host header still answers 2xx (`'any'`).
 *  - anything else (REALITY has no HTTP origin): not probed.
 *
 * Without a successful probe the listener stays L4-only and the plan says so.
 * Like the internal reachability probe, a NAME is resolved first and every
 * answer must be a public literal; the connection is made to one of those
 * literals, never to the name again (DNS rebinding). An origin that is itself
 * a private literal is refused: the control plane never dials its own network.
 */
import type {
  ListenerSecurity,
  ListenerStreamTransport,
} from '../../../src/shared/contracts/edgeProtocolIds';
import { isPublicIpLiteral, addressFamily } from './ip';
import type { OriginTransport } from './layers';

export interface OriginProbeDeps {
  lookup: (name: string) => Promise<string[]>;
  tcpConnect: (opts: { host: string; port: number; timeoutMs: number }) => Promise<{
    ok: boolean;
    error?: string;
  }>;
  /** A verified handshake: `authorized` = the chain verifies; `names` = the leaf's DNS names (SAN + CN). */
  tlsInspect: (opts: {
    host: string;
    port: number;
    servername: string;
    timeoutMs: number;
  }) => Promise<{
    ok: boolean;
    authorized: boolean;
    names: string[];
    error?: string;
  }>;
  /** One request over a fresh handshake with the given Host header; the status line's code, or null. */
  httpsStatus: (opts: {
    host: string;
    port: number;
    servername: string;
    hostHeader: string;
    timeoutMs: number;
  }) => Promise<{ status: number | null; error?: string }>;
}

export interface OriginProbeRequest {
  listenerKey: string;
  originAddress: string;
  originPort: number;
  streamTransport: ListenerStreamTransport;
  security: ListenerSecurity;
  tlsNames: string[];
}

export interface OriginProbeOutcome {
  listenerKey: string;
  originTransport: OriginTransport | null;
  /** Why no transport could be established (a short code, never an address). */
  reason?: string;
}

/** A Host header no origin serves for on purpose: does the node answer for ANY name? */
export const FOREIGN_HOST_HEADER = 'origin-probe.invalid';
const HTTP_TRANSPORTS: ReadonlySet<string> = new Set(['ws', 'httpupgrade', 'grpc', 'xhttp']);

function shortReason(s: string | undefined, fallback: string): string {
  const r = (s ?? '').trim();
  return (r || fallback).slice(0, 40).replace(/[^A-Za-z0-9_.-]/g, '_');
}

/** Resolve the dial address: a public literal as given, a name through the resolver (all answers public). */
async function dialAddress(
  deps: OriginProbeDeps,
  address: string,
): Promise<{ ok: true; host: string } | { ok: false; reason: string }> {
  if (addressFamily(address)) {
    return isPublicIpLiteral(address)
      ? { ok: true, host: address }
      : { ok: false, reason: 'private_address' };
  }
  let answers: string[];
  try {
    answers = await deps.lookup(address);
  } catch {
    return { ok: false, reason: 'resolve_failed' };
  }
  if (answers.length === 0) return { ok: false, reason: 'no_address' };
  if (!answers.every((a) => isPublicIpLiteral(a))) return { ok: false, reason: 'private_address' };
  return { ok: true, host: answers[0]! };
}

export async function probeOriginTransport(
  deps: OriginProbeDeps,
  req: OriginProbeRequest,
  timeoutMs = 6000,
): Promise<OriginProbeOutcome> {
  const out = (originTransport: OriginTransport | null, reason?: string): OriginProbeOutcome => ({
    listenerKey: req.listenerKey,
    originTransport,
    ...(reason ? { reason } : {}),
  });
  if (!HTTP_TRANSPORTS.has(req.streamTransport)) return out(null, 'not_http_transport');
  if (req.security !== 'none' && req.security !== 'tls') return out(null, 'not_http_origin');
  const dial = await dialAddress(deps, req.originAddress);
  if (!dial.ok) return out(null, dial.reason);

  if (req.security === 'none') {
    const r = await deps.tcpConnect({ host: dial.host, port: req.originPort, timeoutMs });
    if (!r.ok) return out(null, shortReason(r.error, 'unreachable'));
    return out({ scheme: 'http', certPublic: false, certNames: [], acceptsHostHeader: 'any' });
  }

  const servername = req.tlsNames[0];
  if (!servername) return out(null, 'no_server_name');
  const hs = await deps.tlsInspect({
    host: dial.host,
    port: req.originPort,
    servername,
    timeoutMs,
  });
  if (!hs.ok) return out(null, shortReason(hs.error, 'handshake_failed'));
  const certNames = [...new Set(hs.names.map((n) => n.trim().toLowerCase()).filter(Boolean))];
  let acceptsHostHeader: OriginTransport['acceptsHostHeader'] = 'names';
  try {
    const st = await deps.httpsStatus({
      host: dial.host,
      port: req.originPort,
      servername,
      hostHeader: FOREIGN_HOST_HEADER,
      timeoutMs,
    });
    if (st.status !== null && st.status >= 200 && st.status < 300) acceptsHostHeader = 'any';
  } catch {
    // The conservative answer stands.
  }
  return out({ scheme: 'https', certPublic: hs.authorized, certNames, acceptsHostHeader });
}

/** Parse Node's `subjectaltname` ("DNS:a.example, DNS:*.b.example, IP Address:...") into DNS names. */
export function dnsNamesOfSan(san: string | undefined | null): string[] {
  if (!san) return [];
  return san
    .split(',')
    .map((p) => p.trim())
    .filter((p) => /^DNS:/i.test(p))
    .map((p) => p.slice(4).trim())
    .filter(Boolean);
}
