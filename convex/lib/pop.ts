/**
 * Server-side proof-of-possession verification (CDN-blinding Phase 2). Pure,
 * isolate-safe helpers used by resolveMember / resolveAdmin in ./http.ts to
 * decide whether a request carries a valid signature from the session's bound
 * key. The actual signature math is @noble/curves (pure JS, runs in the default
 * Convex isolate; no subtle HKDF needed, unlike the HPKE seal/open).
 *
 * evaluatePop does NOT consume the nonce (no ctx, no side effects) so it is
 * directly unit-testable and decoupled from the serializable replayGuard write;
 * the caller consumes the returned nonceHash via replayGuard.consumeNonce.
 */
import { b64UrlToBytes } from '../../src/shared/crypto/envelope';
import {
  buildPopMessage,
  digestB64Url,
  POP_ACCEPTED_VERSIONS,
  POP_NONCE_HEADER,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION_HEADER,
  POP_WINDOW_MS,
  verifyP1363,
} from '../../src/shared/crypto/pop';
import { sha256Hex } from './crypto';

/** replayGuard row lifetime: >= 2x the acceptance window, so a captured signature
 *  (valid for up to 2x window around its ts) cannot outlive its consumed nonce. */
export const REPLAY_TTL_MS = POP_WINDOW_MS * 3;

export interface PopFields {
  sigB64: string;
  ts: number;
  nonceB64: string;
  version: string;
}

/** Read the four PoP request headers, or null if any required one is missing/malformed. */
export function extractPopFields(req: Request): PopFields | null {
  const sigB64 = req.headers.get(POP_SIG_HEADER);
  const tsRaw = req.headers.get(POP_TS_HEADER);
  const nonceB64 = req.headers.get(POP_NONCE_HEADER);
  const version = req.headers.get(POP_VERSION_HEADER);
  if (!sigB64 || !tsRaw || !nonceB64 || !version) return null;
  const ts = Number(tsRaw);
  if (!Number.isFinite(ts)) return null;
  return { sigB64, ts, nonceB64, version };
}

export type PopVerdict = 'ok' | 'invalid';

/**
 * Verify a PoP signature against a session's bound public key. Returns 'ok' plus
 * the nonceHash to consume, or 'invalid'. Never throws. Pure: the caller checks
 * the nonce separately (replayGuard).
 */
export async function evaluatePop(opts: {
  /** base64url raw P-256 public point bound to the session. */
  popPublicKey: string;
  method: string;
  /** pathname only (no query). */
  path: string;
  /** raw query string without a leading '?'. */
  query?: string;
  /** v2: the host the client declared (x-fs-pop-host); bound into the message. */
  host?: string;
  /** v2: the reveal-leg response-ephemeral (x-fs-resp-eph header), bound in. */
  respEph?: string;
  /** EXACT wire body bytes as received (string), '' for none. */
  wireBody: string;
  fields: PopFields;
  nowMs: number;
}): Promise<{ verdict: PopVerdict; nonceHash?: string }> {
  const { fields } = opts;
  // Unknown PoP version: the client must use an accepted canonical format.
  if (!(POP_ACCEPTED_VERSIONS as readonly string[]).includes(fields.version)) {
    return { verdict: 'invalid' };
  }
  // Freshness: symmetric window tolerates modest clock skew either way (the
  // client also corrects with a /healthz-derived offset, P3d).
  if (Math.abs(opts.nowMs - fields.ts) > POP_WINDOW_MS) return { verdict: 'invalid' };

  let pub: Uint8Array;
  let sig: Uint8Array;
  try {
    pub = b64UrlToBytes(opts.popPublicKey);
    sig = b64UrlToBytes(fields.sigB64);
  } catch {
    return { verdict: 'invalid' };
  }

  const bodyHashB64 = await digestB64Url(new TextEncoder().encode(opts.wireBody));
  // buildPopMessage only folds host/respEph in for v2; v1 ignores them. The host
  // is reconstructed from the client-declared header, so the signature verifies
  // only if the client actually signed that host (authenticating it for the
  // allowlist check the caller does on a v2 'ok').
  const message = buildPopMessage({
    version: fields.version,
    method: opts.method,
    path: opts.path,
    query: opts.query,
    host: opts.host ?? '',
    respEph: opts.respEph ?? '',
    bodyHashB64,
    ts: fields.ts,
    nonceB64: fields.nonceB64,
  });
  if (!verifyP1363(pub, message, sig)) return { verdict: 'invalid' };

  const nonceHash = await sha256Hex(fields.nonceB64);
  return { verdict: 'ok', nonceHash };
}

/**
 * Allowed PoP hosts for the v2 cross-vhost check, from POP_EXPECTED_HOST
 * (comma-separated) or, failing that, the host(s) of WEBAUTHN_ORIGIN. Empty when
 * neither is set (then the host is bound + authenticated but not allowlist-
 * enforced, so a misconfigured deployment never locks itself out).
 */
export function allowedPopHosts(): string[] {
  const raw = process.env.POP_EXPECTED_HOST;
  if (raw) {
    return raw
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean);
  }
  const origins = process.env.WEBAUTHN_ORIGIN;
  if (!origins) return [];
  const hosts: string[] = [];
  for (const o of origins.split(',')) {
    try {
      hosts.push(new URL(o.trim()).host.toLowerCase());
    } catch {
      /* skip a malformed origin */
    }
  }
  return hosts;
}
