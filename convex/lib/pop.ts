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
  POP_NONCE_HEADER,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
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
  /** EXACT wire body bytes as received (string), '' for none. */
  wireBody: string;
  fields: PopFields;
  nowMs: number;
}): Promise<{ verdict: PopVerdict; nonceHash?: string }> {
  const { fields } = opts;
  // Unknown PoP version: the client must match the server's pinned format.
  if (fields.version !== POP_VERSION) return { verdict: 'invalid' };
  // Freshness: symmetric window tolerates modest clock skew either way.
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
  const message = buildPopMessage({
    method: opts.method,
    path: opts.path,
    query: opts.query,
    bodyHashB64,
    ts: fields.ts,
    nonceB64: fields.nonceB64,
  });
  if (!verifyP1363(pub, message, sig)) return { verdict: 'invalid' };

  const nonceHash = await sha256Hex(fields.nonceB64);
  return { verdict: 'ok', nonceHash };
}
