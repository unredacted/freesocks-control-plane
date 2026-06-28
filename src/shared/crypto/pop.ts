/**
 * Proof-of-possession (PoP) request signing for the CDN-blinding channel
 * (Phase 2). Closes the cookie-replay hole: a passive CDN that captures the
 * httpOnly `fs_session` / `fs_admin_session` cookie still cannot act as the
 * member, because every authenticated request must also carry a fresh signature
 * over its canonical form, made with a per-session NON-EXTRACTABLE P-256 private
 * key the browser holds and the CDN never sees.
 *
 * This module is the single source of truth for the canonical message both
 * sides build, so client and server cannot drift. It runs in three places:
 *   - the browser signing Worker (signP1363, WebCrypto) -> src/client/lib/pop-worker.ts
 *   - the Convex httpAction isolate verifying (verifyP1363, @noble/curves)
 *     -> convex/lib/http.ts
 *   - tests (both).
 * Both signing (WebCrypto subtle, browser) and verifying (noble, pure JS) are
 * available wherever this is imported; only the relevant half is ever called.
 *
 * Algorithm: ECDSA P-256 over SHA-256. WebCrypto emits the raw r||s (P1363, IEEE
 * 1363) 64-byte signature, NOT DER, and does NOT enforce low-S, so the noble
 * verifier must read compact and pass `lowS: false` (see verifyP1363).
 *
 * Canonical message (UTF-8, '\n'-joined), versioned so Phase 3 can add host
 * binding as a v2 bump without breaking the wire format:
 *   FCP-PoP v1
 *   METHOD
 *   path                (normalized, no query)
 *   canonicalQuery      (sorted, percent-encoded)
 *   bodyHashB64         (base64url SHA-256 of the EXACT wire body bytes)
 *   ts                  (epoch ms, decimal)
 *   nonceB64            (base64url of 16 random bytes, single-use)
 *
 * Host/`:authority` is deliberately NOT bound in v1 (the dev reverse proxy
 * rewrites Host with `changeOrigin`, same reason envelope.buildInfo omits it);
 * cross-vhost replay coverage is a Phase 3 v2 concern. The single-use nonce
 * (replayGuard) + ts window already defeat same-host replay, which is the real
 * passive-CDN threat.
 */
import { p256 } from '@noble/curves/nist.js';
import { bytesToB64Url, canonicalQuery, normalizePath, sha256 } from './envelope';

export const POP_PREFIX = 'FCP-PoP';
/**
 * Current PoP canonical-message version the client signs. v2 (Phase 3) adds two
 * lines after the query: the host and the reveal-leg response-ephemeral, so a
 * captured request cannot be replayed cross-vhost and an active CDN cannot swap
 * the GET reveal-leg ephemeral header undetected. The server still accepts v1
 * during rollout (POP_ACCEPTED_VERSIONS).
 */
export const POP_VERSION = 'v2';
export const POP_ACCEPTED_VERSIONS = ['v1', 'v2'] as const;
/** WebCrypto JWK `alg` for the session key; stored on the session row for agility. */
export const POP_ALG = 'ES256';

/** Per-request PoP headers (lowercased; Convex header reads are case-insensitive). */
export const POP_SIG_HEADER = 'x-fs-pop-sig';
export const POP_TS_HEADER = 'x-fs-pop-ts';
export const POP_NONCE_HEADER = 'x-fs-pop-nonce';
export const POP_VERSION_HEADER = 'x-fs-pop-v';
/** v2: the host the client signed (location.host), so the server reconstructs the
 *  exact canonical message even behind a Host-rewriting dev proxy, then checks it
 *  against its allowlist. */
export const POP_HOST_HEADER = 'x-fs-pop-host';

/**
 * Request-body field carrying the client's base64url raw P-256 public point
 * (65 bytes, 0x04||x||y) at login. Posted inside the SEALED login body, so even
 * the (public, non-secret) key bytes do not appear in CDN logs.
 */
export const POP_PUBKEY_FIELD = 'fsPopPub';

/**
 * PoP freshness window: a signature's `ts` must be within +/- this of server
 * time (symmetric, so it tolerates modest clock skew in either direction without
 * a server-time resync channel; an explicit clock_skew resync is a Phase 3
 * refinement). The replayGuard TTL is a multiple of this so a captured signature
 * cannot outlive its nonce row.
 */
export const POP_WINDOW_MS = 60_000;

export interface PopMessageParts {
  /** Canonical-message version ('v2' default; 'v1' only for back-compat verify). */
  version?: string;
  method: string;
  /** Pathname only, no query string. */
  path: string;
  /** Raw query string without a leading '?'. */
  query?: string;
  /** v2: the host (location.host). Bound so a request cannot be replayed cross-vhost. */
  host?: string;
  /** v2: the reveal-leg response-ephemeral (the x-fs-resp-eph header value), or ''. */
  respEph?: string;
  /** base64url SHA-256 of the exact wire body bytes (see digestB64Url). */
  bodyHashB64: string;
  /** Epoch milliseconds. */
  ts: number;
  /** base64url of the single-use 16-byte nonce. */
  nonceB64: string;
}

/**
 * Build the canonical PoP message bytes. Identical on client and server. v2
 * inserts host + reveal-ephemeral after the query; v1 (back-compat) omits them.
 */
export function buildPopMessage(p: PopMessageParts): Uint8Array {
  const version = p.version ?? POP_VERSION;
  const lines = [
    `${POP_PREFIX} ${version}`,
    p.method.toUpperCase(),
    normalizePath(p.path),
    canonicalQuery(p.query),
  ];
  if (version === 'v2') {
    lines.push(p.host ?? '', p.respEph ?? '');
  }
  lines.push(p.bodyHashB64, String(p.ts), p.nonceB64);
  return new TextEncoder().encode(lines.join('\n'));
}

/** base64url SHA-256 of the given bytes (the request bodyHash). */
export async function digestB64Url(bytes: Uint8Array): Promise<string> {
  return bytesToB64Url(await sha256(bytes));
}

/**
 * Sign the canonical message with a P-256 private CryptoKey (browser/Worker).
 * Returns the raw r||s (P1363) signature, 64 bytes. The key is generated
 * non-extractable; this never touches the private scalar directly.
 */
export async function signP1363(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    message as unknown as ArrayBuffer,
  );
  return new Uint8Array(sig);
}

/**
 * Verify a P1363 signature over the canonical message against a raw P-256 public
 * point (server, pure-JS noble; runs in the Convex default isolate). Two
 * non-negotiable options for WebCrypto compatibility:
 *   - the signature is compact r||s (noble's default format), NOT DER;
 *   - `lowS: false`, because WebCrypto does not produce low-S signatures, so the
 *     default low-S policy would reject ~half of all valid signatures.
 * `prehash` defaults to true, so noble computes SHA-256(message), matching
 * WebCrypto's ECDSA/SHA-256 over the same bytes. Never throws.
 */
export function verifyP1363(
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (signature.length !== 64) return false; // P1363 P-256 is exactly r||s
    return p256.verify(signature, message, publicKeyRaw, { lowS: false });
  } catch {
    return false;
  }
}
