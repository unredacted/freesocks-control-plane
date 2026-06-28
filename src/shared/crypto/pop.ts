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
 * Canonical message (UTF-8, '\n'-joined). Pre-prod there is exactly ONE version:
 *   FCP-PoP v1
 *   METHOD
 *   path                (normalized, no query)
 *   canonicalQuery      (sorted, percent-encoded)
 *   host                (location.host; cross-vhost replay binding)
 *   respEph             (reveal-leg response-ephemeral, or '')
 *   sessionToken        (the public per-session token; binds the sig to ONE session)
 *   bodyHashB64         (base64url SHA-256 of the EXACT wire body bytes)
 *   ts                  (epoch ms, decimal)
 *   nonceB64            (base64url of 16 random bytes, single-use)
 *
 * The host is reconstructed server-side from a client-declared header (so the
 * signature authenticates it) and allowlist-checked when configured. The
 * sessionToken closes the cross-session signature-lift: the client persists one
 * P-256 key across logins, so without it a signature made under session A could
 * be replayed onto session B that reuses the same key (the replayGuard nonce is
 * scoped per-sid). The single-use nonce + ts window defeat same-session replay.
 */
import { p256 } from '@noble/curves/nist.js';
import { bytesToB64Url, canonicalQuery, normalizePath, sha256 } from './envelope';

export const POP_PREFIX = 'FCP-PoP';
/**
 * The single PoP canonical-message version. This is pre-prod (beta), so there is
 * no inter-release wire compatibility to preserve and exactly ONE format is
 * accepted: `v1` binds host + reveal-leg ephemeral + the per-session token (see
 * buildPopMessage). The version line stays for crypto domain separation and a
 * clean future bump after prod launch.
 */
export const POP_VERSION = 'v1';
export const POP_ACCEPTED_VERSIONS = ['v1'] as const;
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
 * NON-httpOnly cookie carrying the PUBLIC per-session token (pst). It binds each
 * PoP signature to exactly one session: the client reads it and signs it into the
 * canonical message; the server reconstructs the message with the session row's
 * OWN stored pst, so a signature is provably for that session and cannot be
 * lifted onto another session that reuses the same persisted key. The pst is NOT
 * a secret — it authorizes nothing without the non-extractable private key — so a
 * client-readable cookie is the correct transport, and the server NEVER trusts
 * the cookie value, only the pst it stored at login.
 */
export const POP_SID_COOKIE = 'fs_pop_sid';

/**
 * PoP freshness window: a signature's `ts` must be within +/- this of server
 * time (symmetric, so it tolerates modest clock skew in either direction without
 * a server-time resync channel; an explicit clock_skew resync is a Phase 3
 * refinement). The replayGuard TTL is a multiple of this so a captured signature
 * cannot outlive its nonce row.
 */
export const POP_WINDOW_MS = 60_000;

export interface PopMessageParts {
  /** Canonical-message version (defaults to the single POP_VERSION). */
  version?: string;
  method: string;
  /** Pathname only, no query string. */
  path: string;
  /** Raw query string without a leading '?'. */
  query?: string;
  /** The host (location.host). Bound so a request cannot be replayed cross-vhost. */
  host?: string;
  /** The reveal-leg response-ephemeral (the x-fs-resp-eph header value), or ''. */
  respEph?: string;
  /**
   * The public per-session token (fs_pop_sid cookie). Binds the signature to one
   * session. Empty string ONLY for a client that has no token yet (then the
   * server, which reconstructs with the session's real pst, rejects it → re-auth).
   */
  sessionToken: string;
  /** base64url SHA-256 of the exact wire body bytes (see digestB64Url). */
  bodyHashB64: string;
  /** Epoch milliseconds. */
  ts: number;
  /** base64url of the single-use 16-byte nonce. */
  nonceB64: string;
}

/**
 * Build the canonical PoP message bytes. Identical on client and server — the
 * single source of truth, so the two cannot drift. One format (see the file
 * header): host + reveal-ephemeral + per-session token are always included.
 */
export function buildPopMessage(p: PopMessageParts): Uint8Array {
  const lines = [
    `${POP_PREFIX} ${p.version ?? POP_VERSION}`,
    p.method.toUpperCase(),
    normalizePath(p.path),
    canonicalQuery(p.query),
    p.host ?? '',
    p.respEph ?? '',
    p.sessionToken,
    p.bodyHashB64,
    String(p.ts),
    p.nonceB64,
  ];
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
