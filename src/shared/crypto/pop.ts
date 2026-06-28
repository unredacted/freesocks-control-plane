/**
 * Proof-of-possession (PoP) request signing for the CDN-blinding channel
 * (Phase 2). Closes the cookie-replay hole: a passive CDN that captures the
 * httpOnly `fs_session` / `fs_admin_session` cookie still cannot act as the
 * member, because every authenticated request must also carry a fresh signature
 * over its canonical form, made with a per-session NON-EXTRACTABLE private key
 * the browser holds and the CDN never sees.
 *
 * This module is the single source of truth for the canonical message both
 * sides build, so client and server cannot drift. It runs in three places:
 *   - the browser signing Worker (signPop, WebCrypto) -> src/client/lib/pop-worker.ts
 *   - the Convex httpAction isolate verifying (verifyPop, @noble/curves)
 *     -> convex/lib/http.ts
 *   - tests (both).
 * Both signing (WebCrypto subtle, browser) and verifying (noble, pure JS) are
 * available wherever this is imported; only the relevant half is ever called.
 *
 * Algorithm agility (per session). The session key is Ed25519 wherever the
 * browser supports it in WebCrypto — a rigid, non-NIST curve with no per-signature
 * nonce and none of ECDSA's low-S/DER footguns — falling back to ECDSA P-256 on
 * older browsers. The algorithm is recorded per session (sessions.popAlg =
 * 'EdDSA' | 'ES256') and the verifier dispatches on it (verifyPop); it is never
 * negotiated at verify time. PoP is deliberately CLASSICAL (not post-quantum): it
 * authenticates an EPHEMERAL session (±window, single-use nonce), so a
 * harvest-now-forge-later attack only ever yields a signature for a long-dead
 * session. The confidentiality layer (X-Wing HPKE) is where PQ matters and is
 * already hybrid. See docs/threat-model-cdn-blinding.md.
 *
 * Signature encodings (both exactly 64 bytes): ECDSA P-256 over SHA-256 is raw
 * r||s (P1363/IEEE-1363), NOT DER, and WebCrypto does NOT enforce low-S, so the
 * noble verifier reads compact and passes `lowS: false`. Ed25519 (RFC 8032) signs
 * the canonical bytes directly (no prehash) and is R||s over a 32-byte public key.
 *
 * Canonical message (UTF-8, '\n'-joined): see buildPopMessage. The algorithm is
 * carried out-of-band (popAlg + the fsPopAlg enrollment field), NOT in the
 * message, so the bytes are identical across algorithms — POP_VERSION need not
 * bump for the curve change, and existing P-256 sessions keep verifying under
 * their stored popAlg (graceful rollover, no forced re-auth).
 */
import { ed25519 } from '@noble/curves/ed25519.js';
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
/** JWK `alg` for an ECDSA P-256 session key (the fallback curve). Stored on the session row. */
export const POP_ALG = 'ES256';
/** JWK `alg` for an Ed25519 session key (the preferred, non-NIST curve). */
export const POP_ALG_ED = 'EdDSA';
/**
 * Request-body field carrying the client's PoP algorithm ('EdDSA' | 'ES256') at
 * enrollment, alongside POP_PUBKEY_FIELD. The server records it on the session
 * (sessions.popAlg) and verifies later requests with the matching scheme.
 */
export const POP_ALG_FIELD = 'fsPopAlg';

/** Per-request PoP headers (lowercased; Convex header reads are case-insensitive). */
export const POP_SIG_HEADER = 'x-fs-pop-sig';
export const POP_TS_HEADER = 'x-fs-pop-ts';
export const POP_NONCE_HEADER = 'x-fs-pop-nonce';
export const POP_VERSION_HEADER = 'x-fs-pop-v';
/** The host the client signed (location.host), so the server reconstructs the
 *  exact canonical message even behind a Host-rewriting dev proxy, then checks it
 *  against its allowlist. */
export const POP_HOST_HEADER = 'x-fs-pop-host';

/**
 * Request-body field carrying the client's base64url raw public key at login: an
 * Ed25519 32-byte key (preferred) or an uncompressed P-256 point (65 bytes,
 * 0x04||x||y, the fallback) — the companion POP_ALG_FIELD says which. Posted
 * inside the SEALED login body, so even the (public, non-secret) key bytes do not
 * appear in CDN logs.
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
   * The public per-session token (the server's stored sessions.popSessionToken,
   * delivered to the client in the login response). Binds the signature to one
   * session, so it cannot be lifted onto another session that reuses the same
   * persisted key. Empty string only for a client with no token yet (then the
   * server, reconstructing with the session's real token, rejects it → re-auth).
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
 * single source of truth, so the two cannot drift. One format: host + reveal-leg
 * ephemeral + per-session token are always included.
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
 * Sign the canonical message with an Ed25519 private CryptoKey (browser/Worker).
 * Returns the 64-byte RFC 8032 signature (R||s). Ed25519 hashes the message
 * internally (SHA-512), so it signs the canonical bytes directly — no prehash.
 */
export async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    message as unknown as ArrayBuffer,
  );
  return new Uint8Array(sig);
}

/**
 * Sign with whichever scheme the session key uses, picked from the CryptoKey's
 * own `algorithm.name` (preserved across the IndexedDB structured-clone), so the
 * Worker needs no separate alg bookkeeping. Both schemes yield 64-byte sigs.
 */
export async function signPop(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return privateKey.algorithm.name === 'Ed25519'
    ? signEd25519(privateKey, message)
    : signP1363(privateKey, message);
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

/**
 * Verify an Ed25519 (RFC 8032) signature over the canonical message against a raw
 * 32-byte public key (server, pure-JS noble; runs in the Convex default isolate).
 * The message is verified directly — Ed25519 hashes it internally, so there is no
 * prehash, matching WebCrypto's Ed25519 sign over the same bytes. Never throws.
 */
export function verifyEd25519(
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (signature.length !== 64) return false; // Ed25519 sig is R||s, exactly 64 bytes
    return ed25519.verify(signature, message, publicKeyRaw);
  } catch {
    return false;
  }
}

/**
 * Verify a PoP signature with the scheme recorded for the session. `alg` is the
 * session's stored `popAlg` ('EdDSA' → Ed25519; anything else → ECDSA P-256, the
 * legacy/default). The server commits to ONE scheme per session before verifying,
 * so there is no cross-algorithm negotiation an attacker can exploit; a
 * mismatched key/scheme just fails closed (the underlying verifier throws → false).
 */
export function verifyPop(
  alg: string | undefined,
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  return alg === POP_ALG_ED
    ? verifyEd25519(publicKeyRaw, message, signature)
    : verifyP1363(publicKeyRaw, message, signature);
}
