/**
 * Manifest signing (CDN-blinding Phase 3, made post-quantum in Phase 4). The
 * manifest key is the trust anchor for everything the server tells the client
 * that it must NOT take on faith from the CDN-fronted endpoints: the short-lived
 * epoch KEM public keys and the versioned revoked-kid list.
 *
 * Phase 4 makes it a HYBRID signature: every statement is signed with BOTH
 * Ed25519 (battle-tested classical) AND ML-DSA-65 (FIPS 204 post-quantum), and
 * the client requires BOTH to verify when it has a PQ key baked. To forge a
 * manifest an attacker must break both schemes, so it stays unforgeable if
 * EITHER holds: a quantum break of Ed25519 is covered by ML-DSA, and an
 * implementation flaw in the young ML-DSA is covered by Ed25519. This mirrors the
 * X-Wing hybrid-KEM reasoning the project already adopted for confidentiality.
 *
 * The PUBLIC keys are baked into the bundle (`VITE_FS_MANIFEST_PK` +
 * `VITE_FS_MANIFEST_PK_PQ`); the SECRET keys (`FS_MANIFEST_SK` +
 * `FS_MANIFEST_SK_PQ`) live only in the Convex deployment env and sign inside the
 * "use node" action. Both schemes are pure-JS noble (no subtle/HKDF), so they run
 * in the browser, the node action, and the default isolate alike. They sign the
 * SAME canonical statement bytes (below), so the message format is unversioned;
 * the hybrid is about the signature SET, not the message.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

/** Versioned statement prefix, folded into every signed message. */
export const MANIFEST_VERSION = 'FCP-manifest v1';

/**
 * Canonical signed statement for a single epoch KEM public key. The client
 * verifies this against the baked manifest key before sealing the login request
 * to `publicKeyB64`, so an active CDN cannot substitute its own epoch key.
 */
export function epochStatement(p: {
  kid: string;
  publicKeyB64: string;
  notAfter: number;
}): Uint8Array {
  return new TextEncoder().encode(
    [MANIFEST_VERSION, 'epoch', p.kid, p.publicKeyB64, String(p.notAfter)].join('\n'),
  );
}

/**
 * Canonical signed statement for the revoked-kid list (Phase 3c). `version` is
 * monotonic; the client rejects a manifest older than the last it saw
 * (anti-rollback). `notAfter` bounds staleness (fail closed past it). The kid
 * list is sorted so the bytes are deterministic.
 */
export function revocationStatement(p: {
  version: number;
  notAfter: number;
  revokedKids: string[];
}): Uint8Array {
  const sorted = [...p.revokedKids].sort().join(',');
  return new TextEncoder().encode(
    [MANIFEST_VERSION, 'revoked', String(p.version), String(p.notAfter), sorted].join('\n'),
  );
}

/** Sign a canonical statement with the Ed25519 manifest secret key (server). */
export function signManifest(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/** Verify an Ed25519 manifest signature against the baked public key. Never throws. */
export function verifyManifest(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** Sign a canonical statement with the ML-DSA-65 manifest secret key (server, Phase 4). */
export function signManifestPq(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

/** Verify an ML-DSA-65 manifest signature against the baked PQ public key. Never throws. */
export function verifyManifestPq(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
