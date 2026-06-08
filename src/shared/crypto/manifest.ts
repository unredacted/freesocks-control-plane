/**
 * Manifest signing (CDN-blinding Phase 3). The manifest key (Ed25519, pure-JS
 * noble) is the trust anchor for everything the server tells the client that the
 * client must NOT take on faith from the CDN-fronted `/config`: the short-lived
 * epoch KEM public keys, and the versioned revoked-kid list. The PUBLIC key is
 * baked into the bundle at build (`VITE_FS_MANIFEST_PK`); the SECRET key
 * (`FS_MANIFEST_SK`) lives only in the Convex deployment env and signs inside the
 * "use node" action.
 *
 * This module builds the canonical signed statements so client and server cannot
 * drift, and wraps sign (server) + verify (client). Both halves are available
 * wherever it is imported; only the relevant one is called. Ed25519 needs no
 * subtle/HKDF, so it runs in the browser, the node action, and the default
 * isolate alike. Migrates to ML-DSA-65 in Phase 4 (a versioned statement bump).
 */
import { ed25519 } from '@noble/curves/ed25519.js';

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

/** Sign a canonical statement with the manifest secret key (server, "use node"). */
export function signManifest(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/** Verify a manifest signature against the baked public key (client). Never throws. */
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
