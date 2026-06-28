// Generate the CDN-blinding key material. Secrets go to the Convex deployment env
// (FS_SERVER_HPKE_SK, FS_MANIFEST_SK, FS_MANIFEST_SK_PQ); the public fields are
// baked into the SPA bundle at build (VITE_*).
//
// As a CLI it prints the full set as JSON: `bun scripts/gen-e2ee-keys.mjs`
//   - pipe the FS_* secrets to `bunx convex env set ...`
//   - put the VITE_* fields in .env.local (dev) / the web build args (prod).
// As a module it exports generateE2eeKeys() — used by scripts/bootstrap-secrets.mjs
// to fill a fresh deploy's .env files in one shot.
//
// Prod keys are generated fresh at cutover; never commit real key values.
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { serverKeyPairFromSeed, serializePublicKey } from '../src/shared/crypto/hpke.ts';
import { bytesToB64Url, kidFromPublicKey, SUITE_ID } from '../src/shared/crypto/envelope.ts';

/**
 * Generate a fresh, internally-consistent CDN-blinding key set: the X-Wing server
 * identity (a 32-byte seed = the private key) + its public key/kid, and the hybrid
 * manifest-signing identity (Ed25519 + ML-DSA-65, both required by the client).
 * Returns secrets (FS_*) and publics (VITE_*) together so they always match.
 */
export async function generateE2eeKeys() {
  // X-Wing server identity: the private key IS a 32-byte seed.
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = await serverKeyPairFromSeed(seed);
  const pk = await serializePublicKey(kp.publicKey);
  const kid = await kidFromPublicKey(pk);

  // Manifest-signing identity (anchors the epoch keys + the revoked-kid list). A
  // Phase 4 HYBRID: Ed25519 (classical) + ML-DSA-65 (FIPS 204 post-quantum). Both
  // sign every statement; the client requires both, so it stays unforgeable if
  // either scheme holds.
  const { secretKey: manifestSk, publicKey: manifestPk } = ed25519.keygen();
  const { secretKey: manifestSkPq, publicKey: manifestPkPq } = ml_dsa65.keygen();

  return {
    // --- secrets: the Convex deployment env (bunx convex env set ...) ---
    FS_SERVER_HPKE_SK: bytesToB64Url(seed),
    FS_MANIFEST_SK: bytesToB64Url(manifestSk),
    FS_MANIFEST_SK_PQ: bytesToB64Url(manifestSkPq),
    // --- public: baked into the bundle (the web build args / .env.local) ---
    VITE_FS_SERVER_HPKE_PK: bytesToB64Url(pk),
    VITE_FS_SERVER_HPKE_KID: kid,
    VITE_FS_E2EE_SUITE_ID: SUITE_ID,
    VITE_FS_MANIFEST_PK: bytesToB64Url(manifestPk),
    VITE_FS_MANIFEST_PK_PQ: bytesToB64Url(manifestPkPq),
  };
}

if (import.meta.main) {
  console.log(JSON.stringify(await generateE2eeKeys(), null, 2));
}
