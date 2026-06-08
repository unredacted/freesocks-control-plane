// Generate the CDN-blinding key material and print it as JSON. Secrets go to
// the Convex deployment env (FS_SERVER_HPKE_SK, FS_MANIFEST_SK); the public
// fields are baked into the SPA bundle at build (VITE_*). Run: bun scripts/gen-e2ee-keys.mjs
//
// Dev: pipe the secrets to `bunx convex env set ...` and the VITE_* fields into
// .env.local (gitignored). Prod keys are generated fresh at cutover; never commit
// real key values.
import { ed25519 } from '@noble/curves/ed25519.js';
import { serverKeyPairFromSeed, serializePublicKey } from '../src/shared/crypto/hpke.ts';
import { bytesToB64Url, kidFromPublicKey, SUITE_ID } from '../src/shared/crypto/envelope.ts';

// X-Wing server identity: the private key IS a 32-byte seed.
const seed = crypto.getRandomValues(new Uint8Array(32));
const kp = await serverKeyPairFromSeed(seed);
const pk = await serializePublicKey(kp.publicKey);
const kid = await kidFromPublicKey(pk);

// Ed25519 manifest-signing identity (anchors the kid set, Phase 3 epoch keys,
// and the revoked-kid list). Migrates to ML-DSA-65 in Phase 4.
const { secretKey: manifestSk, publicKey: manifestPk } = ed25519.keygen();

console.log(
  JSON.stringify(
    {
      // --- secrets: bunx convex env set ... ---
      FS_SERVER_HPKE_SK: bytesToB64Url(seed),
      FS_MANIFEST_SK: bytesToB64Url(manifestSk),
      // --- public: baked into the bundle (.env.local for dev) ---
      VITE_FS_SERVER_HPKE_PK: bytesToB64Url(pk),
      VITE_FS_SERVER_HPKE_KID: kid,
      VITE_FS_E2EE_SUITE_ID: SUITE_ID,
      VITE_FS_MANIFEST_PK: bytesToB64Url(manifestPk),
    },
    null,
    2,
  ),
);
