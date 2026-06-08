'use node';
/**
 * Server-side HPKE crypto, in the Convex NODE runtime (full WebCrypto). The
 * default V8 isolate lacks subtle HKDF (Phase 0 finding, docs/e2ee-phase0-spike.md),
 * so the sealed `httpAction`s in convex/http.ts must reach the X-Wing seal/open
 * here via `ctx.runAction`. This module owns the server static key material.
 *
 * The server private key is the 32-byte X-Wing SEED (FS_SERVER_HPKE_SK,
 * base64url), reconstructed with generateKeyPairDerand. We never store or move a
 * separately expanded ML-KEM key (X-Wing binding caveat).
 *
 * P0d lands the key loader + a self-test. The real open/seal request/response
 * actions land in P1 (the OHTTP exporter flow).
 */
import { internalAction } from '../_generated/server';
import { b64UrlToBytes, buildInfo, SUITE_ID } from '../../src/shared/crypto/envelope';
import { openFrom, sealTo, serverKeyPairFromSeed } from '../../src/shared/crypto/hpke';

/** Load + reconstruct the server X-Wing keypair from the env seed. Fails closed. */
export async function loadServerKeyPair(): Promise<CryptoKeyPair> {
  const b64 = process.env.FS_SERVER_HPKE_SK;
  if (!b64) {
    throw new Error('FS_SERVER_HPKE_SK must be set (bunx convex env set FS_SERVER_HPKE_SK ...)');
  }
  const seed = b64UrlToBytes(b64);
  return serverKeyPairFromSeed(seed);
}

/**
 * Health probe: reconstruct the server keypair from the env seed and run one
 * X-Wing round-trip in the Node runtime. Confirms the env key + the suite work
 * end to end on the server. Run with `bunx convex run e2eeCrypto:selfTest`.
 */
export const selfTest = internalAction({
  args: {},
  handler: async (): Promise<{ ok: boolean; encBytes: number }> => {
    const kp = await loadServerKeyPair();
    const info = buildInfo({
      suiteId: SUITE_ID,
      kid: 'selftest00000000',
      method: 'POST',
      host: 'localhost',
      path: '/api/v1/subscription',
    });
    const aad = new TextEncoder().encode('fcp-selftest');
    const msg = new TextEncoder().encode('node-runtime-selftest');
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, msg);
    const pt = await openFrom(kp.privateKey, enc, info, aad, ct);
    return { ok: new TextDecoder().decode(pt) === 'node-runtime-selftest', encBytes: enc.length };
  },
});
