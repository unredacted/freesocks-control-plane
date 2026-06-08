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
import { v } from 'convex/values';
import {
  b64UrlToBytes,
  buildInfo,
  kidFromPublicKey,
  SUITE_ID,
  type SealedWire,
} from '../../src/shared/crypto/envelope';
import {
  openFrom,
  sealTo,
  serializePublicKey,
  serverKeyPairFromSeed,
} from '../../src/shared/crypto/hpke';
import { serverOpenRequest, serverSealResponse } from '../../src/shared/crypto/channel';

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
      path: '/api/v1/subscription',
      dir: 'req',
    });
    const aad = new TextEncoder().encode('fcp-selftest');
    const msg = new TextEncoder().encode('node-runtime-selftest');
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, msg);
    const pt = await openFrom(kp.privateKey, enc, info, aad, ct);
    return { ok: new TextDecoder().decode(pt) === 'node-runtime-selftest', encBytes: enc.length };
  },
});

/** The server identity for the channel: private key + the kid the client pinned. */
async function serverContext(): Promise<{ priv: CryptoKey; kid: string }> {
  const kp = await loadServerKeyPair();
  const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
  return { priv: kp.privateKey, kid };
}

/**
 * Open a sealed request body (login). Called by the isolate `sealed()` wrapper
 * via ctx.runAction; returns the decrypted request object for the handler.
 */
export const openRequest = internalAction({
  args: { method: v.string(), path: v.string(), wireBody: v.any() },
  handler: async (_ctx, { method, path, wireBody }): Promise<{ plaintext: unknown }> => {
    const { priv, kid } = await serverContext();
    const plaintext = await serverOpenRequest({
      serverPriv: priv,
      serverKid: kid,
      method,
      path,
      wireBody: wireBody as SealedWire,
    });
    return { plaintext };
  },
});

/**
 * Seal a response to the client's ephemeral public key (reveal leg). Called by
 * the wrapper after the handler produces its plaintext JSON.
 */
export const sealResponse = internalAction({
  args: { method: v.string(), path: v.string(), respEphPubB64: v.string(), responseObj: v.any() },
  handler: async (_ctx, { method, path, respEphPubB64, responseObj }): Promise<SealedWire> => {
    const { kid } = await serverContext();
    return serverSealResponse({ serverKid: kid, method, path, respEphPubB64, responseObj });
  },
});
