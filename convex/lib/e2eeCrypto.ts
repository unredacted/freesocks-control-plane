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
import { internal } from '../_generated/api';
import { v } from 'convex/values';
import {
  b64UrlToBytes,
  bytesToB64Url,
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
import {
  epochStatement,
  revocationStatement,
  signManifest,
  signManifestPq,
} from '../../src/shared/crypto/manifest';

/** Epoch-key validity window. Longer than the rotate cadence (crons.ts) so there
 *  is always a live key with overlap; bounds request-direction retroactive
 *  exposure to roughly this plus the sweep grace. */
export const EPOCH_VALIDITY_MS = 30 * 60_000;

/** Load the Ed25519 manifest secret key from env (signs epoch keys + revocations). */
function loadManifestSecret(): Uint8Array {
  const b64 = process.env.FS_MANIFEST_SK;
  if (!b64) throw new Error('FS_MANIFEST_SK must be set (bunx convex env set FS_MANIFEST_SK ...)');
  return b64UrlToBytes(b64);
}

/** Optional ML-DSA-65 manifest secret (Phase 4 hybrid); null if not configured. */
function loadManifestSecretPq(): Uint8Array | null {
  const b64 = process.env.FS_MANIFEST_SK_PQ;
  return b64 ? b64UrlToBytes(b64) : null;
}

/** Sign a manifest statement with Ed25519 + (if configured) ML-DSA-65. */
function signManifestHybrid(message: Uint8Array): { sig: string; sigPq?: string } {
  const sig = bytesToB64Url(signManifest(loadManifestSecret(), message));
  const pqSk = loadManifestSecretPq();
  return pqSk ? { sig, sigPq: bytesToB64Url(signManifestPq(pqSk, message)) } : { sig };
}

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

/** The static server identity: private key + the kid baked into the bundle. */
async function serverContext(): Promise<{ priv: CryptoKey; kid: string }> {
  const kp = await loadServerKeyPair();
  const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
  return { priv: kp.privateKey, kid };
}

/**
 * Mint one fresh epoch KEM keypair, manifest-sign its public key, and store it
 * (Phase 3). Called by the rotate cron. The login request seals to the current
 * epoch key instead of the multi-day static key, so a later key compromise
 * cannot decrypt logins from a swept epoch. The seed is a secret stored only so
 * openRequest can resolve it, and destroyed by keyEpochs.sweepExpired.
 */
export const rotateEpochKey = internalAction({
  args: {},
  handler: async (ctx): Promise<{ kid: string; notAfter: number } | { skipped: true }> => {
    // No manifest key -> E2EE is not configured on this deployment; skip cleanly
    // (the cron would otherwise error every tick). Clients fall back to static.
    if (!process.env.FS_MANIFEST_SK) return { skipped: true };
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const kp = await serverKeyPairFromSeed(seed);
    const pkBytes = await serializePublicKey(kp.publicKey);
    const publicKey = bytesToB64Url(pkBytes);
    const kid = await kidFromPublicKey(pkBytes);
    const notBefore = Date.now();
    const notAfter = notBefore + EPOCH_VALIDITY_MS;
    const { sig, sigPq } = signManifestHybrid(
      epochStatement({ kid, publicKeyB64: publicKey, notAfter }),
    );
    await ctx.runMutation(internal.keyEpochs.insert, {
      kid,
      publicKey,
      seed: bytesToB64Url(seed),
      manifestSig: sig,
      ...(sigPq ? { manifestSigPq: sigPq } : {}),
      notBefore,
      notAfter,
    });
    await ctx.runMutation(internal.keyEpochs.sweepExpired, {});
    return { kid, notAfter };
  },
});

/**
 * Break-glass: publish a new manifest-signed revoked-kid list (Phase 3c). Bumps
 * the monotonic version, signs the full snapshot, and stores it. Run by an
 * operator when a static or epoch key is believed compromised:
 *   bunx convex run lib/e2eeCrypto:signRevocation '{"revokedKids":["<kid>"]}'
 * Pass the FULL set of kids that should be revoked (a snapshot, not a delta);
 * passing fewer kids at a higher version un-revokes the omitted ones.
 */
export const signRevocation = internalAction({
  args: { revokedKids: v.array(v.string()), ttlMs: v.optional(v.number()) },
  handler: async (
    ctx,
    { revokedKids, ttlMs },
  ): Promise<{ version: number; revokedKids: string[]; notAfter: number }> => {
    if (!process.env.FS_MANIFEST_SK) throw new Error('FS_MANIFEST_SK must be set');
    const cur = await ctx.runQuery(internal.keyRevocations.current, {});
    const version = (cur?.version ?? 0) + 1;
    const notAfter = Date.now() + (ttlMs ?? 7 * 86_400_000);
    const { sig, sigPq } = signManifestHybrid(
      revocationStatement({ version, notAfter, revokedKids }),
    );
    await ctx.runMutation(internal.keyRevocations.insert, {
      version,
      revokedKids,
      notAfter,
      manifestSig: sig,
      ...(sigPq ? { manifestSigPq: sigPq } : {}),
    });
    return { version, revokedKids, notAfter };
  },
});

/**
 * Open a sealed request body (login). Called by the isolate `sealed()` wrapper
 * via ctx.runAction; returns the decrypted request object for the handler.
 *
 * The envelope `kid` selects the recipient key: the static key (kid baked into
 * the bundle), or a Phase 3 epoch key resolved from keyEpochs. The kid is also
 * bound into the HPKE `info`, so it must match what the client sealed with.
 */
export const openRequest = internalAction({
  args: { method: v.string(), path: v.string(), wireBody: v.any() },
  handler: async (ctx, { method, path, wireBody }): Promise<{ plaintext: unknown }> => {
    const wire = wireBody as SealedWire;
    const envKid = wire?.fsSealed?.kid;
    const { priv: staticPriv, kid: staticKid } = await serverContext();

    let priv = staticPriv;
    let kid = staticKid;
    if (envKid && envKid !== staticKid) {
      // An epoch-sealed request: resolve the epoch private key by its kid. If the
      // epoch is unknown/swept, open will fail cleanly (client refetches /config).
      const epoch = await ctx.runQuery(internal.keyEpochs.byKid, { kid: envKid });
      if (epoch) priv = (await serverKeyPairFromSeed(b64UrlToBytes(epoch.seed))).privateKey;
      kid = envKid;
    }

    const plaintext = await serverOpenRequest({
      serverPriv: priv,
      serverKid: kid,
      method,
      path,
      wireBody: wire,
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
