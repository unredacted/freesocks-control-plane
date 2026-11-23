/**
 * Server HPKE key management: epoch rotation, the volatile seed store's upkeep,
 * the break-glass revocation list, and a self-test. Default V8 runtime (no
 * "use node"): the isolate has subtle HKDF since the pinned backend, and the
 * manifest signers (Ed25519, ML-DSA-65) are pure-JS noble. The per-request
 * open/seal lives in ./hpkeServer.ts and runs inline in the sealed httpAction.
 *
 * The server private key is the 32-byte X-Wing SEED (FS_SERVER_HPKE_SK,
 * base64url), reconstructed with generateKeyPairDerand. We never store or move a
 * separately expanded ML-KEM key (X-Wing binding caveat).
 */
import { internalAction, type ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import { v } from 'convex/values';
import {
  bytesToB64Url,
  buildInfo,
  b64UrlToBytes,
  kidFromPublicKey,
  SUITE_ID,
} from '../../src/shared/crypto/envelope';
import {
  openFrom,
  sealTo,
  serializePublicKey,
  serverKeyPairFromSeed,
} from '../../src/shared/crypto/hpke';
import {
  epochStatement,
  revocationStatement,
  signManifest,
  signManifestPq,
} from '../../src/shared/crypto/manifest';
import { epochSeedRequest, readLiveEpoch, staticServerKey } from './hpkeServer';

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

/**
 * Health probe: reconstruct the server keypair from the env seed and run one
 * X-Wing round-trip in the V8 runtime. Confirms the env key + the suite work
 * end to end on the server. Run with `bunx convex run lib/hpkeCrypto:selfTest`.
 */
export const selfTest = internalAction({
  args: {},
  handler: async (): Promise<{ ok: boolean; encBytes: number }> => {
    const { keyPair: kp } = await staticServerKey();
    const info = buildInfo({
      suiteId: SUITE_ID,
      kid: 'selftest00000000',
      method: 'POST',
      path: '/api/v1/subscription',
      dir: 'req',
    });
    const aad = new TextEncoder().encode('fcp-selftest');
    const msg = new TextEncoder().encode('v8-runtime-selftest');
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, msg);
    const pt = await openFrom(kp.privateKey, enc, info, aad, ct);
    return { ok: new TextDecoder().decode(pt) === 'v8-runtime-selftest', encBytes: enc.length };
  },
});

type RotateResult = { kid: string; notAfter: number } | { skipped: true };

/**
 * Mint one fresh epoch KEM keypair, manifest-sign its public key, and store it
 * (Phase 3). The login request seals to the current epoch key instead of the
 * multi-day static key, so a later key compromise cannot decrypt logins from a
 * swept epoch. Its seed goes only to the volatile service, which expires it
 * when the in-flight grace period ends.
 */
async function rotateEpoch(ctx: ActionCtx): Promise<RotateResult> {
  // Outcome stamp (the start-stamp lives in keyEpochs.maybeRotate): a throw
  // here (e.g. a bad FS_MANIFEST_SK in signManifestHybrid) would otherwise be
  // invisible next to a fresh heartbeat — the rotation would silently stop
  // and manifest-pinned clients would be unable to seal requests.
  try {
    // No manifest key -> HPKE is not configured on this deployment; skip cleanly
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
    const saved = await epochSeedRequest(kid, {
      method: 'PUT',
      body: JSON.stringify({ seed: bytesToB64Url(seed), expiresAt: notAfter + 10 * 60_000 }),
    });
    if (saved.status !== 204) throw new Error('Could not store the private epoch seed');
    await ctx.runMutation(internal.keyEpochs.insert, {
      kid,
      publicKey,
      manifestSig: sig,
      ...(sigPq ? { manifestSigPq: sigPq } : {}),
      notBefore,
      notAfter,
    });
    await ctx.runMutation(internal.keyEpochs.sweepExpired, {});
    await ctx
      .runMutation(internal.cronHeartbeat.stampOutcome, { name: 'epoch-key-rotate', error: null })
      .catch(() => {});
    return { kid, notAfter };
  } catch (err) {
    await ctx
      .runMutation(internal.cronHeartbeat.stampOutcome, {
        name: 'epoch-key-rotate',
        error: err instanceof Error ? err.message : String(err),
      })
      .catch(() => {});
    throw err;
  }
}

/** Mint and publish a new epoch now (operator use; the cron goes through maintainEpoch). */
export const rotateEpochKey = internalAction({
  args: {},
  handler: async (ctx): Promise<RotateResult> => rotateEpoch(ctx),
});

/**
 * Cron (via keyEpochs.maybeRotate) and the key endpoint's re-mint: rotate when
 * there is no epoch the volatile store can open (a store restart), when the
 * live one is revoked, or when it is due (10 min old). One action, no hops.
 */
export const maintainEpoch = internalAction({
  args: {},
  handler: async (ctx): Promise<null> => {
    const [epoch, revoked] = await Promise.all([
      readLiveEpoch(ctx),
      ctx.runQuery(internal.keyRevocations.current, {}),
    ]);
    if (
      !epoch ||
      revoked?.revokedKids.includes(epoch.kid) ||
      epoch.notBefore + 10 * 60_000 <= Date.now()
    ) {
      await rotateEpoch(ctx);
    }
    return null;
  },
});

/** Initialize the volatile store before client traffic and scrub legacy seed fields. */
export const initializeEpochStore = internalAction({
  args: {},
  handler: async (ctx): Promise<null> => {
    await rotateEpoch(ctx);
    let cursor: string | null = null;
    for (;;) {
      const result: { cursor: string; isDone: boolean } = await ctx.runMutation(
        internal.keyEpochs.stripLegacySeeds,
        { cursor },
      );
      if (result.isDone) return null;
      cursor = result.cursor;
    }
  },
});

/**
 * Break-glass: publish a new manifest-signed revoked-kid list (Phase 3c). Bumps
 * the monotonic version, signs the full snapshot, and stores it. Run by an
 * operator when a static or epoch key is believed compromised:
 *   bunx convex run lib/hpkeCrypto:signRevocation '{"revokedKids":["<kid>"]}'
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
