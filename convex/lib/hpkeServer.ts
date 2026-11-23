/**
 * Server-side HPKE open/seal for the CDN-blinding channel, in the DEFAULT V8
 * runtime. The sealed `httpAction` wrapper (./hpke.ts) and the key endpoint call
 * these helpers inline: no `ctx.runAction`, so a sealed member request costs no
 * function hop for its crypto, and the wire body, the decrypted plaintext and
 * the keys never cross a function boundary (they were action args and results
 * while this ran in a "use node" action).
 *
 * The isolate gained subtle HKDF upstream (convex-backend #55023, plus the
 * conformance work in #58129); the pinned backend has both, and the Phase 0 gate
 * G1 was re-run in V8 against it (docs/hpke-phase0-spike.md, section 7).
 *
 * Key material:
 * - The STATIC keypair is rebuilt from the FS_SERVER_HPKE_SK seed once per
 *   isolate and memoized, keyed by the exact env value: a changed seed rebuilds,
 *   a missing one fails closed, and a failed build is not kept. It lives as long
 *   as the isolate, in the same trust domain as process.env, which every V8
 *   function can already read.
 * - EPOCH private keys are never memoized. Each epoch-sealed request checks the
 *   revoked-kid list and the epoch's public lifetime, then fetches the seed from
 *   the volatile seed store, so a store expiry or a revocation applies to the
 *   very next request, and no epoch key outlives its store entry here.
 *
 * Never log or return a seed, a key, or a plaintext from this module.
 */
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import { b64UrlToBytes, kidFromPublicKey, type SealedWire } from '../../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../../src/shared/crypto/hpke';
import { serverOpenRequest, serverSealResponse } from '../../src/shared/crypto/channel';

type QueryCtx = Pick<ActionCtx, 'runQuery'>;

/** One request to the volatile epoch seed store (internal network, bearer token). */
export async function epochSeedRequest(kid: string, init: RequestInit): Promise<Response> {
  const baseUrl = process.env.HPKE_EPOCH_STORE_URL;
  const token = process.env.HPKE_EPOCH_STORE_TOKEN;
  if (!baseUrl || !token) throw new Error('The private epoch seed store must be configured');
  return fetch(new URL('/v1/seeds/' + encodeURIComponent(kid), baseUrl).toString(), {
    ...init,
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(2000),
  });
}

/** The static server identity: private key + the kid baked into the bundle. */
export type StaticServerKey = { keyPair: CryptoKeyPair; kid: string };

let staticMemo: { seedB64: string; value: Promise<StaticServerKey> } | null = null;

async function buildStaticKey(seedB64: string): Promise<StaticServerKey> {
  const keyPair = await serverKeyPairFromSeed(b64UrlToBytes(seedB64));
  const kid = await kidFromPublicKey(await serializePublicKey(keyPair.publicKey));
  return { keyPair, kid };
}

/**
 * The static keypair, rebuilt from the env seed at most once per isolate and
 * env value. Fails closed when FS_SERVER_HPKE_SK is unset.
 */
export function staticServerKey(): Promise<StaticServerKey> {
  const seedB64 = process.env.FS_SERVER_HPKE_SK;
  if (!seedB64) {
    staticMemo = null;
    return Promise.reject(
      new Error('FS_SERVER_HPKE_SK must be set (bunx convex env set FS_SERVER_HPKE_SK ...)'),
    );
  }
  let memo = staticMemo;
  if (!memo || memo.seedB64 !== seedB64) {
    const built = { seedB64, value: buildStaticKey(seedB64) };
    staticMemo = memo = built;
    // A failed build (malformed seed) is retried on the next call, never kept.
    built.value.catch(() => {
      if (staticMemo === built) staticMemo = null;
    });
  }
  return memo.value;
}

/** The epoch fields the key endpoint publishes. */
export type PublicEpoch = {
  kid: string;
  publicKey: string;
  manifestSig: string;
  manifestSigPq?: string;
  notBefore: number;
  notAfter: number;
};

/** The current epoch, only if the volatile store can still open it. */
export async function readLiveEpoch(ctx: QueryCtx): Promise<PublicEpoch | null> {
  const epoch = await ctx.runQuery(internal.keyEpochs.current, {});
  if (!epoch) return null;
  try {
    const response = await epochSeedRequest(epoch.kid, { method: 'HEAD' });
    return response.ok ? epoch : null;
  } catch {
    return null;
  }
}

/**
 * Open a sealed request body. The envelope `kid` selects the recipient key: the
 * static key, or an epoch key fetched from the volatile seed store. The kid is
 * also bound into the HPKE `info`, so it must match what the client sealed with.
 *
 * Throws on a missing recipient or a failed open (the wrapper turns a throw
 * into a generic 500). Returns `{ unavailable: true }` for a revoked kid, or
 * when an epoch's seed is gone or the store cannot be reached
 * (503 hpke.key_unavailable, which the client retries with a fresh epoch).
 */
export async function openSealedRequest(
  ctx: QueryCtx,
  opts: { method: string; path: string; wireBody: SealedWire },
): Promise<{ plaintext: unknown } | { unavailable: true }> {
  const envKid = opts.wireBody?.fsSealed?.kid;
  if (!envKid) throw new Error('Unknown HPKE recipient');
  // A tab can still hold an epoch revoked after it cached it. Answer the
  // retryable 503 so the client drops it and refetches (picking up the
  // signed revocation and the replacement epoch); never open the body.
  const revoked = await ctx.runQuery(internal.keyRevocations.current, {});
  if (revoked?.revokedKids.includes(envKid)) return { unavailable: true };
  const { keyPair: staticKeys, kid: staticKid } = await staticServerKey();
  let priv = staticKeys.privateKey;
  if (envKid !== staticKid) {
    const epoch = await ctx.runQuery(internal.keyEpochs.byKid, { kid: envKid });
    if (!epoch) return { unavailable: true };
    // A store error's text names the URL (kid only); never pass it on.
    const response = await epochSeedRequest(envKid, { method: 'GET' }).catch(() => null);
    if (!response?.ok) return { unavailable: true };
    const body = (await response.json()) as { seed?: unknown };
    if (typeof body.seed !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.seed)) {
      throw new Error('HPKE epoch seed unavailable');
    }
    const keys = await serverKeyPairFromSeed(b64UrlToBytes(body.seed));
    if ((await kidFromPublicKey(await serializePublicKey(keys.publicKey))) !== envKid) {
      throw new Error('HPKE epoch seed does not match the selected recipient');
    }
    priv = keys.privateKey;
  }
  const plaintext = await serverOpenRequest({
    serverPriv: priv,
    serverKid: envKid,
    method: opts.method,
    path: opts.path,
    wireBody: opts.wireBody,
  });
  return { plaintext };
}

/** Seal a response to the client's ephemeral public key (the reveal leg). */
export async function sealRevealResponse(opts: {
  method: string;
  path: string;
  respEphPubB64: string;
  responseObj: unknown;
}): Promise<SealedWire> {
  const { kid } = await staticServerKey();
  return serverSealResponse({ serverKid: kid, ...opts });
}
