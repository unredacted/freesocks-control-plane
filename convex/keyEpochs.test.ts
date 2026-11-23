/// <reference types="vite/client" />
/**
 * CDN-blinding wiring tests (Phase 3/3c): the epoch-key store semantics
 * (validity window + sweep grace = forward secrecy), the monotonic
 * revoked-kid list, and the hpkeCrypto actions end-to-end — epoch rotation
 * produces a manifest-signed key the client can verify, and openRequest
 * round-trips a sealed login against BOTH the static and an epoch key.
 * (The shared primitives — HPKE, channel, manifest — have their own suites
 * under src/shared/crypto; this covers the Convex wiring around them.)
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import schema from './schema';
import { internal } from './_generated/api';
import { b64UrlToBytes, bytesToB64Url, kidFromPublicKey } from '../src/shared/crypto/envelope';
import {
  deserializePublicKey,
  serializePublicKey,
  serverKeyPairFromSeed,
} from '../src/shared/crypto/hpke';
import { clientPrepareRequest } from '../src/shared/crypto/channel';
import { epochStatement, revocationStatement, verifyManifest } from '../src/shared/crypto/manifest';
import { EPOCH_SWEEP_GRACE_MS } from './keyEpochs';
import { createSeedStore } from '../docker/epoch-seed-store.mjs';

const modules = import.meta.glob('./**/*.*s');

const SERVER_SEED = new Uint8Array(32).fill(7);
const manifestSk = ed25519.keygen().secretKey;
const manifestPk = ed25519.getPublicKey(manifestSk);

async function serverIdentity() {
  const kp = await serverKeyPairFromSeed(SERVER_SEED);
  const pkBytes = await serializePublicKey(kp.publicKey);
  return { pkBytes, kid: await kidFromPublicKey(pkBytes) };
}

beforeEach(() => {
  vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SERVER_SEED));
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('keyEpochs store', () => {
  test('current returns only the newest VALID epoch (expired + future excluded)', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    const mk = (kid: string, notBefore: number, notAfter: number) =>
      t.mutation(internal.keyEpochs.insert, {
        kid,
        publicKey: `pk-${kid}`,
        manifestSig: 'sig',
        notBefore,
        notAfter,
      });
    await mk('expired', now - 60_000, now - 1_000); // over
    await mk('future', now + 60_000, now + 120_000); // not yet
    await mk('older-valid', now - 30_000, now + 60_000);
    await mk('newest-valid', now - 10_000, now + 60_000);
    const cur = await t.query(internal.keyEpochs.current, {});
    expect(cur?.kid).toBe('newest-valid');
    expect(cur).not.toHaveProperty('seed');
    expect(await t.query(internal.keyEpochs.byKid, { kid: 'newest-valid' })).toEqual({
      notAfter: now + 60_000,
    });
    expect(await t.query(internal.keyEpochs.byKid, { kid: 'unknown' })).toBeNull();
  });

  test('sweepExpired removes public metadata past validity and grace', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    const mk = (kid: string, notAfter: number) =>
      t.mutation(internal.keyEpochs.insert, {
        kid,
        publicKey: `pk-${kid}`,
        manifestSig: 'sig',
        notBefore: now - 60_000,
        notAfter,
      });
    await mk('sweep-me', now - EPOCH_SWEEP_GRACE_MS - 1_000); // past grace
    await mk('in-grace', now - EPOCH_SWEEP_GRACE_MS + 60_000); // expired but in grace
    await mk('live', now + 60_000);
    const out = await t.mutation(internal.keyEpochs.sweepExpired, {});
    expect(out.removed).toBe(1);
    expect(await t.query(internal.keyEpochs.byKid, { kid: 'sweep-me' })).toBeNull();
    expect(await t.query(internal.keyEpochs.byKid, { kid: 'in-grace' })).not.toBeNull();
    expect(await t.query(internal.keyEpochs.byKid, { kid: 'live' })).not.toBeNull();
  });
});

describe('keyRevocations store', () => {
  test('current returns the HIGHEST version (monotonic anti-rollback anchor)', async () => {
    const t = convexTest(schema, modules);
    const mk = (version: number) =>
      t.mutation(internal.keyRevocations.insert, {
        version,
        revokedKids: [`kid-v${version}`],
        notAfter: Date.now() + 86_400_000,
        manifestSig: 'sig',
      });
    await mk(1);
    await mk(3);
    await expect(mk(2)).rejects.toThrow(/versions must increase/);
    await expect(mk(3)).rejects.toThrow(/versions must increase/);
    const cur = await t.query(internal.keyRevocations.current, {});
    expect(cur?.version).toBe(3);
    expect(cur?.revokedKids).toEqual(['kid-v3']);
  });
});

describe('hpkeCrypto actions (node runtime)', () => {
  const token = 'a'.repeat(64);

  function restartSeedStore() {
    const store = createSeedStore(token);
    vi.stubEnv('HPKE_EPOCH_STORE_URL', 'http://epoch-store.test');
    vi.stubEnv('HPKE_EPOCH_STORE_TOKEN', token);
    vi.stubGlobal('fetch', (url: URL, init: RequestInit) => store.fetch(new Request(url, init)));
  }

  beforeEach(restartSeedStore);

  test('store restart hides the stale epoch until maintenance publishes a live successor', async () => {
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    await t.action(internal.lib.hpkeCrypto.maintainEpoch, {});
    const old = await t.action(internal.lib.hpkeCrypto.liveEpoch, {});
    expect(old).not.toBeNull();
    restartSeedStore();
    expect(await t.action(internal.lib.hpkeCrypto.liveEpoch, {})).toBeNull();
    await t.action(internal.lib.hpkeCrypto.maintainEpoch, {});
    const next = await t.action(internal.lib.hpkeCrypto.liveEpoch, {});
    expect(next).not.toBeNull();
    expect(next?.kid).not.toBe(old?.kid);
  });

  test('initializeEpochStore retires rows from snapshots that contained private seeds', async () => {
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    const legacy = await t.run(async (ctx) => {
      return ctx.db.insert('keyEpochs', {
        kid: 'legacy',
        publicKey: 'legacy-key',
        seed: bytesToB64Url(SERVER_SEED),
        manifestSig: 'signature',
        notBefore: Date.now() - 1000,
        notAfter: Date.now() + 60_000,
      });
    });
    expect(await t.query(internal.keyEpochs.current, {})).toBeNull();
    await t.action(internal.lib.hpkeCrypto.initializeEpochStore, {});
    expect(await t.run((ctx) => ctx.db.get(legacy))).toBeNull();
    expect(await t.query(internal.keyEpochs.current, {})).not.toBeNull();
    const epochs = await t.run((ctx) => ctx.db.query('keyEpochs').collect());
    expect(epochs).toHaveLength(1);
    expect(epochs[0]).not.toHaveProperty('seed');
  });

  test('rotateEpochKey skips cleanly when the manifest key is unset (dark deploy)', async () => {
    const t = convexTest(schema, modules);
    expect(await t.action(internal.lib.hpkeCrypto.rotateEpochKey, {})).toEqual({ skipped: true });
    await t.run(async (ctx) => {
      expect(await ctx.db.query('keyEpochs').collect()).toHaveLength(0);
    });
  });

  test('rotateEpochKey mints a manifest-signed epoch the client can verify', async () => {
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    const before = Date.now();
    const out = await t.action(internal.lib.hpkeCrypto.rotateEpochKey, {});
    if ('skipped' in out) throw new Error('expected a rotation, got skipped');
    expect(out.notAfter).toBeGreaterThanOrEqual(before + 29 * 60_000);
    const cur = await t.query(internal.keyEpochs.current, {});
    expect(cur?.kid).toBe(out.kid);
    // The stored public key matches the kid…
    expect(await kidFromPublicKey(b64UrlToBytes(cur!.publicKey))).toBe(out.kid);
    // …and the manifest signature verifies against the baked public key.
    expect(
      verifyManifest(
        manifestPk,
        epochStatement({ kid: cur!.kid, publicKeyB64: cur!.publicKey, notAfter: cur!.notAfter }),
        b64UrlToBytes(cur!.manifestSig),
      ),
    ).toBe(true);
  });

  test('signRevocation publishes monotonically-versioned, verifiable lists', async () => {
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    const v1 = await t.action(internal.lib.hpkeCrypto.signRevocation, {
      revokedKids: ['kid-a'],
    });
    expect(v1.version).toBe(1);
    const v2 = await t.action(internal.lib.hpkeCrypto.signRevocation, {
      revokedKids: ['kid-a', 'kid-b'],
    });
    expect(v2.version).toBe(2);
    const cur = await t.query(internal.keyRevocations.current, {});
    expect(cur?.version).toBe(2);
    expect(cur?.revokedKids).toEqual(['kid-a', 'kid-b']);
    expect(
      verifyManifest(
        manifestPk,
        revocationStatement({
          version: cur!.version,
          notAfter: cur!.notAfter,
          revokedKids: cur!.revokedKids,
        }),
        b64UrlToBytes(cur!.manifestSig),
      ),
    ).toBe(true);
  });

  test('openRequest round-trips a sealed login against the STATIC key', async () => {
    const t = convexTest(schema, modules);
    const srv = await serverIdentity();
    const prepared = await clientPrepareRequest({
      serverPub: await deserializePublicKey(srv.pkBytes),
      serverKid: srv.kid,
      method: 'POST',
      path: '/api/v1/auth/account-login',
      policy: { request: 'seal', response: 'plain' },
      bodyObj: { accountId: '1'.repeat(32), captchaToken: 'tok' },
    });
    const out = await t.action(internal.lib.hpkeCrypto.openRequest, {
      method: 'POST',
      path: '/api/v1/auth/account-login',
      wireBody: prepared.body,
    });
    if ('unavailable' in out) throw new Error('expected the recipient to be available');
    expect(out.plaintext).toEqual({ accountId: '1'.repeat(32), captchaToken: 'tok' });
  });

  test('openRequest routes an epoch-sealed login to the epoch key', async () => {
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    const rotated = await t.action(internal.lib.hpkeCrypto.rotateEpochKey, {});
    if ('skipped' in rotated) throw new Error('expected a rotation');
    const epoch = (await t.query(internal.keyEpochs.current, {}))!;
    const prepared = await clientPrepareRequest({
      serverPub: await deserializePublicKey(b64UrlToBytes(epoch.publicKey)),
      serverKid: epoch.kid,
      method: 'POST',
      path: '/api/v1/auth/account-login',
      policy: { request: 'seal', response: 'plain' },
      bodyObj: { accountId: '2'.repeat(32), captchaToken: 'tok2' },
    });
    const out = await t.action(internal.lib.hpkeCrypto.openRequest, {
      method: 'POST',
      path: '/api/v1/auth/account-login',
      wireBody: prepared.body,
    });
    if ('unavailable' in out) throw new Error('expected the recipient to be available');
    expect(out.plaintext).toEqual({ accountId: '2'.repeat(32), captchaToken: 'tok2' });
  });
});

describe('requestRemint', () => {
  test('schedules one maintenance run per throttle window, only while signing is on', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.keyEpochs.requestRemint, {});
    expect(await t.run((ctx) => ctx.db.query('appState').collect())).toHaveLength(0);

    vi.stubEnv('FS_MANIFEST_SK', 'set');
    try {
      await t.mutation(internal.keyEpochs.requestRemint, {});
      await t.mutation(internal.keyEpochs.requestRemint, {});
      const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
      expect(scheduled.filter((f) => f.name.includes('maintainEpoch'))).toHaveLength(1);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
