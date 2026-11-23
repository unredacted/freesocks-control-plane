/// <reference types="vite/client" />
/**
 * Server HPKE in the default V8 runtime (B1): the sealed wrapper opens and seals
 * inline, with no "use node" module and no ctx.runAction hop, and the static key
 * memo and the epoch error paths behave as the threat model says.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import schema from '../schema';
import { internal } from '../_generated/api';
import type { ActionCtx } from '../_generated/server';
import {
  b64UrlToBytes,
  bytesToB64Url,
  kidFromPublicKey,
  type SealedWire,
} from '../../src/shared/crypto/envelope';
import { deserializePublicKey, serializePublicKey } from '../../src/shared/crypto/hpke';
import { clientOpenResponse, clientPrepareRequest } from '../../src/shared/crypto/channel';
import { createSeedStore } from '../../docker/epoch-seed-store.mjs';
import { openSealedRequest, sealRevealResponse, staticServerKey } from './hpkeServer';
import hpkeWrapperSource from './hpke.ts?raw';
import hpkeServerSource from './hpkeServer.ts?raw';
import hpkeCryptoSource from './hpkeCrypto.ts?raw';
import httpSource from '../http.ts?raw';

// Same re-rooting as hpke.test.ts: convex-test resolves function paths from the
// `_generated` key, which Vite rewrites to `./x.ts` for this directory.
const modules = Object.fromEntries(
  Object.entries(import.meta.glob('../**/*.*s')).map(([k, v]) => [
    k.startsWith('./') ? `../lib/${k.slice(2)}` : k,
    v,
  ]),
);

const SEED_A = new Uint8Array(32).fill(7);
const SEED_B = new Uint8Array(32).fill(9);
const TOKEN = 'b'.repeat(64);
const PATH = '/api/v1/auth/account-login';

function queryCtx(t: ReturnType<typeof convexTest>) {
  return { runQuery: t.query.bind(t) } as unknown as Pick<ActionCtx, 'runQuery'>;
}

beforeEach(() => {
  vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SEED_A));
  const store = createSeedStore(TOKEN);
  vi.stubEnv('HPKE_EPOCH_STORE_URL', 'http://epoch-store.test');
  vi.stubEnv('HPKE_EPOCH_STORE_TOKEN', TOKEN);
  vi.stubGlobal('fetch', (url: string, init: RequestInit) => store.fetch(new Request(url, init)));
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** Strip comments so a directive or call named in prose does not count. */
const code = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

describe('the V8 path is pinned', () => {
  test('no server HPKE module is a "use node" module', () => {
    for (const src of [hpkeWrapperSource, hpkeServerSource, hpkeCryptoSource]) {
      expect(code(src)).not.toMatch(/['"]use node['"]/);
    }
  });

  test('the sealed wrapper and the key endpoint make no action hop for crypto', () => {
    expect(code(hpkeWrapperSource)).not.toMatch(/runAction/);
    expect(code(hpkeServerSource)).not.toMatch(/runAction/);
    expect(code(hpkeWrapperSource)).toMatch(/openSealedRequest\(ctx,/);
    expect(code(hpkeWrapperSource)).toMatch(/sealRevealResponse\(/);
    const keysHandler = code(httpSource)
      .split('const hpkeKeysHandler')[1]!
      .split('http.route(')[0]!;
    expect(keysHandler).toMatch(/readLiveEpoch\(ctx\)/);
    expect(keysHandler).not.toMatch(/runAction/);
  });
});

describe('static key memo', () => {
  test('one build per env value; a changed seed rebuilds', async () => {
    const first = staticServerKey();
    expect(staticServerKey()).toBe(first);
    const a = await first;
    vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SEED_B));
    const b = await staticServerKey();
    expect(b.kid).not.toBe(a.kid);
    expect(b.kid).toBe(await kidFromPublicKey(await serializePublicKey(b.keyPair.publicKey)));
  });

  test('fails closed when unset, and a failed build is not kept', async () => {
    vi.stubEnv('FS_SERVER_HPKE_SK', '');
    await expect(staticServerKey()).rejects.toThrow(/FS_SERVER_HPKE_SK must be set/);
    vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(new Uint8Array(31)));
    await expect(staticServerKey()).rejects.toThrow(/32 bytes/);
    // Let the memo's own rejection handler run before the env is fixed.
    await Promise.resolve();
    vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SEED_A));
    await expect(staticServerKey()).resolves.toHaveProperty('kid');
  });
});

describe('inline open / seal', () => {
  async function sealedLogin(serverPubB64: string, kid: string) {
    return clientPrepareRequest({
      serverPub: await deserializePublicKey(b64UrlToBytes(serverPubB64)),
      serverKid: kid,
      method: 'POST',
      path: PATH,
      policy: { request: 'seal', response: 'reveal' },
      bodyObj: { accountId: '3'.repeat(32) },
    });
  }

  test('a sealed request opens and its response seals back to the client ephemeral', async () => {
    const t = convexTest(schema, modules);
    const { keyPair, kid } = await staticServerKey();
    const pk = bytesToB64Url(await serializePublicKey(keyPair.publicKey));
    const prepared = await sealedLogin(pk, kid);
    const opened = await openSealedRequest(queryCtx(t), {
      method: 'POST',
      path: PATH,
      wireBody: prepared.body as SealedWire,
    });
    if ('unavailable' in opened) throw new Error('expected the static key to open');
    const body = opened.plaintext as Record<string, string>;
    expect(body.accountId).toBe('3'.repeat(32));
    const wire = await sealRevealResponse({
      method: 'POST',
      path: PATH,
      respEphPubB64: body.fsRespEph!,
      responseObj: { ok: true },
    });
    expect(
      await clientOpenResponse({
        serverKid: kid,
        method: 'POST',
        path: PATH,
        respEphPriv: prepared.respEphPriv!,
        wire,
      }),
    ).toEqual({ ok: true });
  });

  test('a revoked recipient answers unavailable and is never opened', async () => {
    const t = convexTest(schema, modules);
    const { keyPair, kid } = await staticServerKey();
    await t.mutation(internal.keyRevocations.insert, {
      version: 1,
      revokedKids: [kid],
      notAfter: Date.now() + 60_000,
      manifestSig: 'sig',
    });
    const prepared = await sealedLogin(
      bytesToB64Url(await serializePublicKey(keyPair.publicKey)),
      kid,
    );
    expect(
      await openSealedRequest(queryCtx(t), {
        method: 'POST',
        path: PATH,
        wireBody: prepared.body as SealedWire,
      }),
    ).toEqual({ unavailable: true });
    await expect(
      openSealedRequest(queryCtx(t), {
        method: 'POST',
        path: PATH,
        wireBody: { fsSealed: { v: 1, ct: 'AA' } } as unknown as SealedWire,
      }),
    ).rejects.toThrow(/Unknown HPKE recipient/);
  });

  test('an epoch whose seed is gone, or a store that is down, answers unavailable', async () => {
    const manifestSk = ed25519.keygen().secretKey;
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    await t.action(internal.lib.hpkeCrypto.rotateEpochKey, {});
    const epoch = (await t.query(internal.keyEpochs.current, {}))!;
    const prepared = await sealedLogin(epoch.publicKey, epoch.kid);
    const open = () =>
      openSealedRequest(queryCtx(t), {
        method: 'POST',
        path: PATH,
        wireBody: prepared.body as SealedWire,
      });
    expect(await open()).toHaveProperty('plaintext');
    // Store unreachable: the fetch error (which names the URL) never escapes.
    vi.stubGlobal('fetch', () =>
      Promise.reject(new TypeError('connect refused http://x/v1/seeds')),
    );
    expect(await open()).toEqual({ unavailable: true });
    // Store restarted (empty): no epoch key survives in this module's memory.
    const empty = createSeedStore(TOKEN);
    vi.stubGlobal('fetch', (url: string, init: RequestInit) => empty.fetch(new Request(url, init)));
    expect(await open()).toEqual({ unavailable: true });
  });

  test('a store answer whose seed does not match the kid is refused', async () => {
    const manifestSk = ed25519.keygen().secretKey;
    vi.stubEnv('FS_MANIFEST_SK', bytesToB64Url(manifestSk));
    const t = convexTest(schema, modules);
    await t.action(internal.lib.hpkeCrypto.rotateEpochKey, {});
    const epoch = (await t.query(internal.keyEpochs.current, {}))!;
    const prepared = await sealedLogin(epoch.publicKey, epoch.kid);
    vi.stubGlobal('fetch', async () => Response.json({ seed: bytesToB64Url(SEED_B) }));
    await expect(
      openSealedRequest(queryCtx(t), {
        method: 'POST',
        path: PATH,
        wireBody: prepared.body as SealedWire,
      }),
    ).rejects.toThrow(/does not match the selected recipient/);
  });
});
