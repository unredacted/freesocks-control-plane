// @vitest-environment node
//
// This module runs in the browser and in the Convex "use node" action, both of
// which have full WebCrypto (including subtle HKDF). It does NOT run in the
// Convex default isolate, so the node vitest environment is the faithful test
// surface. (The isolate gap is a runtime property established in the Phase 0
// spike, not a unit-test concern.)
import { describe, expect, test } from 'vitest';
import { MlKem768 } from 'mlkem';
import {
  bytesToB64Url,
  b64UrlToBytes,
  buildInfo,
  canonicalize,
  decodeEnvelope,
  encodeEnvelope,
  isSealedWire,
  kidFromPublicKey,
  normalizePath,
  SUITE_ID,
} from './envelope';
import {
  deserializePublicKey,
  generateEphemeralKeyPair,
  openFrom,
  sealTo,
  serializePublicKey,
  serverKeyPairFromSeed,
  suite,
} from './hpke';

const te = (s: string) => new TextEncoder().encode(s);
const td = (b: Uint8Array) => new TextDecoder().decode(b);

describe('envelope (pure helpers)', () => {
  test('base64url round-trips arbitrary bytes', () => {
    for (const len of [0, 1, 2, 3, 31, 32, 1120, 1216]) {
      const b = new Uint8Array(len);
      for (let i = 0; i < len; i++) b[i] = (i * 37 + 11) & 0xff;
      expect([...b64UrlToBytes(bytesToB64Url(b))]).toEqual([...b]);
    }
  });

  test('base64url is url-safe and unpadded', () => {
    const s = bytesToB64Url(new Uint8Array([0xff, 0xfe, 0xfd, 0xfc, 0xfb]));
    expect(s).not.toMatch(/[+/=]/);
  });

  test('normalizePath strips trailing slash + query, forces leading slash', () => {
    expect(normalizePath('api/v1/account/')).toBe('/api/v1/account');
    expect(normalizePath('/api/v1/account?x=1')).toBe('/api/v1/account');
    expect(normalizePath('/')).toBe('/');
    expect(normalizePath('')).toBe('/');
  });

  test('canonicalize is stable and order-independent for query', () => {
    const a = canonicalize({
      method: 'get',
      host: 'App.Example.ORG',
      path: '/api/v1/account/',
      query: 'b=2&a=1',
    });
    const b = canonicalize({
      method: 'GET',
      host: 'app.example.org',
      path: '/api/v1/account',
      query: 'a=1&b=2',
    });
    expect(a).toBe(b);
  });

  test('buildInfo changes when any bound field changes', () => {
    const base = {
      suiteId: SUITE_ID,
      kid: 'deadbeef',
      method: 'POST',
      host: 'app.example.org',
      path: '/api/v1/auth/account-login',
    };
    const ref = bytesToB64Url(buildInfo(base));
    expect(bytesToB64Url(buildInfo({ ...base, kid: 'feedface' }))).not.toBe(ref);
    expect(bytesToB64Url(buildInfo({ ...base, path: '/api/v1/subscription' }))).not.toBe(ref);
    expect(bytesToB64Url(buildInfo({ ...base, method: 'GET' }))).not.toBe(ref);
    expect(bytesToB64Url(buildInfo(base))).toBe(ref); // deterministic
  });

  test('envelope encode/decode round-trips + isSealedWire', () => {
    const enc = new Uint8Array([1, 2, 3]);
    const ct = new Uint8Array([4, 5, 6, 7]);
    const w = encodeEnvelope({ suiteId: SUITE_ID, kid: 'deadbeef', enc, ct });
    expect(isSealedWire(w)).toBe(true);
    expect(isSealedWire({ nope: true })).toBe(false);
    const d = decodeEnvelope(w);
    expect([...d.ct]).toEqual([...ct]);
    expect([...d.enc!]).toEqual([...enc]);
    expect(d.kid).toBe('deadbeef');
    expect(d.suiteId).toBe(SUITE_ID);
  });
});

describe('hpke X-Wing (X25519 + ML-KEM-768)', () => {
  const info = buildInfo({
    suiteId: SUITE_ID,
    kid: 'deadbeefdeadbeef',
    method: 'POST',
    host: 'app.example.org',
    path: '/api/v1/subscription',
  });
  const aad = te('aad-v1');

  test('round-trips through sealTo / openFrom', async () => {
    const kp = await generateEphemeralKeyPair();
    const msg = te('the 32-digit account number');
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, msg);
    const pt = await openFrom(kp.privateKey, enc, info, aad, ct);
    expect(td(pt)).toBe('the 32-digit account number');
  });

  test('X-Wing wire sizes: enc 1120, public key 1216', async () => {
    const kp = await generateEphemeralKeyPair();
    const pk = await serializePublicKey(kp.publicKey);
    expect(pk.length).toBe(1216);
    const { enc } = await sealTo(kp.publicKey, info, aad, te('x'));
    expect(enc.length).toBe(1120);
  });

  test('public key serialize / deserialize round-trips and still opens', async () => {
    const kp = await generateEphemeralKeyPair();
    const pkBytes = await serializePublicKey(kp.publicKey);
    const pk2 = await deserializePublicKey(pkBytes);
    const { enc, ct } = await sealTo(pk2, info, aad, te('hello'));
    expect(td(await openFrom(kp.privateKey, enc, info, aad, ct))).toBe('hello');
  });

  test('tampered enc fails Open (implicit rejection surfaces at the AEAD)', async () => {
    const kp = await generateEphemeralKeyPair();
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, te('secret'));
    const bad = enc.slice(0);
    bad[0] = bad[0]! ^ 0xff;
    await expect(openFrom(kp.privateKey, bad, info, aad, ct)).rejects.toThrow();
  });

  test('info mismatch fails Open (context binding)', async () => {
    const kp = await generateEphemeralKeyPair();
    const { enc, ct } = await sealTo(kp.publicKey, info, aad, te('secret'));
    const otherInfo = buildInfo({
      suiteId: SUITE_ID,
      kid: 'deadbeefdeadbeef',
      method: 'POST',
      host: 'app.example.org',
      path: '/api/v1/account', // different path
    });
    await expect(openFrom(kp.privateKey, enc, otherInfo, aad, ct)).rejects.toThrow();
  });

  test('seed-based server keypair is deterministic', async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = (i * 7 + 3) & 0xff;
    const a = await serverKeyPairFromSeed(seed);
    const b = await serverKeyPairFromSeed(seed);
    expect([...(await serializePublicKey(a.publicKey))]).toEqual([
      ...(await serializePublicKey(b.publicKey)),
    ]);
    // and a different seed yields a different public key
    const seed2 = new Uint8Array(32);
    seed2[0] = 0xff;
    const c = await serverKeyPairFromSeed(seed2);
    expect([...(await serializePublicKey(c.publicKey))]).not.toEqual([
      ...(await serializePublicKey(a.publicKey)),
    ]);
  });

  test('kid derives deterministically from the public key', async () => {
    const seed = new Uint8Array(32).fill(9);
    const kp = await serverKeyPairFromSeed(seed);
    const pk = await serializePublicKey(kp.publicKey);
    const kid = await kidFromPublicKey(pk);
    expect(kid).toMatch(/^[0-9a-f]{16}$/);
    expect(await kidFromPublicKey(pk)).toBe(kid);
  });

  test('exporter derives the same response secret on both ends (OHTTP response leg basis)', async () => {
    const kp = await generateEphemeralKeyPair();
    const s = await suite().createSenderContext({
      recipientPublicKey: kp.publicKey,
      info: info as unknown as ArrayBuffer,
    });
    const r = await suite().createRecipientContext({
      recipientKey: kp.privateKey,
      enc: s.enc,
      info: info as unknown as ArrayBuffer,
    });
    const label = te('fcp/response/v1') as unknown as ArrayBuffer;
    const ss = new Uint8Array(await s.export(label, 32));
    const rs = new Uint8Array(await r.export(label, 32));
    expect([...ss]).toEqual([...rs]);
    expect(ss.some((b) => b !== 0)).toBe(true);
  });
});

describe('ML-KEM-768 (FIPS 203) primitive identity', () => {
  test('mlkem MlKem768 encap/decap is self-consistent', async () => {
    const m = new MlKem768();
    const [pk, sk] = await m.generateKeyPair();
    expect(pk.length).toBe(1184); // ML-KEM-768 encapsulation key
    const [ct, ss] = await m.encap(pk);
    expect(ct.length).toBe(1088); // ML-KEM-768 ciphertext
    const ss2 = await m.decap(ct, sk);
    expect([...ss]).toEqual([...ss2]);
  });
});
