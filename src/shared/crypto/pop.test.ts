// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { b64UrlToBytes, bytesToB64Url } from './envelope';
import {
  buildPopMessage,
  digestB64Url,
  POP_VERSION,
  signP1363,
  verifyP1363,
  type PopMessageParts,
} from './pop';

/** A WebCrypto P-256 session keypair, with the public point exported raw. */
async function sessionKey() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, pubRaw };
}

const baseParts = (over: Partial<PopMessageParts> = {}): PopMessageParts => ({
  method: 'POST',
  path: '/api/v1/account/regenerate',
  sessionToken: 'tok-default',
  bodyHashB64: 'AAAA',
  ts: 1_700_000_000_000,
  nonceB64: bytesToB64Url(new Uint8Array(16).fill(7)),
  ...over,
});

describe('buildPopMessage', () => {
  test('v1 layout: version, method, path, query, host, respEph, sessionToken, bodyHash, ts, nonce', () => {
    const msg = new TextDecoder().decode(
      buildPopMessage(
        baseParts({ query: 'b=2&a=1', host: 'app.example', respEph: 'EPH', sessionToken: 'PST' }),
      ),
    );
    const lines = msg.split('\n');
    expect(lines[0]).toBe('FCP-PoP v1');
    expect(POP_VERSION).toBe('v1');
    expect(lines[1]).toBe('POST');
    expect(lines[2]).toBe('/api/v1/account/regenerate');
    expect(lines[3]).toBe('a=1&b=2'); // canonicalQuery sorts
    expect(lines[4]).toBe('app.example'); // host
    expect(lines[5]).toBe('EPH'); // reveal-leg ephemeral
    expect(lines[6]).toBe('PST'); // per-session token
    expect(lines[7]).toBe('AAAA'); // bodyHash
    expect(lines[8]).toBe('1700000000000');
    expect(lines).toHaveLength(10);
  });

  test('host, respEph, and sessionToken are each bound (changing any changes the message)', () => {
    const base = buildPopMessage(
      baseParts({ host: 'a.example', respEph: 'E1', sessionToken: 'S1' }),
    );
    const diffHost = buildPopMessage(
      baseParts({ host: 'b.example', respEph: 'E1', sessionToken: 'S1' }),
    );
    const diffEph = buildPopMessage(
      baseParts({ host: 'a.example', respEph: 'E2', sessionToken: 'S1' }),
    );
    const diffTok = buildPopMessage(
      baseParts({ host: 'a.example', respEph: 'E1', sessionToken: 'S2' }),
    );
    expect(bytesToB64Url(base)).not.toBe(bytesToB64Url(diffHost)); // host bound
    expect(bytesToB64Url(base)).not.toBe(bytesToB64Url(diffEph)); // respEph bound
    expect(bytesToB64Url(base)).not.toBe(bytesToB64Url(diffTok)); // sessionToken bound
  });

  test('query ordering does not change the message (canonicalized)', () => {
    const a = buildPopMessage(baseParts({ query: 'a=1&b=2' }));
    const b = buildPopMessage(baseParts({ query: 'b=2&a=1' }));
    expect(bytesToB64Url(a)).toBe(bytesToB64Url(b));
  });

  test('a trailing slash on the path is normalized away', () => {
    const a = buildPopMessage(baseParts({ path: '/api/v1/account' }));
    const b = buildPopMessage(baseParts({ path: '/api/v1/account/' }));
    expect(bytesToB64Url(a)).toBe(bytesToB64Url(b));
  });
});

describe('signP1363 / verifyP1363 round-trip (WebCrypto -> noble)', () => {
  test('a real WebCrypto signature verifies under the noble verifier', async () => {
    const { priv, pubRaw } = await sessionKey();
    const msg = buildPopMessage(baseParts());
    const sig = await signP1363(priv, msg);
    expect(sig.length).toBe(64); // P1363, not DER
    expect(verifyP1363(pubRaw, msg, sig)).toBe(true);
  });

  test('high-S signatures verify too (lowS:false): many fresh sigs all pass', async () => {
    // WebCrypto does not enforce low-S, so ~half of signatures are high-S. A
    // default low-S verifier would reject those. Run enough round-trips that a
    // lowS:true regression would almost certainly fail this test.
    const { priv, pubRaw } = await sessionKey();
    for (let i = 0; i < 30; i++) {
      const msg = buildPopMessage(
        baseParts({ nonceB64: bytesToB64Url(new Uint8Array(16).fill(i)) }),
      );
      const sig = await signP1363(priv, msg);
      expect(verifyP1363(pubRaw, msg, sig)).toBe(true);
    }
  });

  test('a tampered message fails', async () => {
    const { priv, pubRaw } = await sessionKey();
    const sig = await signP1363(priv, buildPopMessage(baseParts()));
    const tampered = buildPopMessage(baseParts({ path: '/api/v1/account/account-id/rotate' }));
    expect(verifyP1363(pubRaw, tampered, sig)).toBe(false);
  });

  test('a tampered signature fails', async () => {
    const { priv, pubRaw } = await sessionKey();
    const msg = buildPopMessage(baseParts());
    const sig = await signP1363(priv, msg);
    sig[0] = sig[0]! ^ 0xff;
    expect(verifyP1363(pubRaw, msg, sig)).toBe(false);
  });

  test('a signature from a different key fails', async () => {
    const signer = await sessionKey();
    const stranger = await sessionKey();
    const msg = buildPopMessage(baseParts());
    const sig = await signP1363(signer.priv, msg);
    expect(verifyP1363(stranger.pubRaw, msg, sig)).toBe(false);
  });

  test('a non-64-byte signature is rejected without throwing', () => {
    const bogusPub = new Uint8Array(65).fill(4);
    expect(verifyP1363(bogusPub, new Uint8Array([1, 2, 3]), new Uint8Array(10))).toBe(false);
  });
});

describe('digestB64Url', () => {
  test('matches a base64url SHA-256 of the body bytes and round-trips', async () => {
    const body = new TextEncoder().encode('{"hello":"world"}');
    const d = await digestB64Url(body);
    expect(b64UrlToBytes(d).length).toBe(32);
    expect(await digestB64Url(body)).toBe(d); // deterministic
    const other = await digestB64Url(new TextEncoder().encode('{}'));
    expect(other).not.toBe(d);
  });
});
