import { describe, expect, test } from 'vitest';
import { base64UrlEncode, hmacSha256Hex, randomHex, sha256Hex, timingSafeEqual } from './crypto';

describe('sha256Hex', () => {
  test('matches the known SHA-256("abc") vector', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  test('hashes the empty string to the known vector', async () => {
    expect(await sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});

describe('hmacSha256Hex', () => {
  test('is deterministic for the same secret+message', async () => {
    const a = await hmacSha256Hex('secret', 'message');
    const b = await hmacSha256Hex('secret', 'message');
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  test('matches the RFC 4231 test-case-2 HMAC-SHA256 vector', async () => {
    // key = "Jefe", data = "what do ya want for nothing?"
    expect(await hmacSha256Hex('Jefe', 'what do ya want for nothing?')).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  test('differs when the message differs', async () => {
    const a = await hmacSha256Hex('secret', 'message-a');
    const b = await hmacSha256Hex('secret', 'message-b');
    expect(a).not.toBe(b);
  });
});

describe('timingSafeEqual', () => {
  test('true for identical strings', () => {
    expect(timingSafeEqual('abcdef', 'abcdef')).toBe(true);
  });

  test('false for same-length but differing strings', () => {
    expect(timingSafeEqual('abcdef', 'abcdeg')).toBe(false);
  });

  test('false for length mismatch', () => {
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('base64UrlEncode', () => {
  test('produces URL-safe output with no +, / or = padding', () => {
    // 0xFB 0xFF 0xBF normally base64s to "+/+/" with padding; url-safe swaps them.
    const out = base64UrlEncode(new Uint8Array([0xfb, 0xff, 0xbf, 0xff, 0xbe]));
    expect(out).not.toMatch(/[+/=]/);
  });

  test('encodes known bytes correctly', () => {
    // "Man" -> "TWFu" (no padding needed, stays the same url-safe).
    expect(base64UrlEncode(new TextEncoder().encode('Man'))).toBe('TWFu');
  });
});

describe('randomHex', () => {
  test('returns 2 hex chars per byte', () => {
    expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/);
    expect(randomHex(32)).toMatch(/^[0-9a-f]{64}$/);
  });

  test('is non-repeating across calls', () => {
    expect(randomHex(16)).not.toBe(randomHex(16));
  });
});
