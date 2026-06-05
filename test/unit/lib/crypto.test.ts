import { describe, expect, it } from 'vitest';
import {
  base64UrlEncode,
  hmacSha256Hex,
  randomHex,
  sha256Hex,
  timingSafeEqual,
  verifyHmacSha256,
} from '../../../src/server/lib/crypto';

describe('crypto', () => {
  it('sha256Hex produces stable output for the same input', async () => {
    const a = await sha256Hex('hello world');
    const b = await sha256Hex('hello world');
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hmacSha256Hex changes when key changes', async () => {
    const a = await hmacSha256Hex('key1', 'msg');
    const b = await hmacSha256Hex('key2', 'msg');
    expect(a).not.toBe(b);
  });

  it('verifyHmacSha256 round trips', async () => {
    const sig = await hmacSha256Hex('secret', 'payload');
    expect(await verifyHmacSha256('secret', 'payload', sig)).toBe(true);
    expect(await verifyHmacSha256('secret', 'payload', 'tampered')).toBe(false);
  });

  it('timingSafeEqual is correct', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'ab')).toBe(false);
  });

  it('randomHex produces hex of expected length', () => {
    expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/);
    expect(randomHex(32)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('base64UrlEncode produces URL-safe output', () => {
    const out = base64UrlEncode(new Uint8Array([1, 2, 3, 4, 5]));
    expect(out).not.toContain('+');
    expect(out).not.toContain('/');
    expect(out).not.toContain('=');
  });
});
