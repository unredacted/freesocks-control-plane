import { describe, expect, test } from 'vitest';
import { parseCookies, signValue, verifySignedValue } from './cookies';

const KEY = 'test-cookie-signing-key';

describe('signValue / verifySignedValue', () => {
  test('round-trips a signed value', async () => {
    const signed = await signValue('abc123', KEY);
    expect(signed).toContain('.');
    expect(await verifySignedValue(signed, KEY)).toBe('abc123');
  });

  test('returns null for a tampered signature', async () => {
    const signed = await signValue('abc123', KEY);
    const tampered = signed.slice(0, -1) + (signed.endsWith('a') ? 'b' : 'a');
    expect(await verifySignedValue(tampered, KEY)).toBeNull();
  });

  test('returns null for a tampered value', async () => {
    const signed = await signValue('abc123', KEY);
    const idx = signed.lastIndexOf('.');
    const tampered = 'xyz999' + signed.slice(idx);
    expect(await verifySignedValue(tampered, KEY)).toBeNull();
  });

  test('returns null when the wrong key is used', async () => {
    const signed = await signValue('abc123', KEY);
    expect(await verifySignedValue(signed, 'other-key')).toBeNull();
  });

  test('returns null for a value with no "."', async () => {
    expect(await verifySignedValue('nodorthere', KEY)).toBeNull();
  });

  test('signValue throws when the value contains a "."', async () => {
    await expect(signValue('a.b', KEY)).rejects.toThrow(/must not contain/);
  });
});

describe('parseCookies', () => {
  test('parses a multi-pair header', () => {
    expect(parseCookies('a=1; b=2')).toEqual({ a: '1', b: '2' });
  });

  test('trims whitespace around keys and values', () => {
    expect(parseCookies('  fs_session = abc.def ;  x=y ')).toEqual({
      fs_session: 'abc.def',
      x: 'y',
    });
  });

  test('returns an empty object for null', () => {
    expect(parseCookies(null)).toEqual({});
  });

  test('skips pairs with no "="', () => {
    expect(parseCookies('a=1; garbage; b=2')).toEqual({ a: '1', b: '2' });
  });
});
