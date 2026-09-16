/**
 * Base64 subscription bodies are BYTES, not latin1 text: a remark carrying a
 * non-ASCII label (a country name, an emoji) must survive a decode/encode round
 * trip instead of coming back mangled or throwing.
 */
import { describe, expect, test } from 'vitest';
import { decodeBase64Loose, encodeBase64, looksLikeBase64 } from './base64';

const NON_ASCII = 'vless://u@203.0.113.10:443?type=tcp#FreeSocks Основной 🇺🇸';

describe('base64', () => {
  test('round-trips non-ASCII text (btoa alone would throw on it)', () => {
    const encoded = encodeBase64(NON_ASCII);
    expect(() => btoa(NON_ASCII)).toThrow();
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(decodeBase64Loose(encoded)).toBe(NON_ASCII);
  });

  test('decodes a UTF-8 body as text, not one char per byte', () => {
    const body = ['#Первый', '#Второй'].join('\n');
    const decoded = decodeBase64Loose(encodeBase64(body))!;
    expect(decoded).toBe(body);
    expect(decoded.length).toBe(body.length);
  });

  test('either alphabet, padded or not; non-base64 stays null', () => {
    const plain = 'vless://u@203.0.113.10:443?type=tcp#a';
    const std = encodeBase64(plain);
    const urlSafe = std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeBase64Loose(std)).toBe(plain);
    expect(decodeBase64Loose(urlSafe)).toBe(plain);
    expect(decodeBase64Loose(`${std.slice(0, 8)}\n${std.slice(8)}`)).toBe(plain);
    expect(decodeBase64Loose('vless://u@h:1#x')).toBeNull();
    expect(looksLikeBase64('a')).toBe(false);
  });

  test('a long body encodes without blowing the argument limit', () => {
    const long = `${'a'.repeat(200_000)}é`;
    expect(decodeBase64Loose(encodeBase64(long))).toBe(long);
  });
});
