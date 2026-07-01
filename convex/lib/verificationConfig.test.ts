// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { sanitizeHttpsUrl, sanitizeOnion } from './verificationConfig';

/** These gate what the "Verify connection" panel renders as a clickable link, so
 *  a non-https / scheme-injecting value must sanitize to '' (never a live href). */
describe('sanitizeHttpsUrl', () => {
  test('accepts a plain https URL (trimmed)', () => {
    expect(sanitizeHttpsUrl('https://github.com/org/repo/releases')).toBe(
      'https://github.com/org/repo/releases',
    );
    expect(sanitizeHttpsUrl('  https://example.org  ')).toBe('https://example.org');
  });

  test('rejects http, other schemes, junk, and over-long input', () => {
    expect(sanitizeHttpsUrl('http://example.org')).toBe(''); // must be https
    expect(sanitizeHttpsUrl('javascript:alert(1)')).toBe('');
    expect(sanitizeHttpsUrl('data:text/html,x')).toBe('');
    expect(sanitizeHttpsUrl('ftp://example.org')).toBe('');
    expect(sanitizeHttpsUrl('example.org')).toBe('');
    expect(sanitizeHttpsUrl('')).toBe('');
    expect(sanitizeHttpsUrl(42)).toBe('');
    expect(sanitizeHttpsUrl('https://' + 'a'.repeat(600))).toBe('');
  });
});

describe('sanitizeOnion', () => {
  test('accepts a bare .onion host or an http(s) .onion URL', () => {
    expect(sanitizeOnion('abcdefghij234567.onion')).toBe('abcdefghij234567.onion');
    expect(sanitizeOnion('http://sub.abcdef.onion/path')).toBe('http://sub.abcdef.onion/path');
    expect(sanitizeOnion('https://abcdef.onion')).toBe('https://abcdef.onion');
  });

  test('rejects non-onion, scheme-injection, and colons in a bare host', () => {
    expect(sanitizeOnion('example.com')).toBe('');
    expect(sanitizeOnion('javascript:x.onion')).toBe(''); // ':' excluded from bare host
    expect(sanitizeOnion('https://example.com')).toBe(''); // URL host must end in .onion
    expect(sanitizeOnion('')).toBe('');
    expect(sanitizeOnion(null)).toBe('');
  });
});
