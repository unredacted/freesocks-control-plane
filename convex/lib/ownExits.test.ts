import { describe, expect, test } from 'vitest';
import { buildOwnExits, isOwnExit, normalizeCidr } from './ownExits';

describe('own exits', () => {
  const exits = buildOwnExits(
    [
      '192.0.2.10',
      '[2001:db8:0:1::5]',
      '2001:db8:0:2:0:0:0:9',
      'node.example.org',
      null,
      7,
      '198.51.100.20',
    ],
    ['203.0.113.0/24', '2001:db8:aa::/48', 'nonsense', '192.0.2.0/4'],
  );

  test('keeps IP literals only; IPv6 by its /64; drops malformed ranges', () => {
    expect(exits).toEqual({
      v4: ['192.0.2.10', '198.51.100.20'],
      v6Prefixes: ['2001:db8:0:1', '2001:db8:0:2'],
      cidrs: ['2001:db8:aa:0:0:0:0:0/48', '203.0.113.0/24'],
    });
  });

  test('matches v4 exactly, v6 within the /64, and the ranges', () => {
    expect(isOwnExit('192.0.2.10', exits)).toBe(true);
    expect(isOwnExit('192.0.2.11', exits)).toBe(false);
    expect(isOwnExit('2001:db8:0:1:ffff::1', exits)).toBe(true);
    expect(isOwnExit('2001:0db8:0000:0002::abcd', exits)).toBe(true);
    expect(isOwnExit('2001:db8:0:3::1', exits)).toBe(false);
    expect(isOwnExit('203.0.113.200', exits)).toBe(true);
    expect(isOwnExit('203.0.114.1', exits)).toBe(false);
    expect(isOwnExit('2001:db8:aa:ffff::1', exits)).toBe(true);
    expect(isOwnExit('2001:db8:ab::1', exits)).toBe(false);
    expect(isOwnExit(null, exits)).toBe(false);
    expect(isOwnExit('not-an-ip', exits)).toBe(false);
  });

  test('normalizes ranges, a bare address being a single host', () => {
    expect(normalizeCidr('198.51.100.7')).toBe('198.51.100.7/32');
    expect(normalizeCidr('2001:db8::/32')).toBe('2001:db8:0:0:0:0:0:0/32');
    expect(normalizeCidr('2001:db8::/8')).toBeNull();
    expect(normalizeCidr('192.0.2.0/33')).toBeNull();
    // An embedded IPv4 tail is read as its two hextets.
    expect(isOwnExit('::ffff:192.0.2.10', buildOwnExits([], ['::ffff:192.0.2.0/120']))).toBe(true);
  });
});
