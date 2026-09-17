import { describe, expect, test } from 'vitest';
import {
  addressFamily,
  bracketIfV6,
  hostPort,
  isIpv4Literal,
  isIpv6Literal,
  isPublicIpLiteral,
  publishAddressOf,
  hasPublishableAddress,
} from './ip';

describe('ip helpers', () => {
  test('families', () => {
    expect(isIpv4Literal('203.0.113.5')).toBe(true);
    expect(isIpv4Literal('256.0.0.1')).toBe(false);
    expect(isIpv4Literal('01.2.3.4')).toBe(false);
    expect(isIpv6Literal('2001:db8::5')).toBe(true);
    expect(isIpv6Literal('[2001:db8::5]')).toBe(true);
    expect(isIpv6Literal('2001:db8:::5')).toBe(false);
    expect(isIpv6Literal('example.com')).toBe(false);
    expect(addressFamily('203.0.113.5')).toBe('v4');
    expect(addressFamily('2001:db8::5')).toBe('v6');
    expect(addressFamily('edge.example')).toBeNull();
  });

  test('public literal rejects private/special ranges', () => {
    for (const bad of [
      '10.0.0.1',
      '127.0.0.1',
      '192.168.1.1',
      '172.16.0.1',
      '169.254.1.1',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '198.18.0.1',
      '::1',
      '::',
      'fe80::1',
      'fd00::1',
      'ff02::1',
      '::ffff:203.0.113.5',
      'not-an-ip',
    ]) {
      expect(isPublicIpLiteral(bad), bad).toBe(false);
    }
    for (const ok of ['203.0.113.5', '8.8.8.8', '2001:db8::5', '2a00:1450::1']) {
      expect(isPublicIpLiteral(ok), ok).toBe(true);
    }
  });

  test('bracketing', () => {
    expect(bracketIfV6('2001:db8::5')).toBe('[2001:db8::5]');
    expect(bracketIfV6('[2001:db8::5]')).toBe('[2001:db8::5]');
    expect(bracketIfV6('203.0.113.5')).toBe('203.0.113.5');
    expect(hostPort('2001:db8::5', 443)).toBe('[2001:db8::5]:443');
  });
});

describe('publishAddressOf', () => {
  test('an L7 edge publishes its hostname and never an IP literal of its own', () => {
    const l7 = { layer: 'l7' as const, addresses: { hostname: 'cdn.example', v4: '198.51.100.1' } };
    expect(publishAddressOf(l7)).toBe('cdn.example');
    expect(hasPublishableAddress({ layer: 'l7', addresses: { v4: '198.51.100.1' } })).toBe(false);
  });

  test('an L4 edge publishes its IPv4; a missing layer means L4 (legacy rows)', () => {
    expect(publishAddressOf({ addresses: { v4: '198.51.100.1' } })).toBe('198.51.100.1');
    expect(publishAddressOf({ layer: 'l4', addresses: { v6: '2001:db8::1' } })).toBeNull();
    expect(hasPublishableAddress({ addresses: {} })).toBe(false);
  });
});
