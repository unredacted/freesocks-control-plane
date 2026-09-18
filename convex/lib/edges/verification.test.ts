import { describe, expect, test } from 'vitest';
import {
  bindingMatches,
  needsEndpointVerification,
  verificationBinding,
  verificationConfigHash,
  verificationCurrent,
  verificationEndpoint,
  verificationStale,
  type VerificationEdgeLike,
  type VerificationListenerLike,
} from './verification';

const listener: VerificationListenerLike = { listenerKey: 'a', revision: 3, configHash: 'lh1' };

function edge(over: Partial<VerificationEdgeLike> = {}): VerificationEdgeLike {
  return {
    layer: 'l4',
    templateHash: 'th1',
    addresses: { v4: '198.51.100.7' },
    listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
    ...over,
  };
}

describe('verificationEndpoint', () => {
  test('prefers the IPv4 literal with the first edge port, then bracketed IPv6, then the hostname', () => {
    expect(verificationEndpoint(edge())).toBe('198.51.100.7:443');
    expect(verificationEndpoint(edge({ addresses: { v6: '2001:db8::7' } }))).toBe(
      '[2001:db8::7]:443',
    );
    expect(verificationEndpoint(edge({ addresses: { hostname: 'front.example' } }))).toBe(
      'front.example:443',
    );
    expect(verificationEndpoint(edge({ addresses: {} }))).toBeNull();
  });
});

describe('verificationConfigHash', () => {
  test('is deterministic and independent of key order / undefined fields', () => {
    const a = verificationConfigHash({
      listenerConfigHash: 'lh1',
      templateHash: 'th1',
      addresses: { v4: '198.51.100.7', v6: undefined },
      listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
    });
    const b = verificationConfigHash({
      listenerConfigHash: 'lh1',
      templateHash: 'th1',
      addresses: { v4: '198.51.100.7' },
      listeners: [
        { originPort: 443, originAddress: '203.0.113.10', edgePort: 443, transport: 'tcp' },
      ],
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  test('changes with the listener hash, the template, an address or a port', () => {
    const base = verificationBinding(edge(), listener)!.configHash;
    expect(verificationBinding(edge(), { ...listener, configHash: 'lh2' })!.configHash).not.toBe(
      base,
    );
    expect(verificationBinding(edge({ templateHash: 'th2' }), listener)!.configHash).not.toBe(base);
    expect(
      verificationBinding(edge({ addresses: { v4: '198.51.100.8' } }), listener)!.configHash,
    ).not.toBe(base);
    expect(
      verificationBinding(
        edge({ listeners: [{ edgePort: 8443, originAddress: '203.0.113.10', originPort: 443 }] }),
        listener,
      )!.configHash,
    ).not.toBe(base);
  });
});

describe('verificationCurrent', () => {
  const current = () => {
    const b = verificationBinding(edge(), listener)!;
    return {
      rung: 'verified' as const,
      by: 'admin' as const,
      at: 1,
      method: 'test_link' as const,
      ...b,
    };
  };

  test('true only for a verified record against the live revision + hash + endpoint', () => {
    expect(verificationCurrent(edge({ verification: current() }), listener)).toBe(true);
    expect(verificationCurrent(edge(), listener)).toBe(false);
    expect(
      verificationCurrent(edge({ verification: { ...current(), rung: 'partial' } }), listener),
    ).toBe(false);
  });

  test('a listener revision bump, a config change or a re-addressing makes it stale', () => {
    const e = edge({ verification: current() });
    expect(verificationCurrent(e, { ...listener, revision: 4 })).toBe(false);
    expect(verificationStale(e, { ...listener, revision: 4 })).toBe(true);
    expect(verificationCurrent(e, { ...listener, configHash: 'lh9' })).toBe(false);
    expect(verificationCurrent({ ...e, addresses: { v4: '198.51.100.9' } }, listener)).toBe(false);
    // A record was never taken: not stale, just absent.
    expect(verificationStale(edge(), listener)).toBe(false);
  });

  test('bindingMatches compares every field of the echo', () => {
    const b = verificationBinding(edge(), listener)!;
    expect(bindingMatches(b, { ...b })).toBe(true);
    expect(bindingMatches(b, { ...b, listenerRevision: 99 })).toBe(false);
    expect(bindingMatches(b, { ...b, configHash: 'x' })).toBe(false);
    expect(bindingMatches(b, { ...b, endpoint: '198.51.100.8:443' })).toBe(false);
    expect(bindingMatches(null, b)).toBe(false);
  });

  test('L4 edges need the tick; L7 edges are verified by their proof', () => {
    expect(needsEndpointVerification({ layer: 'l4' })).toBe(true);
    expect(needsEndpointVerification({})).toBe(true);
    expect(needsEndpointVerification({ layer: 'l7' })).toBe(false);
  });
});
