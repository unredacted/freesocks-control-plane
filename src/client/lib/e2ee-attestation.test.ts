import { describe, expect, test } from 'vitest';
import { classifyAttestation, nextAttestation } from './e2ee-attestation';

describe('classifyAttestation', () => {
  test('a verified epoch is active', () => {
    expect(
      classifyAttestation({ reachable: true, attested: true, epochKid: 'k', notAfter: Date.now() }),
    ).toBe('active');
  });

  test('a manifest-signature failure is the loud warn (the CDN-tamper tell)', () => {
    expect(classifyAttestation({ reachable: true, attested: false, failure: 'signature' })).toBe(
      'warn',
    );
  });

  test('a revoked kid is also loud', () => {
    expect(classifyAttestation({ reachable: true, attested: false, failure: 'revoked' })).toBe(
      'warn',
    );
  });

  // The bug this guards: an expired or absent epoch means the server has no live
  // key (rotation behind, or a cache served us an old response) and the client
  // falls back to the pinned static key. That used to raise the same "don't enter
  // your account number" banner as an actual key swap.
  test('an expired epoch is a quiet operator signal, not a tamper warning', () => {
    expect(classifyAttestation({ reachable: true, attested: false, failure: 'expired' })).toBe(
      'stale',
    );
  });

  test('no published epoch is a quiet operator signal too', () => {
    expect(classifyAttestation({ reachable: true, attested: false, failure: 'absent' })).toBe(
      'stale',
    );
  });

  test('an unreachable endpoint stays quiet (the pinned key is still in use)', () => {
    expect(classifyAttestation({ reachable: false, attested: false })).toBe('unreachable');
  });

  test('a build with no manifest key baked reports unconfigured, not a failure', () => {
    expect(classifyAttestation({ reachable: false, attested: false, configured: false })).toBe(
      'unconfigured',
    );
  });
});

describe('nextAttestation', () => {
  // Re-attesting must not hand a caught CDN an off switch: having been detected, it
  // could otherwise clear the banner by making the next poll inconclusive.
  test('a raised warn survives every inconclusive later verdict', () => {
    for (const later of ['stale', 'unreachable', 'pending'] as const) {
      expect(nextAttestation('warn', later)).toBe('warn');
    }
  });

  test('only a positive attestation clears a warn', () => {
    expect(nextAttestation('warn', 'active')).toBe('active');
  });

  test('a warn still raises from any other state', () => {
    expect(nextAttestation('active', 'warn')).toBe('warn');
    expect(nextAttestation('stale', 'warn')).toBe('warn');
  });

  test('non-warn states track the fresh verdict', () => {
    expect(nextAttestation('active', 'stale')).toBe('stale');
    expect(nextAttestation('unreachable', 'active')).toBe('active');
    expect(nextAttestation('pending', 'unreachable')).toBe('unreachable');
  });
});
