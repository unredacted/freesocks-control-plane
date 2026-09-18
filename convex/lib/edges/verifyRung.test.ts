import { describe, expect, test } from 'vitest';
import { partialRungFor, shapeProtocolFor, type RungProbeRun } from './verifyRung';

const reality = { security: 'reality' as const };
const plain = { security: 'none' as const };

const reachable = (country: string, source: string) => ({
  country,
  source,
  verdict: 'reachable' as const,
});

const shape = (protocol: 'tls-sni' | 'tcp', ok: boolean, requestedAt = 1): RungProbeRun => ({
  source: 'internal',
  status: 'finished',
  probeProtocol: protocol,
  results: [{ ok }],
  requestedAt,
});

describe('shapeProtocolFor', () => {
  test('REALITY and TLS listeners take tls-sni; plaintext takes tcp', () => {
    expect(shapeProtocolFor(reality)).toBe('tls-sni');
    expect(shapeProtocolFor({ security: 'tls' })).toBe('tls-sni');
    expect(shapeProtocolFor(plain)).toBe('tcp');
  });
});

describe('partialRungFor', () => {
  test('partial: provider healthy, enough distinct vantages reachable, shape check passed', () => {
    expect(
      partialRungFor(reality, {
        providerHealthy: true,
        reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
        probeRuns: [shape('tls-sni', true)],
        agreementVantages: 2,
      }),
    ).toBe('partial');
  });

  test('pending until the vantage count, the provider health and the shape run are all there', () => {
    const base = {
      providerHealthy: true,
      reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
      probeRuns: [shape('tls-sni', true)],
      agreementVantages: 2,
    };
    expect(partialRungFor(reality, { ...base, providerHealthy: false })).toBe('pending');
    expect(
      partialRungFor(reality, { ...base, reachability: [reachable('DE', 'globalping')] }),
    ).toBe('pending');
    expect(partialRungFor(reality, { ...base, probeRuns: [] })).toBe('pending');
    // A tcp run is not the shape check a REALITY listener needs.
    expect(partialRungFor(reality, { ...base, probeRuns: [shape('tcp', true)] })).toBe('pending');
    // Only the internal source runs the shape check; XX rows never count as vantages.
    expect(
      partialRungFor(reality, {
        ...base,
        reachability: [reachable('XX', 'internal'), reachable('XX', 'internal')],
      }),
    ).toBe('pending');
  });

  test('unreachable: any outside unreachable verdict, or a failed shape run', () => {
    expect(
      partialRungFor(reality, {
        providerHealthy: true,
        reachability: [
          reachable('DE', 'globalping'),
          { country: 'IR', source: 'globalping', verdict: 'unreachable' },
        ],
        probeRuns: [shape('tls-sni', true)],
        agreementVantages: 2,
      }),
    ).toBe('unreachable');
    expect(
      partialRungFor(reality, {
        providerHealthy: true,
        reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
        probeRuns: [shape('tls-sni', false)],
        agreementVantages: 2,
      }),
    ).toBe('unreachable');
    // The newest shape run wins over an older one.
    expect(
      partialRungFor(reality, {
        providerHealthy: true,
        reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
        probeRuns: [shape('tls-sni', false, 1), shape('tls-sni', true, 2)],
        agreementVantages: 2,
      }),
    ).toBe('partial');
  });

  test('plaintext listeners reach partial on bare tcp (no tls-sni required)', () => {
    expect(
      partialRungFor(plain, {
        providerHealthy: true,
        reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
        probeRuns: [shape('tcp', true)],
        agreementVantages: 2,
      }),
    ).toBe('partial');
  });

  test('camouflage forwarder negative: tls-sni passes, the rung is partial and never verified', () => {
    // A forwarder pointed straight at the camouflage site presents that site's
    // certificate, so the handshake with the listener's SNI succeeds while every
    // real REALITY session would fail. The most this stack can say is `partial`.
    const rung = partialRungFor(reality, {
      providerHealthy: true,
      reachability: [
        reachable('DE', 'globalping'),
        reachable('NL', 'checkhost'),
        reachable('FR', 'ripeatlas'),
      ],
      probeRuns: [shape('tls-sni', true)],
      agreementVantages: 2,
    });
    expect(rung).toBe('partial');
    expect(rung).not.toBe('verified');
  });
});
