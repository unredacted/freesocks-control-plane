import { describe, expect, test } from 'vitest';
import {
  outsideCheckFor,
  partialRungFor,
  shapeProtocolFor,
  type RungProbeRun,
  type RungReachabilityRow,
} from './verifyRung';

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

/** A run of any source over one family. */
const runOf = (
  source: string,
  family: 4 | 6,
  status: RungProbeRun['status'],
  results: Array<{ ok: boolean }> = [],
  requestedAt = 10,
): RungProbeRun => ({
  source,
  status,
  probeProtocol: source === 'internal' ? 'tls-sni' : 'tcp',
  results,
  requestedAt,
  ipVersion: family,
  addressKind: 'ip',
  port: 443,
});

const row = (
  country: string,
  source: string,
  family: 4 | 6,
  verdict: RungReachabilityRow['verdict'],
  okCount = verdict === 'unreachable' ? 0 : 1,
): RungReachabilityRow => ({
  country,
  source,
  verdict,
  ipVersion: family,
  addressKind: 'ip',
  port: 443,
  okCount,
});

/** What stage 4 passes once its own round (requested at 10) is in. */
const check = (
  probeRuns: RungProbeRun[],
  extra: Partial<Parameters<typeof outsideCheckFor>[1]> = {},
) =>
  outsideCheckFor(reality, {
    families: [4, 6],
    providerHealthy: true,
    reachability: [],
    probeRuns,
    agreementVantages: 2,
    roundSince: 10,
    ...extra,
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

  test('a shape run that could not test (failed, timed out, no results) is no refusal', () => {
    const base = {
      providerHealthy: true,
      reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
      agreementVantages: 2,
    };
    for (const status of ['failed', 'timeout'] as const)
      expect(
        partialRungFor(reality, {
          ...base,
          probeRuns: [
            shape('tls-sni', true, 1),
            { ...shape('tls-sni', true, 2), status, results: [] },
          ],
        }),
      ).toBe('partial');
    expect(
      partialRungFor(reality, {
        ...base,
        probeRuns: [{ ...shape('tls-sni', true), results: [] }],
      }),
    ).toBe('pending');
  });

  test('the shape check is read per family: a v6 run never hides or stands in for v4', () => {
    const v4 = { ...shape('tls-sni', true, 1), ipVersion: 4 as const };
    const v6Fails = { ...shape('tls-sni', false, 2), ipVersion: 6 as const };
    const base = {
      providerHealthy: true,
      reachability: [reachable('DE', 'globalping'), reachable('NL', 'checkhost')],
      agreementVantages: 2,
    };
    // A real refusal over IPv6 is a refusal, newest or not.
    expect(
      partialRungFor(reality, { ...base, probeRuns: [{ ...v6Fails, requestedAt: 0 }, v4] }),
    ).toBe('unreachable');
    // An IPv6 run that could not test (no route on FCP's host) is nothing.
    expect(
      partialRungFor(reality, {
        ...base,
        probeRuns: [v4, { ...v6Fails, status: 'failed', results: [] }],
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

describe('outsideCheckFor (a guided run, stage 4)', () => {
  test('the beta mix: reached on IPv4 by FCP itself, nothing could test IPv6, so it passes with IPv6 not checked', () => {
    const r = check([
      // FCP's own probe reached it over IPv4, twice.
      runOf('internal', 4, 'finished', [{ ok: true }], 10),
      runOf('internal', 4, 'finished', [{ ok: true }], 20),
      // FCP's host has no IPv6 route: the run failed `no_route`.
      runOf('internal', 6, 'failed', [], 10),
      runOf('internal', 6, 'failed', [], 20),
      // check-host's job timed out over IPv4 (and takes no IPv6 literal at all).
      runOf('checkhost', 4, 'timeout', [], 10),
      // Globalping refused the request, both families.
      runOf('globalping', 4, 'failed', [], 10),
      runOf('globalping', 6, 'failed', [], 10),
    ]);
    expect(r).toEqual({
      verdict: 'passed',
      families: [
        { family: 4, check: 'reached' },
        { family: 6, check: 'unknown' },
      ],
      notChecked: [6],
    });
  });

  test('a family no source could test is unknown, never unreachable, even alone', () => {
    const r = check(
      [
        runOf('internal', 4, 'failed', [], 10),
        runOf('globalping', 4, 'failed', [], 10),
        runOf('checkhost', 4, 'timeout', [], 10),
      ],
      { families: [4] },
    );
    // The operator's own test link (stage 4b) still comes before anything is published.
    expect(r).toMatchObject({ verdict: 'passed', notChecked: [4] });
  });

  test('reached by one source and refused by none passes, whatever the others could not do', () => {
    const r = check([runOf('checkhost', 4, 'timeout', [], 10)], {
      families: [4],
      reachability: [row('DE', 'checkhost', 4, 'unknown', 1)],
    });
    expect(r).toMatchObject({ verdict: 'passed', notChecked: [] });
  });

  test('only real evidence about the address makes it unreachable', () => {
    // Outside vantages that can test the family agreed it is unreachable.
    expect(
      check([runOf('internal', 4, 'finished', [{ ok: true }], 10)], {
        families: [4],
        reachability: [row('IR', 'globalping', 4, 'unreachable')],
      }).verdict,
    ).toBe('unreachable');
    // FCP's own shape check was refused (ECONNREFUSED, a timeout, a bad handshake).
    expect(
      check([runOf('internal', 4, 'finished', [{ ok: false }], 10)], { families: [4] }).verdict,
    ).toBe('unreachable');
    // A real refusal over IPv6 next to a reach over IPv4: members on IPv6 would fail.
    expect(
      check([
        runOf('internal', 4, 'finished', [{ ok: true }], 10),
        runOf('internal', 6, 'finished', [{ ok: false }], 10),
      ]),
    ).toMatchObject({
      verdict: 'unreachable',
      families: [
        { family: 4, check: 'reached' },
        { family: 6, check: 'refused' },
      ],
    });
  });

  test('a family waits for its own round in flight, until the wait is over', () => {
    const runs = [
      runOf('internal', 4, 'finished', [{ ok: true }], 10),
      runOf('globalping', 4, 'running', [], 10),
    ];
    expect(check(runs, { families: [4] }).verdict).toBe('pending');
    // A run of an earlier round still in flight is not this round's.
    expect(
      check([runs[0]!, runOf('globalping', 4, 'running', [], 5)], { families: [4] }).verdict,
    ).toBe('passed');
    expect(check(runs, { families: [4], final: true }).verdict).toBe('passed');
  });

  test("before its own round only the rung's strong evidence passes (a reused spare)", () => {
    const before = { roundSince: undefined, families: [4] as Array<4 | 6> };
    expect(check([runOf('internal', 4, 'finished', [{ ok: true }], 1)], before).verdict).toBe(
      'pending',
    );
    expect(
      check([runOf('internal', 4, 'finished', [{ ok: true }], 1)], {
        ...before,
        reachability: [
          row('DE', 'globalping', 4, 'reachable'),
          row('NL', 'checkhost', 4, 'reachable'),
        ],
      }).verdict,
    ).toBe('passed');
    // A refusal on record answers at once.
    expect(
      check([], { ...before, reachability: [row('IR', 'globalping', 4, 'unreachable')] }).verdict,
    ).toBe('unreachable');
  });

  test("the provider's own health still holds it; an address with no family never passes", () => {
    const runs = [runOf('internal', 4, 'finished', [{ ok: true }], 10)];
    expect(check(runs, { families: [4], providerHealthy: false }).verdict).toBe('pending');
    expect(check(runs, { families: [], final: true }).verdict).toBe('pending');
  });
});
