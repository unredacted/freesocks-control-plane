import { describe, expect, test } from 'vitest';
import {
  probeScore,
  sustainedBlock,
  sustainedCountries,
  unreachableCountries,
  type SummaryCountry,
} from './verdict';
import { edgeOutage, sustainedCountriesOf } from './sustained';
import { EDGE_DEFAULTS } from '../../edgeConfig';

const MIN = 60_000;
const NOW = 1_800_000_000_000;
const RULE = { checks: 12, networks: 2, minutes: 120 };
const fresh = (c: SummaryCountry) => NOW - c.lastAt <= 30 * MIN;

/** Four hours of failing checks from three networks: the beta case. */
const neverReached = { checks: 42, networks: 3, since: NOW - 4 * 60 * MIN, lastAt: NOW - MIN };

const at = (country: string, verdict: SummaryCountry['verdict'], extra = {}): SummaryCountry => ({
  country,
  verdict,
  lastAt: NOW - MIN,
  ...extra,
});

describe('sustainedBlock (the address on its own)', () => {
  test('unreachable now, never reached, enough checks from enough networks over long enough', () => {
    const c = at('CN', 'unreachable', { wasReachable: false, neverReached });
    expect(sustainedBlock(c, RULE)).toBe(true);
    expect(sustainedBlock({ ...c, verdict: 'unknown' }, RULE)).toBe(false);
    expect(sustainedBlock({ ...c, wasReachable: true }, RULE)).toBe(false);
    expect(sustainedBlock({ ...c, neverReached: undefined }, RULE)).toBe(false);
    expect(sustainedBlock({ ...c, neverReached: { ...neverReached, checks: 11 } }, RULE)).toBe(
      false,
    );
    expect(sustainedBlock({ ...c, neverReached: { ...neverReached, networks: 1 } }, RULE)).toBe(
      false,
    );
    expect(
      sustainedBlock(
        { ...c, neverReached: { ...neverReached, since: neverReached.lastAt - 119 * MIN } },
        RULE,
      ),
    ).toBe(false);
  });
});

describe('sustainedCountries (the address against its node)', () => {
  const listed = ['CN', 'IR', 'RU'];
  const blockedInCn = [
    at('CN', 'unreachable', { wasReachable: false, neverReached }),
    at('IR', 'reachable'),
    at('RU', 'reachable'),
    at('XX', 'reachable'),
  ];
  const sibling = [at('CN', 'reachable'), at('IR', 'reachable'), at('RU', 'reachable')];

  test('never reached from a country while its siblings reach it from there: blocked there', () => {
    expect(sustainedCountries(blockedInCn, [sibling], listed, RULE, fresh)).toEqual(['CN']);
  });

  test('never reached from ANY country is broken, not blocked: nothing counts', () => {
    const everywhere = [
      at('CN', 'unreachable', { wasReachable: false, neverReached }),
      at('IR', 'unreachable', { wasReachable: false, neverReached }),
      at('RU', 'unreachable', { wasReachable: false, neverReached }),
      // FCP's own host reaching it is not a country.
      at('XX', 'reachable'),
    ];
    expect(sustainedCountries(everywhere, [sibling], listed, RULE, fresh)).toEqual([]);
  });

  test('a vantage outage: the node’s other addresses fail from there too, nothing counts', () => {
    const siblingFails = [at('CN', 'unreachable'), at('IR', 'reachable'), at('RU', 'reachable')];
    expect(sustainedCountries(blockedInCn, [siblingFails], listed, RULE, fresh)).toEqual([]);
    // No sibling at all, or one with no fresh word from there, says nothing either.
    expect(sustainedCountries(blockedInCn, [], listed, RULE, fresh)).toEqual([]);
    const stale = [{ ...at('CN', 'reachable'), lastAt: NOW - 31 * MIN }];
    expect(sustainedCountries(blockedInCn, [stale], listed, RULE, fresh)).toEqual([]);
  });

  test('only listed countries, only fresh verdicts', () => {
    expect(sustainedCountries(blockedInCn, [sibling], ['IR', 'RU'], RULE, fresh)).toEqual([]);
    const staleOwn = blockedInCn.map((c) =>
      c.country === 'CN' ? { ...c, lastAt: NOW - 31 * MIN } : c,
    );
    expect(sustainedCountries(staleOwn, [sibling], listed, RULE, fresh)).toEqual([]);
  });

  test('IPv6 never counts: a summary written without the never-reached record is no evidence', () => {
    // probes.ts writes `neverReached` only for the IPv4 (or name) path; an
    // address whose only failing path from CN is IPv6 has none.
    const v6Only = blockedInCn.map((c) =>
      c.country === 'CN' ? at('CN', 'unreachable', { wasReachable: false }) : c,
    );
    expect(sustainedCountries(v6Only, [sibling], listed, RULE, fresh)).toEqual([]);
  });
});

describe('the detector reads it like a transition', () => {
  test('probeScore and unreachableCountries count a sustained country', () => {
    const byCountry = [
      { country: 'CN', verdict: 'unreachable' as const, wasReachable: false, sustained: true },
      { country: 'IR', verdict: 'unreachable' as const, wasReachable: false },
    ];
    expect(probeScore(byCountry, ['CN', 'IR'])).toBe(1);
    expect(unreachableCountries(byCountry)).toEqual(['CN']);
    expect(probeScore(byCountry, ['IR'])).toBe(0);
  });
});

describe('sustainedCountriesOf (stored edges)', () => {
  const cfg = {
    ...EDGE_DEFAULTS,
    probe: { ...EDGE_DEFAULTS.probe, enabled: true, countries: ['CN', 'IR'] },
  };
  const edge = (id: string, byCountry: SummaryCountry[], listenerId = 'l-reality') =>
    ({
      _id: id,
      listenerId,
      reachability: {
        byCountry: byCountry.map((c) => ({ okVantages: 0, failVantages: 0, ...c })),
        updatedAt: NOW,
      },
    }) as never;
  const a = edge('a', [
    at('CN', 'unreachable', { wasReachable: false, neverReached }),
    at('IR', 'reachable'),
  ]);
  const b = edge('b', [at('CN', 'reachable'), at('IR', 'reachable')]);

  test('reads the summaries with the configured rule; ignores the edge itself among its siblings', () => {
    expect(sustainedCountriesOf(a, [a, b], cfg, NOW)).toEqual(['CN']);
    expect(sustainedCountriesOf(a, [a], cfg, NOW)).toEqual([]);
    expect(
      sustainedCountriesOf(a, [b], { ...cfg, probe: { ...cfg.probe, enabled: false } }, NOW),
    ).toEqual([]);
    expect(
      sustainedCountriesOf(a, [b], { ...cfg, detect: { ...cfg.detect, sustainedChecks: 50 } }, NOW),
    ).toEqual([]);
  });

  test('only an address of the SAME listener corroborates: another port or transport proves nothing', () => {
    const otherListener = edge('c', [at('CN', 'reachable'), at('IR', 'reachable')], 'l-ws');
    expect(sustainedCountriesOf(a, [otherListener], cfg, NOW)).toEqual([]);
    expect(sustainedCountriesOf(a, [otherListener, b], cfg, NOW)).toEqual(['CN']);
  });

  test('an outage is the address itself: provider offline, or FCP’s own check failing', () => {
    expect(edgeOutage({ health: 'online', reachability: undefined })).toBe(false);
    expect(edgeOutage({ health: 'offline', reachability: undefined })).toBe(true);
    expect(
      edgeOutage({
        health: 'online',
        reachability: {
          byCountry: [
            { country: 'XX', verdict: 'unreachable', okVantages: 0, failVantages: 1, lastAt: NOW },
          ],
          updatedAt: NOW,
        },
      }),
    ).toBe(true);
  });
});
