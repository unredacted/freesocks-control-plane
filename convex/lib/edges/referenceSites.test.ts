import { describe, expect, test } from 'vitest';
import { cdnRefusedCountries, cdnRefusesAll, type ReferenceSite } from './referenceSites';

const NOW = 1_000_000;
const STALE = 30 * 60_000;
const site = (
  rows: Array<[string, 'reachable' | 'unreachable' | 'mixed', number?]>,
  referenceFor = 'cdn-a',
  enabled = true,
): ReferenceSite => ({
  referenceFor,
  enabled,
  byCountry: rows.map(([country, verdict, age]) => ({
    country,
    verdict,
    lastAt: NOW - (age ?? 0),
  })),
});

describe('reference sites (pure)', () => {
  test('a country refuses the provider when its site fails there and works elsewhere', () => {
    const s = site([
      ['IR', 'unreachable'],
      ['CN', 'mixed'],
      ['DE', 'reachable'],
    ]);
    expect(cdnRefusedCountries([s], 'cdn-a', ['IR', 'CN'], NOW, STALE)).toEqual(['IR']);
    expect(cdnRefusesAll([s], 'cdn-a', ['IR'], NOW, STALE)).toBe(true);
    expect(cdnRefusesAll([s], 'cdn-a', ['IR', 'IR'], NOW, STALE)).toBe(true);
    expect(cdnRefusesAll([s], 'cdn-a', ['IR', 'CN'], NOW, STALE)).toBe(false);
    expect(cdnRefusesAll([s], 'cdn-a', [], NOW, STALE)).toBe(false);
  });

  test('a site nobody reaches is broken; the unknown-country row is no witness', () => {
    expect(
      cdnRefusedCountries([site([['IR', 'unreachable']])], 'cdn-a', ['IR'], NOW, STALE),
    ).toEqual([]);
    expect(
      cdnRefusedCountries(
        [
          site([
            ['IR', 'unreachable'],
            ['XX', 'reachable'],
          ]),
        ],
        'cdn-a',
        ['IR'],
        NOW,
        STALE,
      ),
    ).toEqual([]);
  });

  test('only fresh rows, enabled sites, and that provider count', () => {
    const stale = site([
      ['IR', 'unreachable', STALE + 1],
      ['DE', 'reachable'],
    ]);
    const staleWitness = site([
      ['IR', 'unreachable'],
      ['DE', 'reachable', STALE + 1],
    ]);
    const off = site(
      [
        ['IR', 'unreachable'],
        ['DE', 'reachable'],
      ],
      'cdn-a',
      false,
    );
    const other = site(
      [
        ['IR', 'unreachable'],
        ['DE', 'reachable'],
      ],
      'cdn-b',
    );
    for (const s of [stale, staleWitness, off, other])
      expect(cdnRefusedCountries([s], 'cdn-a', ['IR'], NOW, STALE)).toEqual([]);
    // Any one site of the provider is enough.
    const good = site([
      ['IR', 'unreachable'],
      ['DE', 'reachable'],
    ]);
    expect(cdnRefusedCountries([stale, good], 'cdn-a', ['IR'], NOW, STALE)).toEqual(['IR']);
  });
});
