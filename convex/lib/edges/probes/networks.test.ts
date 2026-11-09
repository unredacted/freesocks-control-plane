/**
 * The Globalping network setting (pure): the listing counted, how
 * `home_first` fills a short country, and the locations each value asks.
 */
import { describe, expect, test } from 'vitest';
import {
  PROBE_COUNTS_FRESH_MS,
  asksByTag,
  countAllProbes,
  countryLocations,
  freshProbeCounts,
  homeFirstSplit,
} from './networks';

const at = (cc: string, tags: string[]) => ({ location: { country: cc }, tags });

describe('the probe listing', () => {
  test('counted per country; untagged probes count in the total only', () => {
    expect(
      countAllProbes([
        at('IR', ['eyeball-network']),
        at('ir', ['datacenter-network', 'x']),
        at('IR', []),
        at('DE', ['eyeball-network']),
        { location: { country: 'nope' }, tags: ['eyeball-network'] },
      ]),
    ).toEqual({
      IR: { eyeball: 1, datacenter: 1, total: 3 },
      DE: { eyeball: 1, datacenter: 0, total: 1 },
    });
  });
  test('a listing without any network tag, or not a list, counts nothing', () => {
    expect(countAllProbes([at('IR', [])])).toBeNull();
    expect(countAllProbes({})).toBeNull();
  });
  test('kept for an hour', () => {
    const counts = { IR: { eyeball: 1, datacenter: 2, total: 3 } };
    expect(freshProbeCounts({ at: 1000, counts }, 1000 + PROBE_COUNTS_FRESH_MS)).toEqual(counts);
    expect(freshProbeCounts({ at: 1000, counts }, 1001 + PROBE_COUNTS_FRESH_MS)).toBeNull();
    expect(freshProbeCounts({ at: 2000, counts }, 1000)).toBeNull();
    expect(freshProbeCounts(null, 1000)).toBeNull();
    expect(freshProbeCounts({ at: 1000, counts: [] }, 1000)).toBeNull();
  });
});

describe('home networks first', () => {
  test('enough home networks; topped up; too few of both', () => {
    expect(homeFirstSplit({ eyeball: 3, datacenter: 0, total: 3 }, 3, 3)).toEqual({
      mode: 'eyeball',
    });
    expect(homeFirstSplit({ eyeball: 2, datacenter: 1, total: 3 }, 3, 3)).toEqual({
      mode: 'topped_up',
      eyeball: 2,
    });
    expect(homeFirstSplit({ eyeball: 1, datacenter: 1, total: 2 }, 3, 3)).toEqual({ mode: 'any' });
    expect(homeFirstSplit({ eyeball: 0, datacenter: 9, total: 9 }, 3, 3)).toEqual({ mode: 'any' });
    // The floor never passes the limit.
    expect(homeFirstSplit({ eyeball: 2, datacenter: 0, total: 2 }, 2, 3)).toEqual({
      mode: 'eyeball',
    });
  });
});

describe('the locations each setting asks', () => {
  const short = { eyeball: 1, datacenter: 5, total: 6 };
  test('home: the home-network tag only', () => {
    expect(countryLocations('IR', 3, 'home', short)).toEqual([
      { country: 'IR', limit: 3, tags: ['eyeball-network'] },
    ]);
  });
  test('home first: topped up to the same limit; home networks without counts', () => {
    expect(countryLocations('IR', 3, 'home_first', short)).toEqual([
      { country: 'IR', limit: 1, tags: ['eyeball-network'] },
      { country: 'IR', limit: 2, tags: ['datacenter-network'] },
    ]);
    expect(countryLocations('IR', 3, 'home_first', null)).toEqual([
      { country: 'IR', limit: 3, tags: ['eyeball-network'] },
    ]);
  });
  test('any: no tag', () => {
    expect(countryLocations('IR', 3, 'any', short)).toEqual([{ country: 'IR', limit: 3 }]);
  });
  test('whether an ask carries a tag', () => {
    expect(asksByTag({ locations: countryLocations('IR', 3, 'home', null) })).toBe(true);
    expect(asksByTag({ locations: [{ country: 'IR', limit: 3 }] })).toBe(false);
    expect(asksByTag({ locations: 'm-1' })).toBe(false);
  });
});
