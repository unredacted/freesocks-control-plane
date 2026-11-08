import { describe, expect, test } from 'vitest';
import {
  FRESH_NAME_BLOCKED,
  countriesOfDetail,
  holdFor,
  holdLive,
  withFreshNameHold,
  type AutoReplaceHold,
} from './autoReplaceHolds';

const whole: AutoReplaceHold = { listenerId: 'l1', code: 'replacement_reblocked', at: 1 };
const fresh: AutoReplaceHold = {
  listenerId: 'l1',
  code: FRESH_NAME_BLOCKED,
  at: 1,
  countries: ['IR'],
  until: 1_000,
};

describe('automatic replacement holds (pure)', () => {
  test('a whole-transport hold never ends; a fresh-name one ends at its time', () => {
    expect(holdLive(whole, 10 ** 15)).toBe(true);
    expect(holdLive(fresh, 999)).toBe(true);
    expect(holdLive(fresh, 1_000)).toBe(false);
  });

  test('a fresh-name hold covers a start only when every country it answers to is held', () => {
    expect(holdFor([fresh], 'l1', ['IR'], 10)).toBe(fresh);
    expect(holdFor([fresh], 'l1', ['IR', 'CN'], 10)).toBeNull();
    expect(holdFor([fresh], 'l1', ['CN'], 10)).toBeNull();
    // A reconcile run names no country: never paused by one.
    expect(holdFor([fresh], 'l1', [], 10)).toBeNull();
    // Another transport, or after its end.
    expect(holdFor([fresh], 'l2', ['IR'], 10)).toBeNull();
    expect(holdFor([fresh], 'l1', ['IR'], 1_000)).toBeNull();
  });

  test('a fresh-name hold covers only a replacement that would reuse its provider', () => {
    const cdn = { ...fresh, provider: 'cdn-a' };
    expect(holdFor([cdn], 'l1', ['IR'], 10, 'cdn-a')).toBe(cdn);
    expect(holdFor([cdn], 'l1', ['IR'], 10, 'cdn-b')).toBeNull();
    // Not known which provider: held.
    expect(holdFor([cdn], 'l1', ['IR'], 10, null)).toBe(cdn);
    expect(holdFor([cdn], 'l1', ['IR'], 10)).toBe(cdn);
    // A pause per provider: blocks on two CDNs make two rows.
    const two = withFreshNameHold([cdn], {
      listenerId: 'l1',
      countries: ['IR'],
      provider: 'cdn-b',
      at: 5,
      until: 900,
    });
    expect(two.map((h) => h.provider)).toEqual(['cdn-a', 'cdn-b']);
  });

  test('a whole-transport hold wins, whatever the countries', () => {
    expect(holdFor([fresh, whole], 'l1', ['IR'], 10)).toBe(whole);
    expect(holdFor([whole], 'l1', [], 10)).toBe(whole);
  });

  test('the countries of an outcome detail, deduplicated and sorted', () => {
    expect(countriesOfDetail('IR')).toEqual(['IR']);
    expect(countriesOfDetail('RU, IR,IR')).toEqual(['IR', 'RU']);
    expect(countriesOfDetail('no affected country')).toEqual([]);
    expect(countriesOfDetail(undefined)).toEqual([]);
  });

  test('a second fresh-name block widens the one row; ended rows are dropped', () => {
    const one = withFreshNameHold([whole], {
      listenerId: 'l1',
      countries: ['IR'],
      edgeId: 'e1',
      at: 100,
      until: 500,
    });
    expect(one).toEqual([
      whole,
      {
        listenerId: 'l1',
        code: FRESH_NAME_BLOCKED,
        at: 100,
        edgeId: 'e1',
        countries: ['IR'],
        until: 500,
      },
    ]);
    const two = withFreshNameHold(one, {
      listenerId: 'l1',
      countries: ['RU'],
      at: 200,
      until: 600,
    });
    expect(two).toHaveLength(2);
    expect(two[1]).toMatchObject({ at: 100, countries: ['IR', 'RU'], until: 600 });
    // Ended by the time of the next block: a new row from that time.
    const later = withFreshNameHold(two, {
      listenerId: 'l1',
      countries: ['CN'],
      at: 700,
      until: 900,
    });
    expect(later).toEqual([
      whole,
      expect.objectContaining({ at: 700, countries: ['CN'], until: 900 }),
    ]);
  });
});
