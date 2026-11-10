/**
 * Which countries an allowlist prefers a name in (docs/edges.md "Names on a
 * country's allowlist"). Example names and ids only.
 */
import { describe, expect, test } from 'vitest';
import { listedCountries, type PreferContext } from './prefer';

const prefer = (lists: Record<string, string>, curated = ['RU', 'IR', 'CN']): PreferContext => ({
  lists: new Map(Object.entries(lists)),
  curated: new Set(curated),
});
const allow = (listId: string, cc: string) => ({ listId, cc, regime: 'allowlist' as const });
const block = (listId: string, cc: string) => ({ listId, cc, regime: 'blocklist' as const });

describe('listedCountries', () => {
  test('nothing is preferred while the switch is off or the name is on no list', () => {
    expect(listedCountries([allow('a', 'RU')], null)).toEqual([]);
    expect(listedCountries(undefined, prefer({ a: 'RU' }))).toEqual([]);
    expect(listedCountries([], prefer({ a: 'RU' }))).toEqual([]);
  });

  test('an allowlist that prefers its names, in its own country', () => {
    expect(listedCountries([allow('a', 'RU')], prefer({ a: 'RU' }))).toEqual(['RU']);
    expect(
      listedCountries(
        [allow('b', 'IR'), allow('a', 'RU'), allow('c', 'RU')],
        prefer({ a: 'RU', b: 'IR' }),
      ),
    ).toEqual(['IR', 'RU']);
  });

  test('a list that does not prefer its names counts for nothing', () => {
    expect(listedCountries([allow('a', 'RU')], prefer({ other: 'RU' }))).toEqual([]);
  });

  test('a block list never prefers, and one for the same country cancels the allowlist', () => {
    expect(listedCountries([block('a', 'RU')], prefer({ a: 'RU' }))).toEqual([]);
    expect(listedCountries([allow('a', 'RU'), block('z', 'RU')], prefer({ a: 'RU' }))).toEqual([]);
    // A block list for another country says nothing about this one.
    expect(listedCountries([allow('a', 'RU'), block('z', 'IR')], prefer({ a: 'RU' }))).toEqual([
      'RU',
    ]);
  });

  test('only a curated country, and only the country the list is for now', () => {
    expect(listedCountries([allow('a', 'TR')], prefer({ a: 'TR' }))).toEqual([]);
    // The stored fact is older than the list's move to another country.
    expect(listedCountries([allow('a', 'RU')], prefer({ a: 'IR' }))).toEqual([]);
  });
});
