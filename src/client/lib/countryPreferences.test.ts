import { describe, expect, test } from 'vitest';
import { moved, preferencePatch, preferenceRows, withRow } from './countryPreferences';

describe('country preferences', () => {
  test('one row per country from both settings, mode countries first', () => {
    expect(
      preferenceRows(
        [
          { country: 'CN', modes: ['reality'] },
          { country: 'IR', modes: ['xhttp'] },
        ],
        [
          { country: 'IR', locations: ['loc-a'] },
          { country: 'RU', locations: ['loc-b'] },
        ],
      ),
    ).toEqual([
      { country: 'CN', modes: ['reality'], locations: [] },
      { country: 'IR', modes: ['xhttp'], locations: ['loc-a'] },
      { country: 'RU', modes: [], locations: ['loc-b'] },
    ]);
    expect(preferenceRows(undefined, null)).toEqual([]);
  });

  test('the patch splits the rows back into the two settings, dropping empty lists', () => {
    expect(
      preferencePatch([
        { country: 'CN', modes: ['reality', 'reality'], locations: [] },
        { country: 'RU', modes: [], locations: ['a', 'b', 'c', 'd'] },
      ]),
    ).toEqual({
      'delivery.country.modes': [{ country: 'CN', modes: ['reality'] }],
      'delivery.country.exits': [{ country: 'RU', locations: ['a', 'b', 'c'] }],
    });
  });

  test('withRow replaces in place, adds at the end, removes with null; moved swaps', () => {
    const rows = [
      { country: 'CN', modes: ['a'], locations: [] },
      { country: 'IR', modes: ['b'], locations: [] },
    ];
    expect(withRow(rows, 'CN', { country: 'CN', modes: ['z'], locations: [] })[0]!.modes).toEqual([
      'z',
    ]);
    expect(
      withRow(rows, 'RU', { country: 'RU', modes: ['c'], locations: [] }).at(-1)!.country,
    ).toBe('RU');
    expect(withRow(rows, 'CN', null).map((r) => r.country)).toEqual(['IR']);
    expect(moved(['a', 'b', 'c'], 0, 1)).toEqual(['b', 'a', 'c']);
    expect(moved(['a', 'b'], 0, -1)).toEqual(['a', 'b']);
  });
});
