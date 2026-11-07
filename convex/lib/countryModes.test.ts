import { describe, expect, test } from 'vitest';
import { parseCountryModes, preferredModesFor } from './countryModes';

describe('parseCountryModes', () => {
  test('keeps valid rows; trims, de-duplicates and caps the slugs', () => {
    expect(
      parseCountryModes([
        { country: 'IR', modes: [' freedom-xhttp ', 'freedom-reality', 'freedom-xhttp'] },
        { country: 'CN', modes: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] },
      ]),
    ).toEqual([
      { country: 'IR', modes: ['freedom-xhttp', 'freedom-reality'] },
      { country: 'CN', modes: ['a', 'b', 'c', 'd', 'e', 'f'] },
    ]);
  });

  test('drops the opt-out, bad codes, empty lists, repeats and non-lists', () => {
    expect(parseCountryModes('nope')).toEqual([]);
    expect(
      parseCountryModes([
        { country: 'ZZ', modes: ['a'] },
        { country: 'ir', modes: ['a'] },
        { country: 'RU', modes: [] },
        { country: 'RU', modes: [1, ''] },
        { country: 'TR', modes: ['a'] },
        { country: 'TR', modes: ['b'] },
        null,
      ]),
    ).toEqual([{ country: 'TR', modes: ['a'] }]);
  });

  test('preferredModesFor', () => {
    const rows = [{ country: 'IR', modes: ['x'] }];
    expect(preferredModesFor(rows, 'IR')).toEqual(['x']);
    expect(preferredModesFor(rows, 'RU')).toBeNull();
    expect(preferredModesFor(rows, null)).toBeNull();
  });
});
