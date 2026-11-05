import { describe, expect, test } from 'vitest';
import { exitLocationsFor, MAX_EXIT_LOCATIONS, parseCountryExits } from './countryExits';

describe('parseCountryExits (fail-safe)', () => {
  test('keeps two-letter countries with codes, in order, de-duplicated and capped', () => {
    expect(
      parseCountryExits([
        { country: 'IR', locations: [' loc-b ', 'loc-a', 'loc-b', 'loc-c', 'loc-d'] },
        { country: 'IR', locations: ['loc-z'] },
        { country: 'RU', locations: ['loc-a'] },
      ]),
    ).toEqual([
      { country: 'IR', locations: ['loc-b', 'loc-a', 'loc-c'].slice(0, MAX_EXIT_LOCATIONS) },
      { country: 'RU', locations: ['loc-a'] },
    ]);
  });

  test('drops the opt-out, bad countries, entries without codes and anything not a list', () => {
    expect(
      parseCountryExits([
        { country: 'ZZ', locations: ['loc-a'] },
        { country: 'ir', locations: ['loc-a'] },
        { country: 'IRN', locations: ['loc-a'] },
        { country: 'CN', locations: [] },
        { country: 'CN', locations: ['', 7, '   '] },
        { country: 'TR' },
        null,
        'IR',
      ]),
    ).toEqual([]);
    expect(parseCountryExits(undefined)).toEqual([]);
    expect(parseCountryExits({ IR: ['loc-a'] })).toEqual([]);
  });
});

describe('exitLocationsFor', () => {
  const exits = [{ country: 'IR', locations: ['loc-b', 'loc-a'] }];
  const base = {
    exits,
    steer: true,
    preferredLocation: null,
    choice: 'IR',
    family: 'freedom' as const,
  };

  test("a freedom key of a member on Automatic who chose a country: that country's locations", () => {
    expect(exitLocationsFor(base)).toEqual(['loc-b', 'loc-a']);
  });

  test('nothing otherwise: a location pick, steering off, another family, no choice, the opt-out, no entry', () => {
    expect(exitLocationsFor({ ...base, preferredLocation: 'loc-c' })).toEqual([]);
    expect(exitLocationsFor({ ...base, steer: false })).toEqual([]);
    expect(exitLocationsFor({ ...base, family: 'privacy' })).toEqual([]);
    expect(exitLocationsFor({ ...base, family: 'none' })).toEqual([]);
    expect(exitLocationsFor({ ...base, choice: null })).toEqual([]);
    expect(exitLocationsFor({ ...base, choice: 'ZZ' })).toEqual([]);
    expect(exitLocationsFor({ ...base, choice: 'RU' })).toEqual([]);
  });
});
