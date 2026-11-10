/**
 * Keys by country in words: one country's count, the numbers no country owns,
 * and what the count is not. Plain words, no em-dashes, no key or member.
 */
import { describe, expect, test } from 'vitest';
import { KEYS_SCOPE, keysLine, keysNotes } from './keyWords';

const NOW = Date.UTC(2026, 10, 10, 12);

describe("one country's keys", () => {
  test('says how many, and how each was set', () => {
    expect(keysLine({ answered: 1180, guessed: 32 }, true)).toBe(
      "1,212 keys are set to it: 1,180 by the member's own answer, 32 by FCP's guess.",
    );
    expect(keysLine({ answered: 3, guessed: 0 }, true)).toBe(
      "3 keys are set to it, by the member's own answer.",
    );
    expect(keysLine({ answered: 0, guessed: 1 }, true)).toBe("1 key is set to it, by FCP's guess.");
    expect(keysLine({ answered: 0, guessed: 0 }, true)).toBe('No key is set to it.');
    expect(keysLine({ answered: 2, guessed: 1 }, true, 'this country')).toBe(
      "3 keys are set to this country: 2 by the member's own answer, 1 by FCP's guess.",
    );
  });

  test('says nothing before the first count: zero would read as "nobody"', () => {
    expect(keysLine({ answered: 0, guessed: 0 }, false)).toBeNull();
  });
});

describe('the numbers no country owns', () => {
  const totals = {
    counted: true,
    countedAt: NOW - 3 * 3_600_000,
    optOut: 40,
    neither: 20150,
    otherGuessed: 0,
  };

  test('the opt-out, the keys with neither, and what is not counted', () => {
    expect(keysNotes(totals, NOW)).toEqual([
      '40 keys have the opt-out: the member chose not to give a country.',
      '20,150 keys of freedom modes have no answer and no guess. That number is counted once a day (last 3 h ago). The numbers per country move as members answer.',
      KEYS_SCOPE,
    ]);
    expect(KEYS_SCOPE).toMatch(/privacy mode carries no country/);
    expect(KEYS_SCOPE).toMatch(/never answered and was never guessed is counted for no country/);
  });

  test('guesses of countries off the list are said only when there are some', () => {
    expect(keysNotes({ ...totals, otherGuessed: 7 }, NOW)[2]).toBe(
      '7 keys are guessed in a country that is not on this list.',
    );
    expect(keysNotes({ ...totals, optOut: 1, neither: 1, otherGuessed: 1 }, NOW)).toEqual([
      '1 key has the opt-out: the member chose not to give a country.',
      '1 key of freedom modes has no answer and no guess. That number is counted once a day (last 3 h ago). The numbers per country move as members answer.',
      '1 key is guessed in a country that is not on this list.',
      KEYS_SCOPE,
    ]);
  });

  test('before the first count it says so, and still says what is not counted', () => {
    expect(
      keysNotes({ counted: false, countedAt: null, optOut: 0, neither: 0, otherGuessed: 0 }, NOW),
    ).toEqual([
      'Keys by country are not counted yet. The first count runs a few minutes after an update.',
      KEYS_SCOPE,
    ]);
  });

  test('plain words: no em-dash, no code, nothing about a member or a key by name', () => {
    for (const line of [
      ...keysNotes(totals, NOW),
      ...keysNotes({ ...totals, otherGuessed: 2 }, NOW),
      keysLine({ answered: 5, guessed: 5 }, true)!,
    ])
      expect(line).not.toMatch(/—|sniRegion|regionSeen|support ID|ZZ|protected/);
  });
});
