import { describe, expect, test } from 'vitest';
import {
  MAX_MEANT_FOR,
  changedCountries,
  cleanMeantFor,
  groupKeyOfLocation,
  meantForBlocked,
} from './meantFor';

describe('cleanMeantFor', () => {
  test('trimmed, upper case, each once, in the order given; listed codes only', () => {
    expect(cleanMeantFor([' ir', 'RU', 'IR', ''], ['IR', 'RU', 'CN'])).toEqual({
      ok: true,
      codes: ['IR', 'RU'],
    });
    expect(cleanMeantFor(['IR', 'TR'], ['IR'])).toEqual({
      ok: false,
      code: 'meant_for_unlisted',
      country: 'TR',
    });
    expect(cleanMeantFor([], ['IR'])).toEqual({ ok: true, codes: [] });
  });

  test(`at most ${MAX_MEANT_FOR} countries`, () => {
    const listed = Array.from({ length: 12 }, (_, i) => `C${i}`);
    expect(cleanMeantFor(listed.slice(0, MAX_MEANT_FOR), listed).ok).toBe(true);
    expect(cleanMeantFor(listed.slice(0, MAX_MEANT_FOR + 1), listed)).toMatchObject({
      ok: false,
      code: 'meant_for_too_many',
    });
  });
});

test('changedCountries: added or removed, each once, sorted', () => {
  expect(changedCountries(['IR', 'RU'], ['RU', 'CN'])).toEqual(['CN', 'IR']);
  expect(changedCountries(['IR'], ['IR'])).toEqual([]);
});

test('a location grades where its addresses do: a CDN zone with every front of its provider', () => {
  expect(groupKeyOfLocation({ provider: 'upcloud', placeKey: 'de-fra1' })).toBe('upcloud:de-fra1');
  expect(groupKeyOfLocation({ provider: 'fastly', placeKey: 'anycast' })).toBe('fastly:global');
});

describe('meantForBlocked', () => {
  test('a mark wins, then the grade, then every address in use blocked there', () => {
    expect(meantForBlocked({ groupMark: 'proven', grade: 'blocked', published: [true] })).toBe(
      false,
    );
    expect(meantForBlocked({ groupMark: 'blocked', grade: null, published: [] })).toBe(true);
    expect(meantForBlocked({ groupMark: null, grade: 'blocked', published: [false] })).toBe(true);
    expect(meantForBlocked({ groupMark: null, grade: 'mixed', published: [true, true] })).toBe(
      true,
    );
    expect(meantForBlocked({ groupMark: null, grade: null, published: [true, false] })).toBe(false);
    // Nothing in use and nothing graded: not known, not blocked.
    expect(meantForBlocked({ groupMark: null, grade: null, published: [] })).toBe(false);
  });
});
