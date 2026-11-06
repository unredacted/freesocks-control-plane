import { describe, expect, test } from 'vitest';
import { asksCountry, isAnswer, mirrorCountry, prefillAnswer } from './countryQuestion';

const view = { applies: true, choice: null, options: ['IR', 'RU'] };

describe('asksCountry', () => {
  test('asked only with the switch, sealing, a key (or mode) that holds a country and options', () => {
    expect(asksCountry({ countryQuestion: true, canSeal: true, view })).toBe(true);
    expect(asksCountry({ countryQuestion: false, canSeal: true, view })).toBe(false);
    expect(asksCountry({ countryQuestion: undefined, canSeal: true, view })).toBe(false);
    expect(asksCountry({ countryQuestion: true, canSeal: false, view })).toBe(false);
    expect(asksCountry({ countryQuestion: true, canSeal: true, view: null })).toBe(false);
    expect(
      asksCountry({ countryQuestion: true, canSeal: true, view: { ...view, applies: false } }),
    ).toBe(false);
    expect(
      asksCountry({ countryQuestion: true, canSeal: true, view: { ...view, options: [] } }),
    ).toBe(false);
  });
});

describe('prefillAnswer', () => {
  test('the first listed candidate, else nothing, never the opt-out', () => {
    expect(prefillAnswer(['IR', 'RU'], 'ru', 'IR')).toBe('RU');
    expect(prefillAnswer(['IR', 'RU'], null, 'IR')).toBe('IR');
    expect(prefillAnswer(['IR', 'RU'], 'DE', undefined)).toBe('');
    expect(prefillAnswer(['IR', 'RU'], 'ZZ')).toBe('');
    expect(prefillAnswer([])).toBe('');
  });
});

describe('isAnswer', () => {
  test('a listed country or the opt-out', () => {
    expect(isAnswer('IR', ['IR'])).toBe(true);
    expect(isAnswer('ZZ', ['IR'])).toBe(true);
    expect(isAnswer('', ['IR'])).toBe(false);
    expect(isAnswer('DE', ['IR'])).toBe(false);
  });
});

describe('mirrorCountry', () => {
  test("what a key's mirrors are set up for", () => {
    expect(mirrorCountry({ ...view, choice: 'IR' })).toEqual({ kind: 'country', country: 'IR' });
    expect(mirrorCountry({ ...view, choice: 'ZZ' })).toEqual({ kind: 'none' });
    expect(mirrorCountry({ ...view, choice: null })).toEqual({ kind: 'unset' });
    // A choice that left the list is no answer any more.
    expect(mirrorCountry({ ...view, choice: 'TR' })).toEqual({ kind: 'unset' });
    expect(mirrorCountry(undefined)).toEqual({ kind: 'unset' });
  });
});
