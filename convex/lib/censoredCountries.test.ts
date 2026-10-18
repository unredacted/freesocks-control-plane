import { describe, expect, test } from 'vitest';
import {
  DEFAULT_CENSORED_COUNTRIES,
  MAX_CENSORED_COUNTRIES,
  censoredCountriesDiff,
  describeCensoredCountries,
  legacyUnion,
  sanitizeCensoredCountries,
  validateCensoredCountries,
} from './censoredCountries';

const entry = (code: string, checkEdges = false, checkNamesInside = false) => ({
  code,
  checkEdges,
  checkNamesInside,
});

describe('legacyUnion', () => {
  test('an install that never set the old keys gets the union of their defaults', () => {
    expect(DEFAULT_CENSORED_COUNTRIES.codes).toEqual([
      'CN',
      'RU',
      'IR',
      'MM',
      'TR',
      'AE',
      'KZ',
      'BY',
    ]);
    // Probe countries keep their probing; MM was curated but never probed.
    expect(DEFAULT_CENSORED_COUNTRIES.edgeChecks).toEqual([
      'CN',
      'RU',
      'IR',
      'TR',
      'AE',
      'KZ',
      'BY',
    ]);
    // Nothing was opted in to checks from inside.
    expect(DEFAULT_CENSORED_COUNTRIES.namesInside).toEqual([]);
  });

  test('orders curated, probe, vantage, privacy, matrix rows; flags follow the old lists', () => {
    const list = legacyUnion({
      curated: ['ir', 'RU'],
      probe: ['TR', 'IR'],
      vantage: ['IR', 'DE'],
      privacy: ['EG'],
      matrix: { rows: [{ countryCode: 'cn' }, { countryCode: 'IR' }, { countryCode: 'bad' }] },
    });
    expect(list).toEqual([
      entry('IR', true, true),
      entry('RU'),
      entry('TR', true),
      // A vantage country that was not curated was never checked: listed, not opted in.
      entry('DE'),
      entry('EG'),
      entry('CN'),
    ]);
  });

  test('an explicitly empty old list stays empty instead of taking its default', () => {
    expect(legacyUnion({ curated: [], probe: [] })).toEqual([]);
  });

  test('reserved and malformed codes are dropped; the union is never truncated', () => {
    expect(legacyUnion({ curated: ['XX', 'ZZ', 'usa', 7, 'IR'], probe: [] })).toEqual([
      entry('IR'),
    ]);
    const many = Array.from({ length: 60 }, (_, i) =>
      String.fromCharCode(65 + Math.floor(i / 26), 65 + (i % 26)),
    );
    // The old lists could together exceed the cap: nothing is dropped (the seed
    // refuses to copy such a union instead).
    expect(legacyUnion({ curated: many.slice(0, 32), probe: many.slice(20) })).toHaveLength(60);
  });
});

describe('sanitizeCensoredCountries / describeCensoredCountries', () => {
  test('drops bad entries, keeps the first of a repeated code, defaults flags to off', () => {
    expect(
      sanitizeCensoredCountries([
        { code: 'ir', checkEdges: true },
        { code: 'IR', checkNamesInside: true },
        { code: 'XX' },
        'RU',
        { code: 'ru', checkNamesInside: 'yes' },
      ]),
    ).toEqual([entry('IR', true), entry('RU')]);
    expect(sanitizeCensoredCountries({})).toBeNull();
    expect(sanitizeCensoredCountries([])).toEqual([]);
  });

  test('derives the code lists in list order', () => {
    const c = describeCensoredCountries(
      [entry('RU', true), entry('IR', false, true), entry('CN', true, true)],
      'stored',
    );
    expect(c.codes).toEqual(['RU', 'IR', 'CN']);
    expect(c.edgeChecks).toEqual(['RU', 'CN']);
    expect(c.namesInside).toEqual(['IR', 'CN']);
  });
});

describe('validateCensoredCountries', () => {
  test('accepts a clean list', () => {
    expect(validateCensoredCountries([{ code: 'ir', checkEdges: true }])).toEqual({
      ok: true,
      list: [entry('IR', true)],
    });
    expect(validateCensoredCountries([])).toEqual({ ok: true, list: [] });
  });

  test('refuses what the read side would silently drop', () => {
    expect(validateCensoredCountries('IR')).toMatchObject({ ok: false });
    expect(validateCensoredCountries([{ code: 'IRN' }])).toMatchObject({ ok: false });
    expect(validateCensoredCountries([{ code: 'ZZ' }])).toMatchObject({ ok: false });
    expect(validateCensoredCountries([{ code: 'IR' }, { code: 'ir' }])).toEqual({
      ok: false,
      message: 'IR is listed twice',
    });
    // A flag given as anything but a boolean would read as off: refused.
    expect(validateCensoredCountries([{ code: 'IR', checkEdges: 'true' }])).toEqual({
      ok: false,
      message: 'IR: checkEdges must be true or false',
    });
    expect(validateCensoredCountries([{ code: 'IR', checkNamesInside: 1 }])).toMatchObject({
      ok: false,
    });
    // A flag left out is off.
    expect(validateCensoredCountries([{ code: 'IR', checkEdges: true }])).toEqual({
      ok: true,
      list: [entry('IR', true)],
    });
    const tooMany = Array.from({ length: MAX_CENSORED_COUNTRIES + 1 }, (_, i) => ({
      code: String.fromCharCode(65 + Math.floor(i / 26), 65 + (i % 26)),
    }));
    expect(validateCensoredCountries(tooMany)).toMatchObject({ ok: false });
  });
});

describe('censoredCountriesDiff', () => {
  test('names what was added, removed and re-flagged', () => {
    expect(
      censoredCountriesDiff(
        [entry('IR', true), entry('RU', true), entry('CN')],
        [entry('IR', true), entry('CN', true), entry('TR')],
      ),
    ).toEqual({ added: ['TR'], removed: ['RU'], flagsChanged: ['CN'] });
  });
});
