/**
 * Country search for CountryPicker (pure apart from Intl).
 *
 * Exports:
 *   countryOptions(locale?)             -> [{ code, name }] sorted by name (English by default: the CMS is English only)
 *   filterCountries(options, query)     code prefix first, then name substring
 */
import { COUNTRY_CODES, countryName } from '../../../../lib/countries';

export interface CountryOption {
  code: string;
  name: string;
}

export function countryOptions(locale = 'en'): CountryOption[] {
  return COUNTRY_CODES.map((code) => ({ code, name: countryName(code, locale) })).sort((a, b) =>
    a.name.localeCompare(b.name, locale),
  );
}

export function filterCountries(options: readonly CountryOption[], query: string): CountryOption[] {
  const q = query.trim().toLowerCase();
  if (q === '') return [...options];
  const byCode = options.filter((o) => o.code.toLowerCase().startsWith(q));
  const byName = options.filter(
    (o) => !o.code.toLowerCase().startsWith(q) && o.name.toLowerCase().includes(q),
  );
  return [...byCode, ...byName];
}
