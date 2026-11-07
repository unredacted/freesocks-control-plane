/**
 * Suggested connection modes by country (pure; unit-tested). The operator lists,
 * per country, the modes to suggest in order (Admin → Connection modes →
 * Country preferences, the `delivery.country.modes` setting). The picker's
 * "Suggested" mark goes to the first of them the member's backend serves
 * (lib/modeSuggestion.ts); a country without an entry keeps the matrix rule.
 *
 * The list is read only server-side: members get the verdict for their own
 * country (the account view) or for the countries on the sign-up question.
 */
import { ELSEWHERE } from './memberCountry';

export const COUNTRY_MODES_KEY = 'delivery.country.modes';
/** Countries the setting may hold. */
export const MAX_COUNTRY_MODE_COUNTRIES = 64;
/** Modes one country may list. */
export const MAX_MODES_PER_COUNTRY = 6;
const MAX_SLUG_LENGTH = 64;

export interface CountryModes {
  country: string;
  /** Mode slugs, most preferred first. */
  modes: string[];
}

const COUNTRY = /^[A-Z]{2}$/;

/**
 * Fail-safe read of the stored setting: entries with a two-letter country
 * (not the opt-out) and at least one mode slug; the first entry of a country
 * wins, slugs are trimmed and de-duplicated in order, at most
 * MAX_MODES_PER_COUNTRY each. Anything else is dropped.
 */
export function parseCountryModes(raw: unknown): CountryModes[] {
  if (!Array.isArray(raw)) return [];
  const out: CountryModes[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (out.length >= MAX_COUNTRY_MODE_COUNTRIES) break;
    if (!entry || typeof entry !== 'object') continue;
    const { country, modes } = entry as { country?: unknown; modes?: unknown };
    if (typeof country !== 'string' || !COUNTRY.test(country) || country === ELSEWHERE) continue;
    if (seen.has(country) || !Array.isArray(modes)) continue;
    const slugs: string[] = [];
    for (const m of modes) {
      if (typeof m !== 'string') continue;
      const slug = m.trim();
      if (slug.length === 0 || slug.length > MAX_SLUG_LENGTH || slugs.includes(slug)) continue;
      slugs.push(slug);
      if (slugs.length === MAX_MODES_PER_COUNTRY) break;
    }
    if (slugs.length === 0) continue;
    seen.add(country);
    out.push({ country, modes: slugs });
  }
  return out;
}

/** The ordered mode slugs for a country, or null when it has no entry. */
export function preferredModesFor(
  entries: readonly CountryModes[],
  country: string | null,
): string[] | null {
  if (!country) return null;
  return entries.find((e) => e.country === country)?.modes ?? null;
}
