/**
 * Exit location by country (pure; unit-tested). docs/privacy.md "Where a member
 * connects from" and docs/edges.md "Exit location by country" are the contract;
 * the short version:
 *
 *  - The operator maps a listed country to up to three location codes of the
 *    member catalog (`delivery.country.exits`), in order.
 *  - A new key of a FREEDOM-family mode, issued for a member on Automatic (no
 *    location pick of their own) whose OWN country choice on the key it
 *    replaces has an entry, narrows softly to those locations, in order
 *    (lib/remnawavePlacement.ts); none that can take it leaves today's
 *    least-loaded choice. Only with ordering by country (`steer`) on.
 *  - Never the guess: a placement chosen by a guess would outlive the guess on
 *    the backend, and a regenerate carries only the choice anyway. The opt-out
 *    (`ZZ`) and no choice at all get today's choice.
 *  - Nothing ever moves a key by itself: the account page offers a one-time
 *    move when the key is elsewhere.
 */
import { ELSEWHERE, type MemberFamily } from './memberCountry';

export const COUNTRY_EXITS_KEY = 'delivery.country.exits';
/** Locations one country may name, in order. */
export const MAX_EXIT_LOCATIONS = 3;
/** Countries the setting may hold (the censored-country list is far shorter). */
export const MAX_EXIT_COUNTRIES = 64;
const MAX_CODE_LENGTH = 64;

export interface CountryExit {
  country: string;
  /** Location codes (`backendServers.location`), in the order they are tried. */
  locations: string[];
}

const COUNTRY = /^[A-Z]{2}$/;

/**
 * Fail-safe read of the stored setting: entries with a two-letter country (not
 * the opt-out) and at least one location code; the first entry of a country
 * wins, codes are trimmed and de-duplicated in order, at most
 * MAX_EXIT_LOCATIONS each. Anything else is dropped.
 */
export function parseCountryExits(raw: unknown): CountryExit[] {
  if (!Array.isArray(raw)) return [];
  const out: CountryExit[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (out.length >= MAX_EXIT_COUNTRIES) break;
    if (!entry || typeof entry !== 'object') continue;
    const { country, locations } = entry as { country?: unknown; locations?: unknown };
    if (typeof country !== 'string' || !COUNTRY.test(country) || country === ELSEWHERE) continue;
    if (seen.has(country) || !Array.isArray(locations)) continue;
    const codes: string[] = [];
    for (const c of locations) {
      if (typeof c !== 'string') continue;
      const code = c.trim();
      if (code.length === 0 || code.length > MAX_CODE_LENGTH || codes.includes(code)) continue;
      codes.push(code);
      if (codes.length === MAX_EXIT_LOCATIONS) break;
    }
    if (codes.length === 0) continue;
    seen.add(country);
    out.push({ country, locations: codes });
  }
  return out;
}

/**
 * The locations a new key narrows to, in order, or [] for today's choice. A
 * member's own location pick always wins, and so does anything that is not a
 * freedom-family key of a member who chose a country themselves.
 */
export function exitLocationsFor(args: {
  exits: readonly CountryExit[];
  /** Ordering by country is on (`delivery.country.steer`). */
  steer: boolean;
  /** The member's location pick (`users.preferredLocation`); null = Automatic. */
  preferredLocation: string | null;
  /** The member's OWN choice on the key being replaced (`liveChoice`), never a guess. */
  choice: string | null;
  /** The family of the mode the new key issues into. */
  family: MemberFamily;
}): string[] {
  if (!args.steer || args.preferredLocation || args.family !== 'freedom') return [];
  if (!args.choice || args.choice === ELSEWHERE) return [];
  return args.exits.find((e) => e.country === args.choice)?.locations ?? [];
}
