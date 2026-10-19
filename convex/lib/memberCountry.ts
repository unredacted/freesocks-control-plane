/**
 * Where a member connects from (pure; unit-tested). docs/privacy.md "Where a
 * member connects from" is the contract; the short version:
 *
 *  - Only keys of a FREEDOM-family mode have a country at all. Any other key
 *    (privacy family, a backend without modes, a family that cannot be told)
 *    gets nothing: no reading, no storage, no country-dependent delivery.
 *  - The member's own choice wins: a country on the censored-country list, or
 *    `ZZ` "Somewhere else". While a choice exists nothing is guessed.
 *  - On Automatic, with `delivery.country.detect` on, the country the CDN
 *    reports is stored as a GUESS, only when it is on the list. A listed
 *    reading replaces the guess; anything else (elsewhere, unknown, Tor)
 *    leaves it, and it expires `stickyDays` after it was last seen. A reading
 *    from one of FCP's own exits (the app refreshing through the tunnel) never
 *    sets or changes it, but keeps an existing one alive.
 *  - With detection off, today's behaviour: the CDN country is used for that one
 *    response's server names and stored nowhere.
 */
import type { CountryContext } from './edges/assignment';
import { resolveWhere, type ResolvedWhere } from './edges/sni/country';

/** The explicit "Somewhere else" choice. */
export const ELSEWHERE = 'ZZ';

export const MEMBER_COUNTRY_KEYS = {
  detect: 'delivery.country.detect',
  stickyDays: 'delivery.country.stickyDays',
  refreshHours: 'delivery.country.refreshHours',
  ownExitRanges: 'delivery.country.ownExitRanges',
  steer: 'delivery.country.steer',
} as const;

export interface MemberCountryConfig {
  /** Store the CDN country as a guess (Automatic members of freedom modes). */
  detect: boolean;
  /** A guess is forgotten this long after it was last seen. */
  stickyDays: number;
  /** A guess still seen is written again at most this often. */
  refreshHours: number;
  /** Operator-entered exit ranges (CIDRs) beside the ones FCP knows. */
  ownExitRanges: string[];
  /**
   * Order a member's addresses by their STORED country (docs/edges.md
   * "Delivery by country"): edges proven there first, blocked ones last.
   */
  steer: boolean;
}

export const MEMBER_COUNTRY_DEFAULTS: MemberCountryConfig = {
  detect: false,
  stickyDays: 30,
  refreshHours: 6,
  ownExitRanges: [],
  steer: false,
};

export const MEMBER_COUNTRY_BOUNDS = {
  stickyDays: { min: 1, max: 90 },
  refreshHours: { min: 1, max: 48 },
  ownExitRanges: { max: 64 },
} as const;

const int = (v: unknown, min: number, max: number, dflt: number) =>
  typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : dflt;

/** From the resolved settings bag (`appSettings.resolved`). */
export function memberCountryConfig(settings: Record<string, unknown>): MemberCountryConfig {
  const D = MEMBER_COUNTRY_DEFAULTS;
  const B = MEMBER_COUNTRY_BOUNDS;
  const ranges = settings[MEMBER_COUNTRY_KEYS.ownExitRanges];
  return {
    detect: settings[MEMBER_COUNTRY_KEYS.detect] === true,
    stickyDays: int(
      settings[MEMBER_COUNTRY_KEYS.stickyDays],
      B.stickyDays.min,
      B.stickyDays.max,
      D.stickyDays,
    ),
    refreshHours: int(
      settings[MEMBER_COUNTRY_KEYS.refreshHours],
      B.refreshHours.min,
      B.refreshHours.max,
      D.refreshHours,
    ),
    ownExitRanges: Array.isArray(ranges)
      ? ranges.filter((r): r is string => typeof r === 'string').slice(0, B.ownExitRanges.max)
      : [],
    steer: settings[MEMBER_COUNTRY_KEYS.steer] === true,
  };
}

export type MemberFamily = 'freedom' | 'privacy' | 'none';

/** The country fields a subscription row carries. */
export interface CountryFields {
  /** The member's choice: a listed country or `ZZ`. Stored name kept from "server-name region". */
  sniRegion?: string | null;
  regionSeenCountry?: string | null;
  regionSeenFirstAt?: number | null;
  regionSeenAt?: number | null;
}

const DAY = 86_400_000;
const HOUR = 3_600_000;

/** The member's choice when it still counts: a listed country, or `ZZ`. */
export function liveChoice(sub: CountryFields, listed: readonly string[]): string | null {
  const c = sub.sniRegion ?? null;
  if (!c) return null;
  return c === ELSEWHERE || listed.includes(c) ? c : null;
}

/** The guess when it still counts: detection on, listed, seen within `stickyDays`. */
export function liveGuess(
  sub: CountryFields,
  cfg: MemberCountryConfig,
  listed: readonly string[],
  now: number,
): { country: string; firstAt: number; at: number } | null {
  const c = sub.regionSeenCountry ?? null;
  const at = sub.regionSeenAt ?? null;
  if (!cfg.detect || !c || at === null || !listed.includes(c)) return null;
  if (now - at > cfg.stickyDays * DAY) return null;
  return { country: c, firstAt: sub.regionSeenFirstAt ?? at, at };
}

/**
 * The row's STORED country: the choice (`ZZ` = none), else the live guess,
 * else none. Every other copy of a country on the row (a cached body's
 * region) must equal this (subscriptions.ts `setStoredCountry`).
 */
export function storedCountry(
  sub: CountryFields,
  cfg: MemberCountryConfig,
  listed: readonly string[],
  now: number,
): string | null {
  const choice = liveChoice(sub, listed);
  if (choice) return choice === ELSEWHERE ? null : choice;
  return liveGuess(sub, cfg, listed, now)?.country ?? null;
}

export interface MemberCountryView {
  /** The key has a country at all (a freedom-family mode). */
  applies: boolean;
  choice: string | null;
  guess: { country: string; firstAt: number; lastAt: number } | null;
  /** What delivery uses now: a listed country, or null (elsewhere / unknown). */
  effective: string | null;
  source: 'choice' | 'guess' | 'none';
}

export function memberCountryView(
  family: MemberFamily,
  sub: CountryFields,
  cfg: MemberCountryConfig,
  listed: readonly string[],
  now: number,
): MemberCountryView {
  if (family !== 'freedom')
    return { applies: false, choice: null, guess: null, effective: null, source: 'none' };
  const choice = liveChoice(sub, listed);
  const g = liveGuess(sub, cfg, listed, now);
  const guess = g ? { country: g.country, firstAt: g.firstAt, lastAt: g.at } : null;
  if (choice)
    return {
      applies: true,
      choice,
      guess: null,
      effective: choice === ELSEWHERE ? null : choice,
      source: 'choice',
    };
  return {
    applies: true,
    choice: null,
    guess,
    effective: guess?.country ?? null,
    source: guess ? 'guess' : 'none',
  };
}

/**
 * The country the mode suggestion reads: what is stored when anything is (a
 * stored "Somewhere else" is an answer: no country), else this request's.
 */
export function suggestionCountry(
  stored: { effective: string | null; source: 'choice' | 'guess' | 'none' },
  requestCountry: string | null,
): string | null {
  return stored.source === 'none' ? requestCountry : stored.effective;
}

/** What one CDN reading does to the stored guess. */
export type GuessUpdate =
  | { kind: 'none' }
  | { kind: 'set'; country: string }
  | { kind: 'refresh' }
  | { kind: 'clear' };

export function nextGuess(args: {
  family: MemberFamily;
  sub: CountryFields;
  cfg: MemberCountryConfig;
  listed: readonly string[];
  now: number;
  /** The CDN country of this request (null when not fronted or unknown). */
  reading: string | null;
  /** The request came from one of FCP's own exits. */
  ownExit: boolean;
}): GuessUpdate {
  const { family, sub, cfg, listed, now } = args;
  if (family !== 'freedom' || !cfg.detect) return { kind: 'none' };
  if (liveChoice(sub, listed)) return { kind: 'none' };
  const g = liveGuess(sub, cfg, listed, now);
  const due = (at: number) => now - at >= cfg.refreshHours * HOUR;
  if (args.ownExit) return g && due(g.at) ? { kind: 'refresh' } : { kind: 'none' };
  const reading = args.reading ? args.reading.trim().toUpperCase() : null;
  if (reading && listed.includes(reading)) {
    if (g && g.country === reading) return due(g.at) ? { kind: 'refresh' } : { kind: 'none' };
    return { kind: 'set', country: reading };
  }
  // Elsewhere or unknown: the guess stays (it is sticky) unless it already lapsed.
  return !g && sub.regionSeenCountry ? { kind: 'clear' } : { kind: 'none' };
}

/**
 * Where the member is, for this response's server names (and, later, edges).
 * `source: 'override'` means a STORED country (the choice or the guess): the
 * body is cacheable under it. `inferred` is the transient detect-off reading.
 */
export function memberWhere(args: {
  family: MemberFamily;
  sub: CountryFields;
  cfg: MemberCountryConfig;
  listed: readonly string[];
  now: number;
  /** The CDN country of this request. */
  reading: string | null;
}): ResolvedWhere {
  const { family, sub, cfg, listed, now } = args;
  const none = (): ResolvedWhere => ({
    where: { country: null, curated: listed } satisfies CountryContext,
    source: 'none',
  });
  if (family !== 'freedom') return none();
  const choice = liveChoice(sub, listed);
  if (choice)
    return {
      where: { country: choice === ELSEWHERE ? null : choice, curated: listed },
      source: 'override',
    };
  if (cfg.detect) {
    const g = liveGuess(sub, cfg, listed, now);
    return g ? { where: { country: g.country, curated: listed }, source: 'override' } : none();
  }
  return resolveWhere({ override: null, inferred: args.reading, curated: listed });
}

/**
 * The country a member's EDGES are ordered by (delivery by country), or null:
 * only with `steer` on, and only a STORED country (the member's choice or the
 * stored guess, `source: 'override'`): a transient reading never shapes which
 * address a member gets, and nothing at all applies outside the freedom family
 * (`memberWhere` gives such a key no country).
 */
export function steeringCountry(
  cfg: Pick<MemberCountryConfig, 'steer'>,
  located: ResolvedWhere,
): string | null {
  if (!cfg.steer || located.source !== 'override') return null;
  return located.where.country;
}
