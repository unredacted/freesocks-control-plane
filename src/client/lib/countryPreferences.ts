/**
 * Country preferences, admin side (Admin → Connection modes): per country, the
 * modes the picker suggests (`delivery.country.modes`, convex/lib/countryModes.ts)
 * and the locations Automatic tries first (`delivery.country.exits`,
 * convex/lib/countryExits.ts). Both settings are edited here as one row per
 * country and saved together; the server reads both fail-safe.
 */
import { exitRows, EXIT_SLOTS } from './countryExits';

/** The server's MAX_MODES_PER_COUNTRY. */
export const MODE_SLOTS = 6;
export const LOCATION_SLOTS = EXIT_SLOTS;

export interface CountryPreferenceRow {
  country: string;
  modes: string[];
  locations: string[];
}

function modeRows(raw: unknown): Array<{ country: string; modes: string[] }> {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((r) => {
    if (!r || typeof r !== 'object') return [];
    const { country, modes } = r as { country?: unknown; modes?: unknown };
    if (typeof country !== 'string' || !Array.isArray(modes)) return [];
    return [{ country, modes: modes.filter((m): m is string => typeof m === 'string') }];
  });
}

/** One row per country holding either list: mode countries first, in order. */
export function preferenceRows(modesRaw: unknown, exitsRaw: unknown): CountryPreferenceRow[] {
  const modes = modeRows(modesRaw);
  const exits = exitRows(exitsRaw);
  const out: CountryPreferenceRow[] = [];
  for (const m of modes) {
    if (out.some((r) => r.country === m.country)) continue;
    out.push({
      country: m.country,
      modes: m.modes,
      locations: exits.find((e) => e.country === m.country)?.locations ?? [],
    });
  }
  for (const e of exits) {
    if (out.some((r) => r.country === e.country)) continue;
    out.push({ country: e.country, modes: [], locations: e.locations });
  }
  return out;
}

/** Ordered, de-duplicated, capped. */
function clean(list: readonly string[], cap: number): string[] {
  const out: string[] = [];
  for (const v of list) if (v && !out.includes(v) && out.length < cap) out.push(v);
  return out;
}

/** The two settings a set of rows saves as (empty lists drop out). */
export function preferencePatch(rows: readonly CountryPreferenceRow[]): {
  'delivery.country.modes': Array<{ country: string; modes: string[] }>;
  'delivery.country.exits': Array<{ country: string; locations: string[] }>;
} {
  const modes: Array<{ country: string; modes: string[] }> = [];
  const exits: Array<{ country: string; locations: string[] }> = [];
  for (const r of rows) {
    const m = clean(r.modes, MODE_SLOTS);
    const l = clean(r.locations, LOCATION_SLOTS);
    if (m.length > 0) modes.push({ country: r.country, modes: m });
    if (l.length > 0) exits.push({ country: r.country, locations: l });
  }
  return { 'delivery.country.modes': modes, 'delivery.country.exits': exits };
}

/** The rows with one country's row put in place (added at the end when new), or removed (null). */
export function withRow(
  rows: readonly CountryPreferenceRow[],
  country: string,
  next: CountryPreferenceRow | null,
): CountryPreferenceRow[] {
  const at = rows.findIndex((r) => r.country === country);
  if (next === null) return rows.filter((r) => r.country !== country);
  if (at < 0) return [...rows, next];
  return [...rows.slice(0, at), next, ...rows.slice(at + 1)];
}

/** Move the item at `i` by `delta` (a no-op past either end). */
export function moved<T>(list: readonly T[], i: number, delta: -1 | 1): T[] {
  const j = i + delta;
  if (j < 0 || j >= list.length) return list.slice();
  const next = list.slice();
  [next[i], next[j]] = [next[j]!, next[i]!];
  return next;
}
