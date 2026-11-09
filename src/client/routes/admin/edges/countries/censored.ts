/**
 * The censored-country list, edited on the Countries tab (pure; unit-tested).
 * The list is saved whole (`PUT /api/v1/admin/censored-countries`), so every
 * edit, from the list editor or from one country's "Checks from here", is a
 * new list built from the one on record.
 *
 * Exports:
 *   CENSORED_LIST_USES                 the one line said above the editor
 *   CHECK_SWITCHES                     the two per-country switches, in words
 *   withCountry(rows, code, max)       the list with one country added at the end
 *   withoutCountry(rows, code)         the list without one country
 *   movedCountry(rows, i, by)          the list with one row moved up or down
 *   withCheck(rows, code, key, on)     the list with one switch of one country set
 */
import type { CensoredCountry } from '../../../../../shared/contracts/admin';

export type CheckKey = 'checkEdges' | 'checkNamesInside';

export const CENSORED_LIST_USES =
  'This list also drives the sign-up "Where are you connecting from?" choice, the status page matrix and the mode suggestion.';

export const CHECK_SWITCHES: ReadonlyArray<{ key: CheckKey; label: string; help: string }> = [
  {
    key: 'checkEdges',
    label: 'Check edges from here',
    help: 'Outside probes ask from networks in this country whether its addresses answer.',
  },
  {
    key: 'checkNamesInside',
    label: 'Check SNIs from inside',
    help: "Checks run on other people's machines in this country, often home connections. Whoever runs one sees the address and the SNI. Turn it on only where that is acceptable.",
  },
];

/** A new country starts with edge checks on and SNI checks from inside off (opt-in). */
export function withCountry(
  rows: readonly CensoredCountry[],
  code: string,
  max: number,
): CensoredCountry[] {
  const c = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c) || rows.some((r) => r.code === c) || rows.length >= max) {
    return [...rows];
  }
  return [...rows, { code: c, checkEdges: true, checkNamesInside: false }];
}

export function withoutCountry(rows: readonly CensoredCountry[], code: string): CensoredCountry[] {
  return rows.filter((r) => r.code !== code);
}

export function movedCountry(
  rows: readonly CensoredCountry[],
  i: number,
  by: -1 | 1,
): CensoredCountry[] {
  const j = i + by;
  const next = [...rows];
  if (i < 0 || i >= rows.length || j < 0 || j >= rows.length) return next;
  [next[i], next[j]] = [next[j]!, next[i]!];
  return next;
}

export function withCheck(
  rows: readonly CensoredCountry[],
  code: string,
  key: CheckKey,
  on: boolean,
): CensoredCountry[] {
  return rows.map((r) => (r.code === code ? { ...r, [key]: on } : r));
}
