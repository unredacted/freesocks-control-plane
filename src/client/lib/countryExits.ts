/**
 * Exit location by country, admin side (docs/edges.md "Exit location by
 * country"): editing `delivery.country.exits` from Servers -> Countries (the
 * Delivery card, and each country page's Exit), and the country page's sentence. The server reads the setting fail-safe
 * (convex/lib/countryExits.ts `parseCountryExits`); these helpers keep what the
 * page writes inside the same rules.
 */

export interface CountryExitRow {
  country: string;
  locations: string[];
}

/** Locations one country may name, in order (the server's MAX_EXIT_LOCATIONS). */
export const EXIT_SLOTS = 3;

/** Read whatever the settings bag holds as rows (anything else is none). */
export function exitRows(raw: unknown): CountryExitRow[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((r) => {
    if (!r || typeof r !== 'object') return [];
    const { country, locations } = r as { country?: unknown; locations?: unknown };
    if (typeof country !== 'string' || !Array.isArray(locations)) return [];
    return [{ country, locations: locations.filter((l): l is string => typeof l === 'string') }];
  });
}

/** The codes a country's slots show, padded to EXIT_SLOTS with ''. */
export function slotsOf(rows: readonly CountryExitRow[], country: string): string[] {
  const codes = rows.find((r) => r.country === country)?.locations ?? [];
  return Array.from({ length: EXIT_SLOTS }, (_, i) => codes[i] ?? '');
}

/**
 * The rows after one slot of one country is set ('' = none): the country's
 * codes close up in order without repeats, and a country left with none is
 * dropped. Other countries keep their place.
 */
export function withSlot(
  rows: readonly CountryExitRow[],
  country: string,
  slot: number,
  code: string,
): CountryExitRow[] {
  const slots = slotsOf(rows, country);
  slots[slot] = code;
  const locations: string[] = [];
  for (const c of slots) if (c && !locations.includes(c)) locations.push(c);
  const others = rows.filter((r) => r.country !== country);
  if (locations.length === 0) return others;
  const at = rows.findIndex((r) => r.country === country);
  const next = { country, locations };
  if (at < 0) return [...others, next];
  return [...rows.slice(0, at), next, ...rows.slice(at + 1)];
}

/**
 * The countries the settings editor shows: every listed one, then any country
 * that still has a mapping but left the list. A mapping there does nothing,
 * but it would apply again the day the country is listed again, so it stays
 * in view, to be cleared.
 */
export function editorCountries(
  listed: readonly string[],
  rows: readonly CountryExitRow[],
): Array<{ code: string; listed: boolean }> {
  return [
    ...listed.map((code) => ({ code, listed: true })),
    ...rows
      .filter((r) => !listed.includes(r.country) && r.locations.length > 0)
      .map((r) => ({ code: r.country, listed: false })),
  ];
}

/**
 * The country page's sentence for where new keys on Automatic go. The mapping
 * applies only with ordering by country on (`steering`): with it off, new keys
 * go least-loaded whatever is set.
 */
export function exitSentence(labels: readonly string[], steering: boolean): string {
  if (labels.length === 0)
    return 'New keys on Automatic go to the least-loaded location. Choose exit locations for this country below.';
  const list =
    labels.length === 1
      ? labels[0]!
      : `${labels.slice(0, -1).join(', ')} or ${labels[labels.length - 1]!}`;
  if (!steering)
    return `Exit locations are set (${list}), but ordering by country is off, so new keys on Automatic go to the least-loaded location. Turn it on under Delivery, on the Countries tab.`;
  return `New keys on Automatic of members who chose this country themselves go to ${list}, the first that can take them.`;
}
