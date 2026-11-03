/**
 * Words for the countries a location is meant for (docs/edges.md "Locations
 * meant for a country"): the line under a location and what saving an edit
 * would move. Pure, so the sentences are tested.
 */
import type { EdgeLocationCountriesEstimate } from '../../../../../shared/contracts/edges';

type NameOf = (code: string) => string;

/** "Iran, Russia" in the order stored. */
export function countryList(codes: readonly string[], nameOf: NameOf): string {
  return codes.map(nameOf).join(', ');
}

/** The line under a location: what it is meant for, or nothing in particular. */
export function meantForLine(codes: readonly string[], nameOf: NameOf): string {
  return codes.length === 0
    ? 'Meant for no country in particular.'
    : `Meant for ${countryList(codes, nameOf)}: members there get an address here first, unless it is blocked there.`;
}

const pct = (moved: number, sampled: number) =>
  sampled === 0 ? 0 : Math.round((moved / sampled) * 100);

/**
 * What saving would move, one sentence per country added or removed. Null
 * while there is nothing to say (no change yet).
 */
export function estimateLines(
  e: EdgeLocationCountriesEstimate | undefined,
  nameOf: NameOf,
): string[] | null {
  if (!e) return null;
  if (!e.valid)
    return [
      e.code === 'meant_for_too_many'
        ? 'A location is meant for at most 8 countries.'
        : 'Only countries on the censored-country list can be chosen.',
    ];
  if (!e.steering)
    return [
      'Addresses are not ordered by country now (Settings, Where members connect from), so nothing moves until that is on.',
    ];
  if (e.countries.length === 0) return null;
  return e.countries.map(({ country, nodes }) => {
    const where = nameOf(country);
    if (nodes.length === 0) return `${where}: no node has an address in use here yet.`;
    const parts = nodes.map(
      (n) => `about ${pct(n.moved, n.sampled)}% on ${n.label ?? n.relaySlug}`,
    );
    return `${where}: ${parts.join(', ')} of members get a different first address.`;
  });
}
