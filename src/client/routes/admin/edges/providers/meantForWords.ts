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
    ? 'Set for no country in particular.'
    : `Set for ${countryList(codes, nameOf)}: members there get an address here first, unless it is blocked there.`;
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
        ? 'A location takes at most 8 countries.'
        : 'Only countries on the censored-country list can be chosen.',
    ];
  if (!e.steering)
    return [
      'Addresses are not ordered by country, so nothing moves until that is on in Settings, Where members connect from.',
    ];
  if (e.countries.length === 0) return null;
  return e.countries.map(({ country, nodes }) => {
    const where = nameOf(country);
    if (nodes.length === 0) return `${where}: no node has an address in use here yet.`;
    const parts = nodes.map(
      (n) => `about ${pct(n.moved, n.sampled)}% of members on ${n.label ?? n.relaySlug}`,
    );
    return `${where}: ${parts.join(', ')} get a different first address.`;
  });
}

/**
 * The words of a location's "only for these countries" switch (docs/edges.md
 * "Addresses only for some countries").
 */
export function onlyForWords(
  codes: readonly string[],
  nameOf: (code: string) => string,
): { line: (only: boolean) => string; on: string; off: string; caveat: string } {
  const list = countryList(codes, nameOf);
  return {
    line: (only) =>
      only
        ? `New addresses here are only for members in ${list}.`
        : 'Addresses here are for everyone.',
    on: `New addresses here go only to members in ${list}. Addresses in use now stay for everyone. Older spares are never put in use here.`,
    off: 'Every address here goes back to everyone, for good. Switching it on again starts from new addresses.',
    caveat:
      'Members elsewhere or with no country never get these addresses. Accounts in those countries can still collect them, so keep at least 4 addresses here.',
  };
}
