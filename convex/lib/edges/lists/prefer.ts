/**
 * Which curated countries a server name is preferred in because an allowlist
 * there holds it (docs/edges.md "Names on a country's allowlist"). Pure;
 * unit-tested.
 *
 * A list is union evidence (true on some networks there, some of the time),
 * so it never makes a name proven: it only puts the name ahead of the ones
 * nobody has judged in that country. Lists that disagree prefer nothing, as
 * they suggest nothing (`listBlocks`, lib/edges/sni/vantage.ts).
 */

/** A name's stored list facts (`sniNames.onLists`), as far as this reads them. */
export interface PreferFact {
  listId: string;
  cc: string;
  regime: 'allowlist' | 'blocklist';
}

/** What decides the preference now; null = nothing is preferred anywhere. */
export interface PreferContext {
  /** The allowlists that prefer their names and are read now: list id -> its country. */
  lists: ReadonlyMap<string, string>;
  /** Names are picked per country only in a curated one. */
  curated: ReadonlySet<string>;
}

export function listedCountries(
  onLists: readonly PreferFact[] | null | undefined,
  prefer: PreferContext | null,
): string[] {
  if (!prefer || !onLists?.length) return [];
  const out = new Set<string>();
  for (const f of onLists) {
    if (f.regime !== 'allowlist' || !prefer.curated.has(f.cc)) continue;
    // The stored fact is as old as the list-facts generation: the list must
    // still be an allowlist for that country that prefers its names.
    if (prefer.lists.get(f.listId) !== f.cc) continue;
    if (onLists.some((g) => g.cc === f.cc && g.regime === 'blocklist')) continue;
    out.add(f.cc);
  }
  return [...out].sort();
}
