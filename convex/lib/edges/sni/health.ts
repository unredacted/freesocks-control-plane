/**
 * Which server names look blocked somewhere, from member reports (pure).
 *
 * The only evidence is `sniReportCounts`: per (name, country, day), the summed
 * fractional weight of deduplicated member reports. A member holds K names on
 * the address they reported, so one report adds 1/K to each of them. That is
 * deliberately coarse. It can only ever SUGGEST that a name is blocked in a
 * country; it never proves a name works, never retires a name, and never
 * changes what members are given. An operator decides.
 *
 * A name is a suspect in a country when, over the window:
 *  - it gathered at least `minWeight` there (a floor, so one report is nothing), and
 *  - it gathered at least `ratio` times what the family's OTHER reported names
 *    average there. When every name gathers reports alike the address or the
 *    node is the likelier cause, and that is the block detector's business.
 *    A name that is the only one reported there passes on the floor alone.
 */
export interface NameCount {
  name: string;
  country: string;
  weight: number;
}

export interface SuspectOptions {
  minWeight: number;
  ratio: number;
}

export const SUSPECT_DEFAULTS: SuspectOptions = { minWeight: 3, ratio: 2 };

/** Reports with no consented, curated country. Never a suspect country. */
export const NO_COUNTRY = 'ZZ';

/** name -> countries it is a suspect in (sorted). `counts` = one family's names only. */
export function suspectNames(
  counts: readonly NameCount[],
  opts: SuspectOptions = SUSPECT_DEFAULTS,
): Map<string, string[]> {
  const byCountry = new Map<string, Map<string, number>>();
  for (const c of counts) {
    if (c.country === NO_COUNTRY || !(c.weight > 0)) continue;
    const names = byCountry.get(c.country) ?? new Map<string, number>();
    names.set(c.name, (names.get(c.name) ?? 0) + c.weight);
    byCountry.set(c.country, names);
  }
  const out = new Map<string, string[]>();
  for (const [country, names] of byCountry) {
    const total = [...names.values()].reduce((a, b) => a + b, 0);
    for (const [name, weight] of names) {
      if (weight < opts.minWeight) continue;
      const others = names.size - 1;
      const otherMean = others > 0 ? (total - weight) / others : 0;
      if (others > 0 && weight < opts.ratio * otherMean) continue;
      out.set(name, [...(out.get(name) ?? []), country].sort());
    }
  }
  return out;
}

/** One report's share per name: 1/K each, nothing for an empty list. */
export function shareOf(names: readonly string[]): number {
  return names.length === 0 ? 0 : 1 / names.length;
}

/** The UTC day a count belongs to, as `YYYY-MM-DD`. */
export function dayOf(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
