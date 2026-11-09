/**
 * A country's default picks (pure; unit-tested). docs/edges.md "A country's
 * default picks" is the contract; in short:
 *
 *  - The fleet keeps, per country (or a few countries together), the picks
 *    their own addresses go to on every freedom node: a location and how many
 *    of each transport it carries (`want`), and fallback places with none.
 *  - Upkeep writes them onto each ready node as entries of its picks
 *    (`relays.providerSet[].audiences`, marked `fromDefault`), adding the
 *    location as a pick serving its countries only where the node did not
 *    pick it. Only locations that carry one of the node's freedom transports.
 *  - A node's own entry for one of those countries wins (its entries are left
 *    alone and the default is not applied there), and a node may opt out.
 *  - A default removed takes its entries away; their addresses stay theirs.
 *    A pick the defaults added goes with its last entry once nothing is live there.
 */

/** One stored default (`countryDefaults` rows). */
export interface CountryDefault {
  codes: readonly string[];
  picks: ReadonlyArray<{ locationId: string; want?: number }>;
}

/** A node's pick as the planner reads and writes it. */
export interface DefaultsPick {
  locationId: string;
  addedAt: number;
  options?: string;
  want?: number;
  audiences?: Array<{ codes: string[]; want?: number; addedAt: number; fromDefault?: true }>;
  audienceOnly?: true;
  fromDefault?: true;
}

export interface DefaultsPlanInput<P extends DefaultsPick> {
  providerSet: readonly P[];
  defaults: readonly CountryDefault[];
  /** Countries this node opted out of (`relays.countryDefaultsOptOut`). */
  optOut: readonly string[];
  /** Whether a location carries one of the node's freedom transports. */
  carries: (locationId: string) => boolean;
  /** Whether the node has a live address at a location (a pick the defaults added stays while it does). */
  liveAt: (locationId: string) => boolean;
  now: number;
}

const sorted = (codes: readonly string[]) => [...new Set(codes)].sort();

/** Stable JSON (object keys sorted): a set written back unchanged compares equal. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v)
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  return JSON.stringify(v);
}
const key = (codes: readonly string[]) => sorted(codes).join(' ');

/** The countries a node's own entries hold (those it keeps whatever the defaults say). */
export function handCodesOf(set: readonly DefaultsPick[]): string[] {
  return [
    ...new Set(
      set.flatMap((p) => (p.audiences ?? []).filter((x) => !x.fromDefault).flatMap((x) => x.codes)),
    ),
  ];
}

/** The defaults that apply to a node: none of its countries kept by hand or opted out. */
export function defaultsFor(
  set: readonly DefaultsPick[],
  defaults: readonly CountryDefault[],
  optOut: readonly string[],
): CountryDefault[] {
  const hand = handCodesOf(set);
  return defaults.filter((d) => !d.codes.some((c) => hand.includes(c) || optOut.includes(c)));
}

/**
 * The node's provider set with the defaults written in, and whether it moved.
 * Entries from the defaults are the only ones it touches.
 */
export function defaultsPlan<P extends DefaultsPick>(
  input: DefaultsPlanInput<P>,
): { providerSet: DefaultsPick[]; changed: boolean; added: string[]; removed: string[] } {
  const { now } = input;
  // What the defaults want here: per location, the entries (codes -> want).
  const wanted = new Map<string, Map<string, number | undefined>>();
  for (const d of defaultsFor(input.providerSet, input.defaults, input.optOut))
    for (const p of d.picks) {
      if (!input.carries(p.locationId)) continue;
      const at = wanted.get(p.locationId) ?? new Map<string, number | undefined>();
      at.set(key(d.codes), p.want);
      wanted.set(p.locationId, at);
    }
  const added: string[] = [];
  const removed: string[] = [];
  const out: DefaultsPick[] = [];
  for (const pick of input.providerSet) {
    const here = wanted.get(pick.locationId) ?? new Map<string, number | undefined>();
    const entries: NonNullable<DefaultsPick['audiences']> = [];
    for (const e of pick.audiences ?? []) {
      if (!e.fromDefault) {
        entries.push(e);
        continue;
      }
      const k = key(e.codes);
      if (!here.has(k)) {
        removed.push(k);
        continue;
      }
      const want = here.get(k);
      entries.push({
        codes: sorted(e.codes),
        ...(want !== undefined ? { want } : {}),
        addedAt: e.addedAt,
        fromDefault: true,
      });
      here.delete(k);
    }
    for (const [k, want] of here) {
      added.push(k);
      entries.push({
        codes: k.split(' '),
        ...(want !== undefined ? { want } : {}),
        addedAt: now,
        fromDefault: true,
      });
    }
    wanted.delete(pick.locationId);
    const { audiences: _a, ...rest } = pick;
    void _a;
    // A pick the defaults added, with nothing of theirs left and nothing live there: gone.
    if (pick.fromDefault && entries.length === 0 && !input.liveAt(pick.locationId)) continue;
    out.push(entries.length > 0 ? { ...rest, audiences: entries } : rest);
  }
  // Locations the node did not pick: added as picks serving their countries only.
  for (const [locationId, here] of wanted) {
    const entries = [...here].map(([k, want]) => {
      added.push(k);
      return {
        codes: k.split(' '),
        ...(want !== undefined ? { want } : {}),
        addedAt: now,
        fromDefault: true as const,
      };
    });
    out.push({
      locationId,
      addedAt: now,
      audiences: entries,
      audienceOnly: true,
      fromDefault: true,
    });
  }
  const changed = canonical(out) !== canonical(input.providerSet);
  return { providerSet: out, changed, added: sorted(added), removed: sorted(removed) };
}
