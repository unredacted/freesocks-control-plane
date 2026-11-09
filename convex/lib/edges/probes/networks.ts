/**
 * Which kinds of network Globalping probes come from (`edge.probe.networks`,
 * pure; unit-tested). Globalping tags every probe as a home network
 * (`eyeball-network`: a consumer ISP, the kind of network members connect
 * from) or a data centre (`datacenter-network`), never both. One setting
 * covers every Globalping ask FCP makes from a checked country: probe rounds
 * of addresses (`probeOps`) and the checks of server names from inside a
 * country (`sniVantageOps`, `sniHuntOps.countryBatch`).
 *
 *  - `home`: home-network probes only. A country with fewer of them than the
 *    ask gets fewer results, and one with none gets none.
 *  - `home_first`: home-network probes first; a country short of them is
 *    topped up with data-centre probes in the same ask (the free probe
 *    listing says how many it has), and any probe when both together are too
 *    few, or when the listing could not be read and nothing matched.
 *  - `any`: any probe Globalping picks.
 *
 * Never tagged, whatever the setting: control countries (an uncensored
 * country asked in the same measurement only tells a blocked address from a
 * broken one; any probe that answers does that) and the timing of a
 * candidate's site from a node's place (FCP's own servers sit in data
 * centres, so that leg is timed from whatever probe is there).
 */
import { normalizeCountry, type VantageClass } from './types';

export const PROBE_NETWORKS = ['home', 'home_first', 'any'] as const;
export type ProbeNetworks = (typeof PROBE_NETWORKS)[number];

export const HOME_TAG = 'eyeball-network';
export const DATACENTRE_TAG = 'datacenter-network';

/** A probe's network type from its tags. */
export function vantageClassOf(tags: unknown): VantageClass {
  if (!Array.isArray(tags)) return 'unknown';
  const t = tags.map((x) => String(x).toLowerCase());
  if (t.includes(HOME_TAG)) return 'eyeball';
  if (t.includes(DATACENTRE_TAG)) return 'datacenter';
  return 'unknown';
}

/**
 * A country's Globalping probes, by network tag, from the free probe listing
 * (`GET /v1/probes`): home-network (`eyeball-network`), data-centre
 * (`datacenter-network`) and all of them.
 */
export interface CountryProbeCounts {
  eyeball: number;
  datacenter: number;
  total: number;
}

/**
 * The listing counted per country. Null when the listing cannot be read, or
 * when it carries no network tag anywhere (then it cannot tell a country with
 * no home-network probe from a listing without tags, and nothing is planned
 * from it). A country absent from the result has no probe.
 */
export function countAllProbes(listing: unknown): Record<string, CountryProbeCounts> | null {
  if (!Array.isArray(listing)) return null;
  const out: Record<string, CountryProbeCounts> = {};
  let tagged = false;
  for (const p of listing as Array<{ location?: { country?: unknown }; tags?: unknown }>) {
    const cls = vantageClassOf(p?.tags);
    if (cls !== 'unknown') tagged = true;
    const cc = normalizeCountry(p?.location?.country);
    if (!cc) continue;
    const c = (out[cc] ??= { eyeball: 0, datacenter: 0, total: 0 });
    c.total++;
    if (cls === 'eyeball') c.eyeball++;
    else if (cls === 'datacenter') c.datacenter++;
  }
  return tagged ? out : null;
}

/** The listing counted for one country (see `countAllProbes`). */
export function countProbesIn(listing: unknown, country: string): CountryProbeCounts | null {
  const all = countAllProbes(listing);
  if (!all) return null;
  return all[country] ?? { eyeball: 0, datacenter: 0, total: 0 };
}

/**
 * How `home_first` fills one country's ask of `limit` probes from its counts:
 * home-network probes only when it has at least `floor` of them; every
 * home-network probe plus data-centre ones up to `limit` when home-network
 * and data-centre probes together reach `floor` (`eyeball` = the home-network
 * share, always under `limit`); any probe otherwise. The total asked is
 * `limit` in every case, so the cost never changes.
 */
export function homeFirstSplit(
  counts: CountryProbeCounts,
  limit: number,
  floor: number,
): { mode: 'eyeball' } | { mode: 'topped_up'; eyeball: number } | { mode: 'any' } {
  const f = Math.max(1, Math.min(floor, limit));
  if (counts.eyeball >= f) return { mode: 'eyeball' };
  if (counts.eyeball > 0 && counts.eyeball + counts.datacenter >= f)
    return { mode: 'topped_up', eyeball: Math.min(counts.eyeball, limit - 1) };
  return { mode: 'any' };
}

export interface GlobalpingLocation {
  country: string;
  limit: number;
  tags?: string[];
}

/**
 * One checked country's Globalping locations under the setting, `limit`
 * probes in all. `home_first` without counts asks home-network probes (the
 * caller asks any probe when none matched).
 */
export function countryLocations(
  country: string,
  limit: number,
  networks: ProbeNetworks,
  counts: CountryProbeCounts | null,
): GlobalpingLocation[] {
  const home = [{ country, limit, tags: [HOME_TAG] }];
  if (networks === 'any') return [{ country, limit }];
  if (networks === 'home' || !counts) return home;
  const split = homeFirstSplit(counts, limit, limit);
  if (split.mode === 'eyeball') return home;
  if (split.mode === 'any') return [{ country, limit }];
  return [
    { country, limit: split.eyeball, tags: [HOME_TAG] },
    { country, limit: limit - split.eyeball, tags: [DATACENTRE_TAG] },
  ];
}

/** A Globalping refusal that means "no probe matched": worth one retry with any probe. */
export function isNoProbesError(status: number | undefined, body: unknown): boolean {
  if (status !== 422) return false;
  const text = JSON.stringify(body ?? '').toLowerCase();
  return text.includes('no_probes_found') || text.includes('no suitable probes');
}

/** Whether an ask carries a network tag (so a "no probes" refusal may be retried with any probe). */
export function asksByTag(req: { locations?: unknown }): boolean {
  return (
    Array.isArray(req.locations) &&
    req.locations.some(
      (l) => !!l && typeof l === 'object' && Array.isArray((l as { tags?: unknown }).tags),
    )
  );
}

/** Where the probe listing counted for address probes is kept (`appState`). */
export const PROBE_COUNTS_KEY = 'globalping:probeCounts';
/** How long that count is used before the listing is read again. */
export const PROBE_COUNTS_FRESH_MS = 3_600_000;

/** The stored count (`{at, counts}`) while fresh, else null (never throws). */
export function freshProbeCounts(
  raw: unknown,
  now: number,
): Record<string, CountryProbeCounts> | null {
  if (!raw || typeof raw !== 'object') return null;
  const { at, counts } = raw as { at?: unknown; counts?: unknown };
  if (typeof at !== 'number' || at > now || now - at > PROBE_COUNTS_FRESH_MS) return null;
  if (!counts || typeof counts !== 'object' || Array.isArray(counts)) return null;
  return counts as Record<string, CountryProbeCounts>;
}
