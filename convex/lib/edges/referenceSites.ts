/**
 * Reference sites: operator-chosen well-known sites served by one CDN
 * provider, kept as custom probe targets (`probeTargets.referenceFor`, docs/edges.md
 * § "Reference sites"). They answer one question before an automatic
 * replacement spends a new name on that provider: does the network refuse the
 * whole CDN? A network that refuses every name the CDN serves refuses a fresh
 * one of ours too, so a replacement there costs a name and strands the apps
 * that never refresh, for nothing.
 *
 * A country counts as refusing the provider when, for some enabled reference
 * site of that provider, both hold (fresh evidence only):
 *  - the site's verdict from that country is `unreachable`;
 *  - the site is `reachable` from some OTHER country: a site nobody reaches is
 *    broken, not refused.
 *
 * No reference site, or none with fresh evidence, refuses nothing: the
 * replacement goes ahead as before.
 *
 * Pure: convex/edgeRotations.ts reads the rows and applies the rule.
 */

export interface ReferenceCountry {
  country: string;
  verdict: 'reachable' | 'unreachable' | 'mixed' | 'unknown';
  lastAt: number;
}

export interface ReferenceSite {
  referenceFor?: string;
  enabled: boolean;
  byCountry: readonly ReferenceCountry[];
}

/**
 * The countries among `countries` where `provider` is refused, by the rule
 * above. `staleAfterMs`: a country row older than this says nothing.
 */
export function cdnRefusedCountries(
  sites: readonly ReferenceSite[],
  provider: string,
  countries: readonly string[],
  now: number,
  staleAfterMs: number,
): string[] {
  const mine = sites
    .filter((s) => s.enabled && s.referenceFor === provider)
    .map((s) => s.byCountry.filter((c) => c.country !== 'XX' && now - c.lastAt <= staleAfterMs));
  return [...new Set(countries)]
    .sort()
    .filter((country) =>
      mine.some(
        (rows) =>
          rows.some((c) => c.country === country && c.verdict === 'unreachable') &&
          rows.some((c) => c.country !== country && c.verdict === 'reachable'),
      ),
    );
}

/** Every one of `countries` refuses `provider` (and there is at least one). */
export function cdnRefusesAll(
  sites: readonly ReferenceSite[],
  provider: string,
  countries: readonly string[],
  now: number,
  staleAfterMs: number,
): boolean {
  const want = new Set(countries);
  if (want.size === 0) return false;
  return cdnRefusedCountries(sites, provider, countries, now, staleAfterMs).length === want.size;
}
