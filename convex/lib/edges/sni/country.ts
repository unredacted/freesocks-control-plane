/**
 * Which country a render is for, and whether its body may be cached (pure;
 * unit-tested).
 *
 * Two sources, in this order:
 *   1. the member's OWN stored answer (`subscriptions.sniRegion`);
 *   2. the country the CDN reports for THIS request (`resolveCountry`, only
 *      when the deployment is fronted by that CDN; otherwise it is a header a
 *      client could forge, and it is ignored).
 * Either counts only if it is a CURATED country; anything else is "no country"
 * and gets the universal pool.
 *
 * The privacy rule: an inferred country is used for that one response and kept
 * NOWHERE. A body chosen by it is therefore never written to the subscription's
 * content cache (that would store the country on the row) and never served as
 * publicly cacheable (a shared cache would hand one country's body to another).
 * The member's own answer is already stored by their choice, so a body chosen
 * by it caches like any other.
 */
import type { CountryContext, PublishedEdge } from '../assignment';

export type CountrySource = 'override' | 'inferred' | 'none';

export interface ResolvedWhere {
  where: CountryContext;
  source: CountrySource;
}

export function resolveWhere(args: {
  override?: string | null;
  inferred: string | null;
  curated: readonly string[];
}): ResolvedWhere {
  const curated = args.curated;
  const norm = (c: string | null | undefined) => (c ? c.trim().toUpperCase() : null);
  const override = norm(args.override);
  if (override && curated.includes(override))
    return { where: { country: override, curated }, source: 'override' };
  const inferred = norm(args.inferred);
  if (inferred && curated.includes(inferred))
    return { where: { country: inferred, curated }, source: 'inferred' };
  return { where: { country: null, curated }, source: 'none' };
}

/** Whether any name this body could carry is judged per country at all. */
export function isCountrySensitive(published: readonly PublishedEdge[]): boolean {
  return published.some(
    (e) =>
      e.sniPick === 'hrw1' &&
      e.serverNames.some((s) => (s.blockedIn?.length ?? 0) > 0 || (s.provenIn?.length ?? 0) > 0),
  );
}

/**
 * May this body be stored in the content cache and served as publicly
 * cacheable? Not when an INFERRED country shaped it.
 */
export function bodyIsCacheable(source: CountrySource, sensitive: boolean): boolean {
  return !(sensitive && source === 'inferred');
}

/**
 * May a CACHED body be served to this request? A cached body was rendered for
 * "no country" or for the member's own answer, never for an inferred one. A
 * request that infers a curated country must not get it when names are judged
 * per country: it could carry a name blocked where the member is right now.
 */
export function cacheIsServable(source: CountrySource, sensitive: boolean): boolean {
  return !(sensitive && source === 'inferred');
}
