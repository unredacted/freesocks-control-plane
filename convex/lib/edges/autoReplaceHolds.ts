/**
 * Holds on a node's automatic replacement of one transport (`relays.autoReplaceHolds`,
 * docs/edges.md § "Replacing a blocked address without a spare"). Two shapes:
 *
 *  - a WHOLE-TRANSPORT hold (no `countries`): a replacement judged blocked again
 *    soon after it went into use (`replacement_reblocked`). It stands until the
 *    operator resumes it.
 *  - a FRESH-NAME hold (`countries`, `until`; code `fresh_name_blocked`): a
 *    detector replacement's new CDN name was found blocked in a country that
 *    triggered it BEFORE any member received it. Nobody could have given that
 *    name away, so the block is not about the name (a network there refuses
 *    every name on that provider), and another name would fare no better. Only
 *    automatic replacements answering to those countries are held, and only
 *    until `until`: one new name per hold period then checks whether the
 *    network has let go. A failed try costs a name nobody received, never a
 *    member's working address. The hold names the CDN provider whose name
 *    failed: a replacement that would go to another provider (or to a load
 *    balancer) is not held by it. Only a block found BEFORE the flip makes
 *    one: after the flip members may already have the name.
 *  - a CDN-REFUSED note (`countries`, `until`, `provider`; code `cdn_refused`):
 *    the detector's start was refused because that provider's reference site
 *    is refused from those countries too (lib/edges/referenceSites.ts). It
 *    holds nothing by itself (the start re-checks the reference sites each
 *    pass); it is what the node page and the attention list show, renewed
 *    each refused pass and gone soon after the refusals stop.
 *
 * Pure: the mutations in convex/edgeRotations.ts read and write the array.
 */

export type AutoReplaceHold = {
  listenerId: string;
  code: string;
  at: number;
  edgeId?: string;
  countries?: string[];
  until?: number;
  /** A fresh-name hold: the provider whose new name was blocked (absent = any). */
  provider?: string;
};

export const FRESH_NAME_BLOCKED = 'fresh_name_blocked';
export const CDN_REFUSED = 'cdn_refused';

/** A hold still in force: a fresh-name hold ends at `until`; a whole-transport one never does. */
export function holdLive(h: Pick<AutoReplaceHold, 'until'>, now: number): boolean {
  return h.until === undefined || h.until > now;
}

/** A hold that covers the whole transport (any country, any trigger reason). */
export function isWholeTransportHold(h: Pick<AutoReplaceHold, 'countries'>): boolean {
  return h.countries === undefined;
}

/**
 * The hold that refuses an automatic replacement of `listenerId` answering to
 * `affectedCountries`, or null. A whole-transport hold wins over a fresh-name
 * one. A fresh-name hold covers the start only when EVERY affected country is
 * one it holds: a block seen elsewhere too is a reason of its own. A start that
 * names no country (a reconcile run) is never covered by one. With `provider`
 * (the one the replacement would use), a fresh-name hold of another provider
 * does not cover it; without it (or null: not known), any provider's does.
 */
export function holdFor<H extends AutoReplaceHold>(
  holds: readonly H[] | undefined,
  listenerId: string,
  affectedCountries: readonly string[],
  now: number,
  provider?: string | null,
): H | null {
  const mine = (holds ?? []).filter((h) => h.listenerId === listenerId && holdLive(h, now));
  const whole = mine.find(isWholeTransportHold);
  if (whole) return whole;
  if (affectedCountries.length === 0) return null;
  return (
    mine.find(
      (h) =>
        h.code === FRESH_NAME_BLOCKED &&
        affectedCountries.every((c) => (h.countries ?? []).includes(c)) &&
        (provider == null || h.provider === undefined || h.provider === provider),
    ) ?? null
  );
}

/** The countries named by a `replacement_blocked` outcome's detail (`IR,CN`). */
export function countriesOfDetail(detail: string | undefined): string[] {
  const out = new Set<string>();
  for (const part of (detail ?? '').split(','))
    if (/^[A-Z]{2}$/.test(part.trim())) out.add(part.trim());
  return [...out].sort();
}

/**
 * The holds with a fresh-name hold for `listenerId` added or widened: one row
 * per transport and provider (its countries joined, its end moved to the later
 * one, its time kept from the first), expired fresh-name rows dropped.
 */
export function withFreshNameHold<H extends AutoReplaceHold>(
  holds: readonly H[] | undefined,
  add: {
    listenerId: string;
    countries: readonly string[];
    edgeId?: string;
    provider?: string;
    at: number;
    until: number;
  },
): AutoReplaceHold[] {
  const kept: AutoReplaceHold[] = (holds ?? []).filter((h) => holdLive(h, add.at));
  const i = kept.findIndex(
    (h) =>
      h.listenerId === add.listenerId &&
      h.code === FRESH_NAME_BLOCKED &&
      h.provider === add.provider,
  );
  if (i >= 0) {
    const prev = kept[i]!;
    kept[i] = {
      ...prev,
      countries: [...new Set([...(prev.countries ?? []), ...add.countries])].sort(),
      until: Math.max(prev.until ?? 0, add.until),
      ...(add.edgeId ? { edgeId: add.edgeId } : {}),
    };
    return kept;
  }
  return [
    ...kept,
    {
      listenerId: add.listenerId,
      code: FRESH_NAME_BLOCKED,
      at: add.at,
      ...(add.edgeId ? { edgeId: add.edgeId } : {}),
      countries: [...new Set(add.countries)].sort(),
      until: add.until,
      ...(add.provider ? { provider: add.provider } : {}),
    },
  ];
}

/**
 * The holds with the CDN-refused note for `listenerId` and `provider` set to
 * the countries refused NOW (replaced, not widened: the reference sites are
 * read afresh each pass), its first time kept, expired rows dropped.
 */
export function withCdnRefusedNote<H extends AutoReplaceHold>(
  holds: readonly H[] | undefined,
  add: {
    listenerId: string;
    countries: readonly string[];
    provider: string;
    edgeId?: string;
    at: number;
    until: number;
  },
): AutoReplaceHold[] {
  const kept: AutoReplaceHold[] = (holds ?? []).filter((h) => holdLive(h, add.at));
  const same = (h: AutoReplaceHold) =>
    h.listenerId === add.listenerId && h.code === CDN_REFUSED && h.provider === add.provider;
  const prev = kept.find(same);
  return [
    ...kept.filter((h) => !same(h)),
    {
      listenerId: add.listenerId,
      code: CDN_REFUSED,
      at: prev?.at ?? add.at,
      ...(add.edgeId ? { edgeId: add.edgeId } : {}),
      countries: [...new Set(add.countries)].sort(),
      until: add.until,
      provider: add.provider,
    },
  ];
}
