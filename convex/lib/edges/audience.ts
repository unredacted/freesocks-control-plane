/**
 * Addresses only for some countries (pure; unit-tested). docs/edges.md
 * "Addresses only for some countries" is the contract; in short:
 *
 *  - A location meant for some countries (`edgeLocations.forCountries.codes`)
 *    may be ONLY for them (`forCountries.only`, since `only.since`). An address
 *    made there from then on gets the location's countries as its AUDIENCE
 *    when it is first published (`edges.audience`, frozen from then on), and a
 *    member is handed it only when their steered country is in it. Members
 *    with no country (none stored, the opt-out, a privacy-family key, a mirror
 *    without the member's choice, steering off) never are: it fails closed.
 *  - The taint rule is the address lanes' (lib/edges/lanes.ts `mayBeTrusted`):
 *    never an address made before the location was switched to only, never one
 *    published before (anyone may have been handed it), never an adopted one
 *    (or one FCP made nothing of),
 *    never one whose address FCP handed out before under another row.
 *  - A replacement for an address everyone may be handed never gets an
 *    audience; one for a contained address takes its own location's when that
 *    location is only for every country the replaced one served.
 *  - An "only" location holds only contained addresses from then on: an
 *    address there that cannot take the audience is never published.
 *  - A node's pick may hold countries of its own (`relays.providerSet[]
 *    .audiences`, docs/edges.md "Countries with their own addresses"): an
 *    address made for them carries them from the start (`edges.audienceIntent`)
 *    and takes them at its first publication wherever it is, under the same
 *    taint rule.
 */

/** A location's containment as stored (`edgeLocations.forCountries`). */
export interface LocationAudience {
  codes: readonly string[];
  only?: { since: number };
}

/** The countries an only location hands its new addresses to, or null when it is not only. */
export function onlyCodesOf(f: LocationAudience | null | undefined): string[] | null {
  if (!f?.only || f.codes.length === 0) return null;
  return [...new Set(f.codes)].sort();
}

/** Whether `a` holds every code of `b`. */
export function covers(a: readonly string[], b: readonly string[]): boolean {
  return b.every((c) => a.includes(c));
}

/** What an address's first publication does to its audience. */
export type AudienceAtPublish =
  /** Everyone may be handed it (not at an only location). */
  | { kind: 'everyone' }
  /** Contained: handed only to members in these countries. */
  | { kind: 'contained'; audience: string[] }
  /** At an only location but it cannot take the audience: never published. */
  | { kind: 'refused'; reason: 'audience_tainted' | 'audience_replaces_everyone' };

/**
 * The audience an address takes when it is FIRST published (`publishedAt`
 * absent). One published before keeps what it has (callers keep its stored
 * audience).
 */
export function audienceAtPublish(input: {
  edge: {
    _creationTime: number;
    publishedAt?: number;
    resources: ReadonlyArray<{ ownership?: string }>;
  };
  location: LocationAudience | null;
  /** FCP handed this address out before under another row (`edgeLanes.seenBefore`). */
  seenBefore: boolean;
  /**
   * The countries it was made for (`edges.audienceIntent`): they win over the
   * location's, and it was made for them, so no switch date applies.
   */
  made?: readonly string[] | null;
  /** A replace: the address it swaps out (its audience; absent = everyone's). */
  replacing?: { audience?: readonly string[] } | null;
}): AudienceAtPublish {
  const onlyHere = onlyCodesOf(input.location);
  // At a location only for some countries, its countries rule: an address made
  // for others (a pick's entry since removed) is never published there, and
  // one made for exactly them still keeps the location's switch-date rule.
  if (input.made?.length && onlyHere && !sameCodes(input.made, onlyHere))
    return { kind: 'refused', reason: 'audience_tainted' };
  const made = input.made?.length && !onlyHere ? [...new Set(input.made)].sort() : null;
  const codes = made ?? onlyHere;
  if (!codes) return { kind: 'everyone' };
  const e = input.edge;
  const clean =
    (made !== null || e._creationTime > input.location!.only!.since) &&
    e.publishedAt === undefined &&
    // FCP made it: at least one resource of its own, none adopted (an address
    // adopted with nothing to manage carries no resource at all).
    e.resources.length > 0 &&
    !e.resources.some((r) => r.ownership === 'adopted') &&
    !input.seenBefore;
  if (!clean) return { kind: 'refused', reason: 'audience_tainted' };
  if (input.replacing) {
    const was = input.replacing.audience;
    // An everyone address is replaced by an everyone address, elsewhere.
    if (!was || was.length === 0) return { kind: 'refused', reason: 'audience_replaces_everyone' };
    if (!covers(codes, was)) return { kind: 'refused', reason: 'audience_replaces_everyone' };
  }
  return { kind: 'contained', audience: codes };
}

/** Whether a member steered by `country` may be handed an address with this audience. */
export function inAudience(
  audience: readonly string[] | undefined,
  country: string | null,
): boolean {
  if (!audience || audience.length === 0) return true;
  return !!country && audience.includes(country);
}

/**
 * Whether automatic selection may use a location for a target: an only
 * location takes only a contained target whose audience it covers (a
 * replacement), or the count fill of that very location (`onlyLocationId`).
 * Any other location takes anything.
 */
export function locationTakes(
  location: LocationAudience | null,
  target: { audience?: readonly string[] | null; countFillHere?: boolean },
): boolean {
  const codes = onlyCodesOf(location);
  if (!codes) return true;
  if (target.countFillHere) return true;
  const a = target.audience;
  return !!a && a.length > 0 && covers(codes, a);
}

/** Whether two audiences name the same countries. */
export function sameCodes(a: readonly string[], b: readonly string[]): boolean {
  const x = [...new Set(a)].sort();
  const y = [...new Set(b)].sort();
  return x.length === y.length && x.every((c, i) => c === y[i]);
}

/** One entry of a pick's own countries as stored (`relays.providerSet[].audiences`). */
export interface PickAudience {
  codes: readonly string[];
  want?: number;
}

/** A node's pick as the audience rules read it. */
export interface PickAudiences {
  audiences?: readonly PickAudience[];
  audienceOnly?: boolean;
}

/**
 * The countries an address made at this pick is for (its `audienceIntent`), or
 * null for one everyone may be handed. `audience`: the countries the run is
 * for (a count's fill: exactly them; a contained replacement: an entry that
 * covers every country the replaced address served).
 */
export function pickIntentFor(
  pick: PickAudiences | null | undefined,
  audience: readonly string[] | null | undefined,
  how: 'exact' | 'covers',
): string[] | null {
  if (!pick || !audience?.length) return null;
  const hit = (pick.audiences ?? []).find((x) =>
    how === 'exact' ? sameCodes(x.codes, audience) : covers(x.codes, audience),
  );
  return hit ? [...new Set(hit.codes)].sort() : null;
}

/**
 * Whether automatic selection may use a node's pick for a target, by its own
 * countries: a fill for some countries only at a pick holding exactly them; a
 * pick that serves its countries only, only for a contained replacement one of
 * its entries covers (anything else made there would be everyone's). A
 * contained replacement may otherwise go anywhere a location allows (the picks
 * covering it rank first).
 */
export function pickTakes(
  pick: PickAudiences | null | undefined,
  target: { fillFor?: readonly string[] | null; audience?: readonly string[] | null },
): boolean {
  if (target.fillFor?.length) return pickIntentFor(pick, target.fillFor, 'exact') !== null;
  if (pick?.audienceOnly) return pickIntentFor(pick, target.audience, 'covers') !== null;
  return true;
}
