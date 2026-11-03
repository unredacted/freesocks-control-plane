/**
 * Locations meant for a country (docs/edges.md "Locations meant for a
 * country"): the operator's statement that a place serves members in some
 * listed countries best. Pure; the assignment reads it as `PublishedEdge.meantFor`
 * (lib/edges/assignment.ts), the location row stores it (`edgeLocations.forCountries`).
 */
import { ANYCAST_PLACE } from './locations';
import { assignEndpoints, type AssignOptions, type PublishedEdge } from './assignment';
import { EDGE_PICK_SAMPLE, sampleSeat } from './edgePick';

/** Countries one location may be meant for. */
export const MAX_MEANT_FOR = 8;

export type MeantForRefusal = 'meant_for_unlisted' | 'meant_for_too_many';

/**
 * The codes as stored: trimmed, upper case, each once, in the order given.
 * Every one must be on the censored-country list (a member elsewhere has no
 * stored country to be steered by), at most `MAX_MEANT_FOR` of them.
 */
export function cleanMeantFor(
  codes: readonly string[],
  listed: readonly string[],
): { ok: true; codes: string[] } | { ok: false; code: MeantForRefusal; country?: string } {
  const out: string[] = [];
  for (const raw of codes) {
    const c = raw.trim().toUpperCase();
    if (!c || out.includes(c)) continue;
    if (!listed.includes(c)) return { ok: false, code: 'meant_for_unlisted', country: c };
    out.push(c);
  }
  if (out.length > MAX_MEANT_FOR) return { ok: false, code: 'meant_for_too_many' };
  return { ok: true, codes: out };
}

/** The countries whose members an edit moves: added or removed, each once, sorted. */
export function changedCountries(before: readonly string[], after: readonly string[]): string[] {
  const out = new Set<string>();
  for (const c of before) if (!after.includes(c)) out.add(c);
  for (const c of after) if (!before.includes(c)) out.add(c);
  return [...out].sort();
}

/**
 * The country group a location's addresses grade in (`countryGroupKey`): a
 * CDN zone's fronts share `<provider>:global`, every other place is
 * `<provider>:<placeKey>`.
 */
export function groupKeyOfLocation(l: { provider: string; placeKey: string }): string {
  return l.placeKey === ANYCAST_PLACE ? `${l.provider}:global` : `${l.provider}:${l.placeKey}`;
}

/**
 * Whether a location meant for `country` is blocked there, for the attention
 * item and the country view: an operator's mark on the location, its grade
 * (two blocked addresses, at least half of the decided ones, none proven), or
 * every published address of it there blocked (`edges.countryState`).
 */
export function meantForBlocked(input: {
  groupMark: 'proven' | 'blocked' | null;
  grade: string | null;
  /** Each published address of the location: blocked there or not. */
  published: readonly boolean[];
}): boolean {
  if (input.groupMark === 'proven') return false;
  if (input.groupMark === 'blocked' || input.grade === 'blocked') return true;
  return input.published.length > 0 && input.published.every(Boolean);
}

/** What one edit of a location's countries does to the members of one country on one node. */
export interface FirstMoves {
  /** Seats sampled that are handed an address at all. */
  sampled: number;
  /** Of those, how many get a different first address. */
  moved: number;
}

/**
 * How many sampled seats in `country` get a different FIRST address when the
 * pool goes from `before` to `after` (the same edges, their `meantFor`
 * edited), as a member steered by that country: the estimate the edit dialog
 * shows before anything is saved. Synthetic seats, no member row.
 */
export function firstAddressMoves(
  before: readonly PublishedEdge[],
  after: readonly PublishedEdge[],
  country: string,
  opts: Omit<AssignOptions, 'edgeCountry' | 'where'> & { curated: readonly string[] },
  sample = EDGE_PICK_SAMPLE,
): FirstMoves {
  const { curated, ...rest } = opts;
  const at = { ...rest, edgeCountry: country, where: { country, curated } };
  let sampled = 0;
  let moved = 0;
  for (let i = 0; i < sample; i++) {
    const seat = sampleSeat(i);
    const was = assignEndpoints(seat, before, at).primary?.edge.edgeId;
    if (!was) continue;
    sampled++;
    if (assignEndpoints(seat, after, at).primary?.edge.edgeId !== was) moved++;
  }
  return { sampled, moved };
}
