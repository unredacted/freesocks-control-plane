/**
 * Locations meant for a country (docs/edges.md "Locations meant for a
 * country"): the operator's statement that a place serves members in some
 * listed countries best. Pure; the assignment reads it as `PublishedEdge.meantFor`
 * (lib/edges/assignment.ts), the location row stores it (`edgeLocations.forCountries`).
 */
import { ANYCAST_PLACE } from './locations';
import {
  assignEndpoints,
  type Assignment,
  type AssignOptions,
  type PublishedEdge,
} from './assignment';
import { EDGE_PICK_SAMPLE, sampleSeat } from './edgePick';

/** Countries one location may be meant for. */
export const MAX_MEANT_FOR = 8;

export type MeantForRefusal = 'meant_for_unlisted' | 'meant_for_too_many';

/**
 * The codes as stored: trimmed, upper case, each once, in the order given.
 * A code ADDED must be on the censored-country list (a member elsewhere has no
 * stored country to be steered by); one the location already had (`stored`)
 * may stay after it left the list, so an edit never has to drop it first, and
 * leaving it out removes it. At most `MAX_MEANT_FOR` of them.
 */
export function cleanMeantFor(
  codes: readonly string[],
  listed: readonly string[],
  stored: readonly string[] = [],
): { ok: true; codes: string[] } | { ok: false; code: MeantForRefusal; country?: string } {
  const out: string[] = [];
  for (const raw of codes) {
    const c = raw.trim().toUpperCase();
    if (!c || out.includes(c)) continue;
    if (!listed.includes(c) && !stored.includes(c))
      return { ok: false, code: 'meant_for_unlisted', country: c };
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
 * A group grade as it counts now: its state while its `until` has not passed
 * (absent = no expiry), else none. The hourly expiry worker deletes or
 * rewrites a lapsed grade later; until then it must not count.
 */
export function liveGrade(
  grade: { state: string; until?: number } | null | undefined,
  now: number,
): string | null {
  if (!grade) return null;
  return grade.until === undefined || grade.until > now ? grade.state : null;
}

/**
 * The endpoint a body hands out first: the backup where the render rule puts
 * it first (`order: 'backup-first'`, backup on) and one was assigned, else the
 * primary (render.ts `deliveryPathsOf`).
 */
export function firstEndpointOf(
  a: Pick<Assignment, 'primary' | 'backup'>,
  backupFirst: boolean,
): Assignment['primary'] {
  return backupFirst && a.backup ? a.backup : a.primary;
}

/** Whether the endpoint handed out first is at a location meant for the member's country. */
export function firstMeantFor(a: Assignment, backupFirst: boolean): boolean {
  return backupFirst && a.backup ? a.backupMeantFor === true : a.primaryMeantFor === true;
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
 * shows before anything is saved. The first address is the one the body hands
 * out first (`backupFirst`: the backup, where the rule puts it first).
 * Synthetic seats, no member row.
 */
export function firstAddressMoves(
  before: readonly PublishedEdge[],
  after: readonly PublishedEdge[],
  country: string,
  opts: Omit<AssignOptions, 'edgeCountry' | 'where'> & {
    curated: readonly string[];
    backupFirst?: boolean;
  },
  sample = EDGE_PICK_SAMPLE,
): FirstMoves {
  const { curated, backupFirst = false, ...rest } = opts;
  const at = { ...rest, edgeCountry: country, where: { country, curated } };
  const firstOf = (pool: readonly PublishedEdge[], seat: string) =>
    firstEndpointOf(assignEndpoints(seat, pool, at), backupFirst)?.edge.edgeId;
  let sampled = 0;
  let moved = 0;
  for (let i = 0; i < sample; i++) {
    const seat = sampleSeat(i);
    const was = firstOf(before, seat);
    if (!was) continue;
    sampled++;
    if (firstOf(after, seat) !== was) moved++;
  }
  return { sampled, moved };
}
