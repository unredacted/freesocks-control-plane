/**
 * Edges grouped by (provider, location), and what an edge counts as in one
 * country (pure; unit-tested). docs/edges.md "Countries: checks and delivery".
 *
 * Censors block ranges, so the edges of one provider location share their
 * fate in a country: two blocked edges there make the whole group blocked, and
 * an edge of that group with nothing decided of its own inherits it. A group
 * never PROVES an edge (only its own checks or a mark do). The account is not
 * part of the key: two accounts in one provider location share its ranges.
 */
import type { TrackState } from './verdict';

export interface GroupableEdge {
  _id: string;
  provider?: string | null;
  placeKey?: string | null;
  layer?: string | null;
  managed: boolean;
  addresses?: { hostname?: string | null };
}

/**
 * The ONE place an edge's group is computed: `<provider>:<placeKey>` for an
 * L4 edge created in a location, `<provider>:global` for a CDN front (an
 * anycast hostname has no location), `adopted:<edgeId>` for an imported edge
 * and `edge:<edgeId>` for an L4 edge without a recorded location (its own
 * group: nothing is inherited across places FCP cannot tell apart).
 */
export function countryGroupKey(e: GroupableEdge): string {
  const l7 = e.layer === 'l7' || !!e.addresses?.hostname;
  if (!e.managed || !e.provider) return `adopted:${e._id}`;
  if (l7) return `${e.provider}:global`;
  if (e.placeKey) return `${e.provider}:${e.placeKey}`;
  return `edge:${e._id}`;
}

/** The provider part of a group key (null for an edge's own group). */
export function providerOfGroup(groupKey: string): string | null {
  const [head] = groupKey.split(':');
  return head === 'adopted' || head === 'edge' ? null : (head ?? null);
}

export type GroupGrade = 'proven' | 'blocked' | 'mixed' | 'unknown';

export interface GradeInput {
  state: TrackState;
  until?: number;
}

/**
 * A group's grade in one country from its edges' combined states: `blocked`
 * when at least two are blocked, they are at least half of the decided ones
 * and none is proven; `proven` when one is proven and none blocked; both =
 * `mixed`; nothing decided = `unknown`. `until` is the earliest expiry among
 * the decided states it rests on.
 */
export function gradeOf(
  states: readonly GradeInput[],
  now: number,
): {
  state: GroupGrade;
  counts: { edges: number; proven: number; blocked: number };
  until?: number;
} {
  const live = states.filter(
    (s) => s.state !== 'unknown' && (s.until === undefined || s.until > now),
  );
  const proven = live.filter((s) => s.state === 'proven').length;
  const blocked = live.filter((s) => s.state === 'blocked').length;
  const counts = { edges: states.length, proven, blocked };
  const untils = live.map((s) => s.until).filter((u): u is number => u !== undefined);
  const until = untils.length > 0 ? Math.min(...untils) : undefined;
  let state: GroupGrade = 'unknown';
  if (blocked >= 2 && blocked * 2 >= live.length && proven === 0) state = 'blocked';
  else if (proven >= 1 && blocked === 0) state = 'proven';
  else if (proven > 0 && blocked > 0) state = 'mixed';
  return { state, counts, ...(until !== undefined ? { until } : {}) };
}

export type EffectiveFrom = 'edge' | 'group' | 'mark';

export interface Effective {
  state: TrackState;
  from?: EffectiveFrom;
  until?: number;
}

/**
 * What an edge counts as in one country, first that applies: its own mark,
 * its group's mark, its own decided state (not expired), its group's
 * `blocked` grade (not expired; inherited only by an edge with nothing decided
 * of its own), else unknown. An inherited `proven` stays unknown.
 */
export function effectiveState(a: {
  edgeMark: 'proven' | 'blocked' | null;
  groupMark: 'proven' | 'blocked' | null;
  own: { state: TrackState; until?: number } | null;
  grade: { state: GroupGrade; until?: number } | null;
  now: number;
}): Effective {
  if (a.edgeMark) return { state: a.edgeMark, from: 'mark' };
  if (a.groupMark) return { state: a.groupMark, from: 'mark' };
  const live = (u?: number) => u === undefined || u > a.now;
  if (a.own && a.own.state !== 'unknown' && live(a.own.until))
    return { state: a.own.state, from: 'edge', ...(a.own.until ? { until: a.own.until } : {}) };
  if (a.grade?.state === 'blocked' && live(a.grade.until))
    return { state: 'blocked', from: 'group', ...(a.grade.until ? { until: a.grade.until } : {}) };
  return { state: 'unknown' };
}

/**
 * Entries of an edge's `countryState` that still count at `now` (an entry
 * past its `until` reads as unknown: the guard for the hour between two
 * expiry passes).
 */
export function liveCountryState<T extends { until?: number }>(
  byCountry: readonly T[] | undefined,
  now: number,
): T[] {
  return (byCountry ?? []).filter((c) => c.until === undefined || c.until > now);
}
