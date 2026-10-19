/**
 * The checks from each country, read for one screen (pure; unit-tested). The
 * server judges everything (`GET countries`, convex/edgeCountry.ts); this only
 * picks the rows a screen shows. Words live in statusWords.ts.
 *
 * Exports:
 *   locationGroupKey(location)                the group key of a provider location (`<provider>:<placeKey>`,
 *                                             `<provider>:global` for a CDN front), as the server keys it
 *   edgeCountryLines(data, edgeId)            one entry per checked country: the edge's row and marks
 *   locationGrades(data, groupKey)            one cell per checked country: the grade, its age, the mark
 *   markConflict(mark, state)                 whether a mark disagrees with what the checks say
 *   edgeHasCountryData(data, edgeId)          the edge has evidence or a mark of its own
 *   newestRoundAt(edge)                       the edge's newest round on record (server time)
 *   checkPending(request, edge, now)          a check the page asked for has not come back yet
 *   CHECK_WAIT_MS                             how long a page waits for it at most
 */
import type {
  CountryGroupGradeRow,
  CountryMarkRow,
  EdgeCountriesEdge,
  EdgeCountriesResponse,
  EdgeCountryRow,
} from '../../../../../shared/contracts/edges';

/** A requested round settles within minutes; past this the page stops waiting for it. */
export const CHECK_WAIT_MS = 15 * 60_000;

/**
 * The group key of a provider location, exactly as the server's
 * `countryGroupKey` keys an edge created there: a CDN front's anycast name has
 * no location (`<provider>:global`), an L4 location is `<provider>:<placeKey>`.
 */
export function locationGroupKey(l: {
  provider: string;
  placeKey: string | null;
  layer: 'l4' | 'l7' | string;
}): string | null {
  if (l.layer === 'l7') return `${l.provider}:global`;
  return l.placeKey ? `${l.provider}:${l.placeKey}` : null;
}

export interface EdgeCountryLine {
  country: string;
  /** The edge's evidence there (null: never checked from there). */
  row: EdgeCountryRow | null;
  /** The operator's mark on this edge there. */
  edgeMark: CountryMarkRow | null;
  /** The operator's mark on the edge's location there. */
  groupMark: CountryMarkRow | null;
}

/** The edge in every checked country, in the order the server lists them. */
export function edgeCountryLines(
  data: EdgeCountriesResponse | null | undefined,
  edgeId: string,
): EdgeCountryLine[] {
  if (!data) return [];
  const edge = data.edges.find((e) => e.edgeId === edgeId) ?? null;
  return data.countries.map((country) => ({
    country,
    row: edge?.countries.find((c) => c.country === country) ?? null,
    edgeMark:
      data.marks.find((m) => m.scope === 'edge' && m.edgeId === edgeId && m.country === country) ??
      null,
    groupMark: edge
      ? (data.marks.find(
          (m) => m.scope === 'group' && m.groupKey === edge.groupKey && m.country === country,
        ) ?? null)
      : null,
  }));
}

export interface LocationGradeCell {
  country: string;
  /** The location's grade there (null: no edge of it was checked from there). */
  grade: CountryGroupGradeRow | null;
  /** The newest round of any of its edges there (ISO), for the age. */
  checkedAt: string | null;
  /** Edges of the location with a round there. */
  checkedEdges: number;
  /** The operator's mark on the location there. */
  mark: CountryMarkRow | null;
  /** The mark disagrees with the location's own checks. */
  conflict: boolean;
}

/** A location in every checked country. */
export function locationGrades(
  data: EdgeCountriesResponse | null | undefined,
  groupKey: string | null,
): LocationGradeCell[] {
  if (!data || !groupKey) return [];
  const edges = data.edges.filter((e) => e.groupKey === groupKey);
  return data.countries.map((country) => {
    const grade = data.groups.find((g) => g.groupKey === groupKey && g.country === country) ?? null;
    const rounds = edges
      .map((e) => e.countries.find((c) => c.country === country)?.lastRound?.at ?? null)
      .filter((at): at is string => at !== null);
    const mark =
      data.marks.find(
        (m) => m.scope === 'group' && m.groupKey === groupKey && m.country === country,
      ) ?? null;
    return {
      country,
      grade,
      checkedAt: rounds.length > 0 ? rounds.reduce((a, b) => (a > b ? a : b)) : null,
      checkedEdges: rounds.length,
      mark,
      conflict: markConflict(mark, grade?.state ?? 'unknown'),
    };
  });
}

/**
 * A mark disagrees with the checks when they say otherwise: a location marked
 * as working whose edges are (partly) blocked there, or one marked blocked
 * whose edges (partly) work. Not known never disagrees.
 */
export function markConflict(
  mark: Pick<CountryMarkRow, 'state'> | null,
  checks: 'proven' | 'blocked' | 'mixed' | 'unknown',
): boolean {
  if (!mark || checks === 'unknown') return false;
  if (checks === 'mixed') return true;
  return checks !== mark.state;
}

/** The edge has something to show without the checks running: evidence, or a mark on it. */
export function edgeHasCountryData(
  data: EdgeCountriesResponse | null | undefined,
  edgeId: string,
): boolean {
  if (!data) return false;
  return (
    data.edges.some((e) => e.edgeId === edgeId) ||
    data.marks.some((m) => m.scope === 'edge' && m.edgeId === edgeId)
  );
}

/** The newest round of the edge on record in any country (the server's clock), or null. */
export function newestRoundAt(edge: EdgeCountriesEdge | null | undefined): string | null {
  let newest: number | null = null;
  for (const c of edge?.countries ?? []) {
    const at = c.lastRound?.at ? Date.parse(c.lastRound.at) : NaN;
    if (Number.isFinite(at) && (newest === null || at > newest)) newest = at;
  }
  return newest === null ? null : new Date(newest).toISOString();
}

/** A "Check from every country now": when this tab asked (its clock) and the newest round then. */
export interface CheckRequest {
  at: number;
  before: string | null;
}

/**
 * A check the page asked for is still out: no round newer than the one on
 * record when it asked has come back (server times compared with each other,
 * never with this tab's clock), and it was asked less than CHECK_WAIT_MS ago.
 */
export function checkPending(
  request: CheckRequest,
  edge: EdgeCountriesEdge | null | undefined,
  now: number,
): boolean {
  if (now - request.at >= CHECK_WAIT_MS) return false;
  const newest = newestRoundAt(edge);
  if (newest === null) return true;
  return request.before !== null && Date.parse(newest) <= Date.parse(request.before);
}
