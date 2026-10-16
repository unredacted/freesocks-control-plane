/**
 * Member COHORTS of an origin: one representative subscription per distinct
 * `backendPlacement` among the active keys pinned to the origin's node (or,
 * for a whole-server origin, every active key of the server). Derived from
 * authoritative membership, never from render snapshots (a member has none
 * before the first binding).
 *
 * The walk never reads every key: the subscriptions indexes end in the
 * placement (`by_backend_server_pinned`, `by_backend_server_state`), so each
 * step reads the FIRST key of the next distinct placement and skips the rest
 * of that placement's keys. A step is one read per cohort, a page is at most
 * COHORT_PAGE of them, and the pages are driven from an action
 * (`edgeCohorts.walk`), so no transaction's read grows with the member count.
 * Keys without a placement (absent or empty) form the `default` cohort.
 */
import type { DatabaseReader } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';

export interface Cohort {
  /** The placement handle, or `default` for keys without one. */
  key: string;
  placement: string | null;
  subscriptionId: Id<'subscriptions'>;
  backendServerId: Id<'backendServers'>;
  nodeName?: string;
}

export interface CohortOrigin {
  backendServerId: Id<'backendServers'>;
  /** Absent = the whole backend server (Outline, a backend-server origin). */
  nodeName?: string;
}

/**
 * Where a walk stands: `default` = the keys without a placement are still to
 * be looked at; `named` = the named placements after `after` (null = from the
 * first). A finished walk has no cursor.
 */
export type CohortCursor = { phase: 'default' } | { phase: 'named'; after: string | null };

export interface CohortPage {
  cohorts: Cohort[];
  /** null = the walk is complete. */
  next: CohortCursor | null;
}

/** Distinct placements one page may look at (each is one index read). */
export const COHORT_PAGE = 50;
/**
 * Placements are operator-scale (mode groups). A walk that finds more than
 * this many refuses (`edge.cohorts_unbounded`) rather than judge a partial
 * membership: the restore and the rehearsal fail closed.
 */
export const MAX_COHORTS = 5000;

export function cohortKeyOf(placement: string | null | undefined): string {
  return placement && placement.length > 0 ? placement : 'default';
}

/** The first active key of the origin whose placement satisfies `range` (one read). */
async function firstKey(
  db: DatabaseReader,
  origin: CohortOrigin,
  range: { op: 'eq'; value: string | undefined } | { op: 'gt'; value: string },
): Promise<Doc<'subscriptions'> | null> {
  if (origin.nodeName !== undefined) {
    const nodeName = origin.nodeName;
    return await db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (ix) => {
        const base = ix
          .eq('backendServerId', origin.backendServerId)
          .eq('pinnedNode', nodeName)
          .eq('state', 'active');
        return range.op === 'eq'
          ? base.eq('backendPlacement', range.value)
          : base.gt('backendPlacement', range.value);
      })
      .first();
  }
  return await db
    .query('subscriptions')
    .withIndex('by_backend_server_state', (ix) => {
      const base = ix.eq('backendServerId', origin.backendServerId).eq('state', 'active');
      return range.op === 'eq'
        ? base.eq('backendPlacement', range.value)
        : base.gt('backendPlacement', range.value);
    })
    .first();
}

function cohortOf(origin: CohortOrigin, s: Doc<'subscriptions'>): Cohort {
  return {
    key: cohortKeyOf(s.backendPlacement),
    placement: s.backendPlacement ? s.backendPlacement : null,
    subscriptionId: s._id,
    backendServerId: origin.backendServerId,
    ...(origin.nodeName ? { nodeName: origin.nodeName } : {}),
  };
}

/**
 * One page of the walk (at most `limit` cohorts, about as many reads). Start
 * with `cursor` null; feed `next` back until it is null.
 */
export async function cohortPage(
  ctx: { db: DatabaseReader },
  origin: CohortOrigin,
  cursor: CohortCursor | null,
  limit = COHORT_PAGE,
): Promise<CohortPage> {
  const cohorts: Cohort[] = [];
  let at: CohortCursor = cursor ?? { phase: 'default' };
  if (at.phase === 'default') {
    // The default cohort: a key with no placement, else one with an empty one.
    const s =
      (await firstKey(ctx.db, origin, { op: 'eq', value: undefined })) ??
      (await firstKey(ctx.db, origin, { op: 'eq', value: '' }));
    if (s) cohorts.push(cohortOf(origin, s));
    at = { phase: 'named', after: null };
  }
  let after = at.after;
  while (cohorts.length < limit) {
    const s = await firstKey(ctx.db, origin, { op: 'gt', value: after ?? '' });
    if (!s || !s.backendPlacement) return { cohorts, next: null };
    cohorts.push(cohortOf(origin, s));
    after = s.backendPlacement;
  }
  return { cohorts, next: { phase: 'named', after } };
}

export function cohortOriginOf(relay: Doc<'relays'>): CohortOrigin | null {
  if (!relay.backendServerId) return null; // a manual origin serves nothing
  return {
    backendServerId: relay.backendServerId,
    ...(relay.nodeName ? { nodeName: relay.nodeName } : {}),
  };
}
