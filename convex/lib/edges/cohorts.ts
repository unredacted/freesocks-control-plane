/**
 * Member COHORTS of an origin origin: one representative subscription per
 * distinct `backendPlacement` among the active keys pinned to the origin's node
 * (or, for a whole-server origin, every active key of the server). Derived from
 * authoritative membership, never from render snapshots (a member has none
 * before the first binding). The keys are walked page by page over an index,
 * every page, never truncated; the size is REPORTED, never assumed.
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

export interface CohortReport {
  cohorts: Cohort[];
  /** Active keys walked (every page). */
  total: number;
}

export interface CohortOrigin {
  backendServerId: Id<'backendServers'>;
  /** Absent = the whole backend server (Outline, a backend-server origin). */
  nodeName?: string;
}

const PAGE = 200;

export function cohortKeyOf(placement: string | null | undefined): string {
  return placement && placement.length > 0 ? placement : 'default';
}

/** Every cohort of an origin plus how many keys were walked. */
export async function cohortReportForOrigin(
  ctx: { db: DatabaseReader },
  origin: CohortOrigin,
): Promise<CohortReport> {
  const seen = new Map<string, Cohort>();
  let total = 0;
  let cursor: string | null = null;
  for (;;) {
    const page: { page: Doc<'subscriptions'>[]; isDone: boolean; continueCursor: string } =
      origin.nodeName
        ? await ctx.db
            .query('subscriptions')
            .withIndex('by_backend_server_pinned', (q) =>
              q
                .eq('backendServerId', origin.backendServerId)
                .eq('pinnedNode', origin.nodeName)
                .eq('state', 'active'),
            )
            .paginate({ cursor, numItems: PAGE })
        : await ctx.db
            .query('subscriptions')
            .withIndex('by_backend_server_state', (q) =>
              q.eq('backendServerId', origin.backendServerId).eq('state', 'active'),
            )
            .paginate({ cursor, numItems: PAGE });
    for (const s of page.page) {
      total++;
      const key = cohortKeyOf(s.backendPlacement);
      if (!seen.has(key)) {
        seen.set(key, {
          key,
          placement: s.backendPlacement ?? null,
          subscriptionId: s._id,
          backendServerId: origin.backendServerId,
          ...(origin.nodeName ? { nodeName: origin.nodeName } : {}),
        });
      }
    }
    if (page.isDone) break;
    cursor = page.continueCursor;
  }
  return { cohorts: [...seen.values()], total };
}

export async function cohortsForOrigin(
  ctx: { db: DatabaseReader },
  origin: CohortOrigin,
): Promise<Cohort[]> {
  return (await cohortReportForOrigin(ctx, origin)).cohorts;
}

function originOf(relay: Doc<'relays'>): CohortOrigin | null {
  if (!relay.backendServerId) return null;
  return {
    backendServerId: relay.backendServerId,
    ...(relay.nodeName ? { nodeName: relay.nodeName } : {}),
  };
}

export async function cohortReportForRelay(
  ctx: { db: DatabaseReader },
  relay: Doc<'relays'>,
): Promise<CohortReport> {
  const origin = originOf(relay);
  if (!origin) return { cohorts: [], total: 0 }; // a manual origin serves nothing
  return cohortReportForOrigin(ctx, origin);
}

export async function cohortsForRelay(
  ctx: { db: DatabaseReader },
  relay: Doc<'relays'>,
): Promise<Cohort[]> {
  return (await cohortReportForRelay(ctx, relay)).cohorts;
}
