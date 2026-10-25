/**
 * The cohort walk, driven from an action (lib/edges/cohorts.ts): each page is
 * its own query of at most COHORT_PAGE index reads, so the restore workflow,
 * the rehearsal and the setup plan never read an origin's keys in one
 * transaction, however many members it has.
 */
import { ConvexError, v } from 'convex/values';
import { internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import {
  MAX_CANDIDATES,
  MAX_COHORTS,
  cohortCandidates,
  cohortOriginOf,
  cohortPage,
  type Cohort,
  type CohortCursor,
  type CohortOrigin,
  type CohortPage,
} from './lib/edges/cohorts';

const cursorValidator = v.union(
  v.null(),
  v.object({ phase: v.literal('default') }),
  v.object({ phase: v.literal('named'), after: v.union(v.string(), v.null()) }),
);

export const cohortValidator = v.object({
  key: v.string(),
  placement: v.union(v.string(), v.null()),
  subscriptionId: v.id('subscriptions'),
  backendServerId: v.id('backendServers'),
  nodeName: v.optional(v.string()),
});

export const page = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.optional(v.string()),
    cursor: cursorValidator,
  },
  handler: (ctx, a): Promise<CohortPage> =>
    cohortPage(
      ctx,
      { backendServerId: a.backendServerId, ...(a.nodeName ? { nodeName: a.nodeName } : {}) },
      a.cursor as CohortCursor | null,
    ),
});

/** One candidate representative of a cohort: what a body fetch needs. */
export interface CohortCandidate {
  subscriptionId: Id<'subscriptions'>;
  backendShortId: string;
  subscriptionUrl: string;
  renderKey: string | null;
  excludeNode: string | null;
}

/**
 * Up to `limit` candidate representatives of one cohort (lib/edges/cohorts.ts
 * `cohortCandidates`), members whose account is active first, then the rest,
 * each group in index order. The rehearsal walks them when a key's body is
 * the backend's placeholder or resolves to another node.
 */
export const candidates = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.optional(v.string()),
    placement: v.union(v.string(), v.null()),
    limit: v.number(),
  },
  handler: async (ctx, a): Promise<CohortCandidate[]> => {
    const subs = await cohortCandidates(
      ctx.db,
      { backendServerId: a.backendServerId, ...(a.nodeName ? { nodeName: a.nodeName } : {}) },
      a.placement,
      Math.max(1, Math.min(a.limit, MAX_CANDIDATES)),
    );
    const active: CohortCandidate[] = [];
    const rest: CohortCandidate[] = [];
    for (const s of subs) {
      const user = await ctx.db.get(s.userId);
      const ref: CohortCandidate = {
        subscriptionId: s._id,
        backendShortId: s.backendShortId,
        subscriptionUrl: s.subscriptionUrl,
        renderKey: s.renderKey ?? null,
        excludeNode: s.excludeNode ?? null,
      };
      (user?.status === 'active' ? active : rest).push(ref);
    }
    return [...active, ...rest];
  },
});

/** The cohort origin of a relay (null: a manual origin serves nobody; or no such relay). */
export const originOfRelay = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<CohortOrigin | null> => {
    const relay = await ctx.db.get(relayId);
    return relay ? cohortOriginOf(relay) : null;
  },
});

/**
 * Every cohort of an origin, page by page. Never a partial answer: past
 * MAX_COHORTS it throws `edge.cohorts_unbounded`, so a check that needs every
 * cohort fails closed instead of judging some of them.
 */
export async function walkCohorts(ctx: ActionCtx, origin: CohortOrigin): Promise<Cohort[]> {
  const out: Cohort[] = [];
  let cursor: CohortCursor | null = null;
  for (;;) {
    const p: CohortPage = await ctx.runQuery(internal.edgeCohorts.page, {
      backendServerId: origin.backendServerId,
      ...(origin.nodeName ? { nodeName: origin.nodeName } : {}),
      cursor,
    });
    out.push(...p.cohorts);
    if (out.length > MAX_COHORTS)
      throw new ConvexError({
        code: 'edge.cohorts_unbounded',
        message: `More than ${MAX_COHORTS} member placements on one origin`,
      });
    if (!p.next) return out;
    cursor = p.next;
  }
}

/** Every cohort of a relay ([] for a manual origin). */
export async function walkRelayCohorts(ctx: ActionCtx, relayId: Id<'relays'>): Promise<Cohort[]> {
  const origin: CohortOrigin | null = await ctx.runQuery(internal.edgeCohorts.originOfRelay, {
    relayId,
  });
  return origin ? walkCohorts(ctx, origin) : [];
}
