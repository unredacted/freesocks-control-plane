/**
 * Pool capacity follows coverage (docs/edges.md § Publication): every deployed,
 * enabled, non-retired listener needs one published slot, so `desiredPublished`
 * is never left below the listener count, and a pool whose free slots cannot
 * hold the coverage deficit is EXPANDED (within the cap) so upkeep can fill it.
 * Shrinking is never automatic; at the cap the operator rebalances.
 *
 * Kept out of origins.ts so relayListeners.ts (which origins.ts imports) can call
 * it without a cycle: it reads the listener rows through the index directly.
 */
import type { MutationCtx } from '../../_generated/server';
import type { Doc } from '../../_generated/dataModel';
import { writeAuditLog } from '../audit';
import { MAX_DESIRED_PUBLISHED } from '../edgeConfig';
import { freeSlotCount } from './pool';
import { setStateOf } from './setState';

export interface PoolCapacityResult {
  /** `desiredPublished` before / after (equal when nothing changed). */
  from: number;
  to: number;
  /** Raised so every coverage listener has a slot (`edge.pool_raised`). */
  raised: boolean;
  /** Expanded a full pool to make room for an uncovered listener (`edge.pool_expanded`, audited). */
  expanded: boolean;
  /** Uncovered coverage listeners that no expansion can make room for (the cap is reached). */
  blocked: number;
}

/**
 * Pure: the `desiredPublished` an origin needs. Never below the coverage
 * listener count, and when the free slots cannot hold the coverage deficit
 * (lib/edges/providerSet.ts: a listener, a diversity group or a pick of the
 * provider set without an address) the pool is expanded to published + what
 * is missing, within the cap. `blocked` is what no expansion can make room for.
 */
export function requiredPoolSize(input: {
  desiredPublished: number;
  publishedEdgeIds: readonly (string | null)[];
  coverageListeners: number;
  deficit: number;
}): PoolCapacityResult {
  const from = input.desiredPublished;
  let to = from;
  let raised = false;
  let expanded = false;
  if (to < input.coverageListeners) {
    to = Math.min(MAX_DESIRED_PUBLISHED, input.coverageListeners);
    raised = to > from;
  }
  const free = freeSlotCount(input.publishedEdgeIds, to);
  if (input.deficit > free) {
    const want = Math.min(MAX_DESIRED_PUBLISHED, to + (input.deficit - free));
    if (want > to) {
      to = want;
      expanded = true;
    }
  }
  const blocked = Math.max(0, input.deficit - freeSlotCount(input.publishedEdgeIds, to));
  return { from, to, raised, expanded, blocked };
}

/**
 * Apply `requiredPoolSize` to an origin row. Never shrinks, never throws; a
 * deleting origin is left alone. Only an EXPANSION is audited (a raise at
 * registration rides in the registration's own audit row).
 */
export async function ensurePoolCapacity(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
): Promise<PoolCapacityResult> {
  const state = await setStateOf(ctx.db, relay);
  const r = requiredPoolSize({
    desiredPublished: relay.desiredPublished,
    publishedEdgeIds: relay.publishedEdgeIds,
    coverageListeners: state.listeners.length,
    deficit: state.deficit,
  });
  if (relay.deleting || r.to === r.from)
    return { ...r, to: r.from, raised: false, expanded: false };
  await ctx.db.patch(relay._id, { desiredPublished: r.to, updatedAt: Date.now() });
  if (r.expanded) {
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.pool_expanded',
      targetType: 'relay',
      targetId: relay._id,
      payload: { relaySlug: relay.slug, from: r.from, to: r.to, blocked: r.blocked },
    });
  }
  return r;
}
