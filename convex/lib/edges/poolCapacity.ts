/**
 * Pool capacity follows coverage (docs/edges.md § Publication): every deployed,
 * enabled, non-retired listener needs one published slot, so `desiredPublished`
 * is never left below the listener count, and a pool that is already full while
 * a listener is uncovered is EXPANDED (within the cap) so upkeep can cover it.
 * Shrinking is never automatic; at the cap the operator rebalances.
 *
 * Kept out of relays.ts so relayListeners.ts (which relays.ts imports) can call
 * it without a cycle: it reads the listener rows through the index directly.
 */
import type { MutationCtx } from '../../_generated/server';
import type { Doc } from '../../_generated/dataModel';
import { writeAuditLog } from '../audit';
import { MAX_DESIRED_PUBLISHED } from '../edgeConfig';
import { coverageListeners, freeSlotCount, publishedCount, uncoveredListeners } from './pool';

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

/** Pure: the `desiredPublished` a relay needs for its listeners. */
export function requiredPoolSize(input: {
  desiredPublished: number;
  publishedEdgeIds: readonly (string | null)[];
  listeners: readonly {
    id: string;
    templateEdgeId?: string | null;
    deployed: boolean;
    enabled: boolean;
    retired: boolean;
  }[];
}): PoolCapacityResult {
  const from = input.desiredPublished;
  let to = from;
  let raised = false;
  let expanded = false;
  const required = coverageListeners(input.listeners).length;
  if (to < required) {
    to = Math.min(MAX_DESIRED_PUBLISHED, required);
    raised = to > from;
  }
  const uncovered = uncoveredListeners(input.listeners).length;
  let blocked = 0;
  if (uncovered > 0 && freeSlotCount(input.publishedEdgeIds, to) === 0) {
    const want = Math.min(
      MAX_DESIRED_PUBLISHED,
      publishedCount(input.publishedEdgeIds) + uncovered,
    );
    if (want > to) {
      to = want;
      expanded = true;
    }
    blocked = Math.max(0, uncovered - freeSlotCount(input.publishedEdgeIds, to));
  }
  return { from, to, raised, expanded, blocked };
}

/**
 * Apply `requiredPoolSize` to a relay row. Never shrinks, never throws; a
 * deleting relay is left alone. Only an EXPANSION is audited (a raise at
 * registration rides in the registration's own audit row).
 */
export async function ensurePoolCapacity(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
): Promise<PoolCapacityResult> {
  const listeners = await ctx.db
    .query('relayListeners')
    .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
    .collect();
  const r = requiredPoolSize({
    desiredPublished: relay.desiredPublished,
    publishedEdgeIds: relay.publishedEdgeIds,
    listeners: listeners.map((l) => ({
      id: l._id as string,
      templateEdgeId: (l.templateEdgeId as string | undefined) ?? null,
      deployed: l.deployed,
      enabled: l.enabled,
      retired: l.retired,
    })),
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
