/**
 * Delivery cohorts (docs/edges.md § "Rendering", the rehearsal): one
 * representative subscription per distinct `backendPlacement` among the
 * subscriptions pinned to a relay's origin, derived from AUTHORITATIVE
 * membership (the subscriptions table), never from render snapshots (members
 * have none before the first binding).
 *
 * The walk is `paginate` over the `(backendServerId, state)` index, every
 * page, never truncated: the cohort set is small by construction (one squad
 * per node) but its size is measured, not assumed. A panel-node origin keeps
 * the subscriptions pinned to its node; a backend-server origin (Outline) is
 * one cohort of the whole server (no placement, no pin).
 */
import type { DatabaseReader } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';

export interface Cohort {
  /** The placement, or `none` for subscriptions without one (stable per relay). */
  key: string;
  placement: string | null;
  /** The representative: the first active subscription of the placement on the walk. */
  subscriptionId: Id<'subscriptions'>;
  backendServerId: Id<'backendServers'>;
  nodeName?: string;
}

const PAGE = 200;

export async function cohortsForOrigin(
  ctx: { db: DatabaseReader },
  origin: { backendServerId: Id<'backendServers'>; nodeName?: string | null },
): Promise<Cohort[]> {
  const byPlacement = new Map<string, Cohort>();
  let cursor: string | null = null;
  for (;;) {
    const page = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_state', (q) =>
        q.eq('backendServerId', origin.backendServerId).eq('state', 'active'),
      )
      .paginate({ cursor, numItems: PAGE });
    for (const sub of page.page) {
      if (origin.nodeName && sub.pinnedNode !== origin.nodeName) continue;
      const placement = sub.backendPlacement ?? null;
      const key = placement ?? 'none';
      if (byPlacement.has(key)) continue;
      byPlacement.set(key, {
        key,
        placement,
        subscriptionId: sub._id,
        backendServerId: origin.backendServerId,
        ...(origin.nodeName ? { nodeName: origin.nodeName } : {}),
      });
    }
    if (page.isDone) break;
    cursor = page.continueCursor;
  }
  return [...byPlacement.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export async function cohortsForRelay(
  ctx: { db: DatabaseReader },
  relay: Doc<'relays'>,
): Promise<Cohort[]> {
  if (!relay.backendServerId) return [];
  return cohortsForOrigin(ctx, {
    backendServerId: relay.backendServerId,
    nodeName: relay.origin.kind === 'panel-node' ? relay.nodeName : null,
  });
}
