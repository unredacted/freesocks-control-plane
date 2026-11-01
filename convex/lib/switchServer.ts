/**
 * The decisions behind the member's "Switch server" action
 * (`account.switchServer`), shared with the read-only check the account view
 * projects (`switchServerAvailable`), so the SPA offers the button exactly when
 * the action can move the key. The action keeps the writes and the reasoning
 * comments; this file holds the conditions both sides must agree on.
 *
 * The action's three levers, cheapest first:
 *  1. another mode group on the key's own backend (an in-place move);
 *  2. another node of the key's current group (rotating the node pin);
 *  3. another mode group anywhere (a re-issue, possibly to another backend).
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { capabilitiesOf } from './backends/capabilities';
import { resolverFor } from './placement';
import { NODE_STATS_STALE_MS } from './remnawavePlacement';

/** Lever 1: the in-place pick is a different group than a KNOWN source. A
 *  legacy row with no recorded group proves nothing either way. */
export function inPlaceMoveProven(source: string | null, picked: string | null): boolean {
  return picked !== null && source !== null && picked !== source;
}

/** Lever 2's precondition: a FRESH stats snapshot shows another node in the
 *  key's group. Unknown or stale counts as unproven. */
export function groupHasOtherNode(
  stats: { nodeCount: number; lastStatsAt: number } | null,
  now: number,
): boolean {
  return stats != null && now - stats.lastStatsAt < NODE_STATS_STALE_MS && stats.nodeCount > 1;
}

/** Lever 3: the unpinned pick lands somewhere provably different: another
 *  group when the source is known, else another backend. */
export function crossPanelMoveProven(
  source: string | null,
  target: { placement: string | null; serverId: string | null },
  ownPanelId: string | null,
): boolean {
  return source !== null
    ? target.placement !== null && target.placement !== source
    : target.serverId !== null && target.serverId !== ownPanelId;
}

/**
 * Whether `account.switchServer` would move this member's key right now, read
 * without side effects. True also when the action would answer the retryable
 * `backend.placement_unresolved` (bring-up on a multi-backend deployment):
 * that state heals by itself, so the button stays.
 *
 * One deliberate difference from the action: when the key's instance row is
 * missing or inactive the action locates the key on the backends; a view never
 * calls a backend, so such a key reads as on an unknown backend.
 */
export async function switchServerAvailable(
  db: DatabaseReader,
  user: Doc<'users'>,
  tier: Doc<'tiers'>,
  sub: Doc<'subscriptions'> | null,
  now: number,
): Promise<boolean> {
  if (!sub) return false;
  const subCaps = capabilitiesOf(sub.backend);
  if (!subCaps.placement && !subCaps.nodePinning) return false;

  const modeId = user.connectionModeId ?? null;
  const source = sub.backendPlacement ?? null;
  const canPlaceBackend = capabilitiesOf(tier.backend).placement && sub.backend === tier.backend;
  const resolver = resolverFor(tier.backend);
  const canPlace = canPlaceBackend && !(await resolver.effectiveGate(db, modeId)).blocked;
  let ownPanelId: string | null = null;
  if (canPlaceBackend && sub.backendServerId) {
    const server = await db.get(sub.backendServerId);
    if (server?.isActive && server.backend === tier.backend) ownPanelId = server._id;
  }

  if (canPlace) {
    const { placement } = await resolver.resolveTarget(db, modeId, {
      onlyServerId: ownPanelId,
      excludePlacement: source,
    });
    if (inPlaceMoveProven(source, placement)) return true;
  }

  // Rotating needs a pin to rotate: a key no app has fetched since it was
  // issued or last moved has none, and the action would refuse.
  if (subCaps.nodePinning && source && sub.pinnedNode) {
    const stats = await db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', source))
      .unique();
    if (groupHasOtherNode(stats, now)) return true;
  }

  if (canPlace) {
    const target = await resolver.resolveTarget(db, modeId, {
      location: user.preferredLocation ?? null,
      excludePlacement: source,
    });
    if (target.unattributedMultiPanel || crossPanelMoveProven(source, target, ownPanelId))
      return true;
  }
  return false;
}
