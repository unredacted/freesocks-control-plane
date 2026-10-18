/**
 * Pure helpers for an origin's PUBLISHED pool (`origins.publishedEdgeIds`,
 * ordered by pool index, nulls are gaps). Generic over the id type so the
 * `Id<'edges'>` brand survives a round trip.
 */

/**
 * Every edge status that is NOT `destroyed`. Reads that must exclude destroyed
 * rows iterate these against the `(relayId|accountId, status)` indexes instead
 * of collecting the whole table and filtering: an origin accumulates destroyed
 * edges forever (they are pruned after 30 days), so an unbounded collect grows
 * without limit and eventually crosses Convex's read cap.
 */
export const EDGE_LIVE_STATUSES = [
  'planning',
  'provisioning',
  'verifying',
  'active',
  'draining',
  'destroying',
  'failed',
  'cancelled',
  'quarantined',
  'needs_operator',
] as const;

export type EdgeLiveStatus = (typeof EDGE_LIVE_STATUSES)[number];

/** Rows read per status per live-edge scan: an origin/account far past this is a bug, not a pool. */
export const LIVE_EDGE_SCAN_LIMIT = 200;

export function nextFreePoolIndex(
  published: readonly (string | null)[],
  desired: number,
): number | null {
  for (let i = 0; i < Math.max(desired, published.length); i++) {
    if (i < desired && (published[i] === null || published[i] === undefined)) return i;
  }
  return null;
}

/** Free (null / missing) slots under `desired`. */
export function freeSlotCount(published: readonly (string | null)[], desired: number): number {
  let n = 0;
  for (let i = 0; i < desired; i++) {
    if (published[i] === null || published[i] === undefined) n++;
  }
  return n;
}

/** The listener facts the coverage rules read (a projection of `relayListeners`). */
export interface PoolListener {
  id: string;
  templateEdgeId?: string | null;
  deployed: boolean;
  enabled: boolean;
  retired: boolean;
}

/** Listeners the pool must cover: deployed, enabled and not retired. */
export function coverageListeners<L extends PoolListener>(listeners: readonly L[]): L[] {
  return listeners.filter((l) => l.deployed && l.enabled && !l.retired);
}

/** Coverage listeners with no template edge (nothing published serves them). */
export function uncoveredListeners<L extends PoolListener>(listeners: readonly L[]): L[] {
  return coverageListeners(listeners).filter((l) => !l.templateEdgeId);
}

export type PoolAllocation = { index: number } | { refused: 'pool_full' | 'pool_reserved' };

/** What one more publication does to the origin's coverage deficit (`setState.admissionOf`). */
export interface PoolAdmit {
  lowersDeficit: boolean;
  deficit: number;
}

/**
 * Reserved allocation (docs/edges.md § Publication): the free slots of a pool
 * are held for what the origin still lacks, its coverage DEFICIT (a listener
 * with nothing published, a group or a pick of its provider set without an
 * address; lib/edges/providerSet.ts). An edge that lowers the deficit gets the
 * lowest free index; any other edge only while the free slots exceed the
 * deficit (`pool_reserved` otherwise), so a second copy for A can never take
 * the slot B is waiting for. No free slot at all is `pool_full`. A shortfall
 * only a cooling pick could fill is not part of the deficit: reserved slots
 * never hold healthy work hostage.
 */
export function allocatePoolIndex(
  published: readonly (string | null)[],
  desired: number,
  admit: PoolAdmit,
): PoolAllocation {
  const index = nextFreePoolIndex(published, desired);
  if (index === null) return { refused: 'pool_full' };
  if (admit.lowersDeficit) return { index };
  if (freeSlotCount(published, desired) <= admit.deficit) return { refused: 'pool_reserved' };
  return { index };
}

export function withEdgeAt<T extends string>(
  published: readonly (T | null)[],
  index: number,
  edgeId: T,
): (T | null)[] {
  const out: (T | null)[] = [...published];
  while (out.length <= index) out.push(null);
  out[index] = edgeId;
  return out;
}

export function withoutEdge<T extends string>(
  published: readonly (T | null)[],
  edgeId: T,
): (T | null)[] {
  const out = published.map((e) => (e === edgeId ? null : e));
  // Trim trailing gaps so `publishedCount` and indexes stay tidy.
  while (out.length > 0 && out[out.length - 1] === null) out.pop();
  return out;
}

export function publishedCount(published: readonly (string | null)[]): number {
  return published.filter((e) => e !== null).length;
}
