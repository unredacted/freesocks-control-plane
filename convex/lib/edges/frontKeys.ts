/**
 * The keys that still hold a node's operator fronts (docs/edges.md
 * "Direct-Host hides and the restore workflow"): an app that has not fetched
 * its subscription since the node's binding was claimed still has the body
 * from before, the operator's front in it, and connects through it. The count
 * lives on the relay (`relays.frontKeys`, convex/edgeFrontKeys.ts); these are
 * the pure rules for when it is due and when it still describes the binding.
 */

export interface FrontKeysRecord {
  at: number;
  /** The binding's `updatedAt` the keys were judged against. */
  since: number;
  stale: number;
  total: number;
}

/** How often a node with fronts is counted again (keys refresh slowly; a count pages every key). */
export const FRONT_KEYS_EVERY_MS = 60 * 60_000;

/** Keys one count page reads (whole subscription rows, cached bodies included). */
export const FRONT_KEYS_PAGE = 50;

/** Whether a node with fronts should be counted again. */
export function frontKeysDue(rec: FrontKeysRecord | undefined | null, now: number): boolean {
  return !rec || now - rec.at >= FRONT_KEYS_EVERY_MS;
}

/** Whether a key has not fetched its subscription since `since` (never fetched counts too). */
export function keyIsStale(lastDeliveredAt: number | undefined, since: number): boolean {
  return (lastDeliveredAt ?? 0) < since;
}

/**
 * The count, when it was made against this binding (a binding claimed again
 * since moves the boundary, so an older count no longer says anything). Null:
 * no count, or one for another claim.
 */
export function frontKeysFor(
  rec: FrontKeysRecord | undefined | null,
  binding: { updatedAt: number } | null | undefined,
): { stale: number; total: number; at: number } | null {
  if (!rec || !binding || rec.since !== binding.updatedAt) return null;
  return { stale: rec.stale, total: rec.total, at: rec.at };
}
