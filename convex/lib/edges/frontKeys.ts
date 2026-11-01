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

/**
 * Whether a node with fronts should be counted again: never counted, counted
 * against another claim of its binding (`claimedAt`, the binding's
 * `updatedAt`; a re-claim moves the boundary, so the old count is hidden and a
 * new one is due at once), or counted over an hour ago.
 */
export function frontKeysDue(
  rec: FrontKeysRecord | undefined | null,
  claimedAt: number | null,
  now: number,
): boolean {
  return !rec || rec.since !== claimedAt || now - rec.at >= FRONT_KEYS_EVERY_MS;
}

/**
 * Whether a key's app may still hold a body from before `since`: no delivery
 * of an edge render since then. Only a rendered body proves it: a delivery
 * stamp alone does not say which body went out (a request that read the cache
 * before the claim may stamp after it), and only a body rendered under a
 * binding leaves the fronts out. `lastRenderedAt` is that proof;
 * `lastRender.at` (written with a render's snapshot) stands in for a key last
 * served before `lastRenderedAt` existed. Never fetched counts as stale too.
 */
export function keyIsStale(
  key: { lastRenderedAt?: number; lastRender?: { at: number } },
  since: number,
): boolean {
  return Math.max(key.lastRenderedAt ?? 0, key.lastRender?.at ?? 0) < since;
}

/**
 * Whether a key counts at all: an active key, or one superseded by a
 * regenerate or a switch that is still inside its grace (`disabled` with a
 * future `deletedAt`): its backend user keeps working for a day, so an app
 * holding its old body still connects through the front.
 */
export function keyInUse(key: { state: string; deletedAt?: number }, now: number): boolean {
  return key.state === 'active' || (key.state === 'disabled' && (key.deletedAt ?? 0) > now);
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
