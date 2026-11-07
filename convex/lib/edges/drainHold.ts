/**
 * Holding a drained L7 front up while apps still use it (docs/edges.md
 * "Fronts kept up for apps that have not refreshed").
 *
 * A replaced or burned edge drains for `edge.drainMinutes` /
 * `edge.burnedDrainMinutes`, then the reconcile destroys it. Most apps never
 * refresh their subscription on their own, so an app that fetched while the
 * edge was published keeps dialling it long after the drain. For an L4 address
 * that is a bill; for an L7 front (a CDN hostname) keeping it costs next to
 * nothing, and a burned front still works outside the country that blocked it.
 * So a drained L7 front is held until the keys that may still hold it have
 * refreshed, or until a hard maximum.
 *
 * Who may hold it: a key in use on the edge's node whose last edge render fell
 * inside the edge's published window, `[publishedAt, drain start)`. A body
 * rendered before the window never had it; one rendered after the drain began
 * leaves it out. It counts KEYS, not apps: a body of that window may not have
 * carried this edge (the pick, a country's steering), which only lengthens a
 * hold; but one key can serve several apps, and the first of them to fetch
 * moves the key's single render stamp, so an app on another device that never
 * refreshes is no longer counted. That app is covered by the hard maximum
 * only, so `maxDays` is the real promise and the count the early exit.
 *
 * Pure: the rules here, the reads and writes in convex/edgeDrainHolds.ts.
 */

const DAY = 24 * 60 * 60_000;

/** How often a held front's holders are counted again (a count pages every key of its node). */
export const DRAIN_HOLD_EVERY_MS = 60 * 60_000;

export interface DrainHoldConfig {
  /** Hold drained L7 fronts at all. */
  enabled: boolean;
  /** The hard maximum, counted from the drain's start (0 = never held). */
  maxDays: number;
  /** Released once this many keys or fewer may still hold it. */
  releaseAtKeys: number;
}

export interface DrainHoldRecord {
  /** The drain's start the window ends at (the edge's `statusChangedAt` when it began draining). */
  since: number;
  /** The hard maximum: released at this time whatever the count says. */
  until: number;
  /** The last count: when, how many keys may still hold it, out of how many in use. */
  at?: number;
  holders?: number;
  keys?: number;
  /** A count was asked for at this time (one at a time per node). */
  requestedAt?: number;
  /** Released (the destroy follows): when, and why. */
  releasedAt?: number;
  /** A `DrainReleaseReason` (stored as a string). */
  releaseReason?: string;
}

export type DrainReleaseReason =
  | 'off'
  | 'not_l7'
  | 'not_managed'
  | 'never_published'
  | 'forced'
  | 'no_node'
  | 'origin_deleting'
  | 'listener_gone'
  | 'max_age'
  | 'account_full'
  | 'location_full'
  | 'refreshed';

export type DrainHoldDecision =
  | { hold: true; recount: boolean; record: DrainHoldRecord }
  | { hold: false; reason: DrainReleaseReason };

export interface DrainHoldEdge {
  layer?: string;
  managed: boolean;
  publishedAt?: number;
  statusChangedAt: number;
  drainUntil?: number;
  drainHold?: DrainHoldRecord;
}

/**
 * Whether a drained edge (its drain has passed) is held up, and whether its
 * holders should be counted again. Checked in this order:
 *
 *  1. the switch, an L7 front FCP manages, one that was ever handed out;
 *  2. a drain with no length (an operator's or the origin delete's "now", a
 *     spare taken out) is never held;
 *  3. only a node's keys can be counted; an origin being deleted, or a
 *     listener retired or gone (the front points at nothing it serves, and a
 *     registration that rebinds it would wait on the front), lets go;
 *  4. the hard maximum;
 *  5. the account or the edge's location at its live-edge cap lets its oldest
 *     held front go (a held front never takes the slot a replacement needs);
 *  6. held until counted, then released once few enough keys may hold it.
 */
export function drainHoldDecision(a: {
  edge: DrainHoldEdge;
  cfg: DrainHoldConfig;
  now: number;
  /** The origin is a node whose keys can be counted (a panel node with a backend server). */
  nodeOrigin: boolean;
  originDeleting: boolean;
  /** The edge's listener still exists and is not retired. */
  listenerLive: boolean;
  /** The account is at its live-edge cap and this is its held front that drained first. */
  accountFullOldest: boolean;
  /** The same for the edge's location's own cap (absent = no such cap). */
  locationFullOldest?: boolean;
}): DrainHoldDecision {
  const { edge, cfg, now } = a;
  if (!cfg.enabled || cfg.maxDays <= 0) return { hold: false, reason: 'off' };
  if ((edge.layer ?? 'l4') !== 'l7') return { hold: false, reason: 'not_l7' };
  if (!edge.managed) return { hold: false, reason: 'not_managed' };
  if (edge.publishedAt === undefined) return { hold: false, reason: 'never_published' };
  const since = edge.statusChangedAt;
  if (edge.drainUntil !== undefined && edge.drainUntil <= since)
    return { hold: false, reason: 'forced' };
  if (!a.nodeOrigin) return { hold: false, reason: 'no_node' };
  if (a.originDeleting) return { hold: false, reason: 'origin_deleting' };
  if (!a.listenerLive) return { hold: false, reason: 'listener_gone' };
  // A record of another drain (the edge drained, came back, drained again) says nothing.
  const prev = edge.drainHold?.since === since ? edge.drainHold : undefined;
  const until = prev?.until ?? since + cfg.maxDays * DAY;
  if (now >= until) return { hold: false, reason: 'max_age' };
  if (a.accountFullOldest) return { hold: false, reason: 'account_full' };
  if (a.locationFullOldest) return { hold: false, reason: 'location_full' };
  const record: DrainHoldRecord = prev ?? { since, until };
  const counted = record.at !== undefined && record.holders !== undefined;
  if (counted && record.holders! <= cfg.releaseAtKeys) return { hold: false, reason: 'refreshed' };
  const asked = record.requestedAt !== undefined && now - record.requestedAt < DRAIN_HOLD_EVERY_MS;
  const fresh = counted && now - record.at! < DRAIN_HOLD_EVERY_MS;
  return { hold: true, recount: !asked && !fresh, record };
}

/** When a key's app was last handed an edge render (0 = never). */
export function renderedAt(key: { lastRenderedAt?: number; lastRender?: { at: number } }): number {
  return Math.max(key.lastRenderedAt ?? 0, key.lastRender?.at ?? 0);
}

/** Whether a key's app may still hold an edge published over `[from, to)`. */
export function keyMayHoldEdge(
  key: { lastRenderedAt?: number; lastRender?: { at: number } },
  window: { from: number; to: number },
): boolean {
  const at = renderedAt(key);
  return at >= window.from && at < window.to;
}

/**
 * At a live-edge cap (an account's or a location's), the held front to let go:
 * the one whose drain began first. None while the cap has room, and none while
 * another edge there is already being destroyed: its slot is on its way, and
 * a `destroying` edge still counts as live, so without this every held front
 * of a full account would be let go in one pass.
 */
export function heldToFree(
  live: ReadonlyArray<{
    _id: string;
    layer?: string;
    managed: boolean;
    status: string;
    drainUntil?: number;
    statusChangedAt: number;
  }>,
  cap: number,
  now: number,
): string | null {
  if (live.length < cap) return null;
  if (live.some((e) => e.status === 'destroying')) return null;
  const held = live
    .filter((e) => heldCandidate(e, now))
    .sort((a, b) => a.statusChangedAt - b.statusChangedAt || (a._id < b._id ? -1 : 1));
  return held[0]?._id ?? null;
}

/** Whether an edge row is a drained L7 front the hold may apply to (cheap pre-filter). */
export function heldCandidate(
  e: { layer?: string; managed: boolean; status: string; drainUntil?: number },
  now: number,
): boolean {
  return (
    (e.layer ?? 'l4') === 'l7' &&
    e.managed &&
    e.status === 'draining' &&
    e.drainUntil !== undefined &&
    e.drainUntil <= now
  );
}
