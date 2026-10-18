/**
 * Admin views that show live infrastructure stay current by themselves.
 *
 * Things change behind an admin page with nobody clicking: the block detector
 * replaces an address in under a minute, upkeep publishes or adds a spare, the
 * role confirms a port change. So every live view polls, and its idle cadence
 * is never `false`: `liveInterval(busy)` is LIVE_IDLE_MS while nothing runs and
 * LIVE_BUSY_MS while something is in flight (a rotation, a setup run, an edge
 * being made or destroyed, a restore). TanStack polls a visible tab only
 * (`refetchIntervalInBackground` stays false), and every fetch resets the
 * interval of each observer of that key, so a card that reads its page's query
 * adds no requests.
 *
 * Static views (settings forms, catalogs, templates) and reads that mint
 * something (test links) never poll. That is why there is no default interval
 * for the `['admin', …]` key prefix: the tree holds both kinds, and a default
 * would have every form re-read its signed (some of them sealed) request.
 *
 * Change detection: a short change (a detector rotation that starts and ends
 * between two polls of a page's lists) is caught by the cheap summary reads.
 * `OriginStamps` keeps, per source (the origin lookup, the fleet summary, the
 * attention list) and origin slug, the last stamp of what matters
 * (`originStamp`, `originStatusStamp`); a source whose stamp for an origin
 * moved reports that origin, and the caller invalidates its lists
 * (`edgesApi.ts` `noteOrigins`). A first sighting is not a change.
 *
 * Exports:
 *   LIVE_IDLE_MS, LIVE_BUSY_MS, liveInterval(busy)   the cadence of a live view
 *   edgeInFlight(edges)                             an edge mid-operation
 *   originBusy(origin)                              a rotation, a restore or a delete runs
 *   originStamp(origin), originStatusStamp(status)  what "the origin changed" means
 *   OriginStamps                                    per-source change detection, debounced per origin
 *   updatedAgoWords(ageMs)                          "Updated 25 s ago"
 */

/** Idle cadence of a live admin view. */
export const LIVE_IDLE_MS = 30_000;
/** Cadence while something on the view is in flight. */
export const LIVE_BUSY_MS = 4_000;
/** One origin's lists are invalidated at most once in this window (several sources see one change). */
export const LIVE_DEBOUNCE_MS = 2_000;

export const liveInterval = (busy: boolean): number => (busy ? LIVE_BUSY_MS : LIVE_IDLE_MS);

/** Edge statuses that move on their own within seconds (a provider call, a check, a destroy). */
const EDGE_IN_FLIGHT = new Set(['planning', 'provisioning', 'verifying', 'destroying']);

/** Some edge is being made, checked or destroyed (or holds an operation lease). */
export function edgeInFlight(
  edges: ReadonlyArray<{ status: string; currentOp?: unknown }>,
): boolean {
  return edges.some((e) => EDGE_IN_FLIGHT.has(e.status) || (e.currentOp ?? null) !== null);
}

/** A rotation, a restore (Remove protection) or a delete runs on the origin. */
export function originBusy(origin: {
  activeRotationId: string | null;
  restore?: unknown;
  deleting?: boolean;
}): boolean {
  return !!origin.activeRotationId || (origin.restore ?? null) !== null || !!origin.deleting;
}

/**
 * What changes on an origin row when members' addresses change: the epoch (every
 * publish and unpublish), the running rotation, the last rotation, the published
 * and spare edges, a pause, a restore phase. Not `updatedAt`: the detector writes
 * the row on every pass, which would read as a change each time.
 */
export function originStamp(o: {
  publicationEpoch: number;
  activeRotationId: string | null;
  lastRotatedAt: string | null;
  publishedEdgeIds: ReadonlyArray<string | null>;
  standbyEdgeIds: readonly string[];
  quarantine: { rotationId: string } | null;
  restore?: { phase: string } | null;
  deleting: boolean;
}): string {
  return [
    o.publicationEpoch,
    o.activeRotationId ?? '',
    o.lastRotatedAt ?? '',
    o.publishedEdgeIds.map((id) => id ?? '').join(','),
    [...o.standbyEdgeIds].sort().join(','),
    o.quarantine?.rotationId ?? '',
    o.restore?.phase ?? '',
    o.deleting ? 'd' : '',
  ].join('|');
}

/** The attention list's judgement of one origin: its status, its run, its counts. */
export function originStatusStamp(s: {
  kind: string;
  code: string | null;
  runId: string | null;
  step: number | null;
  published: number;
  standbys: number;
  offline: number;
}): string {
  return [
    s.kind,
    s.code ?? '',
    s.runId ?? '',
    s.step ?? '',
    s.published,
    s.standbys,
    s.offline,
  ].join('|');
}

export class OriginStamps {
  readonly #seen = new Map<string, string>();
  readonly #refreshedAt = new Map<string, number>();
  readonly #debounceMs: number;

  constructor(debounceMs = LIVE_DEBOUNCE_MS) {
    this.#debounceMs = debounceMs;
  }

  /**
   * Record what `source` reports now and return the origins to refresh: the ones
   * whose stamp moved since this source last reported them, less the ones
   * refreshed within the debounce window (their lists are already being read).
   */
  observe(source: string, stamps: Iterable<readonly [string, string]>, now: number): string[] {
    const changed: string[] = [];
    for (const [slug, stamp] of stamps) {
      const key = `${source}\u0000${slug}`;
      const before = this.#seen.get(key);
      this.#seen.set(key, stamp);
      if (before === undefined || before === stamp) continue;
      const last = this.#refreshedAt.get(slug);
      if (last !== undefined && now - last < this.#debounceMs) continue;
      this.#refreshedAt.set(slug, now);
      changed.push(slug);
    }
    return changed;
  }
}

/** "Updated just now", "Updated 25 s ago" (5 s steps), "Updated 3 min ago", "Updated 2 h ago". */
export function updatedAgoWords(ageMs: number): string {
  const s = Math.max(0, Math.floor(ageMs / 1000));
  if (s < 5) return 'Updated just now';
  if (s < 60) return `Updated ${s - (s % 5)} s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `Updated ${m} min ago`;
  return `Updated ${Math.floor(m / 60)} h ago`;
}
