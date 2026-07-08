/**
 * Remnawave node-load placement (pure fns). At issuance FCP homes a new key to
 * the LEAST-LOADED node of the chosen mode's placement pool, using the per-
 * placement node-load snapshot the healthcheck cron caches in `remnawaveNodeStats`.
 *
 * "Placement" is the opaque handle the generic layer carries (a Remnawave
 * internal-squad UUID); a placement maps to one or more nodes, and its load is
 * the aggregate `usersOnline` (+ optional realtime bandwidth) of those nodes.
 * This module is Remnawave-local by design — the generic backend layer never
 * sees a squad or a node.
 */
import type { DatabaseReader } from '../_generated/server';

// A node-load snapshot older than this is treated as unknown load (the
// healthcheck cron refreshes every 10 min; 30 min matches the instance pool's
// "fresh" window).
const NODE_STATS_STALE_MS = 30 * 60_000;

const DEFAULT_USERS_ONLINE_WEIGHT = 1;
const DEFAULT_BANDWIDTH_WEIGHT = 0; // usersOnline-only until the realtime shape is pinned

/** Scoring weights (admin-tunable via appSettings; JSON-encoded numbers). */
async function placementWeights(
  db: DatabaseReader,
): Promise<{ usersOnline: number; bandwidth: number }> {
  const read = async (key: string, def: number): Promise<number> => {
    const row = await db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    const n = row ? Number(JSON.parse(row.value)) : NaN;
    return Number.isFinite(n) ? n : def;
  };
  return {
    usersOnline: await read(
      'remnawave.nodePlacement.usersOnline_weight',
      DEFAULT_USERS_ONLINE_WEIGHT,
    ),
    bandwidth: await read('remnawave.nodePlacement.bandwidth_weight', DEFAULT_BANDWIDTH_WEIGHT),
  };
}

/**
 * The least-loaded placement of a pool, by cached node load. Fresh+online
 * placements win over stale/offline/unroutable ones (lowest weighted load
 * first); among all-unknown the pool's declaration order decides,
 * deterministically. A single-element (or empty) pool short-circuits. Between
 * cron refreshes the load can drift by a few issuances — bounded + self-correcting.
 *
 * Load score = usersOnline_weight * usersOnline + bandwidth_weight * (realtime bytes).
 * A placement that is offline or maps to zero nodes is treated as unusable-load
 * (sorted after every usable one) but still selectable as a last resort, so a
 * bound-but-degraded pool still issues a key rather than falling through to null.
 */
export async function pickByNodeLoad(db: DatabaseReader, pool: string[]): Promise<string | null> {
  if (pool.length <= 1) return pool[0] ?? null;
  const now = Date.now();
  const w = await placementWeights(db);
  const scored: { placement: string; order: number; usable: boolean; score: number }[] = [];
  for (let order = 0; order < pool.length; order++) {
    const placement = pool[order]!;
    const row = await db
      .query('remnawaveNodeStats')
      .withIndex('by_placement', (q) => q.eq('placement', placement))
      .unique();
    const fresh = row != null && now - row.lastStatsAt < NODE_STATS_STALE_MS;
    // Usable = a fresh snapshot with ≥1 online node. Everything else (stale,
    // offline, never-observed, unroutable) sorts last but stays selectable.
    const usable = fresh && row.online && row.nodeCount > 0;
    const score = usable
      ? w.usersOnline * row.usersOnline + w.bandwidth * (row.trafficBytesRealtime ?? 0)
      : Number.POSITIVE_INFINITY;
    scored.push({ placement, order, usable, score });
  }
  scored.sort(
    (a, b) => Number(b.usable) - Number(a.usable) || a.score - b.score || a.order - b.order,
  );
  return scored[0]!.placement;
}
