/**
 * Coarse fleet-load bands for the public status page + member pickers. Bands
 * are the ONLY load signal that ever leaves the server publicly — raw user
 * counts and per-node numbers stay internal (the same privacy posture as the
 * GB-only donation projection). Two derivations, picked by available data:
 *
 *  - key-capacity utilization (ΣkeyCount / ΣmaxKeys) when every instance of a
 *    location carries a maxKeys cap — the most honest "fullness" signal;
 *  - users-per-online-node (from the remnawaveNodeStats cache) otherwise,
 *    against admin-tunable thresholds.
 *
 * Pure helpers only (no Convex wrappers) so both lib/locations.ts and
 * lib/statusPage.ts share one source of truth.
 */

export type LoadBand = 'quiet' | 'busy' | 'crowded' | 'unknown';

export interface LoadThresholds {
  /** users-per-online-node at/above which a location reads "busy". */
  busyAt: number;
  /** users-per-online-node at/above which a location reads "crowded". */
  crowdedAt: number;
}

export const LOAD_THRESHOLD_DEFAULTS: LoadThresholds = { busyAt: 50, crowdedAt: 150 };

/** Instance-health + node-stats freshness window (the healthcheck cron runs
 *  every 10 min; 30 min tolerates two missed runs before anything reads
 *  stale). Shared by the location online bit and the load-band stats filter. */
export const HEALTH_FRESH_MS = 30 * 60_000;

// Utilization (keyCount/maxKeys) band edges. Not admin-tunable: they're
// capacity ratios, not fleet-specific absolutes.
const UTIL_BUSY = 0.6;
const UTIL_CROWDED = 0.85;

export function bandFromUsersPerNode(usersPerNode: number, th: LoadThresholds): LoadBand {
  if (usersPerNode >= th.crowdedAt) return 'crowded';
  if (usersPerNode >= th.busyAt) return 'busy';
  return 'quiet';
}

export function bandFromUtilization(utilization: number): LoadBand {
  if (utilization >= UTIL_CROWDED) return 'crowded';
  if (utilization >= UTIL_BUSY) return 'busy';
  return 'quiet';
}

/** The minimal per-instance shape the band math needs (structural, so both
 *  backendServers rows and test fixtures fit). */
export interface LoadInstanceShape {
  keyCount: number;
  maxKeys?: number;
}

/** The minimal per-placement node-stats shape the band math needs. */
export interface LoadStatsShape {
  backendServerId: unknown;
  usersOnline: number;
  online: boolean;
  nodeCount: number;
  lastStatsAt: number;
}

/**
 * Compute one location's load band from its instances + the node-stats cache.
 * `statsFreshMs` bounds how old a stats row may be before it's ignored (stale
 * rows are not evidence of quiet — they're no evidence at all).
 */
export function computeLocationLoad(
  instances: LoadInstanceShape[],
  statsRows: (LoadStatsShape & { backendServerId: unknown })[],
  instanceIds: Set<unknown>,
  th: LoadThresholds,
  now: number,
  statsFreshMs: number,
): LoadBand {
  if (instances.length === 0) return 'unknown';

  // Preferred: key-capacity utilization, when EVERY located instance is capped.
  if (instances.every((s) => typeof s.maxKeys === 'number' && s.maxKeys > 0)) {
    const keys = instances.reduce((a, s) => a + s.keyCount, 0);
    const cap = instances.reduce((a, s) => a + (s.maxKeys ?? 0), 0);
    if (cap > 0) return bandFromUtilization(keys / cap);
  }

  // Fallback: users per online node across the location's fresh stats rows.
  let users = 0;
  let nodes = 0;
  for (const row of statsRows) {
    if (!instanceIds.has(row.backendServerId)) continue;
    if (now - row.lastStatsAt > statsFreshMs) continue;
    if (!row.online || row.nodeCount <= 0) continue;
    users += row.usersOnline;
    nodes += row.nodeCount;
  }
  if (nodes === 0) return 'unknown';
  return bandFromUsersPerNode(users / nodes, th);
}
