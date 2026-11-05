/**
 * Coarse fleet-load bands for the public status page + member pickers. Bands
 * are the ONLY load signal that ever leaves the server publicly — raw user
 * counts and per-node numbers stay internal (the same privacy posture as the
 * GB-only donation projection).
 *
 * The band is how hard a location's servers are working: the CPU load its
 * online nodes report (Remnawave `/api/nodes` → `system.stats.loadAvg`, the
 * 5-minute figure, and `system.info.cpus`), summed over the nodes and divided
 * by their cores. 5 minutes so a short spike does not flip the label. Busy
 * from 70%, Crowded from 90%. No node reporting → 'unknown', which the member
 * pages leave unsaid. Users online per node and key-cap fullness are not
 * load: a node can carry many users comfortably, and the label read as "slow"
 * when it was not.
 *
 * Pure helpers only (no Convex wrappers) so both lib/locations.ts and
 * lib/statusPage.ts share one source of truth.
 */

export type LoadBand = 'quiet' | 'busy' | 'crowded' | 'unknown';

/** Instance-health + node-stats freshness window (the healthcheck cron runs
 *  every 10 min; 30 min tolerates two missed runs before anything reads
 *  stale). Shared by the location online bit and the load-band stats filter. */
export const HEALTH_FRESH_MS = 30 * 60_000;

/** CPU load ÷ cores at/above which a location reads busy / crowded. Not
 *  admin-tunable: they are ratios of a node's own capacity, the same on any
 *  fleet. */
export const CPU_BUSY = 0.7;
export const CPU_CROWDED = 0.9;

export function bandFromCpu(utilization: number): LoadBand {
  if (utilization >= CPU_CROWDED) return 'crowded';
  if (utilization >= CPU_BUSY) return 'busy';
  return 'quiet';
}

/** The minimal per-node shape the band math needs (structural, so both
 *  backendNodeInventory rows and test fixtures fit). */
export interface LoadNodeShape {
  backendServerId: unknown;
  online: boolean;
  lastStatsAt: number;
  /** 5-minute load average, as the node reports it (absent: no report). */
  cpuLoad5?: number;
  /** The node's CPU core count (absent: no report). */
  cpuCores?: number;
}

/**
 * One location's load band from the per-node inventory: every fresh, online
 * node of the location's instances that reports its CPU. `statsFreshMs`
 * bounds how old a row may be (a stale row is no evidence at all).
 */
export function computeLocationLoad(
  nodes: readonly LoadNodeShape[],
  instanceIds: Set<unknown>,
  now: number,
  statsFreshMs: number,
): LoadBand {
  let load = 0;
  let cores = 0;
  for (const n of nodes) {
    if (!instanceIds.has(n.backendServerId)) continue;
    if (now - n.lastStatsAt > statsFreshMs) continue;
    if (!n.online) continue;
    if (n.cpuLoad5 === undefined || n.cpuCores === undefined) continue;
    if (!Number.isFinite(n.cpuLoad5) || n.cpuLoad5 < 0 || n.cpuCores <= 0) continue;
    load += n.cpuLoad5;
    cores += n.cpuCores;
  }
  if (cores === 0) return 'unknown';
  return bandFromCpu(load / cores);
}
