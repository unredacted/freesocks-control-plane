/**
 * Member-facing node-location catalog, derived from the backend-server pool:
 * active Remnawave instances that have a `location` code set, deduped by code
 * (several panels may share a location). Non-secret by construction — only the
 * operator-entered code + display label, a coarse online bit, and the coarse
 * load BAND ever leave this projection (never a URL, token, key count, or raw
 * user count). `online` = ≥1 of the code's instances passed a healthcheck
 * within the pool's 30-min "fresh" window.
 */
import type { DatabaseReader } from '../_generated/server';
import {
  computeLocationLoad,
  HEALTH_FRESH_MS,
  LOAD_THRESHOLD_DEFAULTS,
  type LoadBand,
  type LoadThresholds,
} from './loadBands';

export interface LocationEntry {
  code: string;
  label: string;
  online: boolean;
  load: LoadBand;
}

export { HEALTH_FRESH_MS };

/** The `status.*` threshold rows the load bands resolve against (kept
 *  dependency-light here so publicConfig can compute locations without the
 *  full status-page config). */
async function readThresholds(db: DatabaseReader): Promise<LoadThresholds> {
  const read = async (key: string, fallback: number): Promise<number> => {
    const row = await db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (!row) return fallback;
    try {
      const v = JSON.parse(row.value);
      return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 100_000 ? v : fallback;
    } catch {
      return fallback;
    }
  };
  const busyAt = await read('status.loadBusyAt', LOAD_THRESHOLD_DEFAULTS.busyAt);
  const crowdedAt = Math.max(
    await read('status.loadCrowdedAt', LOAD_THRESHOLD_DEFAULTS.crowdedAt),
    busyAt,
  );
  return { busyAt, crowdedAt };
}

export async function resolveLocations(db: DatabaseReader): Promise<LocationEntry[]> {
  const servers = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();
  const statsRows = await db.query('remnawaveNodeStats').collect();
  const thresholds = await readThresholds(db);
  const now = Date.now();

  const byCode = new Map<string, typeof servers>();
  for (const s of servers.sort((a, b) => a.priority - b.priority)) {
    if (!s.location) continue;
    const list = byCode.get(s.location);
    if (list) list.push(s);
    else byCode.set(s.location, [s]);
  }

  const out: LocationEntry[] = [];
  for (const [code, instances] of byCode) {
    const online = instances.some(
      (s) => s.lastHealthOkAt != null && now - s.lastHealthOkAt < HEALTH_FRESH_MS,
    );
    out.push({
      code,
      label: instances.find((s) => s.locationLabel)?.locationLabel ?? code,
      online,
      load: computeLocationLoad(
        instances,
        statsRows,
        new Set(instances.map((s) => s._id)),
        thresholds,
        now,
        HEALTH_FRESH_MS,
      ),
    });
  }
  return out;
}
