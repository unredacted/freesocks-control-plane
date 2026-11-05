/**
 * Member-facing node-location catalog, derived from the backend-server pool:
 * active instances of location-capable backends (the `locations` capability)
 * that have a `location` code set, deduped by code (several backends may share
 * a location). Non-secret by construction — only the
 * operator-entered code + display label, a coarse online bit, and the coarse
 * load BAND ever leave this projection (never a URL, token, key count, or raw
 * user count). `online` = ≥1 of the code's instances passed a healthcheck
 * within the pool's 30-min "fresh" window.
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { BACKEND_IDS } from './backendIds';
import { CAPABILITIES } from './backends/capabilities';
import { computeLocationLoad, HEALTH_FRESH_MS, type LoadBand } from './loadBands';

export interface LocationEntry {
  code: string;
  label: string;
  online: boolean;
  load: LoadBand;
  /** Coarse city coordinates for the member map (null until the operator sets
   *  them on an instance at this location). City-level only — the label
   *  already names the city, so the pair discloses nothing new. */
  coords: { lat: number; lng: number } | null;
}

/** Active instances of every backend type that participates in the location
 *  catalog (the `locations` capability), in backend-id order then priority.
 *  Shared by the member location picker and the status-page projections. */
export async function collectLocationCapableServers(
  db: DatabaseReader,
): Promise<Doc<'backendServers'>[]> {
  const perBackend = await Promise.all(
    BACKEND_IDS.filter((b) => CAPABILITIES[b].locations).map((b) =>
      db
        .query('backendServers')
        .withIndex('by_backend_active', (q) => q.eq('backend', b).eq('isActive', true))
        .collect(),
    ),
  );
  return perBackend.flat();
}

export { HEALTH_FRESH_MS };

export async function resolveLocations(db: DatabaseReader): Promise<LocationEntry[]> {
  const servers = await collectLocationCapableServers(db);
  const nodeRows = await db.query('backendNodeInventory').collect();
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
    // First instance at the code with a full coordinate pair (same convention
    // as the label: any backend at the location may carry it).
    const located = instances.find((s) => s.locationLat != null && s.locationLng != null);
    out.push({
      code,
      label: instances.find((s) => s.locationLabel)?.locationLabel ?? code,
      online,
      coords: located ? { lat: located.locationLat!, lng: located.locationLng! } : null,
      load: computeLocationLoad(
        nodeRows,
        new Set(instances.map((s) => s._id)),
        now,
        HEALTH_FRESH_MS,
      ),
    });
  }
  return out;
}
