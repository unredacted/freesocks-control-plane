/**
 * Member-facing node-location catalog, derived from the backend-server pool:
 * active Remnawave instances that have a `location` code set, deduped by code
 * (several panels may share a location). Non-secret by construction — only the
 * operator-entered code + display label and a coarse online bit ever leave this
 * projection (never a URL, token, or key count). `online` = ≥1 of the code's
 * instances passed a healthcheck within the pool's 30-min "fresh" window.
 */
import type { DatabaseReader } from '../_generated/server';

export interface LocationEntry {
  code: string;
  label: string;
  online: boolean;
}

const HEALTH_FRESH_MS = 30 * 60_000;

export async function resolveLocations(db: DatabaseReader): Promise<LocationEntry[]> {
  const servers = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();
  const now = Date.now();
  const byCode = new Map<string, LocationEntry>();
  for (const s of servers.sort((a, b) => a.priority - b.priority)) {
    if (!s.location) continue;
    const online = s.lastHealthOkAt != null && now - s.lastHealthOkAt < HEALTH_FRESH_MS;
    const existing = byCode.get(s.location);
    if (existing) {
      existing.online = existing.online || online;
      continue;
    }
    byCode.set(s.location, { code: s.location, label: s.locationLabel ?? s.location, online });
  }
  return [...byCode.values()];
}
