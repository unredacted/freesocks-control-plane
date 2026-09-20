/**
 * Server-management configuration (`servers.manage.*` rows in `appSettings`).
 * Everything ships DORMANT: with the defaults FCP makes no additional backend
 * call and accepts no management write.
 *
 *  - `observe`: read each capable backend's nodes, config profiles, Hosts and
 *    mode groups at the tail of the backend healthcheck (and on demand). Read-only.
 *  - `enabled`: accept management WRITES. Off, every write route refuses with
 *    `servers.manage_disabled`. Observation does not depend on it, and turning
 *    it off never hands ownership of anything back to another writer.
 */
import type { DatabaseReader } from '../_generated/server';
import { sanitizeBool } from './edgeConfig';

export interface ServerConfig {
  manage: { enabled: boolean; observe: boolean };
}

export const SERVER_DEFAULTS: ServerConfig = { manage: { enabled: false, observe: false } };

/** Flat path -> appSettings key. */
export const SERVER_KEYS = {
  'manage.enabled': 'servers.manage.enabled',
  'manage.observe': 'servers.manage.observe',
} as const;
export type ServerKeyPath = keyof typeof SERVER_KEYS;

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

export async function resolveServerConfig(db: DatabaseReader): Promise<ServerConfig> {
  const [enabled, observe] = await Promise.all([
    readSetting(db, SERVER_KEYS['manage.enabled']),
    readSetting(db, SERVER_KEYS['manage.observe']),
  ]);
  return {
    manage: {
      enabled: sanitizeBool(enabled, SERVER_DEFAULTS.manage.enabled),
      observe: sanitizeBool(observe, SERVER_DEFAULTS.manage.observe),
    },
  };
}

export function flattenServerConfig(cfg: ServerConfig): Record<ServerKeyPath, boolean> {
  return { 'manage.enabled': cfg.manage.enabled, 'manage.observe': cfg.manage.observe };
}

/** The appSettings writes for a flat patch; unknown paths and non-booleans are ignored. */
export function serverConfigWrites(patch: Record<string, unknown>): {
  writes: { key: string; value: string }[];
  changedKeys: ServerKeyPath[];
} {
  const writes: { key: string; value: string }[] = [];
  const changedKeys: ServerKeyPath[] = [];
  for (const path of Object.keys(SERVER_KEYS) as ServerKeyPath[]) {
    const v = patch[path];
    if (typeof v !== 'boolean') continue;
    writes.push({ key: SERVER_KEYS[path], value: JSON.stringify(v) });
    changedKeys.push(path);
  }
  return { writes, changedKeys };
}
