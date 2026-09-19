/**
 * Server-name family settings (`edge.sni.*` rows in `appSettings`). Dormant by
 * default: with `enabled` off nothing is qualified and no family can be bound.
 */
import type { DatabaseReader } from '../_generated/server';
import { sanitizeBool, sanitizeInt } from './edgeConfig';

export interface SniConfig {
  /** Families may be bound to inbounds, and the qualify cron runs. */
  enabled: boolean;
  /** Names checked per cron tick (every 5 min). */
  qualifyPerTick: number;
  /** A qualified name is checked again after this long. */
  requalifyHours: number;
  /** Consecutive failures after which an active name is suspended. */
  suspendAfterFails: number;
}

export const SNI_DEFAULTS: SniConfig = {
  enabled: false,
  qualifyPerTick: 40,
  requalifyHours: 24,
  suspendAfterFails: 2,
};

export const SNI_BOUNDS = {
  qualifyPerTick: { min: 1, max: 200 },
  requalifyHours: { min: 1, max: 24 * 30 },
  suspendAfterFails: { min: 1, max: 10 },
} as const;

export const SNI_KEYS = {
  enabled: 'edge.sni.enabled',
  qualifyPerTick: 'edge.sni.qualifyPerTick',
  requalifyHours: 'edge.sni.requalifyHours',
  suspendAfterFails: 'edge.sni.suspendAfterFails',
} as const;
type Path = keyof typeof SNI_KEYS;

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

export async function resolveSniConfig(db: DatabaseReader): Promise<SniConfig> {
  const paths = Object.keys(SNI_KEYS) as Path[];
  const raw = Object.fromEntries(
    await Promise.all(paths.map(async (p) => [p, await readSetting(db, SNI_KEYS[p])] as const)),
  ) as Record<Path, unknown>;
  const D = SNI_DEFAULTS;
  const B = SNI_BOUNDS;
  return {
    enabled: sanitizeBool(raw.enabled, D.enabled),
    qualifyPerTick: sanitizeInt(
      raw.qualifyPerTick,
      B.qualifyPerTick.min,
      B.qualifyPerTick.max,
      D.qualifyPerTick,
    ),
    requalifyHours: sanitizeInt(
      raw.requalifyHours,
      B.requalifyHours.min,
      B.requalifyHours.max,
      D.requalifyHours,
    ),
    suspendAfterFails: sanitizeInt(
      raw.suspendAfterFails,
      B.suspendAfterFails.min,
      B.suspendAfterFails.max,
      D.suspendAfterFails,
    ),
  };
}

/** The appSettings writes for a patch; unknown keys and wrong types are ignored. */
export function sniConfigWrites(patch: Record<string, unknown>): {
  writes: { key: string; value: string }[];
  changedKeys: Path[];
} {
  const writes: { key: string; value: string }[] = [];
  const changedKeys: Path[] = [];
  for (const p of Object.keys(SNI_KEYS) as Path[]) {
    const v = patch[p];
    if (p === 'enabled' ? typeof v !== 'boolean' : typeof v !== 'number' || !Number.isFinite(v))
      continue;
    const value =
      p === 'enabled' ? v : sanitizeInt(v, SNI_BOUNDS[p].min, SNI_BOUNDS[p].max, SNI_DEFAULTS[p]);
    writes.push({ key: SNI_KEYS[p], value: JSON.stringify(value) });
    changedKeys.push(p);
  }
  return { writes, changedKeys };
}
