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
  /**
   * Countries where names are blocked selectively, so a member there is given
   * names proven to work there, and a name blocked there is never offered.
   * ISO 3166-1 alpha-2, uppercase.
   */
  curatedCountries: string[];
}

export const SNI_DEFAULTS: SniConfig = {
  enabled: false,
  qualifyPerTick: 40,
  requalifyHours: 24,
  suspendAfterFails: 2,
  curatedCountries: ['CN', 'RU', 'IR', 'MM'],
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
  curatedCountries: 'edge.sni.curatedCountries',
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
    curatedCountries: sanitizeCountries(raw.curatedCountries, D.curatedCountries),
  };
}

export function sanitizeCountries(v: unknown, dflt: string[]): string[] {
  if (!Array.isArray(v)) return dflt;
  const out = [...new Set(v.map((c) => String(c).trim().toUpperCase()))].filter((c) =>
    /^[A-Z]{2}$/.test(c),
  );
  return out.slice(0, 32);
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
    let value: unknown;
    if (p === 'enabled') {
      if (typeof v !== 'boolean') continue;
      value = v;
    } else if (p === 'curatedCountries') {
      if (!Array.isArray(v)) continue;
      value = sanitizeCountries(v, []);
    } else {
      if (typeof v !== 'number' || !Number.isFinite(v)) continue;
      value = sanitizeInt(v, SNI_BOUNDS[p].min, SNI_BOUNDS[p].max, SNI_DEFAULTS[p]);
    }
    writes.push({ key: SNI_KEYS[p], value: JSON.stringify(value) });
    changedKeys.push(p);
  }
  return { writes, changedKeys };
}
