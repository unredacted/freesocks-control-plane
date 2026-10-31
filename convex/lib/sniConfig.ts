/**
 * Server-name family settings (`edge.sni.*` rows in `appSettings`). Dormant by
 * default: with `enabled` off nothing is qualified and no family can be bound.
 */
import type { DatabaseReader } from '../_generated/server';
import { DEFAULT_CENSORED_COUNTRIES, resolveCensoredCountries } from './censoredCountries';
import { sanitizeBool, sanitizeInt } from './edgeConfig';

export interface SniConfig {
  /** Families may be bound to transports, and the qualify cron runs. */
  enabled: boolean;
  /**
   * FCP's own client check tests a send's names on each node, through an
   * address whose endpoint is confirmed, and a pass hands them to that node's
   * members as a person's "It connected" does (docs/edges.md "FCP's own test of
   * a send"). Off: only a person's test does. Ships off.
   */
  autoConfirm: boolean;
  /** Names checked per cron tick (every 5 min). */
  qualifyPerTick: number;
  /** A qualified name is checked again after this long. */
  requalifyHours: number;
  /** Consecutive failures after which an active name is suspended. */
  suspendAfterFails: number;
  /**
   * How many days of attributed member reports count towards "this name looks
   * blocked there". Older counts are deleted, so this is also their retention.
   */
  reportWindowDays: number;
  /**
   * Countries where names are blocked selectively, so a member there is given
   * names proven to work there, and a name blocked there is never offered.
   * ISO 3166-1 alpha-2, uppercase. Not a setting of its own: every country on
   * the censored-country list (lib/censoredCountries.ts).
   */
  curatedCountries: string[];
}

export const SNI_DEFAULTS: SniConfig = {
  enabled: false,
  autoConfirm: false,
  qualifyPerTick: 40,
  requalifyHours: 24,
  suspendAfterFails: 2,
  reportWindowDays: 14,
  curatedCountries: DEFAULT_CENSORED_COUNTRIES.codes,
};

export const SNI_BOUNDS = {
  qualifyPerTick: { min: 1, max: 200 },
  requalifyHours: { min: 1, max: 24 * 30 },
  suspendAfterFails: { min: 1, max: 10 },
  reportWindowDays: { min: 1, max: 60 },
} as const;

export const SNI_KEYS = {
  enabled: 'edge.sni.enabled',
  autoConfirm: 'edge.sni.autoConfirm',
  qualifyPerTick: 'edge.sni.qualifyPerTick',
  requalifyHours: 'edge.sni.requalifyHours',
  suspendAfterFails: 'edge.sni.suspendAfterFails',
  reportWindowDays: 'edge.sni.reportWindowDays',
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
  const [entries, censored] = await Promise.all([
    Promise.all(paths.map(async (p) => [p, await readSetting(db, SNI_KEYS[p])] as const)),
    resolveCensoredCountries(db),
  ]);
  const raw = Object.fromEntries(entries) as Record<Path, unknown>;
  const D = SNI_DEFAULTS;
  const B = SNI_BOUNDS;
  return {
    enabled: sanitizeBool(raw.enabled, D.enabled),
    autoConfirm: sanitizeBool(raw.autoConfirm, D.autoConfirm),
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
    reportWindowDays: sanitizeInt(
      raw.reportWindowDays,
      B.reportWindowDays.min,
      B.reportWindowDays.max,
      D.reportWindowDays,
    ),
    curatedCountries: censored.codes,
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
    let value: unknown;
    if (p === 'enabled' || p === 'autoConfirm') {
      if (typeof v !== 'boolean') continue;
      value = v;
    } else {
      if (typeof v !== 'number' || !Number.isFinite(v)) continue;
      value = sanitizeInt(v, SNI_BOUNDS[p].min, SNI_BOUNDS[p].max, SNI_DEFAULTS[p]);
    }
    writes.push({ key: SNI_KEYS[p], value: JSON.stringify(value) });
    changedKeys.push(p);
  }
  return { writes, changedKeys };
}

// --- checks from inside a country (`edge.sni.vantage.*`) ----------------------------------------

/**
 * Checks of server names from vantages inside curated countries (docs/edges.md
 * "Checks from inside a country"). Dormant by default: with `enabled` off, or
 * with no country opted in, nothing is measured, suggested or applied. Read
 * separately from `SniConfig` so the render path never pays for these rows.
 */
export interface SniVantageConfig {
  enabled: boolean;
  /**
   * Opted-in countries: those on the censored-country list with "check names
   * from inside" (lib/censoredCountries.ts). Not a setting of its own.
   */
  countries: string[];
  sources: { globalping: boolean; ripeatlas: boolean };
  /** A name is checked from a country again after this long. */
  intervalHours: number;
  /** Measurements an hour (one name, one source, one country each). */
  hourlyBudget: number;
  /** Vantages asked per measurement. */
  perCountryLimit: number;
  /** Names per batch (one address, one country), the control included. */
  batchNames: number;
  /** The scoring window, and how long measurement rows are kept. */
  windowDays: number;
  minVantages: number;
  minNetworks: number;
  /** Apply suggestions by themselves (never over an operator's mark). */
  autoApply: boolean;
  /**
   * Real-host controls: every name of a batch is also presented to its REAL
   * site (its public DNS answer) from the same vantages, to tell a blocked
   * name from a blocked address from a censor that checks the name against
   * its real address (docs/edges.md "Real-host controls"). Doubles a batch's
   * measurements (the hourly budget counts them). Evidence only.
   */
  realHost: boolean;
}

export const SNI_VANTAGE_DEFAULTS: SniVantageConfig = {
  enabled: false,
  countries: [],
  sources: { globalping: true, ripeatlas: false },
  intervalHours: 72,
  hourlyBudget: 12,
  perCountryLimit: 3,
  batchNames: 3,
  windowDays: 14,
  minVantages: 3,
  minNetworks: 2,
  autoApply: false,
  realHost: false,
};

export const SNI_VANTAGE_BOUNDS = {
  intervalHours: { min: 6, max: 24 * 30 },
  hourlyBudget: { min: 0, max: 120 },
  perCountryLimit: { min: 1, max: 5 },
  batchNames: { min: 2, max: 6 },
  windowDays: { min: 1, max: 60 },
  minVantages: { min: 1, max: 20 },
  minNetworks: { min: 1, max: 10 },
} as const;
type VantageIntPath = keyof typeof SNI_VANTAGE_BOUNDS;

export const SNI_VANTAGE_KEYS = {
  enabled: 'edge.sni.vantage.enabled',
  'sources.globalping': 'edge.sni.vantage.sources.globalping',
  'sources.ripeatlas': 'edge.sni.vantage.sources.ripeatlas',
  intervalHours: 'edge.sni.vantage.intervalHours',
  hourlyBudget: 'edge.sni.vantage.hourlyBudget',
  perCountryLimit: 'edge.sni.vantage.perCountryLimit',
  batchNames: 'edge.sni.vantage.batchNames',
  windowDays: 'edge.sni.vantage.windowDays',
  minVantages: 'edge.sni.vantage.minVantages',
  minNetworks: 'edge.sni.vantage.minNetworks',
  autoApply: 'edge.sni.vantage.autoApply',
  realHost: 'edge.sni.vantage.realHost',
} as const;
type VantagePath = keyof typeof SNI_VANTAGE_KEYS;
const VANTAGE_BOOLS: readonly VantagePath[] = [
  'enabled',
  'sources.globalping',
  'sources.ripeatlas',
  'autoApply',
  'realHost',
];

export async function resolveSniVantageConfig(db: DatabaseReader): Promise<SniVantageConfig> {
  const paths = Object.keys(SNI_VANTAGE_KEYS) as VantagePath[];
  const [entries, censored] = await Promise.all([
    Promise.all(paths.map(async (p) => [p, await readSetting(db, SNI_VANTAGE_KEYS[p])] as const)),
    resolveCensoredCountries(db),
  ]);
  const raw = Object.fromEntries(entries) as Record<VantagePath, unknown>;
  const D = SNI_VANTAGE_DEFAULTS;
  const int = (p: VantageIntPath) =>
    sanitizeInt(raw[p], SNI_VANTAGE_BOUNDS[p].min, SNI_VANTAGE_BOUNDS[p].max, D[p]);
  return {
    enabled: sanitizeBool(raw.enabled, D.enabled),
    countries: censored.namesInside,
    sources: {
      globalping: sanitizeBool(raw['sources.globalping'], D.sources.globalping),
      ripeatlas: sanitizeBool(raw['sources.ripeatlas'], D.sources.ripeatlas),
    },
    intervalHours: int('intervalHours'),
    hourlyBudget: int('hourlyBudget'),
    perCountryLimit: int('perCountryLimit'),
    batchNames: int('batchNames'),
    windowDays: int('windowDays'),
    minVantages: int('minVantages'),
    minNetworks: int('minNetworks'),
    autoApply: sanitizeBool(raw.autoApply, D.autoApply),
    realHost: sanitizeBool(raw.realHost, D.realHost),
  };
}

/** Measurements a batch of `names` names costs per source: the real-host twins count too. */
export function measurementsPerName(v: Pick<SniVantageConfig, 'realHost'>): number {
  return v.realHost ? 2 : 1;
}

/** The opted-in countries that are also curated: the only ones ever checked. */
export function vantageCountries(v: SniVantageConfig, curated: readonly string[]): string[] {
  return v.countries.filter((c) => curated.includes(c));
}

/**
 * The appSettings writes for a `vantage` patch (`{enabled, countries, sources:
 * {globalping, ripeatlas}, intervalHours, ...}`); unknown keys and wrong types
 * are ignored. `changedKeys` are `vantage.<path>`.
 */
export function sniVantageConfigWrites(patch: Record<string, unknown>): {
  writes: { key: string; value: string }[];
  changedKeys: string[];
} {
  const writes: { key: string; value: string }[] = [];
  const changedKeys: string[] = [];
  const sources =
    patch.sources && typeof patch.sources === 'object'
      ? (patch.sources as Record<string, unknown>)
      : {};
  for (const p of Object.keys(SNI_VANTAGE_KEYS) as VantagePath[]) {
    const v = p.startsWith('sources.') ? sources[p.slice('sources.'.length)] : patch[p];
    let value: unknown;
    if (VANTAGE_BOOLS.includes(p)) {
      if (typeof v !== 'boolean') continue;
      value = v;
    } else {
      if (typeof v !== 'number' || !Number.isFinite(v)) continue;
      const q = p as VantageIntPath;
      value = sanitizeInt(
        v,
        SNI_VANTAGE_BOUNDS[q].min,
        SNI_VANTAGE_BOUNDS[q].max,
        SNI_VANTAGE_DEFAULTS[q],
      );
    }
    writes.push({ key: SNI_VANTAGE_KEYS[p], value: JSON.stringify(value) });
    changedKeys.push(`vantage.${p}`);
  }
  return { writes, changedKeys };
}

/** Sources the config enables that can run (Atlas needs its key). */
export function usableSources(
  v: SniVantageConfig,
  secrets: { ripeAtlasKey: string },
): Array<'globalping' | 'ripeatlas'> {
  const out: Array<'globalping' | 'ripeatlas'> = [];
  if (v.sources.globalping) out.push('globalping');
  if (v.sources.ripeatlas && secrets.ripeAtlasKey.length > 0) out.push('ripeatlas');
  return out;
}

// --- finding names (`edge.sni.hunt.*`) -----------------------------------------------------------

/**
 * Finding candidate names (docs/edges.md "Finding names"). Dormant by default:
 * with `enabled` off no list is swept, nothing is checked and no evidence is
 * fetched; candidates already found stay readable.
 */
export interface SniHuntConfig {
  enabled: boolean;
  /** Sites of the top-sites list resolved by a sweep. */
  depth: number;
  /** Of those, the top ones whose `www.` name is resolved too. */
  wwwDepth: number;
  /** Lookups a second, A and AAAA counted alike. */
  lookupsPerSecond: number;
  /** A new sweep starts this long after the last one ended. */
  sweepEveryDays: number;
  /** Candidates checked per run (each costs up to three handshakes). */
  checksPerTick: number;
  /** A checked candidate is checked again after this long. */
  recheckHours: number;
  /** Candidates per network or family that get evidence (the last 3 slots rotate). */
  shortlist: number;
  /** Certificate-transparency requests an hour, whatever their answer. */
  ctRequestsPerHour: number;
  /** Pages read per domain before its answer is `truncated`. */
  ctPagesPerDomain: number;
  /** Timing measurements an hour. */
  timingPerHour: number;
}

export const SNI_HUNT_DEFAULTS: SniHuntConfig = {
  enabled: false,
  depth: 300_000,
  wwwDepth: 100_000,
  lookupsPerSecond: 20,
  sweepEveryDays: 30,
  checksPerTick: 12,
  recheckHours: 72,
  shortlist: 10,
  ctRequestsPerHour: 6,
  ctPagesPerDomain: 20,
  timingPerHour: 6,
};

export const SNI_HUNT_BOUNDS = {
  depth: { min: 1000, max: 1_000_000 },
  wwwDepth: { min: 0, max: 1_000_000 },
  lookupsPerSecond: { min: 1, max: 50 },
  sweepEveryDays: { min: 1, max: 365 },
  checksPerTick: { min: 1, max: 40 },
  recheckHours: { min: 6, max: 24 * 30 },
  shortlist: { min: 4, max: 30 },
  ctRequestsPerHour: { min: 0, max: 60 },
  ctPagesPerDomain: { min: 1, max: 200 },
  timingPerHour: { min: 0, max: 60 },
} as const;
type HuntIntPath = keyof typeof SNI_HUNT_BOUNDS;

export const SNI_HUNT_KEYS = {
  enabled: 'edge.sni.hunt.enabled',
  depth: 'edge.sni.hunt.depth',
  wwwDepth: 'edge.sni.hunt.wwwDepth',
  lookupsPerSecond: 'edge.sni.hunt.lookupsPerSecond',
  sweepEveryDays: 'edge.sni.hunt.sweepEveryDays',
  checksPerTick: 'edge.sni.hunt.checksPerTick',
  recheckHours: 'edge.sni.hunt.recheckHours',
  shortlist: 'edge.sni.hunt.shortlist',
  ctRequestsPerHour: 'edge.sni.hunt.ctRequestsPerHour',
  ctPagesPerDomain: 'edge.sni.hunt.ctPagesPerDomain',
  timingPerHour: 'edge.sni.hunt.timingPerHour',
} as const;
type HuntPath = keyof typeof SNI_HUNT_KEYS;

export async function resolveSniHuntConfig(db: DatabaseReader): Promise<SniHuntConfig> {
  const paths = Object.keys(SNI_HUNT_KEYS) as HuntPath[];
  const raw = Object.fromEntries(
    await Promise.all(
      paths.map(async (p) => [p, await readSetting(db, SNI_HUNT_KEYS[p])] as const),
    ),
  ) as Record<HuntPath, unknown>;
  const D = SNI_HUNT_DEFAULTS;
  const int = (p: HuntIntPath) =>
    sanitizeInt(raw[p], SNI_HUNT_BOUNDS[p].min, SNI_HUNT_BOUNDS[p].max, D[p]);
  const depth = int('depth');
  return {
    enabled: sanitizeBool(raw.enabled, D.enabled),
    depth,
    wwwDepth: Math.min(int('wwwDepth'), depth),
    lookupsPerSecond: int('lookupsPerSecond'),
    sweepEveryDays: int('sweepEveryDays'),
    checksPerTick: int('checksPerTick'),
    recheckHours: int('recheckHours'),
    shortlist: int('shortlist'),
    ctRequestsPerHour: int('ctRequestsPerHour'),
    ctPagesPerDomain: int('ctPagesPerDomain'),
    timingPerHour: int('timingPerHour'),
  };
}

/** The appSettings writes for a `hunt` patch; unknown keys and wrong types are ignored. */
export function sniHuntConfigWrites(patch: Record<string, unknown>): {
  writes: { key: string; value: string }[];
  changedKeys: string[];
} {
  const writes: { key: string; value: string }[] = [];
  const changedKeys: string[] = [];
  for (const p of Object.keys(SNI_HUNT_KEYS) as HuntPath[]) {
    const v = patch[p];
    let value: unknown;
    if (p === 'enabled') {
      if (typeof v !== 'boolean') continue;
      value = v;
    } else {
      if (typeof v !== 'number' || !Number.isFinite(v)) continue;
      value = sanitizeInt(v, SNI_HUNT_BOUNDS[p].min, SNI_HUNT_BOUNDS[p].max, SNI_HUNT_DEFAULTS[p]);
    }
    writes.push({ key: SNI_HUNT_KEYS[p], value: JSON.stringify(value) });
    changedKeys.push(`hunt.${p}`);
  }
  return { writes, changedKeys };
}
