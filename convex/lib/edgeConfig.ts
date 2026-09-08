/**
 * Relay-edge configuration: the `edge.*` appSettings namespace (the
 * analyticsConfig.ts pattern — typed defaults, per-field sanitizers, a parallel
 * by_key resolver, partial-PATCH writes; deliberately NOT in SETTINGS_DEFAULTS).
 *
 * Three sub-namespaces:
 *   relay.*          rotation / pool / detector knobs (`EdgeConfig`)
 *   relay.render.*   how FCP renders relay endpoints per client family
 *   relay.probe.*    external/internal reachability probes
 * Probe credentials use the billing.secret.* pattern: `edge.secret.*` keys,
 * write-only (blank = unchanged), surfaced to the admin as set/not-set booleans.
 */
import type { DatabaseReader } from '../_generated/server';

const MIN = 60_000;

// --- client families ---------------------------------------------------------

/** Client families the renderer distinguishes (by User-Agent classification). */
export const RENDER_CLIENT_FAMILIES = [
  'singbox',
  'mihomo',
  'xray-links',
  'happ',
  'hiddify',
  'streisand',
  'v2rayng',
  'other',
] as const;
export type RenderClientFamily = (typeof RENDER_CLIENT_FAMILIES)[number];

export function isRenderClientFamily(v: unknown): v is RenderClientFamily {
  return typeof v === 'string' && (RENDER_CLIENT_FAMILIES as readonly string[]).includes(v);
}

export type Ipv6Mode = 'inherit' | 'off' | 'auto-group-only' | 'both';

/** Per-family rendering rule (stored as one JSON row per family). */
export interface ClientRenderRule {
  /** Render relay endpoints for this family; off = pass the panel body through. */
  enabled: boolean;
  /** Emit a named automatic group (sing-box urltest / Mihomo url-test) where the format has one. */
  autoGroup: boolean;
  /** '' = the global relay.render.autoGroupName. */
  autoGroupName: string;
  includeBackup: boolean;
  ipv6Mode: Ipv6Mode;
  /** '' = the global labels. */
  primaryLabel: string;
  backupLabel: string;
  order: 'primary-first' | 'backup-first';
  /** 0 = unlimited. */
  maxEntries: number;
  dropTemplateEntries: boolean;
}

const AUTO_FAMILIES: ReadonlySet<RenderClientFamily> = new Set(['singbox', 'mihomo']);

export function defaultClientRule(family: RenderClientFamily): ClientRenderRule {
  return {
    enabled: true,
    autoGroup: AUTO_FAMILIES.has(family),
    autoGroupName: '',
    includeBackup: true,
    ipv6Mode: 'inherit',
    primaryLabel: '',
    backupLabel: '',
    order: 'primary-first',
    maxEntries: 0,
    dropTemplateEntries: true,
  };
}

// --- main config -------------------------------------------------------------

export interface EdgeConfig {
  /** Master switch for the detector + automatic actions. Ships OFF. */
  enabled: boolean;
  /** Global auto-rotate gate; per-origin opt-in is still required. */
  autoRotate: boolean;
  providerAffinity: 'rotate' | 'sticky';
  desiredPublishedDefault: number;
  standbyPerRelay: number;
  drainMinutes: number;
  burnedDrainMinutes: number;
  sniDrainMinutes: number;
  cooldownMinutes: number;
  maxRotationsPerRelayPerDay: number;
  maxConcurrentRotations: number;
  maxReconcileStartsPerTick: number;
  autoPublishStandby: boolean;
  autoProvisionToDesired: boolean;
  provisionTimeoutMinutes: number;
  pollSeconds: number;
  verifyAttempts: number;
  requireProviderHealth: boolean;
  maxFlipAttempts: number;
  maxRollbackAttempts: number;
  /** Wall-clock cap for one rotation run; past it the run rolls back / quarantines. */
  maxRotationMinutes: number;
  maxDestroyAttempts: number;
  opClaimSeconds: number;
  settleGraceSeconds: number;
  discoveryTimeoutMinutes: number;
  refreshMirrorsAfterFlip: boolean;
  detect: {
    windowMinutes: number;
    minReporters: number;
    minEdgeReporters: number;
    spikeFactor: number;
    loadDropPct: number;
    minLoadUsers: number;
    staleWeight: number;
    requireLoadCorroboration: boolean;
    suspectAt: number;
    clearBelow: number;
    clearAfterEvals: number;
    minBaselineSamples: number;
    probeWeight: number;
    allowProbeOnlyAutoRotate: boolean;
  };
  render: {
    /** Master switch for FCP-rendered relay endpoints; off = the panel body passes through. */
    enabled: boolean;
    autoGroupName: string;
    primaryLabel: string;
    backupLabel: string;
    ipv6Label: string;
    ipv6Mode: Exclude<Ipv6Mode, 'inherit'>;
    preferDistinctProviders: boolean;
    clients: Record<RenderClientFamily, ClientRenderRule>;
  };
  probe: {
    enabled: boolean;
    sources: { globalping: boolean; checkhost: boolean; ripeatlas: boolean; internal: boolean };
    countries: string[];
    intervalMinutes: number;
    suspectedIntervalMinutes: number;
    perCountryLimit: number;
    hourlyBudget: number;
    agreementVantages: number;
    preferEyeball: boolean;
  };
}

const defaultClients = (): Record<RenderClientFamily, ClientRenderRule> =>
  Object.fromEntries(RENDER_CLIENT_FAMILIES.map((f) => [f, defaultClientRule(f)])) as Record<
    RenderClientFamily,
    ClientRenderRule
  >;

export const EDGE_DEFAULTS: EdgeConfig = {
  enabled: false,
  autoRotate: false,
  providerAffinity: 'rotate',
  desiredPublishedDefault: 2,
  standbyPerRelay: 0,
  drainMinutes: 1440,
  burnedDrainMinutes: 60,
  sniDrainMinutes: 1440,
  cooldownMinutes: 120,
  maxRotationsPerRelayPerDay: 3,
  maxConcurrentRotations: 2,
  maxReconcileStartsPerTick: 1,
  autoPublishStandby: true,
  autoProvisionToDesired: false,
  provisionTimeoutMinutes: 20,
  pollSeconds: 20,
  verifyAttempts: 8,
  requireProviderHealth: true,
  maxFlipAttempts: 6,
  maxRollbackAttempts: 6,
  maxRotationMinutes: 120,
  maxDestroyAttempts: 48,
  opClaimSeconds: 60,
  settleGraceSeconds: 30,
  discoveryTimeoutMinutes: 30,
  refreshMirrorsAfterFlip: true,
  detect: {
    windowMinutes: 30,
    minReporters: 4,
    minEdgeReporters: 3,
    spikeFactor: 3,
    loadDropPct: 50,
    minLoadUsers: 5,
    staleWeight: 0.25,
    requireLoadCorroboration: true,
    suspectAt: 0.6,
    clearBelow: 0.3,
    clearAfterEvals: 3,
    minBaselineSamples: 72,
    probeWeight: 0.5,
    allowProbeOnlyAutoRotate: true,
  },
  render: {
    enabled: false,
    autoGroupName: 'FreeSocks Auto',
    primaryLabel: 'FreeSocks Primary',
    backupLabel: 'FreeSocks Backup',
    ipv6Label: 'IPv6',
    ipv6Mode: 'both',
    preferDistinctProviders: true,
    clients: defaultClients(),
  },
  probe: {
    enabled: false,
    sources: { globalping: true, checkhost: true, ripeatlas: false, internal: true },
    countries: ['IR', 'RU', 'CN', 'TR', 'AE', 'KZ', 'BY'],
    intervalMinutes: 15,
    suspectedIntervalMinutes: 5,
    perCountryLimit: 3,
    hourlyBudget: 200,
    agreementVantages: 2,
    preferEyeball: true,
  },
};

// --- sanitizers ----------------------------------------------------------------

export const sanitizeBool = (v: unknown, dflt: boolean): boolean =>
  typeof v === 'boolean' ? v : dflt;

function asNumber(v: unknown): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '') return Number(v);
  return NaN;
}

export function sanitizeInt(v: unknown, min: number, max: number, dflt: number): number {
  const n = asNumber(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.round(n)));
}

export function sanitizeRatio(v: unknown, min: number, max: number, dflt: number): number {
  const n = asNumber(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

export function sanitizeEnum<T extends string>(v: unknown, allowed: readonly T[], dflt: T): T {
  return typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : dflt;
}

// C0 controls + DEL; the range is spelled with escapes so no literal control
// characters live in the source.
const CONTROL_CHARS = /[\x00-\x1f]/g;

/** Member-facing label: trimmed, control chars stripped, ≤`max` chars, else default. */
export function sanitizeLabel(v: unknown, dflt: string, max = 48): string {
  if (typeof v !== 'string') return dflt;
  const s = v.replace(CONTROL_CHARS, '').replace(/\s+/g, ' ').trim();
  return s.length > 0 && s.length <= max ? s : dflt;
}

/** ISO-3166-1 alpha-2 list: uppercased, deduped, ≤40 entries; non-arrays → default. */
export function sanitizeCountryList(v: unknown, dflt: string[]): string[] {
  if (!Array.isArray(v)) return dflt;
  const out: string[] = [];
  for (const c of v) {
    if (typeof c !== 'string') continue;
    const cc = c.trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(cc) && !out.includes(cc)) out.push(cc);
    if (out.length >= 40) break;
  }
  return out;
}

const IPV6_MODES: readonly Ipv6Mode[] = ['inherit', 'off', 'auto-group-only', 'both'];

export function sanitizeClientRule(v: unknown, family: RenderClientFamily): ClientRenderRule {
  const d = defaultClientRule(family);
  if (!v || typeof v !== 'object') return d;
  const o = v as Record<string, unknown>;
  return {
    enabled: sanitizeBool(o.enabled, d.enabled),
    autoGroup: sanitizeBool(o.autoGroup, d.autoGroup),
    autoGroupName: sanitizeLabel(o.autoGroupName, ''),
    includeBackup: sanitizeBool(o.includeBackup, d.includeBackup),
    ipv6Mode: sanitizeEnum(o.ipv6Mode, IPV6_MODES, d.ipv6Mode),
    primaryLabel: sanitizeLabel(o.primaryLabel, ''),
    backupLabel: sanitizeLabel(o.backupLabel, ''),
    order: sanitizeEnum(o.order, ['primary-first', 'backup-first'] as const, d.order),
    maxEntries: sanitizeInt(o.maxEntries, 0, 20, d.maxEntries),
    dropTemplateEntries: sanitizeBool(o.dropTemplateEntries, d.dropTemplateEntries),
  };
}

// --- keys ------------------------------------------------------------------------

/** Dotted config path → appSettings key for every scalar (client rules are one JSON row per family). */
export const EDGE_KEYS = {
  enabled: 'edge.enabled',
  autoRotate: 'edge.autoRotate',
  providerAffinity: 'edge.providerAffinity',
  desiredPublishedDefault: 'edge.desiredPublishedDefault',
  standbyPerRelay: 'edge.standbyPerRelay',
  drainMinutes: 'edge.drainMinutes',
  burnedDrainMinutes: 'edge.burnedDrainMinutes',
  sniDrainMinutes: 'edge.sniDrainMinutes',
  cooldownMinutes: 'edge.cooldownMinutes',
  maxRotationsPerRelayPerDay: 'edge.maxRotationsPerRelayPerDay',
  maxConcurrentRotations: 'edge.maxConcurrentRotations',
  maxReconcileStartsPerTick: 'edge.maxReconcileStartsPerTick',
  autoPublishStandby: 'edge.autoPublishStandby',
  autoProvisionToDesired: 'edge.autoProvisionToDesired',
  provisionTimeoutMinutes: 'edge.provisionTimeoutMinutes',
  pollSeconds: 'edge.pollSeconds',
  verifyAttempts: 'edge.verifyAttempts',
  requireProviderHealth: 'edge.requireProviderHealth',
  maxFlipAttempts: 'edge.maxFlipAttempts',
  maxRollbackAttempts: 'edge.maxRollbackAttempts',
  maxRotationMinutes: 'edge.maxRotationMinutes',
  maxDestroyAttempts: 'edge.maxDestroyAttempts',
  opClaimSeconds: 'edge.opClaimSeconds',
  settleGraceSeconds: 'edge.settleGraceSeconds',
  discoveryTimeoutMinutes: 'edge.discoveryTimeoutMinutes',
  refreshMirrorsAfterFlip: 'edge.refreshMirrorsAfterFlip',
  'detect.windowMinutes': 'edge.detect.windowMinutes',
  'detect.minReporters': 'edge.detect.minReporters',
  'detect.minEdgeReporters': 'edge.detect.minEdgeReporters',
  'detect.spikeFactor': 'edge.detect.spikeFactor',
  'detect.loadDropPct': 'edge.detect.loadDropPct',
  'detect.minLoadUsers': 'edge.detect.minLoadUsers',
  'detect.staleWeight': 'edge.detect.staleWeight',
  'detect.requireLoadCorroboration': 'edge.detect.requireLoadCorroboration',
  'detect.suspectAt': 'edge.detect.suspectAt',
  'detect.clearBelow': 'edge.detect.clearBelow',
  'detect.clearAfterEvals': 'edge.detect.clearAfterEvals',
  'detect.minBaselineSamples': 'edge.detect.minBaselineSamples',
  'detect.probeWeight': 'edge.detect.probeWeight',
  'detect.allowProbeOnlyAutoRotate': 'edge.detect.allowProbeOnlyAutoRotate',
  'render.enabled': 'edge.render.enabled',
  'render.autoGroupName': 'edge.render.autoGroupName',
  'render.primaryLabel': 'edge.render.primaryLabel',
  'render.backupLabel': 'edge.render.backupLabel',
  'render.ipv6Label': 'edge.render.ipv6Label',
  'render.ipv6Mode': 'edge.render.ipv6Mode',
  'render.preferDistinctProviders': 'edge.render.preferDistinctProviders',
  'probe.enabled': 'edge.probe.enabled',
  'probe.sources.globalping': 'edge.probe.sources.globalping',
  'probe.sources.checkhost': 'edge.probe.sources.checkhost',
  'probe.sources.ripeatlas': 'edge.probe.sources.ripeatlas',
  'probe.sources.internal': 'edge.probe.sources.internal',
  'probe.countries': 'edge.probe.countries',
  'probe.intervalMinutes': 'edge.probe.intervalMinutes',
  'probe.suspectedIntervalMinutes': 'edge.probe.suspectedIntervalMinutes',
  'probe.perCountryLimit': 'edge.probe.perCountryLimit',
  'probe.hourlyBudget': 'edge.probe.hourlyBudget',
  'probe.agreementVantages': 'edge.probe.agreementVantages',
  'probe.preferEyeball': 'edge.probe.preferEyeball',
} as const;
export type RelayKeyPath = keyof typeof EDGE_KEYS;

export const clientRuleKey = (family: RenderClientFamily): string =>
  `edge.render.clients.${family}`;

// --- resolve ---------------------------------------------------------------------

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

/** Pure: build a EdgeConfig from raw (already JSON-parsed) values keyed by RelayKeyPath. */
export function sanitizeRelayConfig(
  raw: Partial<Record<RelayKeyPath, unknown>>,
  rawClients: Partial<Record<RenderClientFamily, unknown>> = {},
): EdgeConfig {
  const D = EDGE_DEFAULTS;
  const suspectAt = sanitizeRatio(raw['detect.suspectAt'], 0.3, 1, D.detect.suspectAt);
  // Hysteresis needs clearBelow strictly under suspectAt.
  const clearBelow = Math.min(
    sanitizeRatio(raw['detect.clearBelow'], 0, 1, D.detect.clearBelow),
    Math.max(0, suspectAt - 0.05),
  );
  const clients = Object.fromEntries(
    RENDER_CLIENT_FAMILIES.map((f) => [f, sanitizeClientRule(rawClients[f], f)]),
  ) as Record<RenderClientFamily, ClientRenderRule>;
  return {
    enabled: sanitizeBool(raw.enabled, D.enabled),
    autoRotate: sanitizeBool(raw.autoRotate, D.autoRotate),
    providerAffinity: sanitizeEnum(
      raw.providerAffinity,
      ['rotate', 'sticky'] as const,
      D.providerAffinity,
    ),
    desiredPublishedDefault: sanitizeInt(
      raw.desiredPublishedDefault,
      1,
      4,
      D.desiredPublishedDefault,
    ),
    standbyPerRelay: sanitizeInt(raw.standbyPerRelay, 0, 2, D.standbyPerRelay),
    drainMinutes: sanitizeInt(raw.drainMinutes, 1, 7 * 1440, D.drainMinutes),
    burnedDrainMinutes: sanitizeInt(raw.burnedDrainMinutes, 0, 7 * 1440, D.burnedDrainMinutes),
    sniDrainMinutes: sanitizeInt(raw.sniDrainMinutes, 1, 30 * 1440, D.sniDrainMinutes),
    cooldownMinutes: sanitizeInt(raw.cooldownMinutes, 10, 1440, D.cooldownMinutes),
    maxRotationsPerRelayPerDay: sanitizeInt(
      raw.maxRotationsPerRelayPerDay,
      1,
      12,
      D.maxRotationsPerRelayPerDay,
    ),
    maxConcurrentRotations: sanitizeInt(
      raw.maxConcurrentRotations,
      1,
      10,
      D.maxConcurrentRotations,
    ),
    maxReconcileStartsPerTick: sanitizeInt(
      raw.maxReconcileStartsPerTick,
      0,
      5,
      D.maxReconcileStartsPerTick,
    ),
    autoPublishStandby: sanitizeBool(raw.autoPublishStandby, D.autoPublishStandby),
    autoProvisionToDesired: sanitizeBool(raw.autoProvisionToDesired, D.autoProvisionToDesired),
    provisionTimeoutMinutes: sanitizeInt(
      raw.provisionTimeoutMinutes,
      5,
      120,
      D.provisionTimeoutMinutes,
    ),
    pollSeconds: sanitizeInt(raw.pollSeconds, 5, 300, D.pollSeconds),
    verifyAttempts: sanitizeInt(raw.verifyAttempts, 1, 30, D.verifyAttempts),
    requireProviderHealth: sanitizeBool(raw.requireProviderHealth, D.requireProviderHealth),
    maxFlipAttempts: sanitizeInt(raw.maxFlipAttempts, 1, 20, D.maxFlipAttempts),
    maxRollbackAttempts: sanitizeInt(raw.maxRollbackAttempts, 1, 20, D.maxRollbackAttempts),
    maxRotationMinutes: sanitizeInt(raw.maxRotationMinutes, 10, 24 * 60, D.maxRotationMinutes),
    maxDestroyAttempts: sanitizeInt(raw.maxDestroyAttempts, 1, 500, D.maxDestroyAttempts),
    opClaimSeconds: sanitizeInt(raw.opClaimSeconds, 15, 300, D.opClaimSeconds),
    settleGraceSeconds: sanitizeInt(raw.settleGraceSeconds, 5, 600, D.settleGraceSeconds),
    discoveryTimeoutMinutes: sanitizeInt(
      raw.discoveryTimeoutMinutes,
      5,
      1440,
      D.discoveryTimeoutMinutes,
    ),
    refreshMirrorsAfterFlip: sanitizeBool(raw.refreshMirrorsAfterFlip, D.refreshMirrorsAfterFlip),
    detect: {
      windowMinutes: sanitizeInt(raw['detect.windowMinutes'], 5, 180, D.detect.windowMinutes),
      minReporters: sanitizeInt(raw['detect.minReporters'], 1, 500, D.detect.minReporters),
      minEdgeReporters: sanitizeInt(
        raw['detect.minEdgeReporters'],
        1,
        500,
        D.detect.minEdgeReporters,
      ),
      spikeFactor: sanitizeRatio(raw['detect.spikeFactor'], 1.5, 20, D.detect.spikeFactor),
      loadDropPct: sanitizeInt(raw['detect.loadDropPct'], 10, 95, D.detect.loadDropPct),
      minLoadUsers: sanitizeInt(raw['detect.minLoadUsers'], 1, 10_000, D.detect.minLoadUsers),
      staleWeight: sanitizeRatio(raw['detect.staleWeight'], 0, 1, D.detect.staleWeight),
      requireLoadCorroboration: sanitizeBool(
        raw['detect.requireLoadCorroboration'],
        D.detect.requireLoadCorroboration,
      ),
      suspectAt,
      clearBelow,
      clearAfterEvals: sanitizeInt(raw['detect.clearAfterEvals'], 1, 24, D.detect.clearAfterEvals),
      minBaselineSamples: sanitizeInt(
        raw['detect.minBaselineSamples'],
        12,
        1008,
        D.detect.minBaselineSamples,
      ),
      probeWeight: sanitizeRatio(raw['detect.probeWeight'], 0, 1, D.detect.probeWeight),
      allowProbeOnlyAutoRotate: sanitizeBool(
        raw['detect.allowProbeOnlyAutoRotate'],
        D.detect.allowProbeOnlyAutoRotate,
      ),
    },
    render: {
      enabled: sanitizeBool(raw['render.enabled'], D.render.enabled),
      autoGroupName: sanitizeLabel(raw['render.autoGroupName'], D.render.autoGroupName),
      primaryLabel: sanitizeLabel(raw['render.primaryLabel'], D.render.primaryLabel),
      backupLabel: sanitizeLabel(raw['render.backupLabel'], D.render.backupLabel),
      ipv6Label: sanitizeLabel(raw['render.ipv6Label'], D.render.ipv6Label, 24),
      ipv6Mode: sanitizeEnum(
        raw['render.ipv6Mode'],
        ['off', 'auto-group-only', 'both'] as const,
        D.render.ipv6Mode,
      ),
      preferDistinctProviders: sanitizeBool(
        raw['render.preferDistinctProviders'],
        D.render.preferDistinctProviders,
      ),
      clients,
    },
    probe: {
      enabled: sanitizeBool(raw['probe.enabled'], D.probe.enabled),
      sources: {
        globalping: sanitizeBool(raw['probe.sources.globalping'], D.probe.sources.globalping),
        checkhost: sanitizeBool(raw['probe.sources.checkhost'], D.probe.sources.checkhost),
        ripeatlas: sanitizeBool(raw['probe.sources.ripeatlas'], D.probe.sources.ripeatlas),
        internal: sanitizeBool(raw['probe.sources.internal'], D.probe.sources.internal),
      },
      countries: sanitizeCountryList(raw['probe.countries'], D.probe.countries),
      intervalMinutes: sanitizeInt(raw['probe.intervalMinutes'], 5, 1440, D.probe.intervalMinutes),
      suspectedIntervalMinutes: sanitizeInt(
        raw['probe.suspectedIntervalMinutes'],
        1,
        1440,
        D.probe.suspectedIntervalMinutes,
      ),
      perCountryLimit: sanitizeInt(raw['probe.perCountryLimit'], 1, 10, D.probe.perCountryLimit),
      hourlyBudget: sanitizeInt(raw['probe.hourlyBudget'], 0, 10_000, D.probe.hourlyBudget),
      agreementVantages: sanitizeInt(
        raw['probe.agreementVantages'],
        1,
        10,
        D.probe.agreementVantages,
      ),
      preferEyeball: sanitizeBool(raw['probe.preferEyeball'], D.probe.preferEyeball),
    },
  };
}

export async function resolveEdgeConfig(db: DatabaseReader): Promise<EdgeConfig> {
  const paths = Object.keys(EDGE_KEYS) as RelayKeyPath[];
  // Parallel point reads (the analyticsConfig lesson: sequential awaits march a
  // slow datastore into the 1s UDF limit).
  const [values, clientValues] = await Promise.all([
    Promise.all(paths.map((p) => readSetting(db, EDGE_KEYS[p]))),
    Promise.all(RENDER_CLIENT_FAMILIES.map((f) => readSetting(db, clientRuleKey(f)))),
  ]);
  const raw: Partial<Record<RelayKeyPath, unknown>> = {};
  paths.forEach((p, i) => {
    raw[p] = values[i];
  });
  const rawClients: Partial<Record<RenderClientFamily, unknown>> = {};
  RENDER_CLIENT_FAMILIES.forEach((f, i) => {
    rawClients[f] = clientValues[i];
  });
  return sanitizeRelayConfig(raw, rawClients);
}

// --- writes ----------------------------------------------------------------------

/**
 * Admin partial-PATCH → appSettings writes. Accepts either flat RelayKeyPath
 * keys ({ 'detect.windowMinutes': 15 }) or the nested shape ({ detect: {
 * windowMinutes: 15 } }); unknown keys are ignored. Scalars are stored as given
 * (the resolver sanitizes on read, so an invalid edit can never poison a read);
 * `render.clients.<family>` rules are sanitized on write (one JSON row each).
 * Returns the writes plus the touched paths (the audit payload — never values).
 */
export function edgeConfigWrites(patch: unknown): {
  writes: Array<{ key: string; value: string }>;
  changedKeys: string[];
} {
  const writes: Array<{ key: string; value: string }> = [];
  const changedKeys: string[] = [];
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return { writes, changedKeys };
  const flat: Record<string, unknown> = {};
  const walk = (obj: Record<string, unknown>, prefix: string) => {
    for (const [k, val] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (path === 'render.clients' && val && typeof val === 'object') {
        for (const [fam, rule] of Object.entries(val as Record<string, unknown>)) {
          if (isRenderClientFamily(fam)) flat[`render.clients.${fam}`] = rule;
        }
        continue;
      }
      if (
        val &&
        typeof val === 'object' &&
        !Array.isArray(val) &&
        !(path in EDGE_KEYS) &&
        !path.startsWith('render.clients.')
      ) {
        walk(val as Record<string, unknown>, path);
      } else {
        flat[path] = val;
      }
    }
  };
  walk(patch as Record<string, unknown>, '');
  for (const [path, val] of Object.entries(flat)) {
    if (val === undefined) continue;
    if (path.startsWith('render.clients.')) {
      const fam = path.slice('render.clients.'.length);
      if (!isRenderClientFamily(fam)) continue;
      writes.push({ key: clientRuleKey(fam), value: JSON.stringify(sanitizeClientRule(val, fam)) });
      changedKeys.push(path);
      continue;
    }
    if (!(path in EDGE_KEYS)) continue;
    writes.push({ key: EDGE_KEYS[path as RelayKeyPath], value: JSON.stringify(val) });
    changedKeys.push(path);
  }
  return { writes, changedKeys };
}

// --- probe secrets (write-only) --------------------------------------------------

export const RELAY_SECRET_KEYS = {
  globalpingToken: 'edge.secret.probe.globalping.token',
  ripeAtlasKey: 'edge.secret.probe.ripeatlas.key',
} as const;

export interface RelaySecrets {
  globalpingToken: string;
  ripeAtlasKey: string;
}

const asStr = (raw: unknown): string => (typeof raw === 'string' ? raw : '');

/** DB value else the env fallback (EDGE_PROBE_GLOBALPING_TOKEN / EDGE_PROBE_RIPEATLAS_KEY). */
export async function resolveEdgeSecrets(db: DatabaseReader): Promise<RelaySecrets> {
  const [gp, ra] = await Promise.all([
    readSetting(db, RELAY_SECRET_KEYS.globalpingToken),
    readSetting(db, RELAY_SECRET_KEYS.ripeAtlasKey),
  ]);
  const dbOrEnv = (dbVal: unknown, env: string) => {
    const s = asStr(dbVal).trim();
    if (s.length > 0) return s;
    const e = process.env[env];
    return e && e.trim().length > 0 ? e : '';
  };
  return {
    globalpingToken: dbOrEnv(gp, 'EDGE_PROBE_GLOBALPING_TOKEN'),
    ripeAtlasKey: dbOrEnv(ra, 'EDGE_PROBE_RIPEATLAS_KEY'),
  };
}

export function edgeSecretStatus(s: RelaySecrets): {
  globalpingToken: boolean;
  ripeAtlasKey: boolean;
} {
  return { globalpingToken: s.globalpingToken.length > 0, ripeAtlasKey: s.ripeAtlasKey.length > 0 };
}

/** Blank = unchanged (the UI never round-trips secret values). */
export function edgeSecretWrites(patch: unknown): Array<{ key: string; value: string }> {
  if (!patch || typeof patch !== 'object') return [];
  const p = patch as Record<string, unknown>;
  const writes: Array<{ key: string; value: string }> = [];
  const put = (key: string, raw: unknown) => {
    const s = asStr(raw).trim();
    if (s.length > 0) writes.push({ key, value: JSON.stringify(s) });
  };
  put(RELAY_SECRET_KEYS.globalpingToken, p.globalpingToken);
  put(RELAY_SECRET_KEYS.ripeAtlasKey, p.ripeAtlasKey);
  return writes;
}

/** Millisecond views of the minute/second knobs, shared by the rotation machine + detector. */
export const edgeMs = {
  drain: (cfg: EdgeConfig) => cfg.drainMinutes * MIN,
  burnedDrain: (cfg: EdgeConfig) => cfg.burnedDrainMinutes * MIN,
  cooldown: (cfg: EdgeConfig) => cfg.cooldownMinutes * MIN,
  provisionTimeout: (cfg: EdgeConfig) => cfg.provisionTimeoutMinutes * MIN,
  maxRotation: (cfg: EdgeConfig) => cfg.maxRotationMinutes * MIN,
  discoveryTimeout: (cfg: EdgeConfig) => cfg.discoveryTimeoutMinutes * MIN,
  detectWindow: (cfg: EdgeConfig) => cfg.detect.windowMinutes * MIN,
  sniDrain: (cfg: EdgeConfig) => cfg.sniDrainMinutes * MIN,
  opClaim: (cfg: EdgeConfig) => cfg.opClaimSeconds * 1000,
  settleGrace: (cfg: EdgeConfig) => cfg.settleGraceSeconds * 1000,
  poll: (cfg: EdgeConfig) => cfg.pollSeconds * 1000,
};
