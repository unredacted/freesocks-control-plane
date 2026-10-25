/**
 * Origin-edge configuration: the `edge.*` appSettings namespace (the
 * analyticsConfig.ts pattern — typed defaults, per-field sanitizers, a parallel
 * by_key resolver, partial-PATCH writes; deliberately NOT in SETTINGS_DEFAULTS).
 *
 * Sub-namespaces:
 *   edge.*          rotation / pool knobs (`EdgeConfig`); an origin may override
 *                   its own (`originPolicy`, one inheritance rule)
 *   edge.detect.*   the block detector
 *   edge.l7.*       CDN fronts
 *   edge.render.*   how FCP renders origin endpoints per client family
 *   edge.probe.*    external/internal reachability probes
 * The machinery's timeouts, attempt caps and intervals are constants
 * (`EDGE_PLUMBING`), not settings.
 * Probe credentials use the billing.secret.* pattern: `edge.secret.*` keys,
 * write-only (blank = unchanged), surfaced to the admin as set/not-set booleans.
 */
import type { DatabaseReader } from '../_generated/server';
import { resolveCensoredCountries } from './censoredCountries';
import { drainWarningCodes } from '../../src/shared/contracts/edgeCodes';
import {
  MAX_DESIRED_PUBLISHED,
  MAX_DESIRED_PUBLISHED_DEFAULT,
} from '../../src/shared/contracts/edgeLimits';

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
  /** Render origin endpoints for this family; off = pass the backend body through. */
  enabled: boolean;
  /** Emit a named automatic group (sing-box urltest / Mihomo url-test) where the format has one. */
  autoGroup: boolean;
  /** '' = the global origin.render.autoGroupName. */
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

/**
 * The published-pool cap per origin and the ceiling of the fleet default pool
 * size (src/shared/contracts/edgeLimits.ts, shared with the admin forms).
 * Coverage needs a slot per deployed listener and, with a provider set, an
 * address per diversity group and per pick (lib/edges/providerSet.ts): a set
 * whose steady-state cover would exceed the cap is refused (`edge.set_too_large`).
 */
export { MAX_DESIRED_PUBLISHED, MAX_DESIRED_PUBLISHED_DEFAULT };

/** Deployed, enabled listeners per origin (`edge.listener_cap`; a guided setup's `too_many_inbounds`). */
export const MAX_COVERAGE_LISTENERS = 8;

export interface EdgeConfig {
  /** Master switch for the detector + automatic actions. Ships OFF. */
  enabled: boolean;
  /** Global auto-rotate gate; per-origin opt-in is still required. */
  autoRotate: boolean;
  desiredPublishedDefault: number;
  standbyPerRelay: number;
  /** Verified standbys kept PER coverage listener (on top of `standbyPerRelay`). */
  standbyPerListener: number;
  drainMinutes: number;
  burnedDrainMinutes: number;
  /**
   * The refresh hint FCP sends with an edge-rendered subscription
   * (`profile-update-interval`, whole hours): how often apps that honour it
   * fetch their configuration again, so a rotation reaches them in time.
   */
  updateIntervalHours: number;
  sniDrainMinutes: number;
  cooldownMinutes: number;
  maxRotationsPerRelayPerDay: number;
  maxConcurrentRotations: number;
  autoPublishStandby: boolean;
  autoProvisionToDesired: boolean;
  requireProviderHealth: boolean;
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
    /**
     * The fleet brake: when more than this share (percent) of the evaluated
     * origins is suspected in one detector pass, every automatic rotation is
     * held (a mass block, not one burned address). 100 = never.
     */
    fleetBreakerPct: number;
    /** Automatic (detector) rotations across the whole fleet per UTC day; 0 = none. */
    fleetRotationsPerDay: number;
    /**
     * Sustained unreachability (lib/edges/probes/verdict.ts `sustainedBlock`):
     * an address never reached from a listed country counts as blocked there
     * after this many failing checks, from at least `sustainedNetworks`
     * networks, spread over at least `sustainedMinutes`, while the node's other
     * addresses reach that country.
     */
    sustainedChecks: number;
    sustainedNetworks: number;
    sustainedMinutes: number;
  };
  /** L7 (CDN front) edges. */
  l7: {
    /** Automatic selection of L7 accounts (detector replacements, auto-provision); a guided setup run's chosen account is used either way. Ships off. */
    autoSelect: boolean;
    /** Same-provider L7 replacements per origin per UTC day (a new hostname is not a new frontend IP). */
    maxSameProviderReplacementsPerDay: number;
  };
  render: {
    /** Master switch for FCP-rendered origin endpoints; off = the backend body passes through. */
    enabled: boolean;
    autoGroupName: string;
    primaryLabel: string;
    backupLabel: string;
    ipv6Label: string;
    ipv6Mode: Exclude<Ipv6Mode, 'inherit'>;
    /**
     * Server names handed to ONE member per endpoint, for a listener on the
     * `hrw1` name PRF: each is one more entry, so a member whose first name is
     * blocked still holds working ones. 1 = a single name. No effect on a
     * listener still on the legacy PRF, nor on an L7 front.
     */
    namesPerEndpoint: number;
    /** The same, for the backup endpoint. */
    backupNames: number;
    preferDistinctProviders: boolean;
    clients: Record<RenderClientFamily, ClientRenderRule>;
  };
  probe: {
    enabled: boolean;
    sources: { globalping: boolean; checkhost: boolean; ripeatlas: boolean; internal: boolean };
    /**
     * Not a setting of its own: the countries on the censored-country list with
     * "check edges" (lib/censoredCountries.ts), filled in by `resolveEdgeConfig`.
     */
    countries: string[];
    intervalMinutes: number;
    suspectedIntervalMinutes: number;
    perCountryLimit: number;
    hourlyBudget: number;
    agreementVantages: number;
    preferEyeball: boolean;
    /** Probe the IPv6 path of origin / custom targets (edge targets follow `render.ipv6Mode`). */
    ipv6: boolean;
    /**
     * Globalping probes asked for per hour (a run asks countries x vantages,
     * plus one per control country). A round that would exceed it runs without
     * Globalping. Counted from `probeRuns.tests`.
     */
    globalpingTestsPerHour: number;
  };
  /** Checks of edges from each censored country (edgeCountry.ts, lib/edges/country). */
  country: {
    /** Off: probes behave exactly as before (no controls, no verdicts, no waits). */
    enabled: boolean;
    /**
     * Uncensored countries asked in the same measurement, one vantage each,
     * as `DE US JP` (codes on the censored-country list are ignored). They tell
     * a blocked edge from a broken one.
     */
    controlCountries: string;
    /** Vantages with evidence a round needs before it can decide anything. */
    minProbes: number;
    /** Distinct networks among them. */
    minNetworks: number;
    /** Controls (FCP's own check counts as one) that must work for "blocked". */
    minControls: number;
    /** Blocked rounds, at least 30 minutes apart, before a proven edge counts as blocked. */
    blockedRounds: number;
    /** How long a decided result stands without a new one. */
    windowDays: number;
    /** A spare (active, not published) is checked this often. */
    standbyRecheckHours: number;
    /** How long a setup run or a replacement waits for its first round. */
    preUseWaitMinutes: number;
    /**
     * Delivery by country: proven edges needed before proven ones are handed
     * out exclusively (fewer: proven and not-known edges share the first tier).
     */
    minProvenForExclusive: number;
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
  desiredPublishedDefault: 2,
  standbyPerRelay: 0,
  standbyPerListener: 0,
  drainMinutes: 1440,
  // Twice the refresh hint: an app outside the blocking country that refreshes
  // hourly never races the destroy (docs/edges.md "How fast members move").
  burnedDrainMinutes: 120,
  updateIntervalHours: 1,
  sniDrainMinutes: 1440,
  cooldownMinutes: 120,
  maxRotationsPerRelayPerDay: 3,
  maxConcurrentRotations: 2,
  autoPublishStandby: true,
  autoProvisionToDesired: false,
  requireProviderHealth: true,
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
    allowProbeOnlyAutoRotate: false,
    fleetBreakerPct: 30,
    fleetRotationsPerDay: 12,
    sustainedChecks: 12,
    sustainedNetworks: 2,
    sustainedMinutes: 120,
  },
  l7: {
    autoSelect: false,
    maxSameProviderReplacementsPerDay: 2,
  },
  render: {
    enabled: false,
    autoGroupName: 'FreeSocks Auto',
    // Plain names: most members see one entry, and "Primary" alone reads oddly.
    primaryLabel: 'FreeSocks',
    backupLabel: 'FreeSocks (backup)',
    ipv6Label: 'IPv6',
    ipv6Mode: 'both',
    namesPerEndpoint: 3,
    backupNames: 1,
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
    ipv6: true,
    globalpingTestsPerHour: 400,
  },
  country: {
    enabled: false,
    controlCountries: 'DE US JP',
    minProbes: 3,
    minNetworks: 2,
    minControls: 2,
    blockedRounds: 2,
    windowDays: 14,
    standbyRecheckHours: 12,
    preUseWaitMinutes: 15,
    minProvenForExclusive: 1,
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
  desiredPublishedDefault: 'edge.desiredPublishedDefault',
  standbyPerRelay: 'edge.standbyPerRelay',
  standbyPerListener: 'edge.standbyPerListener',
  drainMinutes: 'edge.drainMinutes',
  burnedDrainMinutes: 'edge.burnedDrainMinutes',
  updateIntervalHours: 'edge.updateIntervalHours',
  sniDrainMinutes: 'edge.sniDrainMinutes',
  cooldownMinutes: 'edge.cooldownMinutes',
  maxRotationsPerRelayPerDay: 'edge.maxRotationsPerRelayPerDay',
  maxConcurrentRotations: 'edge.maxConcurrentRotations',
  autoPublishStandby: 'edge.autoPublishStandby',
  autoProvisionToDesired: 'edge.autoProvisionToDesired',
  requireProviderHealth: 'edge.requireProviderHealth',
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
  'detect.fleetBreakerPct': 'edge.detect.fleetBreakerPct',
  'detect.fleetRotationsPerDay': 'edge.detect.fleetRotationsPerDay',
  'detect.sustainedChecks': 'edge.detect.sustainedChecks',
  'detect.sustainedNetworks': 'edge.detect.sustainedNetworks',
  'detect.sustainedMinutes': 'edge.detect.sustainedMinutes',
  'l7.autoSelect': 'edge.l7.autoSelect',
  'l7.maxSameProviderReplacementsPerDay': 'edge.l7.maxSameProviderReplacementsPerDay',
  'render.enabled': 'edge.render.enabled',
  'render.autoGroupName': 'edge.render.autoGroupName',
  'render.primaryLabel': 'edge.render.primaryLabel',
  'render.backupLabel': 'edge.render.backupLabel',
  'render.ipv6Label': 'edge.render.ipv6Label',
  'render.namesPerEndpoint': 'edge.render.namesPerEndpoint',
  'render.backupNames': 'edge.render.backupNames',
  'render.ipv6Mode': 'edge.render.ipv6Mode',
  'render.preferDistinctProviders': 'edge.render.preferDistinctProviders',
  'probe.enabled': 'edge.probe.enabled',
  'probe.sources.globalping': 'edge.probe.sources.globalping',
  'probe.sources.checkhost': 'edge.probe.sources.checkhost',
  'probe.sources.ripeatlas': 'edge.probe.sources.ripeatlas',
  'probe.sources.internal': 'edge.probe.sources.internal',
  'probe.intervalMinutes': 'edge.probe.intervalMinutes',
  'probe.suspectedIntervalMinutes': 'edge.probe.suspectedIntervalMinutes',
  'probe.perCountryLimit': 'edge.probe.perCountryLimit',
  'probe.hourlyBudget': 'edge.probe.hourlyBudget',
  'probe.agreementVantages': 'edge.probe.agreementVantages',
  'probe.preferEyeball': 'edge.probe.preferEyeball',
  'probe.ipv6': 'edge.probe.ipv6',
  'probe.globalpingTestsPerHour': 'edge.probe.globalpingTestsPerHour',
  'country.enabled': 'edge.country.enabled',
  'country.controlCountries': 'edge.country.controlCountries',
  'country.minProbes': 'edge.country.minProbes',
  'country.minNetworks': 'edge.country.minNetworks',
  'country.minControls': 'edge.country.minControls',
  'country.blockedRounds': 'edge.country.blockedRounds',
  'country.windowDays': 'edge.country.windowDays',
  'country.standbyRecheckHours': 'edge.country.standbyRecheckHours',
  'country.preUseWaitMinutes': 'edge.country.preUseWaitMinutes',
  'country.minProvenForExclusive': 'edge.country.minProvenForExclusive',
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
    desiredPublishedDefault: sanitizeInt(
      raw.desiredPublishedDefault,
      1,
      MAX_DESIRED_PUBLISHED_DEFAULT,
      D.desiredPublishedDefault,
    ),
    standbyPerRelay: sanitizeInt(raw.standbyPerRelay, 0, 2, D.standbyPerRelay),
    standbyPerListener: sanitizeInt(raw.standbyPerListener, 0, 2, D.standbyPerListener),
    drainMinutes: sanitizeInt(raw.drainMinutes, 1, 7 * 1440, D.drainMinutes),
    burnedDrainMinutes: sanitizeInt(raw.burnedDrainMinutes, 0, 7 * 1440, D.burnedDrainMinutes),
    updateIntervalHours: sanitizeUpdateIntervalHours(raw.updateIntervalHours),
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
    autoPublishStandby: sanitizeBool(raw.autoPublishStandby, D.autoPublishStandby),
    autoProvisionToDesired: sanitizeBool(raw.autoProvisionToDesired, D.autoProvisionToDesired),
    requireProviderHealth: sanitizeBool(raw.requireProviderHealth, D.requireProviderHealth),
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
      fleetBreakerPct: sanitizeInt(raw['detect.fleetBreakerPct'], 1, 100, D.detect.fleetBreakerPct),
      fleetRotationsPerDay: sanitizeInt(
        raw['detect.fleetRotationsPerDay'],
        0,
        500,
        D.detect.fleetRotationsPerDay,
      ),
      sustainedChecks: sanitizeInt(raw['detect.sustainedChecks'], 3, 500, D.detect.sustainedChecks),
      // Floor 2, like `probe.agreementVantages`: one network failing is never a block.
      sustainedNetworks: sanitizeInt(
        raw['detect.sustainedNetworks'],
        2,
        10,
        D.detect.sustainedNetworks,
      ),
      sustainedMinutes: sanitizeInt(
        raw['detect.sustainedMinutes'],
        30,
        2880,
        D.detect.sustainedMinutes,
      ),
    },
    l7: {
      autoSelect: sanitizeBool(raw['l7.autoSelect'], D.l7.autoSelect),
      maxSameProviderReplacementsPerDay: sanitizeInt(
        raw['l7.maxSameProviderReplacementsPerDay'],
        0,
        50,
        D.l7.maxSameProviderReplacementsPerDay,
      ),
    },
    render: {
      enabled: sanitizeBool(raw['render.enabled'], D.render.enabled),
      autoGroupName: sanitizeLabel(raw['render.autoGroupName'], D.render.autoGroupName),
      primaryLabel: sanitizeLabel(raw['render.primaryLabel'], D.render.primaryLabel),
      backupLabel: sanitizeLabel(raw['render.backupLabel'], D.render.backupLabel),
      ipv6Label: sanitizeLabel(raw['render.ipv6Label'], D.render.ipv6Label, 24),
      namesPerEndpoint: sanitizeInt(
        raw['render.namesPerEndpoint'],
        1,
        5,
        D.render.namesPerEndpoint,
      ),
      backupNames: sanitizeInt(raw['render.backupNames'], 1, 5, D.render.backupNames),
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
      // From the censored-country list (resolveEdgeConfig); the default is for pure callers.
      countries: D.probe.countries,
      intervalMinutes: sanitizeInt(raw['probe.intervalMinutes'], 5, 1440, D.probe.intervalMinutes),
      suspectedIntervalMinutes: sanitizeInt(
        raw['probe.suspectedIntervalMinutes'],
        1,
        1440,
        D.probe.suspectedIntervalMinutes,
      ),
      perCountryLimit: sanitizeInt(raw['probe.perCountryLimit'], 1, 10, D.probe.perCountryLimit),
      hourlyBudget: sanitizeInt(raw['probe.hourlyBudget'], 0, 10_000, D.probe.hourlyBudget),
      // Floor 2: "unreachable" is agreement between distinct networks; a single
      // failing vantage can never be one.
      agreementVantages: sanitizeInt(
        raw['probe.agreementVantages'],
        2,
        10,
        D.probe.agreementVantages,
      ),
      preferEyeball: sanitizeBool(raw['probe.preferEyeball'], D.probe.preferEyeball),
      ipv6: sanitizeBool(raw['probe.ipv6'], D.probe.ipv6),
      globalpingTestsPerHour: sanitizeInt(
        raw['probe.globalpingTestsPerHour'],
        0,
        100_000,
        D.probe.globalpingTestsPerHour,
      ),
    },
    country: {
      enabled: sanitizeBool(raw['country.enabled'], D.country.enabled),
      controlCountries: sanitizeCountryCodes(
        raw['country.controlCountries'],
        D.country.controlCountries,
      ),
      minProbes: sanitizeInt(raw['country.minProbes'], 2, 10, D.country.minProbes),
      minNetworks: sanitizeInt(raw['country.minNetworks'], 1, 5, D.country.minNetworks),
      minControls: sanitizeInt(raw['country.minControls'], 1, 5, D.country.minControls),
      blockedRounds: sanitizeInt(raw['country.blockedRounds'], 1, 5, D.country.blockedRounds),
      windowDays: sanitizeInt(raw['country.windowDays'], 1, 60, D.country.windowDays),
      standbyRecheckHours: sanitizeInt(
        raw['country.standbyRecheckHours'],
        1,
        168,
        D.country.standbyRecheckHours,
      ),
      preUseWaitMinutes: sanitizeInt(
        raw['country.preUseWaitMinutes'],
        0,
        60,
        D.country.preUseWaitMinutes,
      ),
      minProvenForExclusive: sanitizeInt(
        raw['country.minProvenForExclusive'],
        1,
        5,
        D.country.minProvenForExclusive,
      ),
    },
  };
}

/** At most this many control countries (each one is a probe in every run). */
export const MAX_CONTROL_COUNTRIES = 5;

/**
 * Control countries as their canonical `DE US JP` spelling: codes split on
 * spaces or commas, upper-cased, deduplicated, at most MAX_CONTROL_COUNTRIES.
 * Anything that is not a two-letter code is dropped; nothing usable = default.
 */
export function sanitizeCountryCodes(v: unknown, dflt: string): string {
  const parts = Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[\s,]+/) : [];
  const codes = [
    ...new Set(
      parts
        .filter((x): x is string => typeof x === 'string')
        .map((x) => x.trim().toUpperCase())
        .filter((x) => /^[A-Z]{2}$/.test(x)),
    ),
  ].slice(0, MAX_CONTROL_COUNTRIES);
  return codes.length > 0 ? codes.join(' ') : dflt;
}

/**
 * The control countries a run asks for: the setting's codes minus any country
 * on the censored-country list (a censored vantage cannot vouch for an edge).
 */
export function controlCountriesOf(
  cfg: Pick<EdgeConfig, 'country'>,
  listed: readonly string[],
): string[] {
  return cfg.country.controlCountries
    .split(' ')
    .filter((c) => /^[A-Z]{2}$/.test(c) && !listed.includes(c));
}

/**
 * The retired deployment-wide switch that let every DNS provider's account
 * front traffic (`edge.l7.dnsProvidersFront`). Each DNS account now carries
 * its own choice (`edgeProviderAccounts.frontsTraffic`); the switch's stored
 * value is read once, by `edgeProviderAccounts.migrateDnsFronting`, and put
 * back by `restoreDnsFrontingForRollback`.
 */
export const LEGACY_DNS_PROVIDERS_FRONT_KEY = 'edge.l7.dnsProvidersFront';

export async function resolveEdgeConfig(db: DatabaseReader): Promise<EdgeConfig> {
  const paths = Object.keys(EDGE_KEYS) as RelayKeyPath[];
  // Parallel point reads (the analyticsConfig lesson: sequential awaits march a
  // slow datastore into the 1s UDF limit).
  const [values, clientValues, censored] = await Promise.all([
    Promise.all(paths.map((p) => readSetting(db, EDGE_KEYS[p]))),
    Promise.all(RENDER_CLIENT_FAMILIES.map((f) => readSetting(db, clientRuleKey(f)))),
    resolveCensoredCountries(db),
  ]);
  const raw: Partial<Record<RelayKeyPath, unknown>> = {};
  paths.forEach((p, i) => {
    raw[p] = values[i];
  });
  const rawClients: Partial<Record<RenderClientFamily, unknown>> = {};
  RENDER_CLIENT_FAMILIES.forEach((f, i) => {
    rawClients[f] = clientValues[i];
  });
  const cfg = sanitizeRelayConfig(raw, rawClients);
  return { ...cfg, probe: { ...cfg.probe, countries: censored.edgeChecks } };
}

/** Whole hours, 1..24: the header is read as an integer by the apps that honour it. */
export function sanitizeUpdateIntervalHours(v: unknown): number {
  return sanitizeInt(v, 1, 24, EDGE_DEFAULTS.updateIntervalHours);
}

/**
 * The refresh hint alone (one point read): the subscription route needs it on
 * every request and nothing else of the `edge.*` namespace.
 */
export async function resolveUpdateIntervalHours(db: DatabaseReader): Promise<number> {
  return sanitizeUpdateIntervalHours(await readSetting(db, EDGE_KEYS.updateIntervalHours));
}

/**
 * Drains that are too short for the refresh hint, as `edge.<code>` warnings
 * (never refusals). The rule itself is shared with the settings page
 * (`drainWarningCodes`, src/shared/contracts/edgeCodes.ts).
 */
export function drainWarnings(
  cfg: Pick<EdgeConfig, 'drainMinutes' | 'burnedDrainMinutes' | 'updateIntervalHours'>,
  originDrainMinutes?: number,
): string[] {
  return drainWarningCodes(cfg, originDrainMinutes).map((c) => `edge.${c}`);
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

/** Millisecond views of the minute knobs, shared by the rotation machine + detector. */
export const edgeMs = {
  drain: (cfg: EdgeConfig) => cfg.drainMinutes * MIN,
  burnedDrain: (cfg: EdgeConfig) => cfg.burnedDrainMinutes * MIN,
  cooldown: (cfg: EdgeConfig) => cfg.cooldownMinutes * MIN,
  detectWindow: (cfg: EdgeConfig) => cfg.detect.windowMinutes * MIN,
  sniDrain: (cfg: EdgeConfig) => cfg.sniDrainMinutes * MIN,
};

// --- plumbing (constants, not settings) ------------------------------------------------------------

const PLUMBING_DEFAULTS = {
  /** How long the provider may take to build an edge before the run fails. */
  provisionTimeoutMs: 20 * MIN,
  /** How long to look for a resource whose create call was cut off. */
  discoveryTimeoutMs: 30 * MIN,
  /** Wall-clock cap of one rotation run; past it the run rolls back, else quarantines. */
  maxRotationMs: 120 * MIN,
  /** A running rotation checks the provider this often. */
  pollMs: 20_000,
  /** How long one step holds its claim before another worker may take it over. */
  opClaimMs: 60_000,
  /** Connect checks against a new edge before the run gives up on it. */
  verifyAttempts: 8,
  /** Tries to write the new address to the backend before rolling back. */
  maxFlipAttempts: 6,
  /** Tries to restore the previous state before the origin is quarantined. */
  maxRollbackAttempts: 6,
  /** Destroy passes (each may walk several resources) before the edge is left to the operator. */
  maxDestroyAttempts: 48,
  /** Resources one destroy pass may walk on one edge, in the provider's kind order. */
  maxDestroyStepsPerPass: 12,
  /** Automatic starts one reconcile pass may make (`edge.enabled` is the switch). */
  maxReconcileStartsPerTick: 1,
  /** After an automatic provision fails, upkeep provisions on that origin again only this much later. */
  autoProvisionBackoffMs: 60 * MIN,
  /** Report rows read per origin per evaluation; past it the window is `incomplete` (no rotation). */
  maxReportRowsPerEval: 2000,
  /** Per-step timeout of the authenticated front qualification session. */
  l7QualifyStepTimeoutMs: 10_000,
  /** Front re-proofs one reconcile pass may run (each is an outbound session, not a read). */
  l7MaxRequalifyPerTick: 6,
  /** How long a front qualification stays valid (its binding must also still match). */
  l7QualificationTtlMs: 60 * MIN,
  /** Affected-country evidence wait for a detector-triggered L7 replacement. */
  l7QualifyTimeoutMs: 15 * MIN,
  /** Gap between consecutive runs against the same external probe source within one batch. */
  probeSourceSpacingMs: 1500,
  /** Two blocked rounds closer than this are one look (the repeat is scheduled this far out). */
  countryRepeatMs: 30 * MIN,
  /** A name batch pairs with an address round finished at most this far from it. */
  countryHandshakePairMs: 60 * MIN,
  /** Two paired `path` batches closer than this count once. */
  countryHandshakeRepeatMs: 60 * MIN,
  /** Country-wide guard: this share of the edges checked there in the window turned blocked... */
  countryWideShare: 0.8,
  countryWideWindowMs: 120 * MIN,
  /** ...across at least this many groups and edges. */
  countryWideMinGroups: 2,
  countryWideMinEdges: 3,
};
export type EdgePlumbing = typeof PLUMBING_DEFAULTS;

/**
 * The machinery's timeouts, attempt caps, poll and claim intervals and
 * per-pass caps. Nothing here is an operator decision, so none of it is a
 * setting; tests and the edge-connection gate shorten them through
 * `__setEdgePlumbingForTests`.
 */
export const EDGE_PLUMBING: Readonly<EdgePlumbing> = { ...PLUMBING_DEFAULTS };

/** Test seam: override some plumbing constants; `null` restores every default. */
export function __setEdgePlumbingForTests(patch: Partial<EdgePlumbing> | null): void {
  Object.assign(EDGE_PLUMBING as EdgePlumbing, patch ?? PLUMBING_DEFAULTS);
}

/**
 * How long BEFORE a front qualification expires the reconcile cron renews it.
 * An expired proof makes the edge ineligible for rendering the moment it
 * lapses, so waiting for the expiry would flap a healthy front out of every
 * new subscription body until the next tick re-proves it. A quarter of the
 * TTL, never less than 15 minutes (a proof is an outbound session, not a
 * read) and never as much as half the TTL, so a fresh proof is not due again
 * at once.
 */
export function qualificationRenewLeadMs(): number {
  const ttl = EDGE_PLUMBING.l7QualificationTtlMs;
  return Math.min(Math.max(15 * MIN, ttl * 0.25), ttl / 2);
}

// --- per-origin knobs (one inheritance rule) ---------------------------------------------------------

/** The knobs an origin may override, as stored on `relays` (absent = follow the fleet). */
export interface OriginOverrides {
  standbyPerRelay?: number;
  standbyPerListener?: number;
  cooldownMs?: number;
  maxRotationsPerDay?: number;
  drainMs?: number;
}

/**
 * ONE inheritance rule for every per-origin knob: the origin's own value when
 * it set one, else the fleet's (`edge.*`). Every reader goes through this, so a
 * fleet change applies to each origin that did not override it, and a
 * per-origin value (a drain, a cooldown, a daily cap, spares) is honoured by the
 * rotation machine, the reconcile and the detector alike.
 */
export function originPolicy(o: OriginOverrides, cfg: EdgeConfig) {
  return {
    standbyPerRelay: o.standbyPerRelay ?? cfg.standbyPerRelay,
    standbyPerListener: o.standbyPerListener ?? cfg.standbyPerListener,
    cooldownMs: o.cooldownMs ?? edgeMs.cooldown(cfg),
    maxRotationsPerDay: o.maxRotationsPerDay ?? cfg.maxRotationsPerRelayPerDay,
    drainMs: o.drainMs ?? edgeMs.drain(cfg),
  };
}
export type OriginPolicy = ReturnType<typeof originPolicy>;

/** The override fields an origin set, by their names in the admin contract. */
export function originOverrideNames(o: OriginOverrides): string[] {
  const out: string[] = [];
  if (o.standbyPerRelay !== undefined) out.push('standbyPerRelay');
  if (o.standbyPerListener !== undefined) out.push('standbyPerListener');
  if (o.cooldownMs !== undefined) out.push('cooldownMinutes');
  if (o.maxRotationsPerDay !== undefined) out.push('maxRotationsPerDay');
  if (o.drainMs !== undefined) out.push('drainMinutes');
  return out;
}

// --- bounds (the CMS reads these; `edgeConfig.test.ts` pins them against the sanitizer) ---------

/**
 * Per integer / ratio knob (flat path): the range `sanitizeRelayConfig` clamps
 * to. ONE table, read by the settings UI for its NumberFields and pinned by a
 * test against the sanitizer, so a bound can never drift between the two.
 */
export const EDGE_CONFIG_BOUNDS: Readonly<Record<string, { min: number; max: number }>> = {
  desiredPublishedDefault: { min: 1, max: MAX_DESIRED_PUBLISHED_DEFAULT },
  standbyPerRelay: { min: 0, max: 2 },
  standbyPerListener: { min: 0, max: 2 },
  drainMinutes: { min: 1, max: 7 * 1440 },
  burnedDrainMinutes: { min: 0, max: 7 * 1440 },
  updateIntervalHours: { min: 1, max: 24 },
  sniDrainMinutes: { min: 1, max: 30 * 1440 },
  cooldownMinutes: { min: 10, max: 1440 },
  maxRotationsPerRelayPerDay: { min: 1, max: 12 },
  maxConcurrentRotations: { min: 1, max: 10 },
  'detect.windowMinutes': { min: 5, max: 180 },
  'detect.minReporters': { min: 1, max: 500 },
  'detect.minEdgeReporters': { min: 1, max: 500 },
  'detect.spikeFactor': { min: 1.5, max: 20 },
  'detect.loadDropPct': { min: 10, max: 95 },
  'detect.minLoadUsers': { min: 1, max: 10_000 },
  'detect.staleWeight': { min: 0, max: 1 },
  'detect.suspectAt': { min: 0.3, max: 1 },
  'detect.clearBelow': { min: 0, max: 1 },
  'detect.clearAfterEvals': { min: 1, max: 24 },
  'detect.minBaselineSamples': { min: 12, max: 1008 },
  'detect.probeWeight': { min: 0, max: 1 },
  'detect.fleetBreakerPct': { min: 1, max: 100 },
  'detect.fleetRotationsPerDay': { min: 0, max: 500 },
  'detect.sustainedChecks': { min: 3, max: 500 },
  'detect.sustainedNetworks': { min: 2, max: 10 },
  'detect.sustainedMinutes': { min: 30, max: 2880 },
  'l7.maxSameProviderReplacementsPerDay': { min: 0, max: 50 },
  'render.namesPerEndpoint': { min: 1, max: 5 },
  'render.backupNames': { min: 1, max: 5 },
  'probe.intervalMinutes': { min: 5, max: 1440 },
  'probe.suspectedIntervalMinutes': { min: 1, max: 1440 },
  'probe.perCountryLimit': { min: 1, max: 10 },
  'probe.hourlyBudget': { min: 0, max: 10_000 },
  'probe.agreementVantages': { min: 2, max: 10 },
  'probe.globalpingTestsPerHour': { min: 0, max: 100_000 },
  'country.minProbes': { min: 2, max: 10 },
  'country.minNetworks': { min: 1, max: 5 },
  'country.minControls': { min: 1, max: 5 },
  'country.blockedRounds': { min: 1, max: 5 },
  'country.windowDays': { min: 1, max: 60 },
  'country.standbyRecheckHours': { min: 1, max: 168 },
  'country.preUseWaitMinutes': { min: 0, max: 60 },
  'country.minProvenForExclusive': { min: 1, max: 5 },
  'render.clients.maxEntries': { min: 0, max: 20 },
};

/**
 * The config as flat `path: value` pairs (`detect.windowMinutes`, …), with the
 * per-family render rules kept as objects under `render.clients.<family>`. The
 * CMS diffs and resets against this shape.
 */
export function flattenEdgeConfig(cfg: EdgeConfig): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const walk = (obj: Record<string, unknown>, prefix: string) => {
    for (const [k, val] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (path === 'render.clients') {
        for (const [fam, rule] of Object.entries(val as Record<string, unknown>))
          out[`render.clients.${fam}`] = rule;
        continue;
      }
      if (val && typeof val === 'object' && !Array.isArray(val))
        walk(val as Record<string, unknown>, path);
      else out[path] = val;
    }
  };
  walk(cfg as unknown as Record<string, unknown>, '');
  return out;
}
