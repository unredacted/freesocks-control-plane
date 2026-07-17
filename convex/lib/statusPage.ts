/**
 * The public network-status projection (`GET /api/v1/status`) + its
 * operator-facing config. Everything here is public-safe by construction:
 * location codes/labels and coarse load BANDS only — never a URL, token, raw
 * user count, or per-node number (the privacy posture, matching the GB-only
 * donation projection).
 *
 * Three inputs, all already collected: backendServers (healthcheck cron +
 * fleetStats + keyCount/maxKeys), remnawaveNodeStats (the placement-load
 * cache), and the operator-published `statusIncidents` table. The censorship
 * availability matrix + load thresholds live in the `appSettings` `status.*`
 * namespace (deliberately NOT in SETTINGS_DEFAULTS — typed validation here,
 * fail-safe resolve), edited from Admin → Status.
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { CONNECTION_MODES, isConnectionModeId, resolveConnectionModes } from './connectionModes';
import {
  computeLocationLoad,
  HEALTH_FRESH_MS,
  LOAD_THRESHOLD_DEFAULTS,
  type LoadBand,
  type LoadThresholds,
} from './loadBands';

export type { LoadBand };

// ---------------------------------------------------------------------------
// Types (the public wire shape — mirrored by src/shared/contracts/status.ts)
// ---------------------------------------------------------------------------

export interface StatusLocation {
  code: string;
  label: string;
  online: boolean;
  nodesOnline: number | null;
  nodesTotal: number | null;
  load: LoadBand;
}

export type CensorshipCell = 'available' | 'partial' | 'blocked';

export interface CensorshipRow {
  /** ISO-3166-1 alpha-2, uppercase. */
  countryCode: string;
  /** Optional display override; absent = the SPA renders the code (+ flag). */
  label: string | null;
  cells: Record<string, CensorshipCell>;
}

export interface StatusIncidentView {
  id: string;
  title: string;
  body: string | null;
  severity: 'maintenance' | 'degraded' | 'outage';
  locationCodes: string[];
  startedAt: number;
  resolvedAt: number | null;
}

export interface PublicStatusPage {
  generatedAt: string;
  locations: StatusLocation[];
  censorship: {
    modes: { id: string; label: string | null }[];
    rows: CensorshipRow[];
  };
  incidents: StatusIncidentView[];
}

// ---------------------------------------------------------------------------
// Settings namespace (`status.*`)
// ---------------------------------------------------------------------------

export const STATUS_KEYS = {
  censorship: 'status.censorship',
  loadBusyAt: 'status.loadBusyAt',
  loadCrowdedAt: 'status.loadCrowdedAt',
} as const;

const MAX_CENSORSHIP_ROWS = 40;
const MAX_COUNTRY_LABEL = 60;
const CELL_VALUES = new Set<CensorshipCell>(['available', 'partial', 'blocked']);

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

function sanitizeThreshold(raw: unknown, fallback: number): number {
  return typeof raw === 'number' &&
    Number.isFinite(raw) &&
    Number.isInteger(raw) &&
    raw >= 1 &&
    raw <= 100_000
    ? raw
    : fallback;
}

/** Coerce an operator-supplied censorship matrix: unknown countries/modes/cell
 *  values are dropped (never an error), rows are deduped by country code
 *  (last wins), capped, and sorted by code for a stable public order. */
export function sanitizeCensorshipRows(raw: unknown): CensorshipRow[] {
  if (!raw || typeof raw !== 'object') return [];
  const rows = (raw as Record<string, unknown>).rows;
  if (!Array.isArray(rows)) return [];
  const byCode = new Map<string, CensorshipRow>();
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const o = r as Record<string, unknown>;
    const code = typeof o.countryCode === 'string' ? o.countryCode.trim().toUpperCase() : '';
    if (!/^[A-Z]{2}$/.test(code)) continue;
    const label =
      typeof o.label === 'string' && o.label.trim()
        ? o.label.trim().slice(0, MAX_COUNTRY_LABEL)
        : null;
    const cells: Record<string, CensorshipCell> = {};
    if (o.cells && typeof o.cells === 'object') {
      for (const [modeId, val] of Object.entries(o.cells as Record<string, unknown>)) {
        if (!isConnectionModeId(modeId)) continue;
        if (typeof val === 'string' && CELL_VALUES.has(val as CensorshipCell)) {
          cells[modeId] = val as CensorshipCell;
        }
      }
    }
    byCode.set(code, { countryCode: code, label, cells });
  }
  return [...byCode.values()]
    .sort((a, b) => a.countryCode.localeCompare(b.countryCode))
    .slice(0, MAX_CENSORSHIP_ROWS);
}

export interface StatusPageConfig extends LoadThresholds {
  censorshipRows: CensorshipRow[];
}

/** Resolve the `status.*` namespace, fail-safe. */
export async function resolveStatusConfig(db: DatabaseReader): Promise<StatusPageConfig> {
  const busyAt = sanitizeThreshold(
    await readSetting(db, STATUS_KEYS.loadBusyAt),
    LOAD_THRESHOLD_DEFAULTS.busyAt,
  );
  const crowdedRaw = sanitizeThreshold(
    await readSetting(db, STATUS_KEYS.loadCrowdedAt),
    LOAD_THRESHOLD_DEFAULTS.crowdedAt,
  );
  return {
    busyAt,
    // Invariant: crowded >= busy (a mis-ordered pair would invert the bands).
    crowdedAt: Math.max(crowdedRaw, busyAt),
    censorshipRows: sanitizeCensorshipRows(await readSetting(db, STATUS_KEYS.censorship)),
  };
}

// ---------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------

/**
 * Group located, active Remnawave instances by location code and decorate each
 * code with health, node counts, and the load band. Shared by the public
 * status projection and (single-code) the member node-status badge.
 */
export async function resolveStatusLocations(db: DatabaseReader): Promise<StatusLocation[]> {
  const servers = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();
  const statsRows = await db.query('remnawaveNodeStats').collect();
  const cfg = await resolveStatusConfig(db);
  const now = Date.now();

  const byCode = new Map<string, typeof servers>();
  for (const s of servers) {
    if (!s.location) continue;
    const list = byCode.get(s.location);
    if (list) list.push(s);
    else byCode.set(s.location, [s]);
  }

  const out: StatusLocation[] = [];
  for (const [code, instances] of byCode) {
    const online = instances.some(
      (s) => s.lastHealthOkAt != null && now - s.lastHealthOkAt < HEALTH_FRESH_MS,
    );
    // Node counts from the freshest fleetStats among the code's instances.
    let nodesOnline: number | null = null;
    let nodesTotal: number | null = null;
    let freshest = -1;
    for (const s of instances) {
      if (!s.fleetStats || s.fleetStatsAt == null || s.fleetStatsAt <= freshest) continue;
      freshest = s.fleetStatsAt;
      nodesOnline = s.fleetStats.nodesOnline;
      nodesTotal = s.fleetStats.nodesTotal;
    }
    const label = instances.find((s) => s.locationLabel)?.locationLabel ?? code;
    out.push({
      code,
      label,
      online,
      nodesOnline,
      nodesTotal,
      load: computeLocationLoad(
        instances,
        statsRows,
        new Set(instances.map((s) => s._id)),
        cfg,
        now,
        HEALTH_FRESH_MS,
      ),
    });
  }
  return out.sort((a, b) => a.code.localeCompare(b.code));
}

/** Single-code convenience for the member node-status badge (A4). Returns null
 *  when the code has no located instances (the caller omits the field). */
export async function resolveLocationLoad(
  db: DatabaseReader,
  code: string,
): Promise<LoadBand | null> {
  const servers = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();
  const instances = servers.filter((s) => s.location === code);
  if (instances.length === 0) return null;
  const statsRows = await db.query('remnawaveNodeStats').collect();
  const cfg = await resolveStatusConfig(db);
  const now = Date.now();
  return computeLocationLoad(
    instances,
    statsRows,
    new Set(instances.map((s) => s._id)),
    cfg,
    now,
    HEALTH_FRESH_MS,
  );
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

/** Public incident window: unresolved (any age) + resolved within 30 days. */
const RESOLVED_WINDOW_MS = 30 * 86_400_000;
const PUBLIC_INCIDENT_CAP = 50;

function toIncidentView(r: Doc<'statusIncidents'>): StatusIncidentView {
  return {
    id: r._id as string,
    title: r.title,
    body: r.body ?? null,
    severity: r.severity,
    locationCodes: r.locationCodes,
    startedAt: r.startedAt,
    resolvedAt: r.resolvedAt ?? null,
  };
}

export async function resolvePublicIncidents(
  db: DatabaseReader,
  now: number,
): Promise<StatusIncidentView[]> {
  const rows = await db
    .query('statusIncidents')
    .withIndex('by_startedAt')
    .order('desc')
    .take(PUBLIC_INCIDENT_CAP * 2);
  return rows
    .filter((r) => r.resolvedAt == null || now - r.resolvedAt <= RESOLVED_WINDOW_MS)
    .slice(0, PUBLIC_INCIDENT_CAP)
    .map(toIncidentView);
}

// ---------------------------------------------------------------------------
// Admin incident input validation
// ---------------------------------------------------------------------------

const MAX_INCIDENT_TITLE = 120;
const MAX_INCIDENT_BODY = 2000;
const MAX_INCIDENT_LOCATIONS = 20;
const SEVERITIES = new Set(['maintenance', 'degraded', 'outage']);

export interface IncidentInput {
  title: string;
  body?: string;
  severity: 'maintenance' | 'degraded' | 'outage';
  locationCodes: string[];
  startedAt: number;
}

/** Validate an admin create/update payload. Throws Error with a
 *  caller-presentable message on the first invalid field. */
export function validateIncidentInput(raw: unknown): IncidentInput {
  if (!raw || typeof raw !== 'object') throw new Error('incident must be an object');
  const o = raw as Record<string, unknown>;
  const title = typeof o.title === 'string' ? o.title.trim() : '';
  if (!title) throw new Error('title is required');
  if (title.length > MAX_INCIDENT_TITLE) throw new Error('title too long');
  const body =
    typeof o.body === 'string' && o.body.trim()
      ? o.body.trim().slice(0, MAX_INCIDENT_BODY)
      : undefined;
  if (typeof o.severity !== 'string' || !SEVERITIES.has(o.severity)) {
    throw new Error('severity must be maintenance | degraded | outage');
  }
  const locationCodes: string[] = [];
  if (o.locationCodes !== undefined) {
    if (!Array.isArray(o.locationCodes)) throw new Error('locationCodes must be an array');
    for (const c of o.locationCodes) {
      if (typeof c !== 'string') throw new Error('locationCodes must be strings');
      const code = c.trim();
      if (!code) continue;
      if (code.length > 32) throw new Error('location code too long');
      if (!locationCodes.includes(code)) locationCodes.push(code);
      if (locationCodes.length > MAX_INCIDENT_LOCATIONS) throw new Error('too many locations');
    }
  }
  const startedAt =
    typeof o.startedAt === 'number' && Number.isFinite(o.startedAt) ? o.startedAt : NaN;
  if (!Number.isFinite(startedAt) || startedAt < 0 || startedAt > Date.now() + 86_400_000) {
    throw new Error('startedAt must be a sane epoch-ms timestamp');
  }
  return {
    title,
    body,
    severity: o.severity as IncidentInput['severity'],
    locationCodes,
    startedAt,
  };
}

// ---------------------------------------------------------------------------
// The assembled public page
// ---------------------------------------------------------------------------

export async function resolvePublicStatusPage(db: DatabaseReader): Promise<PublicStatusPage> {
  const [locations, cfg, incidents, modes] = await Promise.all([
    resolveStatusLocations(db),
    resolveStatusConfig(db),
    resolvePublicIncidents(db, Date.now()),
    resolveConnectionModes(db),
  ]);
  return {
    generatedAt: new Date().toISOString(),
    locations,
    censorship: {
      modes: CONNECTION_MODES.map((def) => ({
        id: def.id,
        label: modes.find((m) => m.id === def.id)?.label ?? null,
      })),
      rows: cfg.censorshipRows,
    },
    incidents,
  };
}
