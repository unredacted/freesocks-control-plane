/**
 * Member issue telemetry: config + sanitizers for the OPT-IN diagnostic fields
 * (country / city / ASN) a member may attach when they switch servers or report
 * a connection problem. Stored in the `diagnostics.*` appSettings namespace
 * (the typed `analytics.*` pattern — deliberately NOT in SETTINGS_DEFAULTS).
 *
 * PRIVACY INVARIANTS (see docs/privacy.md):
 * - Telemetry rows (`issueReports`) are UNLINKED: no userId, no subscriptionId,
 *   and never an IP. They answer "what is failing, where, on which networks" —
 *   not "who". The per-user audit log keeps carrying the reason alone.
 * - The member SEES and can EDIT every value before it is sent (the CDN's view
 *   is wrong by construction when they report from inside the VPN), and the
 *   whole block is skippable with one checkbox.
 * - Geo prefill comes from Cloudflare edge headers ONLY when the operator has
 *   turned `cloudflareEnabled` on — off-CDN those headers are client-spoofable
 *   noise, so they are never read. Submitted values are sanitized to narrow
 *   shapes either way (2-letter country, numeric ASN, length-capped city).
 */
import type { DatabaseReader } from '../_generated/server';

export interface DiagnosticsConfig {
  /** Master switch for recording issue-telemetry rows. */
  enabled: boolean;
  /** Trust Cloudflare edge geo headers for the member-visible prefill. */
  cloudflareEnabled: boolean;
  /** Which optional fields the deployment accepts at all. */
  collectCountry: boolean;
  collectCity: boolean;
  collectAsn: boolean;
  /**
   * Header carrying the client ASN. Cloudflare ships no ASN header by default:
   * the operator adds a Transform Rule setting one from `ip.src.asnum` (country
   * and city come from the free "Add visitor location headers" Managed
   * Transform as cf-ipcountry / cf-ipcity). Name is operator-tunable so any
   * fronting CDN can supply it.
   */
  asnHeader: string;
  /** How long telemetry rows are kept (days, 1–365) before the daily sweep. */
  retentionDays: number;
}

export const DIAGNOSTICS_DEFAULTS: DiagnosticsConfig = {
  enabled: true,
  cloudflareEnabled: false,
  collectCountry: true,
  collectCity: true,
  collectAsn: true,
  asnHeader: 'x-client-asn',
  retentionDays: 90,
};

export const DIAGNOSTICS_KEYS = {
  enabled: 'diagnostics.enabled',
  cloudflareEnabled: 'diagnostics.cloudflareEnabled',
  collectCountry: 'diagnostics.collectCountry',
  collectCity: 'diagnostics.collectCity',
  collectAsn: 'diagnostics.collectAsn',
  asnHeader: 'diagnostics.asnHeader',
  retentionDays: 'diagnostics.retentionDays',
} as const;

/** ISO-3166-1 alpha-2 shape, uppercased; Cloudflare's non-country sentinels
 *  (XX unknown, T1 Tor) rejected. Null = absent/invalid. */
export function sanitizeCountry(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(s) || s === 'XX' || s === 'T1') return null;
  return s;
}

/** City: printable text, control chars stripped, capped at 64. The ONE
 *  member-editable free-text telemetry field — it never reaches the audit log
 *  (curated scalars only), only the unlinked issueReports table. */
export function sanitizeCity(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!s) return null;
  return s.slice(0, 64);
}

/** AS number: a positive integer in the 32-bit ASN space. Accepts "AS44244"
 *  style strings too (people paste them like that). Null = absent/invalid. */
export function sanitizeAsn(v: unknown): number | null {
  let n: number | null = null;
  if (typeof v === 'number' && Number.isInteger(v)) n = v;
  else if (typeof v === 'string') {
    const m = /^(?:AS)?(\d{1,10})$/i.exec(v.trim());
    if (m) n = Number(m[1]);
  }
  return n !== null && n >= 1 && n <= 4_294_967_295 ? n : null;
}

/** Header NAME shape (mirrors analytics.ipHeader): lowercase token, else the
 *  default. x-forwarded-for style multi-hop lists make no sense for ASN, but
 *  nothing here is security-path — worst case is a wrong number in telemetry. */
export function sanitizeAsnHeader(v: unknown): string {
  if (typeof v !== 'string') return DIAGNOSTICS_DEFAULTS.asnHeader;
  const s = v.trim().toLowerCase();
  return /^[a-z0-9-]{1,64}$/.test(s) ? s : DIAGNOSTICS_DEFAULTS.asnHeader;
}

export function sanitizeRetentionDays(v: unknown): number {
  const n = typeof v === 'number' ? Math.floor(v) : NaN;
  return Number.isFinite(n) && n >= 1 && n <= 365 ? n : DIAGNOSTICS_DEFAULTS.retentionDays;
}

export async function resolveDiagnosticsConfig(db: DatabaseReader): Promise<DiagnosticsConfig> {
  const read = async (key: string): Promise<unknown> => {
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
  };
  const [enabled, cf, country, city, asn, asnHeader, retention] = await Promise.all([
    read(DIAGNOSTICS_KEYS.enabled),
    read(DIAGNOSTICS_KEYS.cloudflareEnabled),
    read(DIAGNOSTICS_KEYS.collectCountry),
    read(DIAGNOSTICS_KEYS.collectCity),
    read(DIAGNOSTICS_KEYS.collectAsn),
    read(DIAGNOSTICS_KEYS.asnHeader),
    read(DIAGNOSTICS_KEYS.retentionDays),
  ]);
  const bool = (v: unknown, dflt: boolean) => (typeof v === 'boolean' ? v : dflt);
  return {
    enabled: bool(enabled, DIAGNOSTICS_DEFAULTS.enabled),
    cloudflareEnabled: bool(cf, DIAGNOSTICS_DEFAULTS.cloudflareEnabled),
    collectCountry: bool(country, DIAGNOSTICS_DEFAULTS.collectCountry),
    collectCity: bool(city, DIAGNOSTICS_DEFAULTS.collectCity),
    collectAsn: bool(asn, DIAGNOSTICS_DEFAULTS.collectAsn),
    asnHeader: sanitizeAsnHeader(asnHeader),
    retentionDays: sanitizeRetentionDays(retention),
  };
}

/** The submitted (member-editable) telemetry fields, post-sanitize, filtered to
 *  what the deployment collects. Null when the member declined or telemetry is
 *  off entirely. */
export interface TelemetryFields {
  country: string | null;
  city: string | null;
  asn: number | null;
}

export function sanitizeSubmitted(cfg: DiagnosticsConfig, raw: unknown): TelemetryFields | null {
  if (!cfg.enabled || raw === null || raw === undefined || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  return {
    country: cfg.collectCountry ? sanitizeCountry(o.country) : null,
    city: cfg.collectCity ? sanitizeCity(o.city) : null,
    asn: cfg.collectAsn ? sanitizeAsn(o.asn) : null,
  };
}

/** What the CDN edge claims about this request — the member-visible prefill and
 *  the stored `detected*` comparison values. All null unless the operator has
 *  enabled Cloudflare sourcing (off-CDN these headers are client-spoofable). */
export function detectedFromHeaders(cfg: DiagnosticsConfig, req: Request): TelemetryFields {
  if (!cfg.enabled || !cfg.cloudflareEnabled) return { country: null, city: null, asn: null };
  return {
    country: cfg.collectCountry ? sanitizeCountry(req.headers.get('cf-ipcountry')) : null,
    city: cfg.collectCity ? sanitizeCity(req.headers.get('cf-ipcity')) : null,
    asn: cfg.collectAsn ? sanitizeAsn(req.headers.get(cfg.asnHeader)) : null,
  };
}
