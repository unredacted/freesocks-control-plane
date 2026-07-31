/**
 * Analytics relay config (self-hosted Umami). Stored in the `appSettings`
 * `analytics.*` namespace (like `verification.*` / `site.*`: deliberately NOT
 * in SETTINGS_DEFAULTS, so it gets typed validation here instead of leaking
 * through the generic settings allowlist).
 *
 * PRIVACY INVARIANT: `umamiUrl` and `websiteId` are SERVER-SIDE ONLY. The
 * public projection (`publicAnalytics`) carries exactly one boolean — the SPA
 * never learns the operator's Umami host (censorship resistance: a client can't
 * enumerate the operator's analytics infrastructure), and the pageview beacon
 * goes to the same-origin `/api/v1/telemetry` relay instead.
 */
import type { DatabaseReader } from '../_generated/server';
import { checkInfraUrl } from './urlSafety';

export interface AnalyticsConfig {
  /** Master switch for the pageview relay. Ships OFF. */
  enabled: boolean;
  /** Base URL of the operator's self-hosted Umami (https-only); '' = unset. */
  umamiUrl: string;
  /** Umami website id (UUID) the relay reports under; '' = unset. */
  websiteId: string;
  /**
   * Forward the visitor's IP to Umami per request as `payload.ip` (enables
   * Umami-side geo; supported since Umami v2.17.0, older versions ignore it).
   * OFF by default: Umami then sees only this backend's egress IP. Payload
   * placement (never a header) needs no Umami instance config, so a shared
   * multi-site Umami is unaffected for its other sites.
   */
  forwardIp: boolean;
  /**
   * Where the relay reads the visitor IP when forwardIp is on. '' (default) =
   * the fail-closed resolveClientIp (CF_FRONTED / TRUSTED_PROXY_HOPS envs);
   * else the NAME of a single-IP request header set by the operator's fronting
   * CDN, e.g. 'cf-connecting-ip' (Cloudflare) or 'fastly-client-ip' (Fastly).
   * ANALYTICS-ONLY trust, deliberately separate from resolveClientIp: the
   * security-path IP trust (rate-limit buckets) stays env-based and fail-
   * closed, so an admin:settings:write token can't widen it. Worst case for a
   * wrong/spoofed header here is polluted geo in the operator's own Umami.
   * NOTE: cf-connecting-ip additionally needs CADDY_TRUST_CF_HEADER=true on
   * the web (Caddy) service — the stock Caddyfile strips that header.
   */
  ipHeader: string;
  /**
   * Location granularity when forwardIp is on. 'full' (default) = the visitor
   * IP is sent as payload.ip: Umami derives country/region/CITY and keeps real
   * per-visitor uniqueness. 'coarse' = the IP is NEVER sent; the relay instead
   * copies the fronting Cloudflare edge's inbound geo headers (cf-ipcountry +
   * cf-region-code — region needs the free "Add visitor location headers"
   * Managed Transform on the zone) onto the outbound Umami request, which
   * Umami reads when payload.ip is absent. City is structurally absent in
   * coarse mode; unique-visitor counts degrade to per-user-agent buckets
   * (Umami hashes the request IP, which is then always this backend's).
   */
  geoMode: 'full' | 'coarse';
}

export const ANALYTICS_DEFAULTS: AnalyticsConfig = {
  enabled: false,
  umamiUrl: '',
  websiteId: '',
  forwardIp: false,
  ipHeader: '',
  geoMode: 'full',
};

const MAX_URL = 512;

/**
 * The Umami base URL: https-only + the shared infra SSRF denylist (the backend
 * fetches this URL on every pageview, so a stored value is a durable SSRF
 * primitive exactly like a backend panel URL — checkInfraUrl rejects
 * loopback/link-local/metadata literals). ALLOW_INTERNAL_BACKENDS=true (the
 * existing dev knob, already honored inside checkInfraUrl) additionally lifts
 * the https requirement here so a local/compose-network Umami works in dev.
 * Trailing slash stripped so `${umamiUrl}/api/send` composes cleanly. Else ''.
 */
export function sanitizeUmamiUrl(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  if (!s || s.length > MAX_URL) return '';
  const allowInternal = process.env.ALLOW_INTERNAL_BACKENDS === 'true';
  if (!/^https:\/\/[^\s]+$/i.test(s) && !(allowInternal && /^http:\/\/[^\s]+$/i.test(s))) {
    return '';
  }
  if (!checkInfraUrl(s).ok) return '';
  return s.replace(/\/+$/, '');
}

/** An Umami website id: UUID-shaped (lowercased), else ''. */
export function sanitizeWebsiteId(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().toLowerCase();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) ? s : '';
}

/**
 * An HTTP header NAME (RFC 9110 token charset, conservatively narrowed to the
 * chars real client-IP headers use), lowercased; '' = use resolveClientIp.
 * Never trust x-forwarded-for through this knob — it's a multi-hop LIST, and
 * picking the right entry is exactly what TRUSTED_PROXY_HOPS already does
 * fail-closed; naive first-entry reads are client-spoofable.
 */
export function sanitizeIpHeaderName(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().toLowerCase();
  if (s === '' || s === 'x-forwarded-for') return '';
  return /^[a-z0-9-]{1,64}$/.test(s) ? s : '';
}

/** Location granularity; anything unrecognized falls back to 'full'. */
export function sanitizeGeoMode(v: unknown): 'full' | 'coarse' {
  return v === 'coarse' ? 'coarse' : 'full';
}

export async function resolveAnalyticsConfig(db: DatabaseReader): Promise<AnalyticsConfig> {
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
  const enabledVal = await read('analytics.enabled');
  const forwardIpVal = await read('analytics.forwardIp');
  return {
    enabled: typeof enabledVal === 'boolean' ? enabledVal : ANALYTICS_DEFAULTS.enabled,
    umamiUrl: sanitizeUmamiUrl(await read('analytics.umamiUrl')),
    websiteId: sanitizeWebsiteId(await read('analytics.websiteId')),
    forwardIp: typeof forwardIpVal === 'boolean' ? forwardIpVal : ANALYTICS_DEFAULTS.forwardIp,
    ipHeader: sanitizeIpHeaderName(await read('analytics.ipHeader')),
    geoMode: sanitizeGeoMode(await read('analytics.geoMode')),
  };
}

/**
 * The ONLY analytics shape that may reach publicConfig.get. Exactly one key,
 * by construction: a future AnalyticsConfig field can't leak without someone
 * consciously widening this projection. "Effectively enabled" (toggle AND both
 * targets set) so the SPA never beacons into an unconfigured relay.
 */
export function publicAnalytics(cfg: AnalyticsConfig): { enabled: boolean } {
  return { enabled: cfg.enabled && cfg.umamiUrl !== '' && cfg.websiteId !== '' };
}
