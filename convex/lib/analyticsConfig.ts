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
   * Forward the visitor's IP to Umami in the custom `x-freesocks-client-ip`
   * header (enables Umami-side geo). OFF by default: Umami then sees only this
   * backend's egress IP. The custom header name fails CLOSED — Umami ignores it
   * unless the operator sets CLIENT_IP_HEADER=x-freesocks-client-ip on the
   * Umami side (unlike x-forwarded-for, which Umami reads by default).
   */
  forwardIp: boolean;
}

export const ANALYTICS_DEFAULTS: AnalyticsConfig = {
  enabled: false,
  umamiUrl: '',
  websiteId: '',
  forwardIp: false,
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
