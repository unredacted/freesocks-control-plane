/**
 * Operator alerts config (docs/edges.md § "Operator alerts"). Stored in the
 * `appSettings` `alerts.*` namespace (like `analytics.*`: NOT in
 * SETTINGS_DEFAULTS, so it gets typed validation here and never leaks through
 * the generic settings allowlist). Opt-in: nothing is sent until an admin
 * enables it with a webhook URL.
 *
 * SECRETS: the access token and the topic (an ntfy topic is a capability:
 * whoever knows it can read the alerts) are SERVER-SIDE ONLY. The admin view
 * (`alertsView`) carries booleans for them and the webhook's origin, never
 * the path, the topic or the token; a write that leaves a field out keeps it.
 */
import type { DatabaseReader } from '../_generated/server';
import { checkInfraUrl } from './urlSafety';

export interface AlertsConfig {
  /** Master switch. Ships OFF. */
  enabled: boolean;
  /** The webhook: an ntfy server's root URL, or any endpoint taking the same JSON. https only. */
  url: string;
  /** ntfy topic ('' = none: a generic webhook that ignores it). */
  topic: string;
  /** Bearer token for the webhook ('' = none). */
  token: string;
}

export const ALERTS_DEFAULTS: AlertsConfig = { enabled: false, url: '', topic: '', token: '' };

export const ALERTS_KEYS = {
  enabled: 'alerts.enabled',
  url: 'alerts.url',
  topic: 'alerts.topic',
  token: 'alerts.token',
} as const;

const MAX_URL = 512;

/**
 * The webhook URL: https only (ALLOW_INTERNAL_BACKENDS=true also admits http
 * for a local or compose-network receiver in development) and the shared
 * infra SSRF denylist, because the backend posts to it every few minutes. A
 * trailing slash is stripped. Anything else is ''.
 */
export function sanitizeAlertsUrl(v: unknown): string {
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

/** An ntfy topic: letters, digits, `_` and `-` (ntfy's own rule), at most 64; else ''. */
export function sanitizeAlertsTopic(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  return /^[A-Za-z0-9_-]{1,64}$/.test(s) ? s : '';
}

/** A bearer token: printable ASCII without spaces, at most 512; else ''. */
export function sanitizeAlertsToken(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  return /^[\x21-\x7e]{1,512}$/.test(s) ? s : '';
}

export async function resolveAlertsConfig(db: DatabaseReader): Promise<AlertsConfig> {
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
  const [enabled, url, topic, token] = await Promise.all([
    read(ALERTS_KEYS.enabled),
    read(ALERTS_KEYS.url),
    read(ALERTS_KEYS.topic),
    read(ALERTS_KEYS.token),
  ]);
  return {
    enabled: enabled === true,
    url: sanitizeAlertsUrl(url),
    topic: sanitizeAlertsTopic(topic),
    token: sanitizeAlertsToken(token),
  };
}

/** The webhook's origin (scheme + host + port): what the admin view shows of the URL. */
export function urlOrigin(url: string): string {
  if (!url) return '';
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}
