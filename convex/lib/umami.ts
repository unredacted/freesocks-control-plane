/**
 * Umami relay: builds and sends the `/api/send` event for the pageview beacon
 * (POST /api/v1/telemetry). Pure HTTP, no Convex wrappers, modeled on
 * `captcha.ts`.
 *
 * PRIVACY-BY-CONSTRUCTION (docs/privacy.md):
 * - The reported page is resolved against a server-side ROUTE ALLOWLIST — no
 *   free-form path or title from the client ever reaches Umami, so a route
 *   that embeds an identifier can't leak it (unknown routes bucket to
 *   '/other'). Adding a member-facing SPA route means adding a line here.
 * - Referrers are reduced to their ORIGIN (a full referring URL can identify
 *   a private page); in-app referrers are themselves allowlist-checked.
 * - Outbound headers are built from an explicit literal: no inbound header,
 *   cookie, or session value is ever forwarded. The client's User-Agent is
 *   forwarded (Umami drops events without a valid UA) after stripping
 *   non-printable chars — CR/LF removal is header-injection hygiene.
 * - The visitor IP is included ONLY when the operator enabled forwardIp with
 *   geoMode 'full', as `payload.ip` (Umami v2.17+): honored per request with
 *   no Umami instance config, so a shared multi-site Umami instance is
 *   unaffected for its other sites. Older Umami versions simply ignore the
 *   field (no geo). geoMode 'coarse' sends country+region GEO HEADERS instead
 *   (no IP ever, no city ever) — see UmamiEventArgs.geo.
 * - Fail-soft and silent: errors are swallowed, nothing is logged (a log line
 *   here would carry a UA/IP), the response body is never read.
 */
import type { AnalyticsConfig } from './analyticsConfig';

/**
 * Member-facing SPA routes → static Umami page titles. Keep in sync with the
 * route set rendered in src/client/App.svelte. Deliberately English-only and
 * static: the live document.title is localized and could embed dynamic data.
 */
export const ROUTE_ALLOWLIST: Record<string, string> = {
  '/': 'Home',
  '/get-account': 'Get account',
  '/account': 'Account',
  '/login': 'Sign in',
  '/status': 'Network status',
};

const OTHER_ROUTE = { url: '/other', title: 'Other' };

/** Exact allowlist lookup; anything else (or a non-string) buckets to /other. */
export function resolveRoute(v: unknown): { url: string; title: string } {
  if (typeof v !== 'string') return OTHER_ROUTE;
  const title = ROUTE_ALLOWLIST[v];
  return title === undefined ? OTHER_ROUTE : { url: v, title };
}

/**
 * Referrer: an in-app route must itself be on the allowlist (else ''); an
 * external http(s) URL is reduced to its origin; everything else is ''.
 */
export function sanitizeReferrer(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  if (!s || s.length > 512) return '';
  if (s.startsWith('/')) return ROUTE_ALLOWLIST[s] === undefined ? '' : s;
  if (!/^https?:\/\//i.test(s)) return '';
  try {
    const origin = new URL(s).origin;
    return origin === 'null' || origin.length > 128 ? '' : origin;
  } catch {
    return '';
  }
}

/**
 * The three coarse screen buckets the client may report (representative WxH
 * strings so Umami's device classification still parses them). Exact-match:
 * a real resolution can't sneak through as a fingerprint.
 */
export const SCREEN_BUCKETS = ['480x854', '834x1112', '1920x1080'] as const;

export function sanitizeScreen(v: unknown): string {
  return typeof v === 'string' && (SCREEN_BUCKETS as readonly string[]).includes(v) ? v : '';
}

/** Primary language subtag only ('en', 'fa' — the SPA's locale set). */
export function sanitizeLanguage(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().toLowerCase();
  return /^[a-z]{2,3}$/.test(s) ? s : '';
}

/** Hostname charset check for the server-read x-forwarded-host/host header. */
export function sanitizeHostname(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().replace(/:\d+$/, ''); // drop a :port suffix
  return /^[a-z0-9.-]{1,253}$/i.test(s) ? s.toLowerCase() : '';
}

const UA_FALLBACK = 'Mozilla/5.0 (compatible; FreeSocksRelay/1.0)';

/**
 * Printable-ASCII-only UA (strips CR/LF and other control chars — this value
 * becomes an OUTBOUND HEADER, so it's a header-injection vector), capped, with
 * a fixed fallback because Umami drops events lacking a valid User-Agent.
 */
export function sanitizeUserAgent(v: unknown): string {
  if (typeof v !== 'string') return UA_FALLBACK;
  // eslint-disable-next-line no-control-regex
  const s = v
    .replace(/[^\x20-\x7e]/g, '')
    .trim()
    .slice(0, 350);
  return s === '' ? UA_FALLBACK : s;
}

/**
 * Charset/length check for the opt-in forwarded IP. The value comes from
 * resolveClientIp (trusted-proxy-derived), so this is belt-and-braces before
 * embedding it in the outbound JSON — never from the beacon body.
 */
export function sanitizeIp(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  return /^[0-9a-f.:]{2,45}$/i.test(s) ? s : '';
}

/**
 * ISO-3166-1 alpha-2 country for the coarse geo mode, read from the fronting
 * Cloudflare edge's cf-ipcountry. CF's non-country sentinels (XX unknown,
 * T1 Tor) drop to '' (send nothing rather than a junk dimension).
 */
export function sanitizeCountryCode(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().toUpperCase();
  if (s === 'XX' || s === 'T1' || s === 'T2') return '';
  return /^[A-Z]{2}$/.test(s) ? s : '';
}

/** ISO-3166-2 region suffix (cf-region-code, e.g. "MO", "75"); outbound-header
 *  safe charset. Umami combines it with the country ("US-MO") itself. */
export function sanitizeRegionCode(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().toUpperCase();
  return /^[A-Z0-9-]{1,6}$/.test(s) ? s : '';
}

export interface UmamiEventArgs {
  cfg: Pick<AnalyticsConfig, 'umamiUrl' | 'websiteId'>;
  /** The raw (untrusted) beacon body from the client. */
  input: Record<string, unknown> | null;
  userAgent: string | null;
  /** Server-derived site hostname (x-forwarded-host || host), pre-sanitize. */
  hostname: string | null;
  /** Resolved client IP, ONLY when forwardIp is on AND geoMode is 'full'. */
  clientIp: string | null;
  /**
   * Coarse geo (forwardIp on + geoMode 'coarse'): the fronting edge's inbound
   * cf-ipcountry / cf-region-code, pre-sanitize. Sent as OUTBOUND geo headers,
   * which Umami reads when payload.ip is absent — so country/region record
   * WITHOUT the visitor IP ever leaving this backend, and city is structurally
   * absent (the city header is never sent). Mutually exclusive with clientIp:
   * when set, no payload.ip is emitted.
   */
  geo: { country: string | null; region: string | null } | null;
}

/**
 * Forward one pageview to `<umamiUrl>/api/send`. Never throws, never logs,
 * never reads the response body. The 1s timeout is deliberately tight: the
 * real risk isn't a lost pageview, it's a hung Umami holding a Convex action
 * slot per beacon while action concurrency is shared with issuance.
 */
export async function sendUmamiEvent(args: UmamiEventArgs): Promise<void> {
  const { cfg, input, userAgent, hostname, clientIp, geo } = args;
  if (!cfg.umamiUrl || !cfg.websiteId) return;

  const route = resolveRoute(input?.route);
  // Opt-in IP forwarding rides in `payload.ip` (Umami v2.17+): honored
  // PER REQUEST with no Umami instance config, so a shared multi-site Umami
  // is unaffected for its other sites (the instance-global CLIENT_IP_HEADER
  // approach couldn't offer that). Umami then ignores proxy geo headers and
  // does a local GeoIP lookup — deterministic regardless of what fronts it.
  // The value comes ONLY from the resolved-clientIp argument, never from the
  // untrusted beacon body — and NEVER alongside coarse geo (payload.ip would
  // make Umami skip the geo headers entirely).
  const ip = geo ? '' : sanitizeIp(clientIp);
  const payload = {
    type: 'event',
    payload: {
      website: cfg.websiteId,
      hostname: sanitizeHostname(hostname),
      url: route.url,
      title: route.title,
      referrer: sanitizeReferrer(input?.referrer),
      screen: sanitizeScreen(input?.screen),
      language: sanitizeLanguage(input?.language),
      ...(ip ? { ip } : {}),
    },
  };

  // Explicit header literal: nothing from the inbound request is forwarded
  // except the sanitized UA (Umami rejects UA-less events).
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'user-agent': sanitizeUserAgent(userAgent),
  };
  // Coarse geo mode: Umami reads Cloudflare-style geo headers when payload.ip
  // is absent. cf-ipcity is deliberately NEVER sent — city stays structurally
  // out of the operator's Umami. The INBOUND values are spoof-gated upstream:
  // Caddy strips the CF geo headers unless CADDY_TRUST_CF_HEADER=true, so on a
  // non-CF-fronted deployment a client can't inject geo values here. (Caveat,
  // documented: an Umami itself fronted by Cloudflare with IP-geolocation on
  // will overwrite cf-ipcountry.)
  if (geo) {
    const country = sanitizeCountryCode(geo.country);
    const region = sanitizeRegionCode(geo.region);
    if (country) {
      headers['cf-ipcountry'] = country;
      if (region) headers['cf-region-code'] = region;
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1000);
  try {
    await fetch(`${cfg.umamiUrl}/api/send`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
      // Never follow redirects: the SSRF denylist (checkInfraUrl) ran against
      // the CONFIGURED host at save time, so a permitted host answering 30x
      // could otherwise steer the relay (and the opt-in payload IP) to a
      // loopback/link-local/metadata address it couldn't register directly.
      // The response is never read, so dropping the redirect loses nothing.
      redirect: 'manual',
    });
  } catch {
    // Fail-soft by design: a lost pageview is the intended failure mode.
  } finally {
    clearTimeout(timer);
  }
}
