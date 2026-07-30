/**
 * Anonymous pageview beacon → POST /api/v1/telemetry (the server-side Umami
 * relay). PRIVACY RULES (docs/privacy.md):
 *
 * - Raw fetch with `credentials: 'omit'`, NEVER apiClient and NEVER
 *   navigator.sendBeacon: apiClient attaches PoP signatures (signEligible()
 *   signs everything under /api/, which would cryptographically bind pageviews
 *   to the member's session) and sendBeacon cannot omit cookies same-origin
 *   (it would carry fs_session). credentials:'omit' makes session correlation
 *   structurally impossible.
 * - Route path only, query/hash stripped client-side (so ?ref= codes never
 *   leave the page) AND allowlist-checked server-side; /admin never reports.
 * - Screen is bucketed to three coarse classes; language is the SPA's active
 *   locale (a bare primary subtag), not navigator.language.
 * - Fire-and-forget: the response is ignored, errors are swallowed.
 */
const TELEMETRY_PATH = '/api/v1/telemetry';

/** Coarse screen buckets (Umami-parseable WxH). Keep in sync with the server's
 *  SCREEN_BUCKETS allowlist in convex/lib/umami.ts. */
export function screenBucket(width: number): string {
  if (!Number.isFinite(width) || width <= 0) return '';
  if (width < 768) return '480x854';
  if (width < 1280) return '834x1112';
  return '1920x1080';
}

/** Pathname only — a query string can carry ?ref= codes and the like. */
export function stripQueryHash(p: string): string {
  const cut = Math.min(...[p.indexOf('?'), p.indexOf('#')].filter((i) => i >= 0).concat(p.length));
  return p.slice(0, cut);
}

/** External referrer → origin only (a full URL can identify a private page). */
export function originOnly(ref: string): string {
  if (!ref || !/^https?:\/\//i.test(ref)) return '';
  try {
    const origin = new URL(ref).origin;
    return origin === 'null' ? '' : origin;
  } catch {
    return '';
  }
}

/**
 * The security-relevant client guards, pure so they're unit-testable: never
 * report admin navigation, and dedupe repeats of the same path (the caller's
 * $effect re-runs on config refetches, not just navigations).
 */
export function shouldTrack(pathname: string, lastPath: string): boolean {
  if (pathname.startsWith('/admin')) return false;
  return pathname !== lastPath;
}

let lastPath = '';
/** Previous in-app route → the SPA-navigation referrer ('' on first paint,
 *  where the external document.referrer origin is used instead). */
let prevInApp = '';

export function trackPageview(pathname: string): void {
  if (typeof window === 'undefined') return;
  if (!shouldTrack(pathname, lastPath)) return;
  const route = stripQueryHash(pathname);
  const referrer = lastPath === '' ? originOnly(document.referrer) : prevInApp;
  lastPath = pathname;
  prevInApp = route;
  void fetch(TELEMETRY_PATH, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      route,
      referrer,
      screen: screenBucket(window.innerWidth),
      // The SPA's active locale (a bare primary subtag, lower-entropy than
      // navigator.language). setLocale maintains <html lang>; reading it here
      // avoids importing the runes-based i18n module into this pure file.
      language: document.documentElement.lang || 'en',
    }),
    keepalive: true,
    credentials: 'omit',
  }).catch(() => {
    // Fail-soft by design: analytics must never surface to the user.
  });
}
