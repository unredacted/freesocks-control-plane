/**
 * Visitor platform detection for the connect-your-app section: preselect the
 * platform tab that matches the visitor's device so iOS/desktop users don't
 * land on Android instructions (previously hardcoded). Pure UA parsing, kept
 * separate from `navigator` so it's unit-testable; the `detectClientPlatform`
 * wrapper does the browser read (SSR-safe).
 */
export type PlatformKey = 'android' | 'ios' | 'windows' | 'desktop';

export function detectPlatform(ua: string, maxTouchPoints = 0): PlatformKey {
  const s = ua.toLowerCase();
  if (s.includes('android')) return 'android';
  if (s.includes('iphone') || s.includes('ipod') || s.includes('ipad')) return 'ios';
  // iPadOS 13+ reports as "Macintosh"; distinguish it by touch support.
  if (s.includes('macintosh') && maxTouchPoints > 1) return 'ios';
  if (s.includes('windows')) return 'windows';
  if (
    s.includes('macintosh') ||
    s.includes('mac os x') ||
    s.includes('linux') ||
    s.includes('cros')
  )
    return 'desktop';
  // Unknown (or an exotic mobile UA): the audience is mobile-majority, and
  // Android is the majority of that majority.
  return 'android';
}

export function detectClientPlatform(): PlatformKey {
  if (typeof navigator === 'undefined') return 'android';
  return detectPlatform(navigator.userAgent, navigator.maxTouchPoints ?? 0);
}
