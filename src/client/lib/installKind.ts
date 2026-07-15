/**
 * Classify a client app's install link by where it actually points (Google Play /
 * App Store / GitHub / direct APK / plain website), so the member "set up your
 * app" cards can label the Install button. DERIVED from the URL rather than
 * stored in the DB: it can never drift when an admin edits the URL, and
 * admin-added clients get it for free.
 */
export type InstallKind = 'play' | 'appStore' | 'github' | 'apk' | 'website';

export function installKind(url: string): InstallKind {
  try {
    const u = new URL(url);
    // A direct package download outranks the host (e.g. a .apk GitHub asset).
    if (u.pathname.toLowerCase().endsWith('.apk')) return 'apk';
    const host = u.hostname.toLowerCase().replace(/^www\./, '');
    if (host === 'play.google.com') return 'play';
    if (host === 'apps.apple.com' || host === 'itunes.apple.com') return 'appStore';
    if (host === 'github.com') return 'github';
  } catch {
    // Not a parseable URL - fall through to the generic label.
  }
  return 'website';
}
