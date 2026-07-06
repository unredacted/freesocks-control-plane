/**
 * Client "one-tap import" deep links: wrap a subscription URL in each VPN
 * client's URL scheme so tapping the link (or scanning a QR of it) opens the app
 * and imports the sub as a REMOTE, auto-updating profile — instead of the OS
 * treating the raw https URL as a web page (which just opens a browser, the
 * problem these solve). Our /api/v1/sub route serves per-User-Agent formats
 * (sing-box JSON, clash YAML, base64 vless), so each client gets what it expects.
 *
 * Schemes verified 2026-07 against each client's official docs / source:
 *  - Hiddify:      hiddify://import/<rawUrl>#<name>                    (hiddify-app wiki — modern form, URL raw in path)
 *  - sing-box:     sing-box://import-remote-profile?url=<enc>#<name>   (sing-box.sagernet.org — url % encoded; needs sing-box JSON)
 *  - Karing:       karing://install-config?url=<enc>&name=<enc>        (karing.app/cooperation/scheme — "parameters must be urlencoded")
 *  - v2rayNG:      v2rayng://install-sub?url=<enc>#<name>              (2dust/v2rayNG UrlSchemeActivity — name in fragment, %-encoded)
 *  - Shadowrocket: sub://<base64(url#name)>                            (iOS; standard base64; name via #frag inside the URL)
 *  - Clash family: clash://install-config?url=<enc>&name=<enc>         (ClashX/Verge/Meta/Stash — %-encoded)
 * Streisand is intentionally ABSENT — it has no config-import scheme (clipboard /
 * in-app QR only, confirmed against its docs), so its users use the plain link + QR.
 *
 * Reality checks from the research: a custom-scheme QR only works if that app is
 * installed (iOS Camera then shows "Open in <app>"); a raw https QR always opens a
 * browser; so we pair these with the plain link + the install list in SetupGuidance.
 */

export interface ImportApp {
  id: string;
  /** Proper-noun app name — NOT translated. */
  name: string;
  /** Build the import deep link for a subscription URL + display name. */
  build: (subscriptionUrl: string, profileName: string) => string;
}

/** The profile title clients show for the imported subscription. */
export const IMPORT_PROFILE_NAME = 'FreeSocks';

const enc = encodeURIComponent;

/** Standard base64 of an (ASCII) string — Shadowrocket's `sub://` form. */
function base64(s: string): string {
  return typeof btoa === 'function' ? btoa(s) : s;
}

export const IMPORT_APPS: ImportApp[] = [
  {
    id: 'hiddify',
    name: 'Hiddify',
    // Modern form: the URL is RAW in the path (not encoded); name in the fragment.
    build: (u, n) => `hiddify://import/${u}#${enc(n)}`,
  },
  {
    id: 'sing-box',
    name: 'sing-box',
    // Official remote-profile import: percent-encoded url + a name fragment.
    build: (u, n) => `sing-box://import-remote-profile?url=${enc(u)}#${enc(n)}`,
  },
  {
    id: 'karing',
    name: 'Karing',
    build: (u, n) => `karing://install-config?url=${enc(u)}&name=${enc(n)}`,
  },
  {
    id: 'v2rayng',
    name: 'v2rayNG',
    // Android: the `install-sub` host; name in the fragment (the &name= param is buggy).
    build: (u, n) => `v2rayng://install-sub?url=${enc(u)}#${enc(n)}`,
  },
  {
    id: 'shadowrocket',
    name: 'Shadowrocket',
    // iOS: sub://<base64(url#name)> — standard base64; the #fragment names the profile
    // (Shadowrocket strips it before fetching, so it doesn't affect the request).
    build: (u, n) => `sub://${base64(`${u}#${n}`)}`,
  },
  {
    id: 'clash',
    name: 'Clash',
    // The Clash family (ClashX / Clash Verge Rev / Clash Meta / Stash): install-config.
    build: (u, n) => `clash://install-config?url=${enc(u)}&name=${enc(n)}`,
  },
];
