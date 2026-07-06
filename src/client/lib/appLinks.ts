/**
 * Client "one-tap import" deep-link BUILDERS, keyed by `schemeId`. The DB-driven
 * client catalog (convex/lib/clientCatalog.ts, surfaced via publicConfig.clients)
 * references a builder by its `schemeId`; this module is the single place the
 * fussy per-app URL-scheme ENCODING lives. A catalog entry with no `schemeId` (or
 * an unknown one) has no one-tap import — manual paste / in-app QR only (e.g.
 * Streisand, Outline). Wrapping the subscription URL in the client's scheme is
 * what makes a tap / QR scan import into the app instead of opening a browser.
 *
 * Schemes verified 2026-07 against each client's official docs/source:
 *  - Hiddify:      hiddify://import/<rawUrl>#<name>                    (URL raw in path)
 *  - sing-box:     sing-box://import-remote-profile?url=<enc>#<name>   (url % encoded; needs sing-box JSON)
 *  - Karing:       karing://install-config?url=<enc>&name=<enc>        ("parameters must be urlencoded")
 *  - v2rayNG:      v2rayng://install-sub?url=<enc>#<name>              (name in fragment, %-encoded)
 *  - Shadowrocket: sub://<base64(url#name)>                            (iOS; standard base64)
 *  - Clash family: clash://install-config?url=<enc>&name=<enc>        (ClashX / Verge / Meta / Stash)
 *
 * The account/reveal legs deliver the subscription URL HPKE-sealed; only the proxy
 * client's later fetch of it is unsealed (a dumb client can't decrypt).
 */

/** The profile title clients show for the imported subscription. */
export const IMPORT_PROFILE_NAME = 'FreeSocks';

const enc = encodeURIComponent;

/** Standard base64 of an (ASCII) string — Shadowrocket's `sub://` form. */
function base64(s: string): string {
  return typeof btoa === 'function' ? btoa(s) : s;
}

/** Per-scheme deep-link builders, keyed by the id a `clients` catalog row stores. */
export const SCHEME_BUILDERS: Record<
  string,
  (subscriptionUrl: string, profileName: string) => string
> = {
  hiddify: (u, n) => `hiddify://import/${u}#${enc(n)}`,
  'sing-box': (u, n) => `sing-box://import-remote-profile?url=${enc(u)}#${enc(n)}`,
  karing: (u, n) => `karing://install-config?url=${enc(u)}&name=${enc(n)}`,
  v2rayng: (u, n) => `v2rayng://install-sub?url=${enc(u)}#${enc(n)}`,
  shadowrocket: (u, n) => `sub://${base64(`${u}#${n}`)}`,
  clash: (u, n) => `clash://install-config?url=${enc(u)}&name=${enc(n)}`,
};

/** The scheme ids the admin CMS can assign to a client (for the editor dropdown). */
export const SCHEME_IDS = Object.keys(SCHEME_BUILDERS);

/**
 * Build the import deep link for a catalog scheme id, or null when the scheme is
 * absent/unknown (the client is manual / QR-only, e.g. Streisand, Outline).
 */
export function buildImportLink(
  schemeId: string | null | undefined,
  subscriptionUrl: string,
  profileName: string = IMPORT_PROFILE_NAME,
): string | null {
  if (!schemeId) return null;
  const build = SCHEME_BUILDERS[schemeId];
  return build ? build(subscriptionUrl, profileName) : null;
}
