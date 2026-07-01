/**
 * Verification / E2EE-transparency config. The out-of-band verification channels
 * shown in the "Verify connection" panel are per-deployment (a signed-release or
 * verify-page URL, an optional Tor .onion mirror, a public source-repo URL), and
 * an operator may want to hide the whole E2EE badge + panel. Stored in the
 * `appSettings` `verification.*` namespace (like `theme.*` / `billing.*`: NOT in
 * SETTINGS_DEFAULTS, so it gets typed validation here instead of leaking through
 * the generic settings allowlist), resolved fail-safe, and exposed (non-secret)
 * via publicConfig.get so the panel renders only the channels that actually exist.
 */
import type { DatabaseReader } from '../_generated/server';

export interface VerificationConfig {
  /** Master switch for the E2EE badge + verify panel (independent of the baked pins). */
  showPanel: boolean;
  /** URL where users compare fingerprints (signed release / verify page); '' = unset. */
  releaseUrl: string;
  /** Tor .onion mirror address; '' = unset (the panel omits that channel). */
  onionAddress: string;
  /** Public source-repo URL for the reproducible-build path; '' = unset. */
  sourceUrl: string;
  /** Published verifier-extension URL (web store); '' = unset (panel shows "planned"). */
  extensionUrl: string;
}

export const VERIFICATION_DEFAULTS: VerificationConfig = {
  showPanel: true,
  releaseUrl: '',
  onionAddress: '',
  sourceUrl: '',
  extensionUrl: '',
};

const MAX_URL = 512;

/**
 * Trim + length-cap; require an `https://` URL (so it's safe to render as a link
 * and can't smuggle a `javascript:`/`data:` scheme) else ''. https-only is also
 * the right censorship-resistance stance for a published channel.
 */
export function sanitizeHttpsUrl(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  if (!s || s.length > MAX_URL) return '';
  return /^https:\/\/[^\s]+$/i.test(s) ? s : '';
}

/**
 * A Tor `.onion` address: a bare host (`abc…xyz.onion`) or an http(s) URL whose
 * host ends in `.onion`. `.onion` is commonly served over plain http (the address
 * is self-authenticating), so http is allowed here specifically. Else ''.
 */
export function sanitizeOnion(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim();
  if (!s || s.length > MAX_URL) return '';
  if (/^https?:\/\//i.test(s)) {
    return /^https?:\/\/[a-z0-9.-]+\.onion(\/[^\s]*)?$/i.test(s) ? s : '';
  }
  // Bare host only: hostname chars + `.onion`. Excludes ':' so a scheme-like
  // value (e.g. javascript:x.onion) can never slip through as a "bare host".
  return /^[a-z0-9.-]+\.onion$/i.test(s) ? s : '';
}

export async function resolveVerification(db: DatabaseReader): Promise<VerificationConfig> {
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
  const showPanelVal = await read('verification.showPanel');
  return {
    showPanel: typeof showPanelVal === 'boolean' ? showPanelVal : VERIFICATION_DEFAULTS.showPanel,
    releaseUrl: sanitizeHttpsUrl(await read('verification.releaseUrl')),
    onionAddress: sanitizeOnion(await read('verification.onionAddress')),
    sourceUrl: sanitizeHttpsUrl(await read('verification.sourceUrl')),
    extensionUrl: sanitizeHttpsUrl(await read('verification.extensionUrl')),
  };
}
