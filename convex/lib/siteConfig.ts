/**
 * Site-chrome config: an admin-toggleable announcement banner (on/off + text) and
 * a footer "View source" repo link (on/off + URL). Both are per-deployment,
 * non-secret, and member-facing, so the operator can broadcast a notice or publish
 * the source repo without a redeploy. Stored in the `appSettings` `site.*` namespace
 * (like `verification.*` / `theme.*`: deliberately NOT in SETTINGS_DEFAULTS, so it
 * gets typed validation here instead of leaking through the generic settings
 * allowlist), resolved fail-safe, and exposed (non-secret) via publicConfig.get so
 * the SPA renders the banner + footer link off live config.
 */
import type { DatabaseReader } from '../_generated/server';
import { sanitizeHttpsUrl } from './verificationConfig';

export interface SiteConfig {
  /** Master switch for the site-wide announcement banner. */
  bannerEnabled: boolean;
  /** Banner message (operator free text; rendered as ESCAPED text by the SPA,
   *  never as HTML). '' = empty (the banner hides even if enabled). */
  bannerText: string;
  /** Master switch for the footer "View source" repo link. */
  repoEnabled: boolean;
  /** Public source-repo URL shown in the footer (https-only); '' = unset (hidden). */
  repoUrl: string;
  /** Public Terms of Service URL shown in the footer (https-only); '' = unset (hidden). */
  tosUrl: string;
  /** Public Privacy Policy URL shown in the footer (https-only); '' = unset (hidden). */
  privacyUrl: string;
  /** Public transparency-report URL shown in the footer (https-only); '' = unset (hidden). */
  transparencyUrl: string;
  /** X (Twitter) profile URL shown as a footer icon (https-only); '' = unset (hidden). */
  socialXUrl: string;
  /** Mastodon profile URL shown as a footer icon (https-only); '' = unset (hidden). */
  socialMastodonUrl: string;
  /** Bluesky profile URL shown as a footer icon (https-only); '' = unset (hidden). */
  socialBlueskyUrl: string;
}

export const SITE_DEFAULTS: SiteConfig = {
  bannerEnabled: false,
  bannerText: '',
  repoEnabled: false,
  repoUrl: '',
  tosUrl: '',
  privacyUrl: '',
  transparencyUrl: '',
  socialXUrl: '',
  socialMastodonUrl: '',
  socialBlueskyUrl: '',
};

const MAX_BANNER = 280;

/**
 * Trim + length-cap the banner text (a one-liner). The SPA renders it as escaped
 * text (never `{@html}`), so there is no markup/scheme to sanitize here — only a
 * sane length bound so a runaway value can't dominate the page.
 */
export function sanitizeBannerText(v: unknown, max = MAX_BANNER): string {
  if (typeof v !== 'string') return '';
  return v.trim().slice(0, max);
}

export async function resolveSiteConfig(db: DatabaseReader): Promise<SiteConfig> {
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
  const bannerEnabledVal = await read('site.bannerEnabled');
  const repoEnabledVal = await read('site.repoEnabled');
  return {
    bannerEnabled:
      typeof bannerEnabledVal === 'boolean' ? bannerEnabledVal : SITE_DEFAULTS.bannerEnabled,
    bannerText: sanitizeBannerText(await read('site.bannerText')),
    repoEnabled: typeof repoEnabledVal === 'boolean' ? repoEnabledVal : SITE_DEFAULTS.repoEnabled,
    // https-only (rejects `javascript:`/`data:`) so it's safe to render as an <a href>.
    repoUrl: sanitizeHttpsUrl(await read('site.repoUrl')),
    tosUrl: sanitizeHttpsUrl(await read('site.tosUrl')),
    privacyUrl: sanitizeHttpsUrl(await read('site.privacyUrl')),
    transparencyUrl: sanitizeHttpsUrl(await read('site.transparencyUrl')),
    socialXUrl: sanitizeHttpsUrl(await read('site.socialXUrl')),
    socialMastodonUrl: sanitizeHttpsUrl(await read('site.socialMastodonUrl')),
    socialBlueskyUrl: sanitizeHttpsUrl(await read('site.socialBlueskyUrl')),
  };
}
