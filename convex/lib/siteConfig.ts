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
  /** Optional banner link target (https-only; '' = no link). Rendered as an
   *  <a href> AFTER the banner text, labeled by bannerLinkLabel — so the banner
   *  can point at e.g. a blog post without pasting the raw URL into the text. */
  bannerLinkUrl: string;
  /** The banner link's visible label (operator free text, escaped; '' with a
   *  set URL falls back to the URL's hostname). */
  bannerLinkLabel: string;
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
  /** Support email rendered as mailto: links (footer, FAQ, account pages);
   *  '' = unset (every support-link surface hides). */
  supportEmail: string;
  /** Home hero title override (verbatim, all locales); '' = the built-in
   *  translated title (i18n stays authoritative). */
  heroTitle: string;
  /** Home hero subtitle override (verbatim, all locales); '' = the built-in
   *  translated subtitle (which interpolates the membership limits). */
  heroSubtitle: string;
  /** Rotating hero title variants (verbatim, all locales): 2+ animates the
   *  home hero through them; 1 shows it statically; empty falls back to
   *  heroTitle, then the built-in translated variant list. */
  heroTitles: string[];
  /** The deployment's name where FCP names itself outside the SPA: the title a
   *  proxy app shows for the subscription (`profile-title`). '' = unset, which
   *  means SITE_NAME_DEFAULT. Plain text, one line. */
  name: string;
}

/** The name used while `site.name` is unset. */
export const SITE_NAME_DEFAULT = 'FreeSocks';

export const SITE_DEFAULTS: SiteConfig = {
  bannerEnabled: false,
  bannerText: '',
  bannerLinkUrl: '',
  bannerLinkLabel: '',
  repoEnabled: false,
  repoUrl: '',
  tosUrl: '',
  privacyUrl: '',
  transparencyUrl: '',
  socialXUrl: '',
  socialMastodonUrl: '',
  socialBlueskyUrl: '',
  supportEmail: '',
  heroTitle: '',
  heroSubtitle: '',
  heroTitles: [],
  name: '',
};

const MAX_BANNER = 280;
const MAX_BANNER_LINK_LABEL = 60;
const MAX_EMAIL = 254;
const MAX_HERO_TITLE = 160;
const MAX_HERO_SUBTITLE = 500;
const MAX_HERO_TITLES = 8;
const MAX_SITE_NAME = 40;

/** One line of plain text: control characters dropped, trimmed, capped. */
export function sanitizeSiteName(v: unknown): string {
  if (typeof v !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return v
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, MAX_SITE_NAME);
}

/** The `profile-title` value for a site name, in the `base64:` form Remnawave
 *  sends and proxy apps decode (UTF-8 survives an HTTP header that way). */
export function profileTitleValue(name: string): string {
  const bytes = new TextEncoder().encode(name || SITE_NAME_DEFAULT);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return `base64:${btoa(bin)}`;
}

/** The site name alone (one point read): the subscription route needs nothing else. */
export async function resolveSiteName(db: DatabaseReader): Promise<string> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'site.name'))
    .unique();
  let stored: unknown;
  try {
    stored = row ? JSON.parse(row.value) : undefined;
  } catch {
    stored = undefined;
  }
  return sanitizeSiteName(stored) || SITE_NAME_DEFAULT;
}

/**
 * Sanitize the rotating hero-title list: keep plain trimmed strings, drop
 * empties and over-long entries, cap the list length. Always returns an array.
 */
export function sanitizeHeroTitles(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((s): s is string => typeof s === 'string')
    .map((s) => s.trim().slice(0, MAX_HERO_TITLE))
    .filter((s) => s.length > 0)
    .slice(0, MAX_HERO_TITLES);
}

// Conservative charset (standard simple email shape). Deliberately excludes
// every character with meaning inside a mailto: href (?, &, :, /, #, %, commas,
// angle brackets, whitespace) so the value interpolates safely with no escaping.
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

/**
 * Validate an operator-typed support email. Anything that doesn't look like a
 * plain single address (or exceeds the RFC length bound) collapses to '' so a
 * bad value hides the support links instead of rendering a broken/unsafe one.
 */
export function sanitizeEmail(v: unknown): string {
  if (typeof v !== 'string') return '';
  const trimmed = v.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_EMAIL) return '';
  return EMAIL_RE.test(trimmed) ? trimmed : '';
}

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
  // Parallel point reads: 16 sequential awaits here were a major slice of
  // publicConfig.get's round-trip budget (the 1s UDF limit bit on beta
  // 2026-07-31 when the datastore slowed down).
  const [
    bannerEnabledVal,
    bannerTextVal,
    bannerLinkUrlVal,
    bannerLinkLabelVal,
    repoEnabledVal,
    repoUrlVal,
    tosUrlVal,
    privacyUrlVal,
    transparencyUrlVal,
    socialXUrlVal,
    socialMastodonUrlVal,
    socialBlueskyUrlVal,
    supportEmailVal,
    heroTitleVal,
    heroSubtitleVal,
    heroTitlesVal,
    nameVal,
  ] = await Promise.all([
    read('site.bannerEnabled'),
    read('site.bannerText'),
    read('site.bannerLinkUrl'),
    read('site.bannerLinkLabel'),
    read('site.repoEnabled'),
    read('site.repoUrl'),
    read('site.tosUrl'),
    read('site.privacyUrl'),
    read('site.transparencyUrl'),
    read('site.socialXUrl'),
    read('site.socialMastodonUrl'),
    read('site.socialBlueskyUrl'),
    read('site.supportEmail'),
    read('site.heroTitle'),
    read('site.heroSubtitle'),
    read('site.heroTitles'),
    read('site.name'),
  ]);
  return {
    bannerEnabled:
      typeof bannerEnabledVal === 'boolean' ? bannerEnabledVal : SITE_DEFAULTS.bannerEnabled,
    bannerText: sanitizeBannerText(bannerTextVal),
    // https-only like every other operator link, so it's safe as an <a href>.
    bannerLinkUrl: sanitizeHttpsUrl(bannerLinkUrlVal),
    bannerLinkLabel: sanitizeBannerText(bannerLinkLabelVal, MAX_BANNER_LINK_LABEL),
    repoEnabled: typeof repoEnabledVal === 'boolean' ? repoEnabledVal : SITE_DEFAULTS.repoEnabled,
    // https-only (rejects `javascript:`/`data:`) so it's safe to render as an <a href>.
    repoUrl: sanitizeHttpsUrl(repoUrlVal),
    tosUrl: sanitizeHttpsUrl(tosUrlVal),
    privacyUrl: sanitizeHttpsUrl(privacyUrlVal),
    transparencyUrl: sanitizeHttpsUrl(transparencyUrlVal),
    socialXUrl: sanitizeHttpsUrl(socialXUrlVal),
    socialMastodonUrl: sanitizeHttpsUrl(socialMastodonUrlVal),
    socialBlueskyUrl: sanitizeHttpsUrl(socialBlueskyUrlVal),
    supportEmail: sanitizeEmail(supportEmailVal),
    heroTitle: sanitizeBannerText(heroTitleVal, MAX_HERO_TITLE),
    heroSubtitle: sanitizeBannerText(heroSubtitleVal, MAX_HERO_SUBTITLE),
    heroTitles: sanitizeHeroTitles(heroTitlesVal),
    name: sanitizeSiteName(nameVal),
  };
}
