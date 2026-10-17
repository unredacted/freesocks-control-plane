/**
 * The title a proxy app shows for a member's subscription (`profile-title`):
 * FCP's own, never the backend's (which names the backend product). It is the
 * service name members see (`subscription.siteName`, Admin, Settings, the same
 * name their connections are labelled with), cleaned like those labels: no
 * lone surrogate, no control characters, no comma, no pipe, whitespace
 * collapsed, at most 32 code points (a cut never splits a character),
 * `FreeSocks` while unset.
 */
import type { DatabaseReader } from '../_generated/server';

export const DEFAULT_SITE_NAME = 'FreeSocks';
const MAX_SITE_NAME = 32;
// A UTF-16 surrogate half with no partner: invalid text, dropped so the title
// is exactly the name the connection labels carry.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** The service name from a stored value, with the built-in default. */
export function subscriptionSiteName(v: unknown): string {
  if (typeof v !== 'string') return DEFAULT_SITE_NAME;
  const text = v
    .replace(LONE_SURROGATE_RE, '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f,|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return Array.from(text).slice(0, MAX_SITE_NAME).join('').trim() || DEFAULT_SITE_NAME;
}

/** The `profile-title` value for a name, in the `base64:` form Remnawave sends
 *  and proxy apps decode (UTF-8 survives an HTTP header that way). */
export function profileTitleValue(name: string): string {
  const bytes = new TextEncoder().encode(name || DEFAULT_SITE_NAME);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return `base64:${btoa(bin)}`;
}

/** The service name (one point read): the subscription route needs nothing else. */
export async function resolveSubscriptionSiteName(db: DatabaseReader): Promise<string> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'subscription.siteName'))
    .unique();
  if (!row) return DEFAULT_SITE_NAME;
  try {
    return subscriptionSiteName(JSON.parse(row.value));
  } catch {
    return DEFAULT_SITE_NAME;
  }
}
