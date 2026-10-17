/**
 * The title a proxy app shows for a member's subscription (`profile-title`):
 * FCP's own, never the backend's (which names the backend product). It is the
 * service name members see (`subscription.siteName`, Admin, Settings), the
 * same name their connections are labelled with and cleaned the same way
 * (`memberSiteName`), `FreeSocks` while unset.
 */
import type { DatabaseReader } from '../_generated/server';
import { DEFAULT_SITE_NAME, memberSiteName } from './memberEntryNames';

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
    return memberSiteName(JSON.parse(row.value));
  } catch {
    return DEFAULT_SITE_NAME;
  }
}
