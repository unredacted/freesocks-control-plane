/**
 * The title a proxy app shows for a member's subscription (`profile-title`):
 * FCP's own, never the backend's (which names the backend product). It is the
 * service name members see (`subscription.siteName`, Admin, Settings), cleaned
 * the way their connection names are (`memberSiteName`, `FreeSocks` while
 * unset), and the member's connection mode by its English member-facing name:
 * `FreeSocks · Freedom XHTTP` (src/shared/entryNames.ts `subscriptionTitle`).
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { cleanNamePart, subscriptionTitle } from '../../src/shared/entryNames';
import {
  BUILT_IN_FAMILY_NAMES_EN,
  BUILT_IN_MODE_NAMES_EN,
  resolveModeCatalog,
  type ConnectionMode,
  type ConnectionModeFamily,
} from './connectionModes';
import { DEFAULT_SITE_NAME, memberSiteName } from './memberEntryNames';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './placement';

const MAX_MODE_NAME = 48;

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

/** 'my-new-mode' -> 'My New Mode' (a mode with neither a label nor a built-in name). */
const humanize = (slug: string) =>
  slug
    .split('-')
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(' ');

/**
 * A mode's name in the title, in English: its family's name and its own, as the
 * picker names them, `Freedom XHTTP`. Each part is the admin's label when one is
 * set (it overrides the copy in every locale, so it is what members read),
 * else the built-in English name (`BUILT_IN_*_NAMES_EN`). A family label's
 * trailing "Mode" is left out ("Freedom Mode" titles as "Freedom"), and so is
 * the family when the mode's own label already starts with it.
 */
export function modeTitleName(
  mode: Pick<ConnectionMode, 'id' | 'label'>,
  family: Pick<ConnectionModeFamily, 'id' | 'label'> | null,
): string {
  const leaf = mode.label?.trim() || BUILT_IN_MODE_NAMES_EN[mode.id] || humanize(mode.id);
  const fam =
    family?.label?.trim().replace(/\s+mode$/i, '') ||
    (family ? BUILT_IN_FAMILY_NAMES_EN[family.id] : '') ||
    '';
  const name = !fam || leaf.toLowerCase().startsWith(fam.toLowerCase()) ? leaf : `${fam} ${leaf}`;
  return cleanNamePart(name, MAX_MODE_NAME);
}

/**
 * The member's current connection mode by its title name, or null when it has
 * none on this key's backend (Outline has no modes): the mode they chose, else
 * the effective default on the backend (what their key issued into).
 */
export async function memberModeName(
  db: DatabaseReader,
  sub: Pick<Doc<'subscriptions'>, 'userId' | 'backend'>,
): Promise<string | null> {
  const user = await db.get(sub.userId);
  // The availability (bound and served pools) is read only to find the default.
  const slug =
    user?.connectionModeId ??
    effectiveDefaultFor(await resolveCatalogWithAvailability(db), sub.backend);
  const catalog = await resolveModeCatalog(db);
  const mode = catalog.modes.find((m) => m.id === slug && m.backends.includes(sub.backend));
  if (!mode) return null;
  const family = catalog.families.find((f) => f.id === mode.family) ?? null;
  return modeTitleName(mode, family) || null;
}

/** The title for one key: `<site name> · <mode name>`, the site name alone without a mode. */
export async function resolveSubscriptionTitle(
  db: DatabaseReader,
  sub: Pick<Doc<'subscriptions'>, 'userId' | 'backend'> | null,
): Promise<string> {
  const [siteName, modeName] = await Promise.all([
    resolveSubscriptionSiteName(db),
    sub ? memberModeName(db, sub) : null,
  ]);
  return subscriptionTitle(siteName, modeName);
}
