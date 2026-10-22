/**
 * Which mode family a subscription belongs to, for everything country-related
 * (lib/memberCountry.ts). FAIL CLOSED: a key is `freedom` only when at least
 * one signal says freedom and none says privacy; a privacy signal anywhere, a
 * backend without connection modes (Outline) or no readable signal at all
 * gives no country handling.
 *
 * The signals (any of them may disagree with the others mid-switch):
 *  - the placement the key was issued into (`backendPlacement` -> the mode
 *    whose pool holds it, `modePlacements`);
 *  - the mode of the enrolled node the key is pinned to (`panelNodeIntents.mode`);
 *  - the member's stored mode (unset = the effective default on their backend).
 */
import type { DatabaseReader } from '../_generated/server';
import type { Doc } from '../_generated/dataModel';
import { resolveModeCatalog } from './connectionModes';
import type { MemberFamily } from './memberCountry';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './placement';
import { poolFromConfig } from './remnawavePlacement';

type SubLike = Pick<
  Doc<'subscriptions'>,
  'backend' | 'backendPlacement' | 'backendServerId' | 'pinnedNode' | 'userId'
>;

/** The mode slugs whose bound pool holds this placement. */
export async function modesOfPlacement(db: DatabaseReader, placement: string): Promise<string[]> {
  // One row per mode on this backend: a small set.
  const rows = await db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', 'remnawave'))
    .collect();
  return rows.filter((r) => poolFromConfig(r.config).includes(placement)).map((r) => r.modeSlug);
}

export async function memberFamilyOf(
  db: DatabaseReader,
  sub: SubLike,
  user?: Pick<Doc<'users'>, 'connectionModeId'> | null,
): Promise<MemberFamily> {
  if (sub.backend !== 'remnawave') return 'none';
  const catalog = await resolveModeCatalog(db);
  const familyOf = (slug: string | null | undefined) =>
    slug ? (catalog.modes.find((m) => m.id === slug)?.family ?? null) : null;
  const signals: (string | null)[] = [];
  if (sub.backendPlacement)
    for (const slug of await modesOfPlacement(db, sub.backendPlacement))
      signals.push(familyOf(slug));
  if (sub.backendServerId && sub.pinnedNode) {
    const intent = await db
      .query('panelNodeIntents')
      .withIndex('by_server_name', (q) =>
        q.eq('backendServerId', sub.backendServerId!).eq('name', sub.pinnedNode!),
      )
      .first();
    if (intent) signals.push(familyOf(intent.mode));
  }
  const member = user === undefined ? await db.get(sub.userId) : user;
  const stored = member?.connectionModeId ?? null;
  if (stored) signals.push(familyOf(stored));
  else {
    const withAvailability = await resolveCatalogWithAvailability(db);
    signals.push(familyOf(effectiveDefaultFor(withAvailability, 'remnawave')));
  }
  if (signals.includes('privacy')) return 'privacy';
  return signals.includes('freedom') ? 'freedom' : 'none';
}

/** The family of the mode(s) a placement is bound to, alone (the in-place switch). */
export async function familyOfPlacement(
  db: DatabaseReader,
  placement: string | null | undefined,
): Promise<MemberFamily> {
  if (!placement) return 'none';
  const catalog = await resolveModeCatalog(db);
  const families = (await modesOfPlacement(db, placement)).map(
    (slug) => catalog.modes.find((m) => m.id === slug)?.family ?? null,
  );
  if (families.includes('privacy')) return 'privacy';
  return families.includes('freedom') ? 'freedom' : 'none';
}
