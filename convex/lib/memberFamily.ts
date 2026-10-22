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
import { resolveModeCatalog, type ModeCatalog } from './connectionModes';
import type { MemberFamily } from './memberCountry';
import { effectiveDefaultFor, resolveCatalogWithAvailability } from './placement';
import { poolFromConfig } from './remnawavePlacement';

type SubLike = Pick<
  Doc<'subscriptions'>,
  'backend' | 'backendPlacement' | 'backendServerId' | 'pinnedNode' | 'userId'
>;

/**
 * What judging a key reads that is the same for every key: the catalog, the
 * bound pools, the effective default and an enrolled node's mode. A caller
 * judging many keys in one transaction (a page of the deploy clean-up) passes
 * one `familyReads()`, so each is read once instead of once per key.
 */
export interface FamilyReads {
  catalog?: Promise<ModeCatalog>;
  placements?: Promise<Doc<'modePlacements'>[]>;
  defaultSlug?: Promise<string | null>;
  nodeModes: Map<string, Promise<string | null>>;
}
export const familyReads = (): FamilyReads => ({ nodeModes: new Map() });

/** The mode slugs whose bound pool holds this placement. */
export async function modesOfPlacement(
  db: DatabaseReader,
  placement: string,
  reads?: FamilyReads,
): Promise<string[]> {
  // One row per mode on this backend: a small set.
  const read = () =>
    db
      .query('modePlacements')
      .withIndex('by_backend', (q) => q.eq('backend', 'remnawave'))
      .collect();
  const rows = await (reads ? (reads.placements ??= read()) : read());
  return rows.filter((r) => poolFromConfig(r.config).includes(placement)).map((r) => r.modeSlug);
}

export async function memberFamilyOf(
  db: DatabaseReader,
  sub: SubLike,
  user?: Pick<Doc<'users'>, 'connectionModeId'> | null,
  reads: FamilyReads = familyReads(),
): Promise<MemberFamily> {
  if (sub.backend !== 'remnawave') return 'none';
  const catalog = await (reads.catalog ??= resolveModeCatalog(db));
  const familyOf = (slug: string | null | undefined) =>
    slug ? (catalog.modes.find((m) => m.id === slug)?.family ?? null) : null;
  const signals: (string | null)[] = [];
  if (sub.backendPlacement)
    for (const slug of await modesOfPlacement(db, sub.backendPlacement, reads))
      signals.push(familyOf(slug));
  if (sub.backendServerId && sub.pinnedNode) {
    const key = `${sub.backendServerId}|${sub.pinnedNode}`;
    let mode = reads.nodeModes.get(key);
    if (!mode) {
      mode = db
        .query('panelNodeIntents')
        .withIndex('by_server_name', (q) =>
          q.eq('backendServerId', sub.backendServerId!).eq('name', sub.pinnedNode!),
        )
        .first()
        .then((intent) => intent?.mode ?? null);
      reads.nodeModes.set(key, mode);
    }
    const nodeMode = await mode;
    if (nodeMode !== null) signals.push(familyOf(nodeMode));
  }
  const member = user === undefined ? await db.get(sub.userId) : user;
  const stored = member?.connectionModeId ?? null;
  if (stored) signals.push(familyOf(stored));
  else
    signals.push(
      familyOf(
        await (reads.defaultSlug ??= resolveCatalogWithAvailability(db).then((c) =>
          effectiveDefaultFor(c, 'remnawave'),
        )),
      ),
    );
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
