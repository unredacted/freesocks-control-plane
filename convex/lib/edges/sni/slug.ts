/**
 * An SNI list's slug (docs/edges.md "Renaming a list"). A list's page and its
 * API routes are addressed by its slug, and a rename moves the slug with the
 * name. The slugs a list held before stay on its row (`formerSlugs`) so an old
 * address keeps resolving: an audit row, an alert link, a saved setup, a seed
 * file or an API caller that still holds one finds the same list.
 *
 *   sniFamilyBySlug(db, slug)        the list at a slug: its slug now, else one it held before
 *   renamedSlug(family, label)       the slug a new name gives, or why it cannot be used
 *   withFormerSlug(family, next)     the `formerSlugs` to store when the slug moves to `next`
 *
 * Every by-slug read of `sniFamilies` goes through `sniFamilyBySlug`, so a
 * slug another list holds (now or before) is never free. A list keeps every
 * slug it held until it is deleted: a backend's saved setup, an audit row or a
 * seed file may still name one, and nothing rewrites those.
 */
import type { DatabaseReader } from '../../../_generated/server';
import type { Doc } from '../../../_generated/dataModel';
import {
  SNI_LIST_SLUG,
  isReservedSniListSlug,
  sniListSlugFor,
} from '../../../../src/shared/contracts/sni';

/** The list at a slug: the one that has it now, else the one that held it before a rename. */
export async function sniFamilyBySlug(
  db: DatabaseReader,
  slug: string,
): Promise<Doc<'sniFamilies'> | null> {
  const current = await db
    .query('sniFamilies')
    .withIndex('by_slug', (q) => q.eq('slug', slug))
    .unique();
  if (current) return current;
  // Lists are few (one per cover site), and this runs only on a miss.
  const all = await db.query('sniFamilies').collect();
  return all.find((f) => f.formerSlugs?.includes(slug)) ?? null;
}

export type RenamedSlug =
  | { ok: true; slug: string }
  | { ok: false; code: 'edge.sni.slug_empty' | 'edge.sni.slug_reserved'; message: string };

/** The slug a list's new name gives, checked like a new list's (uniqueness is the caller's read). */
export function renamedSlug(label: string): RenamedSlug {
  const slug = sniListSlugFor(label);
  if (!SNI_LIST_SLUG.test(slug))
    return {
      ok: false,
      code: 'edge.sni.slug_empty',
      message: "A list's address comes from its name. Use a letter or a digit in it",
    };
  if (isReservedSniListSlug(slug))
    return {
      ok: false,
      code: 'edge.sni.slug_reserved',
      message: 'That name gives the address of an SNIs page. Pick another',
    };
  return { ok: true, slug };
}

/**
 * The former slugs once the list moves to `next`: the one it leaves joins
 * them, `next` leaves them (a list may take back a slug it held), newest last.
 */
export function withFormerSlug(
  family: Pick<Doc<'sniFamilies'>, 'slug' | 'formerSlugs'>,
  next: string,
): string[] {
  return [...(family.formerSlugs ?? []), family.slug].filter(
    (s, i, all) => s !== next && all.indexOf(s) === i,
  );
}
