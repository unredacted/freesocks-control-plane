/**
 * "Add an SNI list" (AddSniListDialog; pure, unit-tested): the one form every
 * entry point opens, prefilled from where it was opened. An SNI list is one
 * cover site (the real site a REALITY port shows anyone without a member's
 * key) plus the SNIs that site serves.
 *
 *   draftFrom(prefill)       the form's first values (blank, or from a found site or a seed)
 *   slugFor(coverSite)       the short id a cover site suggests: `www.site.example` -> `site-example`
 *   slugProblem(slug)        why a short id cannot be used, or null
 *   draftProblem(draft)      the first reason the form cannot be sent, or null
 *   createBody(draft)        the `POST sni/families` body
 */
import { isReservedSniListSlug, type SniTransport } from '../../../../../../shared/contracts/sni';

/** What an entry point already knows. Every field is optional and stays editable. */
export interface ListPrefill {
  label?: string;
  slug?: string;
  coverSite?: string;
  port?: number;
  requireH2?: boolean;
  /** A network's slug: the cover site and every SNI must resolve inside it. */
  network?: string;
}

/**
 * Where the dialog was opened: the form (blank, or prefilled), or a node's
 * REALITY port (its own cover site; the list takes in the SNIs it lists now).
 */
export type AddListFrom =
  | { kind: 'site'; prefill?: ListPrefill }
  | { kind: 'port'; backendSlug: string; transport: SniTransport; nodeUuid: string | null };

export interface ListDraft {
  label: string;
  slug: string;
  coverSite: string;
  /** As typed: digits only, checked by `draftProblem`. */
  port: string;
  requireH2: boolean;
  /** '' = anywhere. */
  network: string;
}

const SLUG = /^[a-z0-9][a-z0-9-]{0,39}$/;

/** The short id a cover site suggests (the server makes it unique only for a port's list). */
export function slugFor(coverSite: string): string {
  return coverSite
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/^www\./, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/, '');
}

/** The form's first values. A cover site with no short id or name given suggests both. */
export function draftFrom(p: ListPrefill = {}): ListDraft {
  const coverSite = (p.coverSite ?? '').trim();
  return {
    label: p.label ?? coverSite.replace(/^www\./, ''),
    slug: p.slug ?? slugFor(coverSite),
    coverSite,
    port: String(p.port ?? 443),
    requireH2: p.requireH2 ?? false,
    network: p.network ?? '',
  };
}

/** Why a short id cannot be used, or null. */
export function slugProblem(slug: string): string | null {
  const s = slug.trim();
  if (s === '') return 'Give it a short id.';
  if (!SLUG.test(s))
    return 'Lowercase letters, digits and dashes, up to 40, starting with one of the first two.';
  if (isReservedSniListSlug(s)) return `"${s}" is the address of an SNIs page. Pick another.`;
  return null;
}

/** The first reason the form cannot be sent, or null. */
export function draftProblem(d: ListDraft): string | null {
  if (d.label.trim() === '') return 'Give the list a name.';
  const slug = slugProblem(d.slug);
  if (slug) return slug;
  const site = d.coverSite.trim();
  if (site === '' || !site.includes('.') || /\s/.test(site))
    return 'The cover site is a hostname or an address, such as site.example.';
  if (!/^\d{1,5}$/.test(d.port.trim()) || Number(d.port) < 1 || Number(d.port) > 65535)
    return 'The port is a number from 1 to 65535.';
  return null;
}

/** The `POST sni/families` body for a draft `draftProblem` passed. */
export function createBody(d: ListDraft): {
  slug: string;
  label: string;
  targetAddress: string;
  targetPort: number;
  requireH2: boolean;
  network?: string;
} {
  return {
    slug: d.slug.trim(),
    label: d.label.trim(),
    targetAddress: d.coverSite.trim(),
    targetPort: Number(d.port.trim()),
    requireH2: d.requireH2,
    ...(d.network ? { network: d.network } : {}),
  };
}
