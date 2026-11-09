/**
 * "Add an SNI list" (AddSniListDialog; pure, unit-tested): the one form every
 * entry point opens, prefilled from where it was opened. An SNI list is one
 * cover site (the real site a REALITY port shows anyone without a member's
 * key) plus the SNIs that site serves.
 *
 *   draftFrom(prefill)       the form's first values (blank, or from a found site or a seed)
 *   slugFor(coverSite)       the short id a cover site suggests: `www.site.example` -> `site-example`
 *   coverSiteKind(site)      hostname, IPv4 or IPv6 literal, or null when it is neither
 *   slugProblem(slug)        why a short id cannot be used, or null
 *   draftProblem(draft)      the first reason the form cannot be sent, or null
 *   createBody(draft)        the `POST sni/families` body
 *   seedFrom(proposal)       the dialog for a seed's missing list (its short id locked)
 */
import {
  isReservedSniListSlug,
  type SniHuntImported,
  type SniTransport,
} from '../../../../../../shared/contracts/sni';

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
  /**
   * `lockSlug`: the short id cannot be edited. A seed's list: the next import
   * of the seed finds its list by that short id.
   */
  | { kind: 'site'; prefill?: ListPrefill; lockSlug?: boolean }
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

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** A cover site without the brackets of an IPv6 literal: `[2001:db8::1]` -> `2001:db8::1`. */
const unbracket = (site: string) => site.trim().replace(/^\[(.*)\]$/, '$1');

/**
 * What a cover site is: a hostname (with a dot), an IPv4 literal or an IPv6
 * literal (bare or in brackets), or null when it is none of them. The server
 * checks the rest (a public address, a real hostname).
 */
export function coverSiteKind(site: string): 'hostname' | 'ipv4' | 'ipv6' | null {
  const s = unbracket(site);
  if (s === '' || /[\s/]/.test(s)) return null;
  if (s.includes(':')) {
    if (!/^[0-9a-f:.]+$/i.test(s)) return null;
    try {
      // The URL parser checks an IPv6 literal strictly (groups, `::` once, an IPv4 tail).
      new URL(`http://[${s}]/`);
      return 'ipv6';
    } catch {
      return null;
    }
  }
  if (/^[0-9.]+$/.test(s)) return IPV4.test(s) ? 'ipv4' : null;
  return s.includes('.') ? 'hostname' : null;
}

/** The short id a cover site suggests (the server makes it unique only for a port's list). */
export function slugFor(coverSite: string): string {
  const site = coverSite.trim().toLowerCase();
  // A port after a hostname, an IPv4 or a bracketed IPv6 literal; never a bare IPv6's last group.
  const host = site.startsWith('[')
    ? site.replace(/^\[(.*)\](:\d+)?$/, '$1')
    : (site.match(/:/g) ?? []).length === 1
      ? site.replace(/:\d+$/, '')
      : site;
  return host
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
  if (coverSiteKind(d.coverSite) === null)
    return 'The cover site is a hostname or an IP address, such as site.example.';
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
    targetAddress: unbracket(d.coverSite),
    targetPort: Number(d.port.trim()),
    requireH2: d.requireH2,
    ...(d.network ? { network: d.network } : {}),
  };
}

/**
 * The dialog for a list a seed describes and FCP does not have yet, prefilled
 * from the seed. Its short id is locked: importing the seed again puts its
 * SNIs into the list with that short id.
 */
export function seedFrom(f: SniHuntImported['proposals']['families'][number]): AddListFrom {
  return {
    kind: 'site',
    lockSlug: true,
    prefill: {
      slug: f.slug,
      label: f.label,
      coverSite: f.targetAddress,
      port: f.targetPort,
      requireH2: f.requireH2,
      network: f.network,
    },
  };
}
