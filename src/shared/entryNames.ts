/**
 * The connection names members see in their apps (a link's `#remark`, a
 * sing-box outbound tag, a Clash proxy name, an Xray config's `remarks`), and
 * the names of the groups beside them. ONE scheme for every connection mode,
 * built here and nowhere else: the edge renderer (convex/lib/edges/render.ts)
 * names the entries it writes, the member relabel step
 * (convex/lib/memberEntryNames.ts) names the entries the backend named after a
 * node, and the admin pages show the same names. Pure; English for every
 * locale (a member's language is not known where a body is made).
 *
 *   <flag> <place> · <how>[ · <form>][ #<n>]
 *
 *   🇨🇦 Example City · Direct        a node, dialled directly (`Direct 2`, `Direct 3`
 *                                   for further server names of the same place)
 *   🇧🇷 via Example Town                 a load balancer address (L4) in that place
 *   🇧🇷 via Example Town A / B           two addresses in the same place
 *   via relay A                      an address whose location has no member-facing name
 *   🌐 via CDN 1 / 2                 a CDN front (L7), numbered in body order; never the CDN's name
 *   … · Domain / · IPv4 / · IPv6     one address in several forms (its name, its raw IPs)
 *   … #2                             a further server name for the same address (auto groups only)
 *
 * Only a member-facing place name an operator typed for the purpose reaches a
 * name (`edgeLocations.memberPlace`, `backendServers.locationLabel`), never a
 * provider's own region name. No comma (a Clash rule splits on it), no pipe
 * (FCP's own remark separator) and no control character survives
 * `cleanNamePart`.
 */

/** Between the parts of a name (a middle dot: no comma, no pipe, no dash). */
export const ENTRY_NAME_SEP = ' · ';
/** The url-test group (sing-box `urltest`, Mihomo `url-test`) the renderer adds. */
export const AUTO_GROUP_NAME = '⚡ Auto (fastest)';
/** What a CDN front's name starts with (a CDN has no place a member could use). */
export const CDN_MARK = '🌐';
/** The longest member-facing place name, in characters. */
export const MAX_PLACE_NAME = 24;

/** The forms one address can take in a body. */
export type EntryForm = 'domain' | 'ipv4' | 'ipv6';
export const FORM_TAGS: Record<EntryForm, string> = {
  domain: 'Domain',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
};

/** A member-facing place: what an operator called it for members, and its country. */
export interface MemberPlace {
  name: string | null;
  /** ISO 3166-1 alpha-2, uppercase. */
  country: string | null;
}

/** What one connection goes through. */
export type EntryRoute =
  /** A node, dialled directly. `n` counts from 1 within its place (1 carries no number). */
  | { kind: 'direct'; place: MemberPlace; n: number }
  /** A load balancer address. `letter` tells two addresses of one place apart. */
  | { kind: 'relay'; place: MemberPlace; letter: string | null }
  /** A CDN front, numbered among the fronts of the body. */
  | { kind: 'cdn'; n: number };

// A UTF-16 surrogate half with no partner: invalid text that
// `encodeURIComponent` throws on.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Operator text made safe inside a connection name: no control characters, no
 * comma (a Clash rule splits on it), no pipe (FCP's own remark separator), no
 * lone surrogate, whitespace collapsed, length capped in code points (a cut
 * never splits a character, so the name always encodes).
 */
export function cleanNamePart(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  const text = v
    .replace(LONE_SURROGATE_RE, '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f,|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return Array.from(text).slice(0, max).join('').trim();
}

/**
 * An ISO 3166-1 alpha-2 code a flag can be drawn for, uppercased, or null:
 * two letters, and none of the codes ISO leaves to private use (AA, QM-QZ,
 * XA-XZ, ZZ), which backends and CDNs use for "unknown".
 */
export function placeCountry(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const c = v.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) return null;
  if (c === 'AA' || c === 'ZZ' || c.startsWith('X') || (c.startsWith('Q') && c >= 'QM'))
    return null;
  return c;
}

/** The flag of a country (a pair of regional indicators; some systems draw the two letters). */
export function flagEmoji(country: unknown): string | null {
  const c = placeCountry(country);
  if (!c) return null;
  return String.fromCodePoint(...[...c].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

/** A member-facing place from stored values: the name cleaned, the country checked. */
export function memberPlaceOf(name: unknown, country: unknown): MemberPlace {
  return {
    name: cleanNamePart(name, MAX_PLACE_NAME) || null,
    country: placeCountry(country),
  };
}

/** `A`, `B`, ... `Z`, then `AA`, `AB`, ... for the n-th (from 0) address of one place. */
export function placeLetter(i: number): string {
  const one = (k: number) => String.fromCharCode(65 + k);
  return i < 26 ? one(i) : `${one(Math.floor(i / 26) - 1)}${one(i % 26)}`;
}

/** The flag and the place name, as they lead a name ('' when neither is known). */
function placeHead(place: MemberPlace): string {
  return [flagEmoji(place.country), place.name].filter((s): s is string => !!s).join(' ');
}

/**
 * The name of a connection without its form or spare number: what tells one
 * address (or one direct server name) from another.
 */
export function entryBase(route: EntryRoute): string {
  switch (route.kind) {
    case 'direct': {
      const how = route.n > 1 ? `Direct ${route.n}` : 'Direct';
      const head = placeHead(route.place);
      return head ? `${head}${ENTRY_NAME_SEP}${how}` : how;
    }
    case 'relay':
      // No member-facing name: no flag either, and always a letter.
      if (!route.place.name) return `via relay ${route.letter ?? 'A'}`;
      return [flagEmoji(route.place.country), 'via', route.place.name, route.letter]
        .filter((s): s is string => !!s)
        .join(' ');
    case 'cdn':
      return `${CDN_MARK} via CDN ${route.n}`;
  }
}

/**
 * A connection's whole name: its base, the form tag when the same address is in
 * the body in more than one form, and ` #<n>` for a further server name (the
 * second name of an address is `#2`).
 */
export function entryName(
  route: EntryRoute,
  opts: { form?: EntryForm | null; spare?: number } = {},
): string {
  const form = opts.form ? `${ENTRY_NAME_SEP}${FORM_TAGS[opts.form]}` : '';
  const spare = opts.spare && opts.spare > 1 ? ` #${opts.spare}` : '';
  return `${entryBase(route)}${form}${spare}`;
}

/**
 * The subscription title apps show (`profile-title`): the service name and the
 * member's connection mode, `FreeSocks · Freedom XHTTP`; the service name alone
 * when the mode is not known.
 */
export function subscriptionTitle(siteName: string, modeName: string | null): string {
  return modeName ? `${siteName}${ENTRY_NAME_SEP}${modeName}` : siteName;
}
