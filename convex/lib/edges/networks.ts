/**
 * Networks (pure; unit-tested): where a site's addresses come from, so a
 * REALITY transport's target, its server names and the addresses members dial
 * can all sit on ONE provider network (docs/edges.md "Networks").
 *
 * A network is one or more autonomous systems (ASNs) and the address ranges
 * they announce, plus ranges an operator adds by hand. Every membership check
 * is local, against those ranges: no address is ever sent anywhere to be
 * classified (the refresh asks for an ASN's announced ranges, nothing else).
 *
 * Nothing here knows a provider. A network is data the operator (or a later
 * discovery) enters; code only compares addresses with ranges.
 */
import { addressFamily } from './ip';
import { inCidr, normalizeCidr } from '../ownExits';

export interface NetworkPrefixes {
  v4: readonly string[];
  v6: readonly string[];
}

/** At most this many ranges per address family (a document array holds 8192). */
export const MAX_NETWORK_PREFIXES = 4000;
/** Ranges an operator may enter by hand. */
export const MAX_MANUAL_PREFIXES = 256;
/** ASNs per network. */
export const MAX_NETWORK_ASNS = 8;
/** Announced ranges are read again after this long. */
export const NETWORK_REFRESH_MS = 24 * 3_600_000;
/** Why a read of announced ranges failed (`edgeNetworks.refreshError`). */
export const NETWORK_REFRESH_ERRORS = [
  'timeout',
  'rate_limited',
  'service_error',
  'too_large',
  'bad_answer',
  'unreachable',
] as const;
export type NetworkRefreshError = (typeof NETWORK_REFRESH_ERRORS)[number];

/** `AS64500`, `as64500` or `64500` as a number; null when it is not an ASN. */
export function normalizeAsn(raw: unknown): number | null {
  const s = typeof raw === 'number' ? String(raw) : typeof raw === 'string' ? raw.trim() : '';
  const m = /^(?:as)?(\d{1,10})$/i.exec(s);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isInteger(n) && n > 0 && n <= 4_294_967_295 ? n : null;
}

/** A range as stored (`<address>/<bits>`, normalised), or null. */
export function normalizePrefix(raw: unknown): string | null {
  if (typeof raw !== 'string' || !raw.includes('/')) return null;
  return normalizeCidr(raw);
}

/**
 * The ranges of several lists, deduplicated and sorted, split by family and
 * capped (`truncated` when a cap cut some off: membership then answers "off"
 * for an address in a dropped range, never "on" for one outside).
 */
export function mergePrefixes(
  lists: ReadonlyArray<readonly unknown[]>,
  cap = MAX_NETWORK_PREFIXES,
): { v4: string[]; v6: string[]; truncated: boolean } {
  const v4 = new Set<string>();
  const v6 = new Set<string>();
  for (const list of lists)
    for (const raw of list) {
      const p = normalizePrefix(raw);
      if (!p) continue;
      (addressFamily(p.split('/')[0]!) === 'v4' ? v4 : v6).add(p);
    }
  const sorted = (s: Set<string>) => [...s].sort();
  const a = sorted(v4);
  const b = sorted(v6);
  return {
    v4: a.slice(0, cap),
    v6: b.slice(0, cap),
    truncated: a.length > cap || b.length > cap,
  };
}

/**
 * What membership checks read: every range an operator entered by hand (they
 * are few and chosen on purpose, so a cap never drops one), then the announced
 * ranges up to the cap of each address family.
 */
export function combinePrefixes(
  announced: readonly unknown[],
  manual: readonly unknown[],
  cap = MAX_NETWORK_PREFIXES,
): { v4: string[]; v6: string[]; truncated: boolean } {
  const own = mergePrefixes([manual], Number.MAX_SAFE_INTEGER);
  const ann = mergePrefixes([announced], Number.MAX_SAFE_INTEGER);
  const fill = (mine: string[], theirs: string[]) => {
    const seen = new Set(mine);
    const room = Math.max(0, cap - mine.length);
    const extra = theirs.filter((p) => !seen.has(p));
    return { list: [...mine, ...extra.slice(0, room)].sort(), cut: extra.length > room };
  };
  const v4 = fill(own.v4, ann.v4);
  const v6 = fill(own.v6, ann.v6);
  return { v4: v4.list, v6: v6.list, truncated: v4.cut || v6.cut };
}

/** Whether two range sets are the same (both sorted, as stored). */
export function samePrefixes(a: NetworkPrefixes, b: NetworkPrefixes): boolean {
  return a.v4.join(' ') === b.v4.join(' ') && a.v6.join(' ') === b.v6.join(' ');
}

/** Whether one address lies on the network. A name or anything else is not. */
export function onNetwork(ip: string, p: NetworkPrefixes): boolean {
  const t = ip.trim().replace(/^\[|\]$/g, '');
  const fam = addressFamily(t);
  if (!fam) return false;
  return (fam === 'v4' ? p.v4 : p.v6).some((c) => inCidr(t, c));
}

/** Whether there is at least one address and every one lies on the network. */
export function allOnNetwork(ips: readonly string[], p: NetworkPrefixes): boolean {
  return ips.length > 0 && ips.every((ip) => onNetwork(ip, p));
}

/** Whether the network has any range to compare with yet. */
export function hasPrefixes(p: NetworkPrefixes | null | undefined): p is NetworkPrefixes {
  return !!p && p.v4.length + p.v6.length > 0;
}

/**
 * Where an L4 edge's addresses sit: `on` when it has one and every one it
 * serves (IPv4 and IPv6) lies on the network, `off` when one does not,
 * `unknown` when the edge has no literal yet or the network has no ranges.
 */
export function edgeNetworkVerdict(
  addresses: { v4?: string; v6?: string },
  p: NetworkPrefixes | null | undefined,
): 'on' | 'off' | 'unknown' {
  const ips = [addresses.v4, addresses.v6].filter((a): a is string => !!a);
  if (ips.length === 0 || !hasPrefixes(p)) return 'unknown';
  return allOnNetwork(ips, p) ? 'on' : 'off';
}

/**
 * What a family's network says about one name (qualification): the target's
 * addresses must all lie on it (`q_target_off_network`), then the name must
 * resolve, every answer on it (`q_off_network`: a censor resolving the name
 * would see another network than the address it is presented to). Null when
 * both hold.
 */
export function qualificationNetworkCode(
  targetAddresses: readonly string[],
  nameAddresses: readonly string[],
  p: NetworkPrefixes,
): 'q_target_off_network' | 'q_off_network' | null {
  if (!allOnNetwork(targetAddresses, p)) return 'q_target_off_network';
  if (!allOnNetwork(nameAddresses, p)) return 'q_off_network';
  return null;
}

/**
 * The announced ranges in a RIPEstat `announced-prefixes` answer
 * (`{status, data: {prefixes: [{prefix}]}}`). A malformed answer is an error,
 * never an empty network.
 */
export function parseAnnouncedPrefixes(
  body: unknown,
): { ok: true; prefixes: string[] } | { ok: false; error: NetworkRefreshError } {
  const data = (body as { data?: { prefixes?: unknown } } | null)?.data;
  const list = data?.prefixes;
  if (!Array.isArray(list)) return { ok: false, error: 'bad_answer' };
  const out: string[] = [];
  for (const row of list) {
    const p = normalizePrefix((row as { prefix?: unknown } | null)?.prefix);
    if (p) out.push(p);
  }
  return { ok: true, prefixes: out };
}

/** The refresh URL for one ASN (the only thing the request carries). */
export function announcedPrefixesUrl(asn: number): string {
  return `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`;
}
