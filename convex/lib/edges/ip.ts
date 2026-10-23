/**
 * IP-literal helpers for origin edges: classify an address family, reject
 * non-public literals (an edge address must be a routable public IP, never a
 * private/loopback/link-local value a mis-provisioned LB could report), and
 * bracket IPv6 for URI/host:port contexts.
 */

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpv4Literal(s: string): boolean {
  const m = V4_RE.exec(s.trim());
  if (!m) return false;
  // Each octet 0..255 with no leading zeros (the canonical dotted-quad form).
  return m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o);
}

/** Conservative IPv6 literal check (hex groups + `::`, optional brackets, no zone id). */
export function isIpv6Literal(s: string): boolean {
  const t = s.trim().replace(/^\[|\]$/g, '');
  if (!/^[0-9a-fA-F:.]+$/.test(t) || !t.includes(':')) return false;
  if (t.includes(':::')) return false;
  const parts = t.split('::');
  if (parts.length > 2) return false;
  const groups = parts.flatMap((p) => (p === '' ? [] : p.split(':')));
  if (groups.some((g) => g.length === 0 || g.length > 4 || !/^[0-9a-fA-F]+$/.test(g))) {
    // Allow an embedded IPv4 tail (::ffff:192.0.2.4).
    const last = groups[groups.length - 1];
    if (
      !(
        last &&
        isIpv4Literal(last) &&
        groups.slice(0, -1).every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))
      )
    ) {
      return false;
    }
  }
  // An embedded IPv4 tail fills two of the eight groups (`v6Groups` reads it so).
  const last = groups[groups.length - 1];
  const count = groups.length + (last !== undefined && last.includes('.') ? 1 : 0);
  if (parts.length === 1 && count !== 8) return false;
  if (parts.length === 2 && count > 7) return false;
  return true;
}

/** The eight 16-bit groups of an IPv6 literal (an embedded IPv4 tail is two of them). */
function v6Groups(t: string): number[] {
  const [head = '', tail] = t.split('::');
  const parse = (part: string): number[] =>
    part === ''
      ? []
      : part.split(':').flatMap((g) => {
          if (!g.includes('.')) return [parseInt(g, 16)];
          const [a = 0, b = 0, c = 0, d = 0] = g.split('.').map(Number);
          return [(a << 8) | b, (c << 8) | d];
        });
  const left = parse(head);
  if (tail === undefined) return left;
  const right = parse(tail);
  return [...left, ...new Array<number>(8 - left.length - right.length).fill(0), ...right];
}

/**
 * The one spelling of an IP literal, so two ways of writing the same address
 * compare equal: IPv4 as its dotted quad; IPv6 lower-case and compressed
 * (RFC 5952: no leading zeros, the longest run of zero groups as `::`), and an
 * IPv4-mapped IPv6 (`::ffff:192.0.2.1`, `::ffff:c000:201`) as its IPv4. Null
 * for anything that is not an IP literal (a name).
 */
export function canonicalIp(s: string): string | null {
  const t = s
    .trim()
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (isIpv4Literal(t)) return t;
  if (!isIpv6Literal(t)) return null;
  const g = v6Groups(t);
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff)
    return [g[6]! >> 8, g[6]! & 255, g[7]! >> 8, g[7]! & 255].join('.');
  return v6Text(g);
}

/** An IPv6 address's groups in the compressed form (RFC 5952). */
function v6Text(g: readonly number[]): string {
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j > i ? j : i + 1;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

/**
 * An address range in CIDR notation (`192.0.2.0/24`, `2001:db8::/32`): its
 * family, its prefix length and the address the range starts at. Null when it
 * is not one. `start` differs from the written address when bits are set past
 * the prefix (`192.0.2.10/24` starts at `192.0.2.0`): providers refuse such a
 * range.
 */
export function parseCidr(
  s: string,
): { family: AddressFamily; prefix: number; start: string; startsRange: boolean } | null {
  const m = /^([^/\s]+)\/(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const [, addr = '', len = ''] = m;
  const prefix = Number(len);
  if (String(prefix) !== len) return null;
  if (isIpv4Literal(addr)) {
    if (prefix > 32) return null;
    const n = v4Octets(addr).reduce((acc, o) => acc * 256 + o, 0);
    const size = 2 ** (32 - prefix);
    const first = n - (n % size);
    const start = [24, 16, 8, 0].map((b) => Math.floor(first / 2 ** b) % 256).join('.');
    return { family: 'v4', prefix, start, startsRange: first === n };
  }
  if (isIpv6Literal(addr) && !addr.startsWith('[')) {
    if (prefix > 128) return null;
    const g = v6Groups(addr.toLowerCase());
    const masked = g.map((x, i) => {
      const bits = Math.min(16, Math.max(0, prefix - 16 * i));
      return bits === 0 ? 0 : x & ((0xffff << (16 - bits)) & 0xffff);
    });
    return {
      family: 'v6',
      prefix,
      start: v6Text(masked),
      startsRange: masked.every((x, i) => x === g[i]),
    };
  }
  return null;
}

export type AddressFamily = 'v4' | 'v6';

export function addressFamily(s: string): AddressFamily | null {
  if (isIpv4Literal(s)) return 'v4';
  if (isIpv6Literal(s)) return 'v6';
  return null;
}

function v4Octets(s: string): number[] {
  return s.trim().split('.').map(Number);
}

/**
 * True for a globally routable literal. Rejects RFC 1918, loopback, link-local,
 * 0.0.0.0/8, CGNAT (100.64/10), multicast/reserved, benchmarking (198.18/15),
 * documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24 are ALLOWED so
 * fixtures can use them: they are not routable but harmless), and for IPv6:
 * ::, ::1, fc00::/7, fe80::/10, ff00::/8, ::ffff:0:0/96 mapped v4.
 */
export function isPublicIpLiteral(s: string): boolean {
  const fam = addressFamily(s);
  if (fam === 'v4') {
    const [a = 0, b = 0] = v4Octets(s);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a >= 224) return false;
    return true;
  }
  if (fam === 'v6') {
    const t = s
      .trim()
      .replace(/^\[|\]$/g, '')
      .toLowerCase();
    // By value, however it is written: `::`, `::1`, an IPv4-mapped address in
    // either spelling (`::ffff:192.0.2.1`, `0:0:0:0:0:ffff:192.0.2.1`) and the
    // rest of 0000::/8 are never public.
    const firstVal = v6Groups(t)[0] ?? 0;
    if (firstVal < 0x0100) return false;
    if ((firstVal & 0xfe00) === 0xfc00) return false; // fc00::/7
    if ((firstVal & 0xffc0) === 0xfe80) return false; // fe80::/10
    if ((firstVal & 0xff00) === 0xff00) return false; // multicast
    return true;
  }
  return false;
}

// --- the address an edge PUBLISHES -------------------------------------------------------

/**
 * What members are actually sent to, by the edge's layer: an L7 (CDN) edge
 * publishes its hostname and never an IP literal (its frontend addresses are
 * the CDN's and change under it); an L4 edge publishes its IPv4 literal (the
 * v6 literal rides along as a separate rendered entry, it is never the primary).
 *
 * Every gate that used to read `addresses.v4` reads this instead, so a layer
 * that addresses by name is not silently unpublishable.
 */
export interface PublishableEdge {
  layer?: 'l4' | 'l7' | null;
  addresses: { v4?: string | null; v6?: string | null; hostname?: string | null };
}

export function publishAddressOf(edge: PublishableEdge): string | null {
  if ((edge.layer ?? 'l4') === 'l7') return edge.addresses.hostname ?? null;
  return edge.addresses.v4 ?? null;
}

export function hasPublishableAddress(edge: PublishableEdge): boolean {
  return publishAddressOf(edge) !== null;
}

/** `[v6]` for host:port and URI contexts; v4 unchanged. */
export function bracketIfV6(addr: string): string {
  return isIpv6Literal(addr) && !addr.startsWith('[') ? `[${addr}]` : addr;
}

export function hostPort(addr: string, port: number): string {
  return `${bracketIfV6(addr)}:${port}`;
}
