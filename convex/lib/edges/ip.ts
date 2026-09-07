/**
 * IP-literal helpers for relay edges: classify an address family, reject
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
    // Allow an embedded IPv4 tail (::ffff:1.2.3.4).
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
  if (parts.length === 1 && groups.length !== 8) return false;
  if (parts.length === 2 && groups.length > 7) return false;
  return true;
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
    const [a, b] = v4Octets(s);
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
    if (t === '::' || t === '::1') return false;
    if (t.startsWith('::ffff:')) return false;
    const first = t.split(':')[0];
    if (first.length === 0) return false; // ::-prefixed compressed leading zeros
    const firstVal = parseInt(first, 16);
    if (Number.isNaN(firstVal)) return false;
    if ((firstVal & 0xfe00) === 0xfc00) return false; // fc00::/7
    if ((firstVal & 0xffc0) === 0xfe80) return false; // fe80::/10
    if ((firstVal & 0xff00) === 0xff00) return false; // multicast
    return true;
  }
  return false;
}

/** `[v6]` for host:port and URI contexts; v4 unchanged. */
export function bracketIfV6(addr: string): string {
  return isIpv6Literal(addr) && !addr.startsWith('[') ? `[${addr}]` : addr;
}

export function hostPort(addr: string, port: number): string {
  return `${bracketIfV6(addr)}:${port}`;
}
