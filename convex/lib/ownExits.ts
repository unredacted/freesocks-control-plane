/**
 * FCP's own exit addresses (pure; unit-tested): the addresses traffic leaves
 * the service from, so a member's app that refreshes its subscription THROUGH
 * the tunnel is recognised and its CDN country is not mistaken for theirs
 * (docs/privacy.md "Where a member connects from").
 *
 * Only infrastructure addresses go in (node public and management addresses,
 * origin addresses, edge addresses, operator-entered ranges). A member's
 * address is compared with them in the HTTP action and kept nowhere: no
 * function argument, row, log line or audit row ever carries it.
 *
 * IPv4 matches exactly or by CIDR; IPv6 by the /64 the address sits in (a
 * node's outgoing v6 address can be any of its /64) or by CIDR.
 */
import { addressFamily, isIpv4Literal } from './edges/ip';

export interface OwnExits {
  v4: string[];
  /** The first four hextets (the /64), normalised: `2001:db8:0:1`. */
  v6Prefixes: string[];
  /** Operator-entered ranges, normalised `<address>/<bits>`. */
  cidrs: string[];
}

export const EMPTY_OWN_EXITS: OwnExits = { v4: [], v6Prefixes: [], cidrs: [] };

/** The eight hextets of an IPv6 literal as numbers, or null. */
function v6Hextets(s: string): number[] | null {
  let t = s
    .trim()
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (addressFamily(t) !== 'v6') return null;
  // An embedded IPv4 tail (::ffff:192.0.2.4) is written as its two hextets.
  const lastColon = t.lastIndexOf(':');
  const last = t.slice(lastColon + 1);
  if (isIpv4Literal(last)) {
    const o = last.split('.').map(Number);
    const hi = ((o[0]! << 8) | o[1]!).toString(16);
    const lo = ((o[2]! << 8) | o[3]!).toString(16);
    t = `${t.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = t.split('::');
  const parse = (p: string) => (p === '' ? [] : p.split(':').map((g) => parseInt(g, 16)));
  const left = parse(halves[0] ?? '');
  const right = halves.length === 2 ? parse(halves[1] ?? '') : null;
  const all = right
    ? [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right]
    : left;
  return all.length === 8 && all.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff)
    ? all
    : null;
}

function v6Prefix64(s: string): string | null {
  const h = v6Hextets(s);
  return h
    ? h
        .slice(0, 4)
        .map((g) => g.toString(16))
        .join(':')
    : null;
}

function v4Number(s: string): number | null {
  if (!isIpv4Literal(s)) return null;
  return s
    .trim()
    .split('.')
    .map(Number)
    .reduce((acc, o) => acc * 256 + o, 0);
}

/** A CIDR as `<address>/<bits>`, normalised; null when malformed. */
export function normalizeCidr(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const [addr, bitsRaw] = raw.trim().split('/');
  if (!addr) return null;
  const fam = addressFamily(addr);
  if (!fam) return null;
  const max = fam === 'v4' ? 32 : 128;
  const bits = bitsRaw === undefined ? max : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < (fam === 'v4' ? 8 : 16) || bits > max) return null;
  if (fam === 'v4') return `${addr.trim()}/${bits}`;
  const h = v6Hextets(addr)!;
  return `${h.map((g) => g.toString(16)).join(':')}/${bits}`;
}

function inCidr(ip: string, cidr: string): boolean {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!addr || !Number.isInteger(bits)) return false;
  const fam = addressFamily(ip);
  if (fam !== addressFamily(addr)) return false;
  if (fam === 'v4') {
    const a = v4Number(ip);
    const b = v4Number(addr);
    if (a === null || b === null) return false;
    const shift = 32 - bits;
    return Math.floor(a / 2 ** shift) === Math.floor(b / 2 ** shift);
  }
  const a = v6Hextets(ip);
  const b = v6Hextets(addr);
  if (!a || !b) return false;
  let left = bits;
  for (let i = 0; i < 8 && left > 0; i++) {
    const take = Math.min(16, left);
    const mask = (0xffff << (16 - take)) & 0xffff;
    if ((a[i]! & mask) !== (b[i]! & mask)) return false;
    left -= take;
  }
  return true;
}

/** Build the set from infrastructure addresses (anything not an IP literal is ignored). */
export function buildOwnExits(addresses: readonly unknown[], ranges: readonly unknown[]): OwnExits {
  const v4 = new Set<string>();
  const v6 = new Set<string>();
  for (const a of addresses) {
    if (typeof a !== 'string') continue;
    const t = a.trim().replace(/^\[|\]$/g, '');
    if (isIpv4Literal(t)) v4.add(t);
    else {
      const p = v6Prefix64(t);
      if (p) v6.add(p);
    }
  }
  const cidrs = new Set<string>();
  for (const r of ranges) {
    const c = normalizeCidr(r);
    if (c) cidrs.add(c);
  }
  return { v4: [...v4].sort(), v6Prefixes: [...v6].sort(), cidrs: [...cidrs].sort() };
}

/** Is this client address one of FCP's own exits? */
export function isOwnExit(ip: string | null, exits: OwnExits): boolean {
  if (!ip) return false;
  const t = ip.trim().replace(/^\[|\]$/g, '');
  const fam = addressFamily(t);
  if (fam === 'v4' && exits.v4.includes(t)) return true;
  if (fam === 'v6') {
    const p = v6Prefix64(t);
    if (p && exits.v6Prefixes.includes(p)) return true;
  }
  return exits.cidrs.some((c) => inCidr(t, c));
}
