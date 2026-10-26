/**
 * A network's ranges compiled for fast membership (pure; unit-tested). The
 * top-sites sweep (docs/edges.md "Finding names") tests every answer of
 * hundreds of thousands of names against each hunting network's ranges (up to
 * 4,000 per address family), which `onNetwork`'s linear walk cannot do within
 * a step. Ranges become sorted, merged intervals and an address is found by
 * binary search; the answers agree with `onNetwork` (tested).
 */
import { addressFamily } from '../../ip';
import { v4Number, v6Hextets } from '../../../ownExits';
import type { NetworkPrefixes } from '../../networks';

export interface CompiledRanges {
  v4: { lo: number[]; hi: number[] };
  v6: { lo: bigint[]; hi: bigint[] };
}

function v6Big(ip: string): bigint | null {
  const h = v6Hextets(ip);
  return h ? h.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n) : null;
}

/** Sorted, merged intervals; `next(x)` is the address after `x` (adjacent spans join). */
function merged<T extends number | bigint>(
  spans: [T, T][],
  next: (x: T) => T,
): { lo: T[]; hi: T[] } {
  spans.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const lo: T[] = [];
  const hi: T[] = [];
  for (const [a, b] of spans) {
    const last = hi.length - 1;
    if (last >= 0 && a <= next(hi[last]!)) {
      if (b > hi[last]!) hi[last] = b;
    } else {
      lo.push(a);
      hi.push(b);
    }
  }
  return { lo, hi };
}

/** Compile normalised `<address>/<bits>` ranges (as `edgeNetworks.prefixes` stores them). */
export function compileRanges(p: NetworkPrefixes): CompiledRanges {
  const v4: [number, number][] = [];
  for (const c of p.v4) {
    const [addr, bits] = c.split('/');
    const n = v4Number(addr ?? '');
    const b = Number(bits);
    if (n === null || !Number.isInteger(b) || b < 0 || b > 32) continue;
    const size = 2 ** (32 - b);
    const start = n - (n % size);
    v4.push([start, start + size - 1]);
  }
  const v6: [bigint, bigint][] = [];
  for (const c of p.v6) {
    const [addr, bits] = c.split('/');
    const n = v6Big(addr ?? '');
    const b = Number(bits);
    if (n === null || !Number.isInteger(b) || b < 0 || b > 128) continue;
    const host = (1n << BigInt(128 - b)) - 1n;
    const start = n & ~host & ((1n << 128n) - 1n);
    v6.push([start, start | host]);
  }
  return { v4: merged(v4, (x) => x + 1), v6: merged(v6, (x) => x + 1n) };
}

function inSpans<T extends number | bigint>(s: { lo: T[]; hi: T[] }, x: T): boolean {
  let a = 0;
  let b = s.lo.length - 1;
  while (a <= b) {
    const m = (a + b) >> 1;
    if (x < s.lo[m]!) b = m - 1;
    else if (x > s.hi[m]!) a = m + 1;
    else return true;
  }
  return false;
}

/** Whether one address lies in the compiled ranges. A name or anything else does not. */
export function inRanges(r: CompiledRanges, ip: string): boolean {
  const t = ip.trim().replace(/^\[|\]$/g, '');
  const fam = addressFamily(t);
  if (fam === 'v4') {
    const n = v4Number(t);
    return n !== null && inSpans(r.v4, n);
  }
  if (fam === 'v6') {
    const n = v6Big(t);
    return n !== null && inSpans(r.v6, n);
  }
  return false;
}

/** Whether the compiled ranges hold any IPv6 range (the sweep then asks for AAAA too). */
export function hasV6(r: CompiledRanges): boolean {
  return r.v6.lo.length > 0;
}

/** The keys of the networks any of the answers falls in (a sweep hit). */
export function networksHit(
  answers: readonly string[],
  networks: ReadonlyArray<{ key: string; ranges: CompiledRanges }>,
): string[] {
  const out: string[] = [];
  for (const n of networks) if (answers.some((ip) => inRanges(n.ranges, ip))) out.push(n.key);
  return out;
}
