/**
 * A country list's ranges as stored and read (pure; unit-tested; docs/edges.md
 * "Country lists"). Ranges are sorted, merged intervals per address family,
 * written as fixed-width hex lines `lo-hi` in chunks bounded by encoded bytes
 * (a Convex document holds at most 1 MiB). Each chunk is keyed by its first
 * `lo`, so a lookup reads the one chunk that can hold an address and finds it
 * by binary search over the fixed-width lines, without decoding the rest.
 */
import { addressFamily } from '../ip';
import { v4Number } from '../../ownExits';
import { v6Big } from '../sni/hunt/ranges';

export type ListFamily = 'v4' | 'v6';

export interface Spans<T extends number | bigint> {
  lo: T[];
  hi: T[];
}

export interface ListRanges {
  v4: Spans<number>;
  v6: Spans<bigint>;
}

export const emptyRanges = (): ListRanges => ({ v4: { lo: [], hi: [] }, v6: { lo: [], hi: [] } });

/** Encoded bytes per chunk: half a Convex document, whatever the family. */
export const CHUNK_MAX_BYTES = 512 * 1024;

const WIDTH: Record<ListFamily, number> = { v4: 8, v6: 32 };
/** One line and its newline: `lo-hi\n`. */
const stride = (f: ListFamily) => WIDTH[f] * 2 + 2;

/** An address as the fixed-width hex every chunk sorts by. */
export function hexOf(f: ListFamily, x: number | bigint): string {
  return x.toString(16).padStart(WIDTH[f], '0');
}

/** An address literal's family and key; null for anything else. */
export function addressKey(ip: string): { family: ListFamily; hex: string } | null {
  const t = ip.trim().replace(/^\[|\]$/g, '');
  const fam = addressFamily(t);
  if (fam === 'v4') {
    const n = v4Number(t);
    return n === null ? null : { family: 'v4', hex: hexOf('v4', n) };
  }
  if (fam === 'v6') {
    const n = v6Big(t);
    return n === null ? null : { family: 'v6', hex: hexOf('v6', n) };
  }
  return null;
}

export interface EncodedChunk {
  family: ListFamily;
  index: number;
  firstLo: string;
  text: string;
}

/** Both families as chunks of at most `maxBytes` of text each. */
export function encodeChunks(r: ListRanges, maxBytes = CHUNK_MAX_BYTES): EncodedChunk[] {
  const out: EncodedChunk[] = [];
  for (const f of ['v4', 'v6'] as const) {
    const s = r[f] as Spans<number | bigint>;
    const per = Math.max(1, Math.floor(maxBytes / stride(f)));
    for (let start = 0, index = 0; start < s.lo.length; start += per, index++) {
      const lines: string[] = [];
      for (let i = start; i < Math.min(s.lo.length, start + per); i++)
        lines.push(`${hexOf(f, s.lo[i]!)}-${hexOf(f, s.hi[i]!)}`);
      out.push({ family: f, index, firstLo: lines[0]!.slice(0, WIDTH[f]), text: lines.join('\n') });
    }
  }
  return out;
}

/** Whether a chunk's text holds an address (its hex key, same family). */
export function chunkHolds(text: string, f: ListFamily, hex: string): boolean {
  const w = WIDTH[f];
  const n = Math.floor((text.length + 1) / stride(f));
  let a = 0;
  let b = n - 1;
  while (a <= b) {
    const m = (a + b) >> 1;
    const at = m * stride(f);
    const lo = text.slice(at, at + w);
    const hi = text.slice(at + w + 1, at + 2 * w + 1);
    if (hex < lo) b = m - 1;
    else if (hex > hi) a = m + 1;
    else return true;
  }
  return false;
}

/** A chunk's spans, for a diff against the version before. */
export function decodeChunk(text: string, f: 'v4'): Spans<number>;
export function decodeChunk(text: string, f: 'v6'): Spans<bigint>;
export function decodeChunk(text: string, f: ListFamily): Spans<number> | Spans<bigint> {
  const w = WIDTH[f];
  const lo: Array<number | bigint> = [];
  const hi: Array<number | bigint> = [];
  for (const line of text ? text.split('\n') : []) {
    const a = line.slice(0, w);
    const b = line.slice(w + 1, 2 * w + 1);
    lo.push(f === 'v4' ? parseInt(a, 16) : BigInt(`0x${a}`));
    hi.push(f === 'v4' ? parseInt(b, 16) : BigInt(`0x${b}`));
  }
  return { lo, hi } as Spans<number> | Spans<bigint>;
}

/** Chunks in index order back to one family's spans. */
export function joinSpans<T extends number | bigint>(parts: ReadonlyArray<Spans<T>>): Spans<T> {
  const lo: T[] = [];
  const hi: T[] = [];
  for (const p of parts) {
    lo.push(...p.lo);
    hi.push(...p.hi);
  }
  return { lo, hi };
}

const SLASH64 = 64n;

/** IPv6 spans as the /64s they touch, merged: two addresses in one /64 are one /64. */
function slash64s(s: Spans<bigint>): Spans<bigint> {
  const lo: bigint[] = [];
  const hi: bigint[] = [];
  for (let i = 0; i < s.lo.length; i++) {
    const a = s.lo[i]! >> SLASH64;
    const b = s.hi[i]! >> SLASH64;
    const last = hi.length - 1;
    // The spans are sorted, so their /64s are too: join each to the one before when they touch.
    if (last >= 0 && a <= hi[last]! + 1n) {
      if (b > hi[last]!) hi[last] = b;
    } else {
      lo.push(a);
      hi.push(b);
    }
  }
  return { lo, hi };
}

/**
 * How much space spans cover, in the unit each family is compared in: single
 * IPv4 addresses, IPv6 /64s (a v6 address count does not fit a number, and a
 * /64 is the smallest network anyone hands out). Each /64 counts once.
 */
export function sizeOf(f: 'v4', s: Spans<number>): number;
export function sizeOf(f: 'v6', s: Spans<bigint>): number;
export function sizeOf(f: ListFamily, s: Spans<number> | Spans<bigint>): number {
  let total = 0;
  if (f === 'v4') {
    for (let i = 0; i < s.lo.length; i++) total += (s.hi[i] as number) - (s.lo[i] as number) + 1;
    return total;
  }
  const g = slash64s(s as Spans<bigint>);
  for (let i = 0; i < g.lo.length; i++) total += Number(g.hi[i]! - g.lo[i]! + 1n);
  return total;
}

/**
 * What two versions share, in the same units: IPv4 addresses, or the IPv6
 * /64s both touch (different addresses in one /64 share that /64).
 */
export function commonSize(f: 'v4', a: Spans<number>, b: Spans<number>): number;
export function commonSize(f: 'v6', a: Spans<bigint>, b: Spans<bigint>): number;
export function commonSize(
  f: ListFamily,
  a: Spans<number> | Spans<bigint>,
  b: Spans<number> | Spans<bigint>,
): number {
  if (f === 'v4') return sizeOf('v4', intersect(a as Spans<number>, b as Spans<number>));
  const both = intersect(slash64s(a as Spans<bigint>), slash64s(b as Spans<bigint>));
  let total = 0;
  for (let i = 0; i < both.lo.length; i++) total += Number(both.hi[i]! - both.lo[i]! + 1n);
  return total;
}

/** The spans both sets cover (both sorted and merged). */
export function intersect<T extends number | bigint>(a: Spans<T>, b: Spans<T>): Spans<T> {
  const lo: T[] = [];
  const hi: T[] = [];
  let i = 0;
  let j = 0;
  while (i < a.lo.length && j < b.lo.length) {
    const l = a.lo[i]! > b.lo[j]! ? a.lo[i]! : b.lo[j]!;
    const h = a.hi[i]! < b.hi[j]! ? a.hi[i]! : b.hi[j]!;
    if (l <= h) {
      lo.push(l);
      hi.push(h);
    }
    if (a.hi[i]! < b.hi[j]!) i++;
    else j++;
  }
  return { lo, hi };
}
