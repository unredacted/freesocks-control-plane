/**
 * Reading a country list (pure; unit-tested; docs/edges.md "Country lists").
 * One entry per line: a name, a `*.` wildcard, an address or a range.
 * Comments (`#`, `//`) and blank lines are skipped. What cannot be used is
 * counted, never guessed at:
 *
 *  - `tooBroad`: a range shorter than /8 (IPv4) or /16 (IPv6), or a wildcard
 *    over a public suffix (`*.co.uk`);
 *  - `nonPublic`: an address or range in private or reserved space (a range
 *    that only touches it keeps its public part);
 *  - `invalid`: anything else;
 *  - `capped`: entries past the caps below.
 *
 * Names in Unicode become their ASCII form (`xn--`), the form a ClientHello
 * carries.
 */
import { getDomain } from 'tldts';
import { addressFamily, parseCidr } from '../ip';
import { v4Number } from '../../ownExits';
import { merged, v6Big } from '../sni/hunt/ranges';
import { huntName } from '../sni/hunt/sources';
import type { ListRanges, Spans } from './intervals';

/** Names a list may hold (exact names and wildcards together). */
export const MAX_LIST_NAMES = 20_000;
/** Merged intervals a list may hold, per address family. */
export const MAX_LIST_INTERVALS = 100_000;
const MAX_SAMPLES = 5;
const SAMPLE_CHARS = 80;

export interface ParsedList {
  /** Exact names, sorted. */
  names: string[];
  /** Wildcard bases (`*.example.com` is `example.com`), sorted. */
  wildcards: string[];
  ranges: ListRanges;
  /** Lines that held an entry (not blank, not a comment). */
  entries: number;
  dropped: { invalid: number; nonPublic: number; tooBroad: number; capped: number };
  /** The first few lines that could not be read, trimmed. */
  samples: string[];
}

function v4Block(cidr: string): [number, number] {
  const [a, b] = cidr.split('/');
  const n = v4Number(a!)!;
  const size = 2 ** (32 - Number(b));
  return [n, n + size - 1];
}

function v6Block(cidr: string): [bigint, bigint] {
  const [a, b] = cidr.split('/');
  const n = v6Big(a!)!;
  return [n, n | ((1n << BigInt(128 - Number(b))) - 1n)];
}

/**
 * Private and reserved space, the same blocks `isPublicIpLiteral` refuses
 * (documentation ranges stay usable, as there; a test keeps the two in step).
 */
export const RESERVED_V4: ReadonlyArray<[number, number]> = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '224.0.0.0/3',
].map(v4Block);

export const RESERVED_V6: ReadonlyArray<[bigint, bigint]> = [
  '::/8',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
].map(v6Block);

/** What is left of [lo, hi] outside the reserved blocks (sorted, disjoint). */
function clipV4(lo: number, hi: number): Array<[number, number]> {
  let parts: Array<[number, number]> = [[lo, hi]];
  for (const [rl, rh] of RESERVED_V4) {
    const next: Array<[number, number]> = [];
    for (const [a, b] of parts) {
      if (b < rl || a > rh) {
        next.push([a, b]);
        continue;
      }
      if (a < rl) next.push([a, rl - 1]);
      if (b > rh) next.push([rh + 1, b]);
    }
    parts = next;
  }
  return parts;
}

function clipV6(lo: bigint, hi: bigint): Array<[bigint, bigint]> {
  let parts: Array<[bigint, bigint]> = [[lo, hi]];
  for (const [rl, rh] of RESERVED_V6) {
    const next: Array<[bigint, bigint]> = [];
    for (const [a, b] of parts) {
      if (b < rl || a > rh) {
        next.push([a, b]);
        continue;
      }
      if (a < rl) next.push([a, rl - 1n]);
      if (b > rh) next.push([rh + 1n, b]);
    }
    parts = next;
  }
  return parts;
}

/** A name in the form a ClientHello carries, or null. */
function asciiName(raw: string): string | null {
  let t = raw;
  if (/[^\x00-\x7f]/.test(t)) {
    try {
      t = new URL(`http://${t}`).hostname;
    } catch {
      return null;
    }
  }
  return huntName(t);
}

type Entry =
  | { kind: 'name'; name: string }
  | { kind: 'wildcard'; name: string }
  | { kind: 'v4'; lo: number; hi: number }
  | { kind: 'v6'; lo: bigint; hi: bigint }
  | { kind: 'invalid' }
  | { kind: 'tooBroad' };

/** One token as an entry. */
export function readEntry(token: string): Entry {
  const t = token.replace(/^\[|\]$/g, '');
  if (t.includes('/')) {
    const c = parseCidr(t);
    if (!c) return { kind: 'invalid' };
    if (c.prefix < (c.family === 'v4' ? 8 : 16)) return { kind: 'tooBroad' };
    if (c.family === 'v4') {
      const [lo, hi] = v4Block(`${c.start}/${c.prefix}`);
      return { kind: 'v4', lo, hi };
    }
    const [lo, hi] = v6Block(`${c.start}/${c.prefix}`);
    return { kind: 'v6', lo, hi };
  }
  const fam = addressFamily(t);
  if (fam === 'v4') {
    const n = v4Number(t);
    return n === null ? { kind: 'invalid' } : { kind: 'v4', lo: n, hi: n };
  }
  if (fam === 'v6') {
    const n = v6Big(t);
    return n === null ? { kind: 'invalid' } : { kind: 'v6', lo: n, hi: n };
  }
  if (t.startsWith('*.')) {
    const base = asciiName(t.slice(2));
    if (!base) return { kind: 'invalid' };
    // A wildcard over a public suffix would match a whole registry.
    if (getDomain(base, { allowPrivateDomains: false }) === null) return { kind: 'tooBroad' };
    return { kind: 'wildcard', name: base };
  }
  const name = asciiName(t);
  return name ? { kind: 'name', name } : { kind: 'invalid' };
}

/** The entry on a line, without its comment; null for a blank or comment line. */
function tokenOf(line: string): string | null {
  let t = line.replace(/^﻿/, '');
  const hash = t.search(/(^|\s)#/);
  if (hash >= 0) t = t.slice(0, hash);
  const slashes = t.search(/(^|\s)\/\//);
  if (slashes >= 0) t = t.slice(0, slashes);
  t = t.trim();
  if (!t) return null;
  return t.split(/[\s,;]+/)[0] ?? null;
}

function capSpans<T extends number | bigint>(s: Spans<T>): { spans: Spans<T>; capped: number } {
  if (s.lo.length <= MAX_LIST_INTERVALS) return { spans: s, capped: 0 };
  return {
    spans: { lo: s.lo.slice(0, MAX_LIST_INTERVALS), hi: s.hi.slice(0, MAX_LIST_INTERVALS) },
    capped: s.lo.length - MAX_LIST_INTERVALS,
  };
}

export function parseList(text: string): ParsedList {
  const dropped = { invalid: 0, nonPublic: 0, tooBroad: 0, capped: 0 };
  const samples: string[] = [];
  const names = new Set<string>();
  const wildcards = new Set<string>();
  const v4: Array<[number, number]> = [];
  const v6: Array<[bigint, bigint]> = [];
  let entries = 0;
  const sample = (line: string) => {
    if (samples.length < MAX_SAMPLES) samples.push(line.trim().slice(0, SAMPLE_CHARS));
  };
  for (const line of text.split(/\r?\n/)) {
    const token = tokenOf(line);
    if (token === null) continue;
    entries++;
    const e = readEntry(token);
    switch (e.kind) {
      case 'invalid':
        dropped.invalid++;
        sample(line);
        break;
      case 'tooBroad':
        dropped.tooBroad++;
        sample(line);
        break;
      case 'name':
      case 'wildcard': {
        const set = e.kind === 'name' ? names : wildcards;
        if (set.has(e.name)) break;
        if (names.size + wildcards.size >= MAX_LIST_NAMES) dropped.capped++;
        else set.add(e.name);
        break;
      }
      case 'v4': {
        const kept = clipV4(e.lo, e.hi);
        if (kept.length !== 1 || kept[0]![0] !== e.lo || kept[0]![1] !== e.hi) dropped.nonPublic++;
        v4.push(...kept);
        break;
      }
      case 'v6': {
        const kept = clipV6(e.lo, e.hi);
        if (kept.length !== 1 || kept[0]![0] !== e.lo || kept[0]![1] !== e.hi) dropped.nonPublic++;
        v6.push(...kept);
        break;
      }
    }
  }
  const m4 = capSpans(merged(v4, (x) => x + 1));
  const m6 = capSpans(merged(v6, (x) => x + 1n));
  dropped.capped += m4.capped + m6.capped;
  return {
    names: [...names].sort(),
    wildcards: [...wildcards].sort(),
    ranges: { v4: m4.spans, v6: m6.spans },
    entries,
    dropped,
    samples,
  };
}

/**
 * The content a version stands for, as one string: what the hash compares, so
 * a list that only moved its comments or its order is the same version.
 */
export function canonicalText(p: ParsedList): string {
  const lines: string[] = [];
  for (const n of p.names) lines.push(`n ${n}`);
  for (const n of p.wildcards) lines.push(`w ${n}`);
  for (let i = 0; i < p.ranges.v4.lo.length; i++)
    lines.push(`4 ${p.ranges.v4.lo[i]!.toString(16)}-${p.ranges.v4.hi[i]!.toString(16)}`);
  for (let i = 0; i < p.ranges.v6.lo.length; i++)
    lines.push(`6 ${p.ranges.v6.lo[i]!.toString(16)}-${p.ranges.v6.hi[i]!.toString(16)}`);
  return lines.join('\n');
}
