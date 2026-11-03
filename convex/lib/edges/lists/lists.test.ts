import { describe, expect, test } from 'vitest';
import { isPublicIpLiteral } from '../ip';
import { v4Number } from '../../ownExits';
import { v6Big } from '../sni/hunt/ranges';
import {
  addressKey,
  CHUNK_MAX_BYTES,
  chunkHolds,
  decodeChunk,
  encodeChunks,
  commonSize,
  intersect,
  joinSpans,
  sizeOf,
  type ListRanges,
} from './intervals';
import {
  canonicalText,
  MAX_LIST_INTERVALS,
  MAX_LIST_NAMES,
  parseList,
  RESERVED_V4,
  RESERVED_V6,
} from './parse';
import { holdReasons, type GuardInput } from './guards';
import { matchKeys } from './names';

const v4 = (s: string) => v4Number(s)!;
const v6 = (s: string) => v6Big(s)!;

describe('parseList', () => {
  test('reads names, wildcards, addresses and ranges; skips comments', () => {
    const p = parseList(
      [
        '﻿# a comment',
        '',
        'Example.com.',
        'a.example.com # inline comment',
        '*.example.org',
        '// another comment',
        '192.0.2.10',
        '198.51.100.0/24',
        '203.0.113.77/26',
        '2001:db8::/48',
        '[2001:db8:1::1]',
      ].join('\n'),
    );
    expect(p.names).toEqual(['a.example.com', 'example.com']);
    expect(p.wildcards).toEqual(['example.org']);
    expect(p.entries).toBe(8);
    expect(p.dropped).toEqual({ invalid: 0, nonPublic: 0, tooBroad: 0, capped: 0 });
    expect(p.ranges.v4.lo).toEqual([v4('192.0.2.10'), v4('198.51.100.0'), v4('203.0.113.64')]);
    expect(p.ranges.v4.hi).toEqual([v4('192.0.2.10'), v4('198.51.100.255'), v4('203.0.113.127')]);
    expect(p.ranges.v6.lo).toEqual([v6('2001:db8::'), v6('2001:db8:1::1')]);
  });

  test('names in Unicode become their ASCII form', () => {
    expect(parseList('пример.рф').names).toEqual(['xn--e1afmkfd.xn--p1ai']);
  });

  test('counts what it cannot use, and keeps a sample', () => {
    const p = parseList(
      ['not a name!', 'a*b.example.com', '0.0.0.0/7', '*.co.uk', '10.1.2.0/24', 'fc00::1'].join(
        '\n',
      ),
    );
    expect(p.dropped).toEqual({ invalid: 2, nonPublic: 2, tooBroad: 2, capped: 0 });
    expect(p.samples).toEqual(['not a name!', 'a*b.example.com', '0.0.0.0/7', '*.co.uk']);
    expect(p.ranges.v4.lo).toEqual([]);
    expect(p.ranges.v6.lo).toEqual([]);
  });

  test('a range touching reserved space keeps its public part', () => {
    // 100.0.0.0/8 holds CGNAT (100.64.0.0/10) in its middle.
    const p = parseList('100.0.0.0/8');
    expect(p.dropped.nonPublic).toBe(1);
    expect(p.ranges.v4.lo).toEqual([v4('100.0.0.0'), v4('100.128.0.0')]);
    expect(p.ranges.v4.hi).toEqual([v4('100.63.255.255'), v4('100.255.255.255')]);
  });

  test('merges adjacent and repeated ranges, and dedupes names', () => {
    const p = parseList(
      ['192.0.2.0/25', '192.0.2.128/25', '192.0.2.5', 'example.com', 'example.com'].join('\n'),
    );
    expect(p.ranges.v4.lo).toEqual([v4('192.0.2.0')]);
    expect(p.ranges.v4.hi).toEqual([v4('192.0.2.255')]);
    expect(p.names).toEqual(['example.com']);
  });

  test('an exact name and a wildcard over it are both kept', () => {
    const p = parseList('example.com\n*.example.com');
    expect(p.names).toEqual(['example.com']);
    expect(p.wildcards).toEqual(['example.com']);
  });

  test('caps names and intervals, counting what is past the cap', () => {
    const names = Array.from({ length: MAX_LIST_NAMES + 3 }, (_, i) => `n${i}.example.com`);
    expect(parseList(names.join('\n')).dropped.capped).toBe(3);
    // Every other /32 in 192.0.0.0/14 (never adjacent, so nothing merges).
    const base = v4('192.0.0.0');
    const lines: string[] = [];
    for (let i = 0; i < MAX_LIST_INTERVALS + 2; i++) {
      const n = base + 2 * i;
      lines.push([24, 16, 8, 0].map((b) => Math.floor(n / 2 ** b) % 256).join('.'));
    }
    const p = parseList(lines.join('\n'));
    expect(p.ranges.v4.lo.length).toBe(MAX_LIST_INTERVALS);
    expect(p.dropped.capped).toBe(2);
  });

  test('the canonical text ignores order and comments', () => {
    const a = parseList('example.com\n192.0.2.0/24\n# x\n*.example.org');
    const b = parseList('*.example.org\n192.0.2.0/24 # y\nexample.com');
    expect(canonicalText(a)).toBe(canonicalText(b));
    expect(canonicalText(a)).not.toBe(canonicalText(parseList('example.com')));
  });

  test('what was left out is part of the content', () => {
    const base = 'example.com\n192.0.2.0/24';
    expect(canonicalText(parseList(base))).not.toBe(
      canonicalText(parseList(`${base}\nnot a name!`)),
    );
    expect(canonicalText(parseList(base))).not.toBe(canonicalText(parseList(`${base}\n0.0.0.0/4`)));
  });
});

describe('reserved space', () => {
  const ip4 = (n: number) => [24, 16, 8, 0].map((b) => Math.floor(n / 2 ** b) % 256).join('.');
  const ip6 = (n: bigint) =>
    Array.from({ length: 8 }, (_, i) => ((n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(
      ':',
    );

  test('every reserved IPv4 block is what isPublicIpLiteral refuses', () => {
    for (const [lo, hi] of RESERVED_V4) {
      expect(isPublicIpLiteral(ip4(lo))).toBe(false);
      expect(isPublicIpLiteral(ip4(hi))).toBe(false);
      const outside = [lo - 1, hi + 1].filter(
        (n) => n >= 0 && n < 2 ** 32 && !RESERVED_V4.some(([a, b]) => n >= a && n <= b),
      );
      for (const n of outside) expect(isPublicIpLiteral(ip4(n))).toBe(true);
    }
  });

  test('every reserved IPv6 block is what isPublicIpLiteral refuses', () => {
    for (const [lo, hi] of RESERVED_V6) {
      expect(isPublicIpLiteral(ip6(lo))).toBe(false);
      expect(isPublicIpLiteral(ip6(hi))).toBe(false);
      const outside = [lo - 1n, hi + 1n].filter(
        (n) => n >= 0n && n < 1n << 128n && !RESERVED_V6.some(([a, b]) => n >= a && n <= b),
      );
      for (const n of outside) expect(isPublicIpLiteral(ip6(n))).toBe(true);
    }
  });
});

describe('chunks', () => {
  const ranges = (lines: string): ListRanges => parseList(lines).ranges;

  test('a lookup finds addresses at the edges of every chunk', () => {
    const r = ranges(
      Array.from({ length: 50 }, (_, i) => `198.51.${i}.0/25`)
        .concat(['2001:db8::/48', '2001:db8:5::/48'])
        .join('\n'),
    );
    // Room for 7 IPv4 lines a chunk.
    const chunks = encodeChunks(r, 7 * 18);
    const v4Chunks = chunks.filter((c) => c.family === 'v4');
    expect(v4Chunks.length).toBe(8);
    expect(v4Chunks.map((c) => c.index)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    const holds = (ip: string) => {
      const k = addressKey(ip);
      if (!k) return false;
      const chunk = chunks
        .filter((c) => c.family === k.family && c.firstLo <= k.hex)
        .sort((a, b) => (a.firstLo < b.firstLo ? 1 : -1))[0];
      return !!chunk && chunkHolds(chunk.text, k.family, k.hex);
    };
    for (let i = 0; i < 50; i++) {
      expect(holds(`198.51.${i}.0`)).toBe(true);
      expect(holds(`198.51.${i}.127`)).toBe(true);
      expect(holds(`198.51.${i}.128`)).toBe(false);
    }
    expect(holds('198.50.255.255')).toBe(false);
    expect(holds('2001:db8::1')).toBe(true);
    expect(holds('2001:db8:5:ffff:ffff:ffff:ffff:ffff')).toBe(true);
    expect(holds('2001:db8:1::1')).toBe(false);
    expect(holds('example.com')).toBe(false);
  });

  test('decoding gives the spans back', () => {
    const r = ranges('192.0.2.0/24\n203.0.113.0/24\n2001:db8::/32');
    const chunks = encodeChunks(r, 18);
    const back4 = joinSpans(
      chunks.filter((c) => c.family === 'v4').map((c) => decodeChunk(c.text, 'v4')),
    );
    const back6 = joinSpans(
      chunks.filter((c) => c.family === 'v6').map((c) => decodeChunk(c.text, 'v6')),
    );
    expect(back4).toEqual(r.v4);
    expect(back6).toEqual(r.v6);
  });

  test('full lists stay within the chunk size', () => {
    const lo: bigint[] = [];
    const hi: bigint[] = [];
    for (let i = 0n; i < BigInt(MAX_LIST_INTERVALS); i++) {
      lo.push((1n << 125n) + i * 4n);
      hi.push((1n << 125n) + i * 4n + 1n);
    }
    const v4lo = Array.from({ length: MAX_LIST_INTERVALS }, (_, i) => 2 ** 24 + i * 4);
    const chunks = encodeChunks({
      v4: { lo: v4lo, hi: v4lo.map((x) => x + 1) },
      v6: { lo, hi },
    });
    for (const c of chunks) expect(c.text.length).toBeLessThanOrEqual(CHUNK_MAX_BYTES);
    expect(chunks.filter((c) => c.family === 'v6').length).toBe(13);
  });

  test('sizes and overlaps', () => {
    const a = ranges('192.0.2.0/24\n198.51.100.0/24');
    const b = ranges('192.0.2.128/25\n203.0.113.0/24');
    expect(sizeOf('v4', a.v4)).toBe(512);
    expect(sizeOf('v4', intersect(a.v4, b.v4))).toBe(128);
    const c = ranges('2001:db8::/63');
    expect(sizeOf('v6', c.v6)).toBe(2);
  });

  test('IPv6 counts each /64 once, and shares a /64 two addresses in it touch', () => {
    const two = ranges('2001:db8::1\n2001:db8::9');
    expect(two.v6.lo).toHaveLength(2);
    expect(sizeOf('v6', two.v6)).toBe(1);
    const other = ranges('2001:db8::5');
    expect(commonSize('v6', two.v6, other.v6)).toBe(1);
    expect(commonSize('v6', two.v6, ranges('2001:db8:0:1::5').v6)).toBe(0);
    expect(commonSize('v4', ranges('192.0.2.0/24').v4, ranges('192.0.2.128/25').v4)).toBe(128);
  });
});

describe('holdReasons', () => {
  const base: GuardInput = {
    previous: { names: 100, v4: 10_000, v6: 0 },
    next: { names: 100, v4: 10_000, v6: 0 },
    common: { names: 100, v4: 10_000, v6: 0 },
    entries: 200,
    invalid: 0,
    tooBroad: 0,
    capped: 0,
    jumpFactor: 10,
    minOverlap: 0.5,
  };

  test('an ordinary update goes through', () => {
    expect(holdReasons(base)).toEqual([]);
    expect(
      holdReasons({
        ...base,
        next: { ...base.next, names: 110 },
        common: { ...base.common, names: 95 },
      }),
    ).toEqual([]);
  });

  test('the first version waits', () => {
    expect(holdReasons({ ...base, previous: null })).toEqual(['first_version']);
  });

  test('an emptied list waits', () => {
    expect(
      holdReasons({
        ...base,
        next: { names: 0, v4: 0, v6: 0 },
        common: { names: 0, v4: 0, v6: 0 },
      }),
    ).toEqual(['emptied']);
  });

  test('a jump either way waits', () => {
    expect(holdReasons({ ...base, next: { ...base.next, v4: 200_000 } })).toContain('jump');
    expect(
      holdReasons({
        ...base,
        next: { ...base.next, names: 5 },
        common: { ...base.common, names: 5 },
      }),
    ).toEqual(['jump', 'replaced']);
  });

  test('a replacement of the same size waits', () => {
    expect(holdReasons({ ...base, common: { ...base.common, v4: 0 } })).toEqual(['replaced']);
  });

  test('a change in IPv6 alone counts', () => {
    const six = { ...base, previous: { ...base.previous!, v6: 10 } };
    expect(
      holdReasons({ ...six, next: { ...six.next, v6: 1_000 }, common: { ...six.common, v6: 10 } }),
    ).toEqual(['jump', 'replaced']);
    // IPv6 appearing for the first time.
    expect(holdReasons({ ...base, next: { ...base.next, v6: 4 } })).toEqual(['jump']);
  });

  test('broad ranges, unreadable lines and caps wait', () => {
    expect(holdReasons({ ...base, tooBroad: 1 })).toEqual(['too_broad']);
    expect(holdReasons({ ...base, invalid: 10 })).toEqual([]);
    expect(holdReasons({ ...base, invalid: 11 })).toEqual(['invalid']);
    expect(holdReasons({ ...base, capped: 1 })).toEqual(['capped']);
  });
});

describe('matchKeys', () => {
  test('a name is held by its exact row and by wildcards over its parents', () => {
    expect(matchKeys('a.b.example.com')).toEqual([
      { name: 'a.b.example.com', wildcard: false },
      { name: 'b.example.com', wildcard: true },
      { name: 'example.com', wildcard: true },
    ]);
  });

  test('a wildcard never holds its apex', () => {
    expect(matchKeys('example.com')).toEqual([{ name: 'example.com', wildcard: false }]);
  });

  test('wildcards stop at the site, never a public suffix', () => {
    expect(matchKeys('a.example.co.uk')).toEqual([
      { name: 'a.example.co.uk', wildcard: false },
      { name: 'example.co.uk', wildcard: true },
    ]);
  });
});
