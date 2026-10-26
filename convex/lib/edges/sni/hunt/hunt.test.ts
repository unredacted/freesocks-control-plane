/**
 * Finding names, the pure parts (docs/edges.md "Finding names"): the range
 * matcher the sweep uses, the source parsers, the check helpers and the score.
 * Fixtures use documentation ranges and example names only.
 */
import { describe, expect, test } from 'vitest';
import { onNetwork } from '../../networks';
import { compileRanges, hasV6, inRanges, networksHit } from './ranges';
import {
  certSpotterUrl,
  decodeChunk,
  encodeChunk,
  huntName,
  parseCertSpotterPage,
  parseSeed,
  parseTrancoLatest,
  retryAfterMs,
  siteOf,
  trancoDownloadUrl,
  trancoEntries,
} from './sources';
import { answersOnNetwork, extraFact, ownTargetCode, shownAnswers } from './check';
import {
  nearPoints,
  passesAfterCheck,
  popularityPoints,
  scoreCandidate,
  stateAfterCheck,
} from './score';

const NET = {
  v4: ['192.0.2.0/25', '192.0.2.128/25', '198.51.100.0/24', '203.0.113.64/26'],
  v6: ['2001:db8:10::/48'],
};

describe('ranges', () => {
  test('agrees with onNetwork, across merged and separate ranges, in both families', () => {
    const r = compileRanges(NET);
    const probes = [
      '192.0.2.0',
      '192.0.2.127',
      '192.0.2.128',
      '192.0.2.255',
      '192.0.3.0',
      '198.51.99.255',
      '198.51.100.7',
      '203.0.113.63',
      '203.0.113.64',
      '203.0.113.127',
      '203.0.113.128',
      '2001:db8:10::1',
      '2001:db8:10:ffff::9',
      '2001:db8:11::1',
      '[2001:db8:10::5]',
      'example.com',
      '',
    ];
    for (const ip of probes) expect(inRanges(r, ip), ip).toBe(onNetwork(ip, NET));
    // Two adjacent /25s are one interval.
    expect(r.v4.lo.length).toBe(3);
    expect(hasV6(r)).toBe(true);
    expect(hasV6(compileRanges({ v4: NET.v4, v6: [] }))).toBe(false);
  });

  test('a hit names every network an answer falls in, and only those', () => {
    const a = { key: 'a', ranges: compileRanges({ v4: ['192.0.2.0/24'], v6: [] }) };
    const b = { key: 'b', ranges: compileRanges({ v4: [], v6: ['2001:db8::/32'] }) };
    expect(networksHit(['192.0.2.9'], [a, b])).toEqual(['a']);
    // An AAAA-only name is a hit too.
    expect(networksHit(['2001:db8::1'], [a, b])).toEqual(['b']);
    expect(networksHit(['192.0.2.9', '2001:db8::1'], [a, b])).toEqual(['a', 'b']);
    expect(networksHit(['198.51.100.1'], [a, b])).toEqual([]);
  });
});

describe('sources', () => {
  test('a candidate name is a lowercase hostname, never a wildcard or an address', () => {
    expect(huntName(' WWW.Example.COM. ')).toBe('www.example.com');
    expect(huntName('*.example.com')).toBeNull();
    expect(huntName('192.0.2.1')).toBeNull();
    expect(huntName('localhost')).toBeNull();
    expect(huntName(42)).toBeNull();
  });

  test('a site is the registrable domain, public-suffix aware', () => {
    expect(siteOf('a.b.example.com')).toBe('example.com');
    expect(siteOf('shop.example.co.uk')).toBe('example.co.uk');
    expect(siteOf('example.org')).toBe('example.org');
  });

  test('the top-sites list: in rank order, www right after its site within its depth', () => {
    const csv = '1,example.com\n2,example.org\n3,*.bad\nnot a line\n4,example.net\n5,example.edu\n';
    expect(trancoEntries(csv, 4, 2)).toEqual([
      { rank: 1, name: 'example.com' },
      { rank: 1, name: 'www.example.com' },
      { rank: 2, name: 'example.org' },
      { rank: 2, name: 'www.example.org' },
      { rank: 4, name: 'example.net' },
    ]);
    const e = trancoEntries(csv, 5, 0);
    expect(decodeChunk(encodeChunk(e))).toEqual(e);
    expect(parseTrancoLatest({ list_id: 'ABC12', created_on: '2026-10-25T22:00:00' })).toEqual({
      listId: 'ABC12',
      date: '2026-10-25',
    });
    expect(parseTrancoLatest({ list_id: '../x' })).toBeNull();
    expect(trancoDownloadUrl('ABC12', 1000)).toBe('https://tranco-list.eu/download/ABC12/1000');
  });

  test('certificate transparency asks for subdomains and continues after the last id', () => {
    const u = new URL(certSpotterUrl('example.com', '42'));
    expect(u.searchParams.get('include_subdomains')).toBe('true');
    expect(u.searchParams.get('expand')).toBe('dns_names');
    expect(u.searchParams.get('after')).toBe('42');
    expect(new URL(certSpotterUrl('example.com')).searchParams.has('after')).toBe(false);
    expect(
      parseCertSpotterPage([
        { id: '7', dns_names: ['a.example.com', '*.example.com'] },
        { id: '9', dns_names: ['B.example.com', 'a.example.com'] },
      ]),
    ).toEqual({ names: ['a.example.com', 'b.example.com'], lastId: '9', done: false });
    expect(parseCertSpotterPage([])).toEqual({ names: [], lastId: null, done: true });
    expect(parseCertSpotterPage({ error: 'x' })).toBeNull();
  });

  test('a 429 waits for its Retry-After, capped at a day, else an hour', () => {
    const now = 1_000_000;
    expect(retryAfterMs('120', now)).toBe(now + 120_000);
    expect(retryAfterMs(null, now)).toBe(now + 3_600_000);
    expect(retryAfterMs('999999', now)).toBe(now + 24 * 3_600_000);
  });

  test('a seed: networks and families, unusable ones dropped whole', () => {
    const seed = parseSeed({
      networks: [
        {
          network: { slug: 'net-a', label: 'Net A', asns: [64500, 'x'] },
          families: [
            {
              create_family: {
                slug: 'fam-a',
                label: 'Fam A',
                targetAddress: 'Example.com',
                targetPort: 443,
                requireH2: true,
              },
              import_names: { lines: ['a.example.com', 'a.example.com', '*.example.com'] },
              target: { tranco_rank: 1234 },
            },
            { create_family: { slug: 'Bad Slug', targetAddress: 'example.org' } },
          ],
        },
        { network: { slug: '' } },
      ],
    });
    expect(seed).toEqual([
      {
        slug: 'net-a',
        label: 'Net A',
        asns: [64500],
        families: [
          {
            slug: 'fam-a',
            label: 'Fam A',
            targetAddress: 'example.com',
            targetPort: 443,
            requireH2: true,
            names: ['a.example.com'],
            rank: 1234,
          },
        ],
      },
    ]);
    expect(parseSeed({ nope: true })).toBeNull();
  });
});

describe('checks', () => {
  const P = { v4: ['192.0.2.0/24'], v6: ['2001:db8::/32'] };

  test('the complete answer set is judged: one off-network AAAA fails an on-network A', () => {
    expect(answersOnNetwork(['192.0.2.1', '2001:db8::1'], P)).toBe('all');
    expect(answersOnNetwork(['2001:db8::1'], P)).toBe('all');
    expect(answersOnNetwork(['192.0.2.1', '2001:db9::1'], P)).toBe('some');
    expect(answersOnNetwork(['198.51.100.1'], P)).toBe('none');
    expect(answersOnNetwork([], P)).toBe('none');
    expect(answersOnNetwork(['192.0.2.1'], null)).toBe('unknown');
  });

  test('the addresses shown are cut only after the full set was judged', () => {
    const answers = [
      '2001:db8::2',
      '192.0.2.9',
      '198.51.100.1',
      '192.0.2.3',
      '192.0.2.4',
      '192.0.2.5',
    ];
    expect(shownAnswers(answers, P)).toEqual(['192.0.2.3', '192.0.2.4', '192.0.2.5', '192.0.2.9']);
    expect(shownAnswers(['2001:db8::2'], P)).toEqual(['2001:db8::2']);
  });

  test('a network candidate is its own target: its answers off the network are its own code', () => {
    expect(ownTargetCode('q_target_off_network')).toBe('q_off_network');
    expect(ownTargetCode(null)).toBeNull();
    expect(ownTargetCode('q_cert')).toBe('q_cert');
  });

  test('an extra handshake: accepted, refused, or not reached (an error, never a verdict)', () => {
    expect(extraFact({ ok: true, protocol: 'TLSv1.3' })).toEqual({ value: true });
    expect(extraFact({ ok: false, error: 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE' })).toEqual({
      value: false,
    });
    expect(extraFact({ ok: false, error: 'timeout' })).toEqual({ error: 'timeout' });
    expect(extraFact({ ok: false, error: 'ECONNRESET' })).toEqual({ error: 'ECONNRESET' });
  });
});

describe('score', () => {
  test('popularity and nearness points', () => {
    expect(popularityPoints(1)).toBe(25);
    expect(popularityPoints(10_000)).toBe(20);
    expect(popularityPoints(undefined)).toBe(0);
    expect(popularityPoints(5_000_000)).toBe(2.5);
    expect([10, 30, 60, 120, 200].map(nearPoints)).toEqual([30, 22, 12, 4, 0]);
  });

  test('a candidate that would not qualify never ranks', () => {
    const r = scoreCandidate({ rank: 1, code: 'q_cert', passes: 3, cluster: 9, mlkem: true });
    expect(r).toMatchObject({ passed: false, baseScore: 0, score: 0 });
  });

  test('missing evidence counts half: measured good > unmeasured > measured bad', () => {
    const base = { rank: 50_000, code: null, alpn: 'h2', mlkem: true, passes: 2, cluster: 3 };
    const unmeasured = scoreCandidate(base);
    const good = scoreCandidate({ ...base, near: 30, country: 20 });
    const bad = scoreCandidate({ ...base, near: 0, country: 0 });
    expect(unmeasured.baseScore).toBe(good.baseScore);
    expect(unmeasured.baseScore).toBe(bad.baseScore);
    expect(good.score).toBeGreaterThan(unmeasured.score);
    expect(unmeasured.score).toBeGreaterThan(bad.score);
    expect(unmeasured.score - unmeasured.baseScore).toBe(25);
    expect(scoreCandidate({ ...base, penalty: 40 }).score).toBe(unmeasured.score - 40);
  });

  test('states: ignored and added stay; a pass is ready; off a network it was on is gone', () => {
    expect(stateAfterCheck('ignored', null, true)).toBe('ignored');
    expect(stateAfterCheck('added', 'q_cert', true)).toBe('added');
    expect(stateAfterCheck('failing', null, false)).toBe('new');
    expect(stateAfterCheck('new', 'q_off_network', true)).toBe('gone');
    expect(stateAfterCheck('new', 'q_off_network', false)).toBe('failing');
    expect(stateAfterCheck('gone', 'q_off_network', false)).toBe('gone');
    expect(stateAfterCheck('new', 'q_timeout', true)).toBe('failing');
  });

  test('a pass counts towards stability only a day after the last one', () => {
    const DAY = 24 * 3_600_000;
    let p = passesAfterCheck({ passes: 0 }, true, 0);
    expect(p).toEqual({ passes: 1, lastPassAt: 0 });
    p = passesAfterCheck(p, true, DAY - 1);
    expect(p.passes).toBe(1);
    p = passesAfterCheck(p, true, DAY);
    expect(p.passes).toBe(2);
    expect(passesAfterCheck(p, false, 2 * DAY)).toEqual({ passes: 0 });
  });
});
