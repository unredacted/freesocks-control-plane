/**
 * Real-host controls (pure): one vantage's check of FCP's address and of the
 * name's real site, read together; a batch's pairs read into one reading.
 */
import { describe, expect, test } from 'vitest';
import {
  pairClass,
  readRealHost,
  readingOf,
  EMPTY_COUNTS,
  type PairMeasurement,
  type PairReading,
} from './realHost';

const r = (outcome: PairReading['outcome'], extra: Partial<PairReading> = {}): PairReading => ({
  outcome,
  ...extra,
});
const ELSE = { reachedElse: true, tcp: null };

describe('pairClass', () => {
  test('the five readings', () => {
    expect(pairClass(r('ok'), r('ok'), ELSE)).toBe('works');
    expect(pairClass(r('answered'), r('ok'), ELSE)).toBe('works');
    expect(pairClass(r('reset'), r('reset'), ELSE)).toBe('name_blocked');
    expect(pairClass(r('timeout', { stage: 'connect' }), r('ok'), ELSE)).toBe('address_blocked');
    expect(pairClass(r('refused'), r('ok'), ELSE)).toBe('address_blocked');
    expect(pairClass(r('reset', { stage: 'handshake' }), r('ok'), ELSE)).toBe('ip_name_match');
    expect(pairClass(r('cert_mismatch'), r('ok'), ELSE)).toBe('ip_name_match');
    expect(pairClass(r('ok'), r('timeout'), ELSE)).toBe('ours_only');
  });

  test('both failing says nothing from a vantage that reached nothing else', () => {
    expect(pairClass(r('reset'), r('timeout'), { reachedElse: false, tcp: null })).toBe(
      'inconclusive',
    );
  });

  test('an unknown stage falls back to the TCP reading of the address, else says nothing', () => {
    expect(pairClass(r('timeout'), r('ok'), { reachedElse: true, tcp: 'works' })).toBe(
      'ip_name_match',
    );
    expect(pairClass(r('timeout'), r('ok'), { reachedElse: true, tcp: 'fails' })).toBe(
      'address_blocked',
    );
    expect(pairClass(r('timeout'), r('ok'), ELSE)).toBe('inconclusive');
  });

  test('a failure after the handshake is no handshake failure', () => {
    // TLS completed, then no answer: the name got through, whatever the TCP reading says.
    expect(pairClass(r('timeout', { stage: 'response' }), r('ok'), ELSE)).toBe('inconclusive');
    expect(
      pairClass(r('timeout', { stage: 'response' }), r('ok'), { reachedElse: true, tcp: 'works' }),
    ).toBe('inconclusive');
  });

  test('errors on either side are inconclusive', () => {
    expect(pairClass(r('error'), r('ok'), ELSE)).toBe('inconclusive');
    expect(pairClass(r('ok'), r('error'), ELSE)).toBe('inconclusive');
  });
});

describe('readingOf', () => {
  const o = { minVantages: 3, minNetworks: 2 };
  test('thin below the floors, the two-thirds class, else mixed', () => {
    expect(readingOf({ ...EMPTY_COUNTS, ipNameMatch: 2 }, 2, o)).toBe('thin');
    expect(readingOf({ ...EMPTY_COUNTS, ipNameMatch: 3 }, 1, o)).toBe('thin');
    expect(readingOf({ ...EMPTY_COUNTS, ipNameMatch: 2, works: 1 }, 2, o)).toBe('ip_name_match');
    expect(readingOf({ ...EMPTY_COUNTS, ipNameMatch: 2, works: 2 }, 2, o)).toBe('mixed');
    // Inconclusive pairs never count either way.
    expect(readingOf({ ...EMPTY_COUNTS, works: 3, inconclusive: 9 }, 3, o)).toBe('works');
  });
});

describe('readRealHost', () => {
  const v = (n: number) => ({ asn: `AS${64500 + n}`, vantage: `v${n}` });
  const batch = (
    oursA: PairReading['outcome'][],
    realA: PairReading['outcome'][],
    oursB: PairReading['outcome'][] = ['ok', 'ok', 'ok'],
    stage?: PairReading['stage'],
  ): PairMeasurement[] => [
    {
      name: 'a.example',
      source: 'globalping',
      role: 'ours',
      results: oursA.map((outcome, i) => ({ outcome, ...v(i), ...(stage ? { stage } : {}) })),
    },
    {
      name: 'a.example',
      source: 'globalping',
      role: 'real',
      // The real site's vantages answer in another order: pairing is by key.
      results: realA.map((outcome, i) => ({ outcome, ...v(i) })).reverse(),
    },
    {
      name: 'b.example',
      source: 'globalping',
      role: 'ours',
      results: oursB.map((outcome, i) => ({ outcome, ...v(i) })),
    },
  ];
  const o = { minVantages: 3, minNetworks: 2, tcp: null };

  test('our address failing the handshake while the real site works: the name is matched to its address', () => {
    const s = readRealHost(
      'a.example',
      batch(['reset', 'reset', 'reset'], ['ok', 'ok', 'ok'], undefined, 'handshake'),
      o,
    );
    expect(s).toEqual({
      reading: 'ip_name_match',
      counts: { ...EMPTY_COUNTS, ipNameMatch: 3 },
      vantages: 3,
      networks: 3,
      realAddress: null,
    });
  });

  test('both failing from vantages that reach another name: the name is blocked', () => {
    const s = readRealHost(
      'a.example',
      batch(['reset', 'reset', 'reset'], ['reset', 'reset', 'reset']),
      o,
    );
    expect(s?.reading).toBe('name_blocked');
    // ... but from vantages that reach nothing at all, nothing is said.
    const dark = readRealHost(
      'a.example',
      batch(['reset', 'reset', 'reset'], ['reset', 'reset', 'reset'], ['reset', 'reset', 'reset']),
      o,
    );
    expect(dark?.reading).toBe('thin');
    expect(dark?.counts.inconclusive).toBe(3);
  });

  test('pairs by vantage key, never across vantages; a name without a real-site check is not read', () => {
    const s = readRealHost(
      'a.example',
      batch(['timeout', 'ok', 'ok'], ['ok', 'ok', 'ok'], undefined, 'connect'),
      o,
    );
    expect(s?.counts).toEqual({ ...EMPTY_COUNTS, addressBlocked: 1, works: 2 });
    expect(s?.reading).toBe('works');
    expect(readRealHost('b.example', batch(['ok'], ['ok']), o)).toBeNull();
  });

  test('without vantage keys, pairs by network in order', () => {
    const m: PairMeasurement[] = [
      {
        name: 'a.example',
        source: 'ripeatlas',
        role: 'ours',
        results: [
          r('refused', { asn: 'AS1' }),
          r('refused', { asn: 'AS2' }),
          r('refused', { asn: 'AS3' }),
        ],
      },
      {
        name: 'a.example',
        source: 'ripeatlas',
        role: 'real',
        results: [r('ok', { asn: 'AS3' }), r('ok', { asn: 'AS2' }), r('ok', { asn: 'AS1' })],
      },
    ];
    expect(readRealHost('a.example', m, o)?.reading).toBe('address_blocked');
  });

  test('sources that dialled different real addresses are never pooled', () => {
    const src = (source: string, site: string, ours: PairReading['outcome']) => [
      {
        name: 'a.example',
        source,
        role: 'ours' as const,
        results: [0, 1, 2].map((i) =>
          r(ours, { asn: `AS${i}`, vantage: `${source}${i}`, stage: 'connect' }),
        ),
      },
      {
        name: 'a.example',
        source,
        role: 'real' as const,
        realAddress: site,
        results: [0, 1, 2].map((i) => r('ok', { asn: `AS${i}`, vantage: `${source}${i}` })),
      },
    ];
    // Globalping reached its real site 192.0.2.50 (our address fails to connect);
    // Atlas dialled 192.0.2.60 with only two answers: not pooled into one reading.
    const m: PairMeasurement[] = [
      ...src('globalping', '192.0.2.50', 'timeout'),
      ...src('ripeatlas', '192.0.2.60', 'ok').map((x) => ({
        ...x,
        results: x.results.slice(0, 2),
      })),
    ];
    const s = readRealHost('a.example', m, o);
    expect(s).toMatchObject({
      reading: 'address_blocked',
      realAddress: '192.0.2.50',
      vantages: 3,
      counts: { ...EMPTY_COUNTS, addressBlocked: 3 },
    });
  });
});
