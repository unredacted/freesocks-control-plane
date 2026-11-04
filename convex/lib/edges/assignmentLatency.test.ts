/**
 * Latency over the whole path in the assignment (docs/edges.md "Latency over
 * the whole path"): the owner's scenarios on a node in the middle of the US
 * with one address beside it and one far away (meant for Iran), and later one
 * in Europe (meant for Russia) and a second in the US (meant for China); that blocked
 * still wins, the backup still leaves the primary's provider first, the floor
 * counts proven edges among the best group, and that nothing moves without
 * figures: no country, no figures, or every figure equal gives today's walk.
 */
import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  fnv1a32,
  type Assignment,
  type AssignOptions,
  type PublishedEdge,
} from './assignment';
import { pathFigure, type LatencyInputs } from './latency';
import type { ListenerProto } from './protocols';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const NODE: LatencyInputs = { node: { lat: 40, lng: -100 }, measured: {} };
const LISTED = ['IR', 'RU', 'CN'];
const N = 400;

const keyOf = (i: number) =>
  (fnv1a32(`member:${i}`) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);

const edge = (
  id: string,
  poolIndex: number,
  country: string,
  over: Partial<PublishedEdge> = {},
): PublishedEdge => ({
  edgeId: id,
  poolIndex,
  provider: 'p1',
  locationKey: `p1:${id}`,
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'node-a-relay-a1' },
  edgePort: 443,
  layer: 'l4',
  addresses: { v4: `203.0.113.${poolIndex + 1}` },
  memberPlace: { country },
  proto: REALITY,
  serverNames: ['a.example', 'b.example', 'c.example'].map((sni) => ({
    sni,
    status: 'active' as const,
  })),
  ...over,
});

// Stand-ins: an address beside the node, one far from it (meant for Iran), and
// later one in Europe (meant for Russia) and a second in the US (meant for China).
const usA = edge('us-a', 0, 'US');
const far = edge('far', 1, 'GE', { meantFor: ['IR'] });
const eu = edge('eu', 2, 'PL', { meantFor: ['RU'], provider: 'p2' });
const usB = edge('us-b', 3, 'US', { meantFor: ['CN'], provider: 'p2' });
const TODAY = [usA, far];
const LATER = [usA, far, eu, usB];

const pathsFor = (pool: readonly PublishedEdge[], country: string, inputs = NODE) =>
  new Map(
    pool.flatMap((e) => {
      const f = pathFigure(e, country, inputs);
      return f ? [[e.edgeId, f.ms] as const] : [];
    }),
  );

/** As delivery does it for a member whose stored country is `country`, latency ordering on. */
function steered(
  country: string,
  pool: readonly PublishedEdge[],
  over: Partial<AssignOptions> = {},
): AssignOptions {
  return {
    now: 1,
    preferDistinctProviders: true,
    includeBackup: true,
    edgePick: 'hrw1',
    where: { country, curated: LISTED },
    edgeCountry: country,
    pathMs: pathsFor(pool, country),
    ...over,
  };
}

function firsts(pool: readonly PublishedEdge[], opts: AssignOptions): Record<string, number> {
  const out: Record<string, number> = {};
  for (let i = 0; i < N; i++) {
    const id = assignEndpoints(keyOf(i), pool, opts).primary?.edge.edgeId ?? 'none';
    out[id] = (out[id] ?? 0) + 1;
  }
  return out;
}

const shape = (a: Assignment) => ({
  primary: a.primary ? [a.primary.edge.edgeId, a.primary.sni] : null,
  backup: a.backup ? [a.backup.edge.edgeId, a.backup.sni] : null,
});

describe("the owner's scenarios (a node in the US; an address beside it and one far away meant for Iran)", () => {
  test('a member in the US gets the address beside the node first', () => {
    expect(firsts(TODAY, steered('US', TODAY))).toEqual({ 'us-a': N });
  });

  test('a member in Iran gets the address meant for it first', () => {
    expect(firsts(TODAY, steered('IR', TODAY))).toEqual({ far: N });
  });

  test('members in Germany and Brazil get the address beside the node first: the whole path, not the nearest address', () => {
    expect(firsts(TODAY, steered('DE', TODAY))).toEqual({ 'us-a': N });
    expect(firsts(TODAY, steered('BR', TODAY))).toEqual({ 'us-a': N });
  });

  test('the backup is still handed out: the other address', () => {
    const a = assignEndpoints(keyOf(1), TODAY, steered('US', TODAY));
    expect(a.primary?.edge.edgeId).toBe('us-a');
    expect(a.backup?.edge.edgeId).toBe('far');
    expect(a.primaryBand).toBe(0);
    expect(a.backupBand).toBe(2);
  });

  test('with one in Europe (meant for Russia) and a second in the US (meant for China), members split within their near band', () => {
    const de = firsts(LATER, steered('DE', LATER));
    expect(Object.keys(de).sort()).toEqual(['eu', 'us-a', 'us-b']);
    for (const n of Object.values(de)) expect(n).toBeGreaterThan(N / 6);
    const us = firsts(LATER, steered('US', LATER));
    expect(Object.keys(us).sort()).toEqual(['us-a', 'us-b']);
    for (const n of Object.values(us)) expect(n).toBeGreaterThan(N / 4);
    // Meant for still wins for its own countries.
    expect(firsts(LATER, steered('RU', LATER))).toEqual({ eu: N });
    expect(firsts(LATER, steered('CN', LATER))).toEqual({ 'us-b': N });
    expect(firsts(LATER, steered('IR', LATER))).toEqual({ far: N });
  });

  test('a measured member leg counts, and the node leg is added to it', () => {
    const plain = TODAY.map((e) => ({ ...e, meantFor: undefined }));
    const timed = (usMs: number): LatencyInputs => ({
      ...NODE,
      measured: { 'p1:far': { IR: 50 }, 'p1:us-a': { IR: usMs } },
    });
    // The far address is 50 ms from Iran but its leg to the US node is long:
    // against 210 ms to the US one both paths are near (a split, as without meant for).
    const close = firsts(
      plain,
      steered('IR', plain, { pathMs: pathsFor(plain, 'IR', timed(210)) }),
    );
    expect(Object.keys(close).sort()).toEqual(['far', 'us-a']);
    // At 300 ms to the US one, the far address's whole path is shorter by a band.
    const far = firsts(plain, steered('IR', plain, { pathMs: pathsFor(plain, 'IR', timed(300)) }));
    expect(far).toEqual({ far: N });
  });
});

describe('what latency never changes', () => {
  test('blocked there still wins: a near address blocked in the country goes after a far one', () => {
    const pool = [{ ...usA, blockedIn: ['US'] }, far];
    expect(firsts(pool, steered('US', pool))).toEqual({ far: N });
  });

  test('the backup leaves the primary provider first, then takes the nearer band', () => {
    const near2 = edge('us-a2', 4, 'US');
    const far2 = edge('far-2', 5, 'GE', { provider: 'p2' });
    const pool = [usA, near2, far2];
    for (let i = 0; i < 50; i++) {
      const a = assignEndpoints(keyOf(i), pool, steered('US', pool));
      expect(['us-a', 'us-a2']).toContain(a.primary?.edge.edgeId);
      expect(a.backup?.edge.edgeId).toBe('far-2');
    }
    const sameProvider = [usA, near2, edge('far-3', 6, 'GE')];
    for (let i = 0; i < 50; i++) {
      const a = assignEndpoints(keyOf(i), sameProvider, steered('US', sameProvider));
      expect(['us-a', 'us-a2']).toContain(a.backup?.edge.edgeId);
    }
  });

  test('the floor counts proven edges among the near group: proven far edges do not make one near one exclusive', () => {
    const provenNear = edge('near-proven', 0, 'US', { provenIn: ['US'] });
    const unknownNear = edge('near-unknown', 1, 'US');
    const provenFar = [2, 3, 4].map((i) => edge(`far-${i}`, i, 'GE', { provenIn: ['US'] }));
    const pool = [provenNear, unknownNear, ...provenFar];
    const got = firsts(pool, steered('US', pool, { minProvenForExclusive: 3 }));
    expect(Object.keys(got).sort()).toEqual(['near-proven', 'near-unknown']);
  });

  test("no country: figures are ignored (the opt-out and members with none keep today's walk)", () => {
    const plain: AssignOptions = {
      now: 1,
      preferDistinctProviders: true,
      includeBackup: true,
      edgePick: 'hrw1',
    };
    for (let i = 0; i < N; i++) {
      const without = assignEndpoints(keyOf(i), LATER, plain);
      const withFigures = assignEndpoints(keyOf(i), LATER, {
        ...plain,
        pathMs: pathsFor(LATER, 'US'),
      });
      expect(shape(withFigures)).toEqual(shape(without));
      expect(withFigures.primaryBand).toBeUndefined();
    }
  });

  test('no figures, or every figure equal: exactly the steered walk without latency', () => {
    for (const country of ['US', 'IR', 'DE']) {
      const base = steered(country, LATER, { pathMs: undefined });
      const equal = new Map(LATER.map((e) => [e.edgeId, 120]));
      for (let i = 0; i < N; i++) {
        const without = assignEndpoints(keyOf(i), LATER, base);
        expect(shape(assignEndpoints(keyOf(i), LATER, { ...base, pathMs: new Map() }))).toEqual(
          shape(without),
        );
        expect(shape(assignEndpoints(keyOf(i), LATER, { ...base, pathMs: equal }))).toEqual(
          shape(without),
        );
      }
    }
  });

  test('an L7 front has no figure: it ranks with the nearest', () => {
    const front = edge('front', 7, 'US', {
      layer: 'l7',
      addresses: { hostname: 'f.example.org' },
      memberPlace: undefined,
      provider: 'cdn',
    });
    const pool = [usA, far, front];
    // For a member in the US the far address is far; the front shares the near band with the US one.
    expect(Object.keys(firsts(pool, steered('US', pool))).sort()).toEqual(['front', 'us-a']);
    // For a member in Germany too: the US address's whole path is the best one known.
    expect(Object.keys(firsts(pool, steered('DE', pool))).sort()).toEqual(['front', 'us-a']);
  });
});
