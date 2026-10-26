/**
 * `hrw1`, rendezvous over edges (docs/edges.md "Address enumeration"): the
 * properties the anti-enumeration design rests on. A blocked address's holders
 * scatter instead of moving together, its replacement reaches a random slice
 * of about 2 in P members (3 in P+1 of the blocked address's own holders), and a growing pool moves only the members the new
 * address outranks.
 */
import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  edgeScore,
  fnv1a32,
  mix32,
  type Assignment,
  type PublishedEdge,
} from './assignment';
import type { ListenerProto } from './protocols';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };

const keyOf = (i: number) =>
  (fnv1a32(`member:${i}`) >>> 0).toString(16).padStart(8, '0') +
  (fnv1a32(`rest:${i}`) >>> 0).toString(16).padStart(8, '0').repeat(7);

const edge = (id: string, poolIndex: number, provider = 'p1'): PublishedEdge => ({
  edgeId: id,
  poolIndex,
  provider,
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'node-a-relay-a1' },
  edgePort: 443,
  addresses: { v4: `203.0.113.${poolIndex + 1}` },
  proto: REALITY,
  serverNames: [{ sni: 'a.example', status: 'active' }],
});

const pool = (n: number, prefix = 'e') =>
  Array.from({ length: n }, (_, i) => edge(`${prefix}${i}`, i, i % 2 === 0 ? 'p1' : 'p2'));

const HRW = {
  now: 1,
  preferDistinctProviders: true,
  includeBackup: true,
  edgePick: 'hrw1' as const,
};
const LEGACY = { now: 1, preferDistinctProviders: true, includeBackup: true };

const pair = (a: Assignment) => [a.primary?.edge.edgeId ?? null, a.backup?.edge.edgeId ?? null];
const holds = (a: Assignment, id: string) => pair(a).includes(id);

const MEMBERS = 4000;

describe('hrw1 edge pick', () => {
  test('the score is mixed: one bit of the key or of the edge id moves about half its bits', () => {
    let flipped = 0;
    let pairs = 0;
    for (let i = 0; i < 200; i++) {
      const a = edgeScore(keyOf(i), 'e1');
      const b = edgeScore(keyOf(i), 'e2');
      flipped += popcount(a ^ b);
      pairs++;
    }
    expect(flipped / pairs).toBeGreaterThan(14);
    expect(flipped / pairs).toBeLessThan(18);
    expect(mix32(0)).toBe(0);
  });

  test('primaries spread evenly over the pool', () => {
    const edges = pool(8);
    const count = new Map<string, number>();
    for (let k = 0; k < MEMBERS; k++) {
      const id = assignEndpoints(keyOf(k), edges, HRW).primary!.edge.edgeId;
      count.set(id, (count.get(id) ?? 0) + 1);
    }
    for (const e of edges) {
      expect(count.get(e.edgeId) ?? 0).toBeGreaterThan((MEMBERS / 8) * 0.75);
      expect(count.get(e.edgeId) ?? 0).toBeLessThan((MEMBERS / 8) * 1.25);
    }
  });

  test('an address that leaves moves only its holders, and they scatter', () => {
    const edges = pool(8);
    const blocked = 'e3';
    const without = edges.filter((e) => e.edgeId !== blocked);
    const landed = new Map<string, number>();
    let holders = 0;
    for (let k = 0; k < MEMBERS; k++) {
      const before = assignEndpoints(keyOf(k), edges, HRW);
      const after = assignEndpoints(keyOf(k), without, HRW);
      if (!holds(before, blocked)) {
        expect(pair(after)).toEqual(pair(before));
        continue;
      }
      holders++;
      if (before.primary!.edge.edgeId !== blocked) continue;
      const to = after.primary!.edge.edgeId;
      landed.set(to, (landed.get(to) ?? 0) + 1);
    }
    expect(holders).toBeGreaterThan(0);
    // The primary holders of the blocked address go to many addresses, none
    // taking more than a third of them (legacy sends them all to one index).
    expect(landed.size).toBeGreaterThanOrEqual(5);
    const primaryHolders = [...landed.values()].reduce((a, b) => a + b, 0);
    for (const n of landed.values()) expect(n).toBeLessThan(primaryHolders / 3);
  });

  test('a replacement reaches about 3 in P+1 of its predecessor holders (legacy: every primary holder)', () => {
    // A holder's other address sat below the blocked one in their ranking, so
    // the fresh address (a new, independent score) beats it with probability
    // 3/(P+1): the third-highest of P scores, not 2/P. Measured on one
    // provider; the backup's provider preference adds a little.
    for (const P of [8, 16]) {
      const edges = pool(P);
      const target = edges[2]!;
      const replaced = edges.map((e) =>
        e.edgeId === target.edgeId ? { ...e, edgeId: 'fresh' } : e,
      );
      for (const distinct of [false, true]) {
        const opts = { ...HRW, preferDistinctProviders: distinct };
        let holders = 0;
        let gotIt = 0;
        for (let k = 0; k < MEMBERS; k++) {
          if (!holds(assignEndpoints(keyOf(k), edges, opts), target.edgeId)) continue;
          holders++;
          if (holds(assignEndpoints(keyOf(k), replaced, opts), 'fresh')) gotIt++;
        }
        const share = gotIt / holders;
        const expected = 3 / (P + 1);
        if (!distinct) {
          expect(share).toBeGreaterThan(expected * 0.75);
          expect(share).toBeLessThan(expected * 1.25);
        } else expect(share).toBeLessThan(4 / (P + 1));
      }
      // The pre-image of `inherit`: every member who had it first gets the next one first.
      let legacyPrimaryHolders = 0;
      let legacyGotIt = 0;
      for (let k = 0; k < MEMBERS; k++) {
        if (assignEndpoints(keyOf(k), edges, LEGACY).primary?.edge.edgeId !== target.edgeId)
          continue;
        legacyPrimaryHolders++;
        if (assignEndpoints(keyOf(k), replaced, LEGACY).primary?.edge.edgeId === 'fresh')
          legacyGotIt++;
      }
      expect(legacyPrimaryHolders).toBeGreaterThan(0);
      expect(legacyGotIt).toBe(legacyPrimaryHolders);
    }
  });

  test('a new address moves only the members it now outranks (legacy reshuffles nearly all)', () => {
    const edges = pool(8);
    const grown = [...edges, edge('new', 8, 'p2')];
    let hrwMoved = 0;
    let legacyMoved = 0;
    for (let k = 0; k < MEMBERS; k++) {
      const before = assignEndpoints(keyOf(k), edges, HRW);
      const after = assignEndpoints(keyOf(k), grown, HRW);
      if (pair(after).join() !== pair(before).join()) {
        hrwMoved++;
        expect(holds(after, 'new')).toBe(true);
      }
      const lb = assignEndpoints(keyOf(k), edges, LEGACY);
      const la = assignEndpoints(keyOf(k), grown, LEGACY);
      if (lb.primary?.edge.edgeId !== la.primary?.edge.edgeId) legacyMoved++;
    }
    expect(hrwMoved / MEMBERS).toBeLessThan(0.35);
    expect(legacyMoved / MEMBERS).toBeGreaterThan(0.7);
  });

  test('the backup keeps its failure-domain preference: another provider first', () => {
    const edges = pool(6);
    for (let k = 0; k < 500; k++) {
      const a = assignEndpoints(keyOf(k), edges, HRW);
      expect(a.backup!.edge.provider).not.toBe(a.primary!.edge.provider);
    }
  });

  test('ineligible edges are walked past and the pool order plays no part', () => {
    const edges = pool(5);
    const shuffled = [...edges].reverse().map((e, i) => ({ ...e, poolIndex: i }));
    for (let k = 0; k < 300; k++) {
      expect(pair(assignEndpoints(keyOf(k), shuffled, HRW))).toEqual(
        pair(assignEndpoints(keyOf(k), edges, HRW)),
      );
      const top = assignEndpoints(keyOf(k), edges, HRW).primary!.edge.edgeId;
      const off = edges.map((e) => (e.edgeId === top ? { ...e, eligible: false } : e));
      expect(assignEndpoints(keyOf(k), off, HRW).primary!.edge.edgeId).not.toBe(top);
    }
  });

  test('by country: proven edges first, ranked by score inside the tier', () => {
    const edges = pool(6).map((e, i) => (i < 3 ? { ...e, provenIn: ['IR'] } : e));
    const seen = new Set<string>();
    for (let k = 0; k < 600; k++) {
      const a = assignEndpoints(keyOf(k), edges, { ...HRW, edgeCountry: 'IR' });
      expect(a.primaryTier).toBe(0);
      seen.add(a.primary!.edge.edgeId);
    }
    expect([...seen].sort()).toEqual(['e0', 'e1', 'e2']);
  });
});

function popcount(x: number): number {
  let n = 0;
  for (let v = x >>> 0; v; v &= v - 1) n++;
  return n;
}
