/**
 * Delivery by country in the assignment (docs/edges.md "Delivery by country"):
 * the tiers, the backup key, the replay of fixed roles, and the proof the
 * detector's `country_scoped` veto rests on (`steeringAvoids`), cross-checked
 * against `assignEndpoints` itself.
 */
import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  edgeTier,
  endpointsFor,
  fnv1a32,
  steeringAvoids,
  type DeliveryPath,
  type PublishedEdge,
} from './assignment';
import type { ListenerProto } from './protocols';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const PROTOS = [REALITY, SS, WS];

const keyOf = (i: number) =>
  (fnv1a32(`member:${i}`) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);

const edge = (
  over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number },
): PublishedEdge => ({
  provider: 'p1',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'node-a-relay-a1' },
  edgePort: 443,
  addresses: { v4: `203.0.113.${over.poolIndex + 1}` },
  proto: REALITY,
  serverNames: ['a.example', 'b.example', 'c.example'].map((sni) => ({
    sni,
    status: 'active' as const,
  })),
  ...over,
});

const OPTS = { now: 1, preferDistinctProviders: true, includeBackup: true };

/** A deterministic pseudo-random corpus of pools (the same generator as the pin below). */
function corpus(seed0: number, pools: number) {
  let seed = seed0;
  const rnd = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
  const out: Array<{ edges: PublishedEdge[]; rnd: () => number }> = [];
  for (let pool = 0; pool < pools; pool++) {
    const n = 1 + Math.floor(rnd() * 6);
    const edges: PublishedEdge[] = Array.from({ length: n }, (_, i) => ({
      edgeId: `e${pool}-${i}`,
      poolIndex: i,
      provider: ['p1', 'p2', 'p3'][Math.floor(rnd() * 3)]!,
      ...(rnd() < 0.5 ? { locationKey: `loc${Math.floor(rnd() * 3)}` } : {}),
      listenerId: 'l1',
      listenerKey: 'k',
      matchRule: { kind: 'remark', remark: 'r' },
      proto: PROTOS[Math.floor(rnd() * 3)]!,
      edgePort: 443,
      layer: rnd() < 0.15 ? 'l7' : 'l4',
      addresses:
        rnd() < 0.15
          ? { hostname: `f${i}.example.org` }
          : rnd() < 0.2
            ? { v6: '2001:db8::1' }
            : { v4: `203.0.113.${i + 1}` },
      serverNames: ['a.example', 'b.example', 'c.example', 'd.example'].map((sni) => ({
        sni,
        status: rnd() < 0.15 ? ('retired' as const) : ('active' as const),
        ...(rnd() < 0.3 ? { blockedIn: ['IR'] } : {}),
        ...(rnd() < 0.3 ? { provenIn: ['IR'] } : {}),
      })),
      ...(rnd() < 0.5 ? { sniPick: 'hrw1' as const } : {}),
      ...(rnd() < 0.15 ? { eligible: false } : {}),
      ...(rnd() < 0.4 ? { blockedIn: ['IR'] } : {}),
      ...(rnd() < 0.4 ? { provenIn: ['IR'] } : {}),
    }));
    out.push({ edges, rnd });
  }
  return out;
}

describe('assignEndpoints without a country', () => {
  test('is exactly the assignment it always was (pinned over a fixed corpus)', () => {
    // The digest was taken from main's assignEndpoints before delivery by
    // country existed, over this same corpus: 12,000 assignments, byte for byte.
    let digest = 0x811c9dc5;
    let pool = 0;
    for (const { edges, rnd } of corpus(7, 300)) {
      for (let k = 0; k < 40; k++) {
        const key = (fnv1a32(`${pool}:${k}`) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);
        const o = {
          now: 1,
          preferDistinctProviders: rnd() < 0.7,
          includeBackup: rnd() < 0.8,
          canEmitV6: rnd() < 0.5,
          namesPerEndpoint: 1 + Math.floor(rnd() * 3),
          backupNames: 1 + Math.floor(rnd() * 2),
          ...(rnd() < 0.5
            ? { where: { country: rnd() < 0.5 ? 'IR' : null, curated: ['IR', 'RU'] } }
            : {}),
        };
        const a = assignEndpoints(key, edges, { ...o, edgeCountry: null });
        expect(JSON.stringify(assignEndpoints(key, edges, o))).toBe(JSON.stringify(a));
        digest = fnv1a32(`${digest}:${JSON.stringify(a)}`);
      }
      pool++;
    }
    expect(digest).toBe(2698451639);
  });
});

describe('assignEndpoints by tier', () => {
  const four = (over: Record<number, Partial<PublishedEdge>> = {}) =>
    [0, 1, 2, 3].map((i) =>
      edge({ edgeId: `e${i}`, poolIndex: i, provider: `p${i}`, ...(over[i] ?? {}) }),
    );

  test('edges proven in the country come first, blocked ones never while another is assignable', () => {
    const pool = four({ 1: { provenIn: ['IR'] }, 2: { blockedIn: ['IR'] } });
    for (let i = 0; i < 300; i++) {
      const a = assignEndpoints(keyOf(i), pool, { ...OPTS, edgeCountry: 'IR' });
      expect(a.primary!.edge.edgeId).toBe('e1');
      expect(a.primaryTier).toBe(0);
      // The backup is never the blocked one while others exist.
      expect(a.backup!.edge.edgeId).not.toBe('e2');
      expect(a.backupTier).toBe(1);
    }
    // Another country is unaffected by IR's marks.
    expect(assignEndpoints(keyOf(1), pool, { ...OPTS, edgeCountry: 'RU' }).primaryTier).toBe(1);
  });

  test('a blocked edge is used when nothing else is assignable', () => {
    const pool = four({
      0: { blockedIn: ['IR'] },
      1: { blockedIn: ['IR'] },
      2: { eligible: false },
      3: { eligible: false },
    });
    const a = assignEndpoints(keyOf(3), pool, { ...OPTS, edgeCountry: 'IR' });
    expect(['e0', 'e1']).toContain(a.primary!.edge.edgeId);
    expect(a.primaryTier).toBe(2);
  });

  test('members move only when a tier changes: blocking one edge moves only its members', () => {
    const before = four();
    const after = four({ 2: { blockedIn: ['IR'] } });
    let moved = 0;
    for (let i = 0; i < 2000; i++) {
      const a = assignEndpoints(keyOf(i), before, { ...OPTS, edgeCountry: 'IR' });
      const b = assignEndpoints(keyOf(i), after, { ...OPTS, edgeCountry: 'IR' });
      if (a.primary!.edge.edgeId !== 'e2')
        expect(b.primary!.edge.edgeId).toBe(a.primary!.edge.edgeId);
      else moved++;
    }
    expect(moved).toBeGreaterThan(300);
    // Inside one tier the spread is the ordinary one: nobody's primary differs.
    for (let i = 0; i < 500; i++)
      expect(
        assignEndpoints(keyOf(i), before, { ...OPTS, edgeCountry: 'IR' }).primary!.edge.edgeId,
      ).toBe(assignEndpoints(keyOf(i), before, OPTS).primary!.edge.edgeId);
  });

  test('minProvenForExclusive: with too few proven edges, proven and not known share a tier', () => {
    const pool = four({ 1: { provenIn: ['IR'] } });
    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i++) {
      const a = assignEndpoints(keyOf(i), pool, {
        ...OPTS,
        edgeCountry: 'IR',
        minProvenForExclusive: 2,
      });
      counts.set(a.primary!.edge.edgeId, (counts.get(a.primary!.edge.edgeId) ?? 0) + 1);
      // The tier reported is still the edge's own.
      expect(a.primaryTier).toBe(a.primary!.edge.edgeId === 'e1' ? 0 : 1);
    }
    expect(counts.size).toBe(4);
  });

  test('a backup blocked in the member’s country is left out behind a primary that is not', () => {
    const pool = four({ 1: { blockedIn: ['IR'] }, 2: { eligible: false }, 3: { eligible: false } });
    for (let i = 0; i < 200; i++) {
      const a = assignEndpoints(keyOf(i), pool, { ...OPTS, edgeCountry: 'IR' });
      expect(a.primary!.edge.edgeId).toBe('e0');
      expect(a.backup).toBeNull();
      expect(a.backupTier).toBeUndefined();
      // Another country still gets both.
      expect(assignEndpoints(keyOf(i), pool, { ...OPTS, edgeCountry: 'RU' }).backup).not.toBeNull();
      // A mirror without the member's choice keeps it: its reader may be anywhere.
      expect(
        assignEndpoints(keyOf(i), pool, { ...OPTS, avoidBlockedIn: ['IR'] }).backup!.edge.edgeId,
      ).toBe('e1');
    }
    // Every edge blocked there: the primary is blocked too, and so may the backup be.
    const all = four({ 0: { blockedIn: ['IR'] }, 1: { blockedIn: ['IR'] }, 2: { eligible: false } });
    const b = assignEndpoints(keyOf(5), all.slice(0, 3), { ...OPTS, edgeCountry: 'IR' });
    expect(b.primaryTier).toBe(2);
    expect(b.backupTier).toBe(2);
  });

  test('the backup key: not blocked, another provider, the better tier, another location, the walk', () => {
    const pool = [
      edge({ edgeId: 'e0', poolIndex: 0, provider: 'p1', provenIn: ['IR'], locationKey: 'p1:a' }),
      edge({ edgeId: 'e1', poolIndex: 1, provider: 'p1', provenIn: ['IR'], locationKey: 'p1:b' }),
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'p2', blockedIn: ['IR'] }),
      edge({ edgeId: 'e3', poolIndex: 3, provider: 'p2' }),
      edge({ edgeId: 'e4', poolIndex: 4, provider: 'p3', provenIn: ['IR'] }),
    ];
    for (let i = 0; i < 400; i++) {
      const a = assignEndpoints(keyOf(i), pool, { ...OPTS, edgeCountry: 'IR' });
      const p = a.primary!.edge;
      const b = a.backup!.edge;
      expect(edgeTier(p, 'IR')).toBe(0);
      expect(b.edgeId).not.toBe('e2');
      // Another provider exists that is not blocked, so the backup is one.
      expect(b.provider).not.toBe(p.provider);
      // Among the other providers' edges, a proven one (tier 0) wins over a not-known one.
      if (p.provider === 'p1') expect(b.edgeId).toBe('e4');
      if (p.provider === 'p3') expect(['e0', 'e1']).toContain(b.edgeId);
    }
  });
});

describe('endpointsFor: a replay keeps the roles it is given', () => {
  test('the stored backup stays the backup, whatever the seed would pick over the two', () => {
    const p = edge({ edgeId: 'e0', poolIndex: 0 });
    const b = edge({ edgeId: 'e1', poolIndex: 1, provider: 'p2' });
    for (let i = 0; i < 100; i++) {
      const a = endpointsFor(keyOf(i), p, b, {});
      expect([a.primary!.edge.edgeId, a.backup!.edge.edgeId]).toEqual(['e0', 'e1']);
      // ...and, when the seed agrees, the names are the assignment's own.
      const full = assignEndpoints(keyOf(i), [p, b], OPTS);
      if (full.primary!.edge.edgeId === 'e0') expect(a).toEqual(full);
    }
  });
});

const PATHS: DeliveryPath[] = [
  { format: 'links', canEmitV6: true },
  { format: 'singbox', canEmitV6: true },
  { format: 'clash', canEmitV6: false },
];

describe('steeringAvoids', () => {
  const chosen = edge({ edgeId: 'c', poolIndex: 0, blockedIn: ['IR'] });

  test('yes: the chosen edge is blocked there and a distinct edge serves every path it serves', () => {
    expect(
      steeringAvoids(chosen, [chosen, edge({ edgeId: 'o', poolIndex: 1 })], 'IR', PATHS, ['IR']),
    ).toBe(true);
  });

  test('no when the chosen edge is only not known there (two not-known edges rank equally)', () => {
    const unknown = edge({ edgeId: 'c', poolIndex: 0 });
    expect(
      steeringAvoids(unknown, [unknown, edge({ edgeId: 'o', poolIndex: 1 })], 'IR', PATHS, ['IR']),
    ).toBe(false);
  });

  test('no when the only unblocked edge is the chosen one, or the alternative is blocked too', () => {
    expect(steeringAvoids(chosen, [chosen], 'IR', PATHS, ['IR'])).toBe(false);
    expect(
      steeringAvoids(
        chosen,
        [chosen, edge({ edgeId: 'o', poolIndex: 1, blockedIn: ['IR'] })],
        'IR',
        PATHS,
        ['IR'],
      ),
    ).toBe(false);
  });

  test('no when the alternative does not serve one of the paths', () => {
    // Another listener: a body carrying the chosen one may not carry it.
    expect(
      steeringAvoids(
        chosen,
        [chosen, edge({ edgeId: 'o', poolIndex: 1, listenerKey: 'b2' })],
        'IR',
        PATHS,
        ['IR'],
      ),
    ).toBe(false);
    // IPv6 only, where a path cannot emit IPv6.
    expect(
      steeringAvoids(
        chosen,
        [chosen, edge({ edgeId: 'o', poolIndex: 1, addresses: { v6: '2001:db8::2' } })],
        'IR',
        PATHS,
        ['IR'],
      ),
    ).toBe(false);
    // Every name blocked in IR on an hrw1 listener.
    const names = ['a.example', 'b.example'].map((sni) => ({
      sni,
      status: 'active' as const,
      blockedIn: ['IR'],
    }));
    expect(
      steeringAvoids(
        { ...chosen, sniPick: 'hrw1' },
        [
          { ...chosen, sniPick: 'hrw1' },
          edge({ edgeId: 'o', poolIndex: 1, sniPick: 'hrw1', serverNames: names }),
        ],
        'IR',
        PATHS,
        ['IR'],
      ),
    ).toBe(false);
  });

  test('cross-check: whenever it says yes, no member in that country gets the chosen edge first on any path', () => {
    const paths: DeliveryPath[] = [
      ...PATHS,
      { format: 'links', canEmitV6: true, backupFirst: true },
    ];
    let checked = 0;
    for (const { edges } of corpus(11, 400)) {
      for (const c of edges) {
        if (!steeringAvoids(c, edges, 'IR', paths, ['IR', 'RU'], { universal: true })) continue;
        checked++;
        for (const path of paths) {
          for (let k = 0; k < 60; k++) {
            const base = {
              ...OPTS,
              canEmitV6: path.canEmitV6,
              where: { country: 'IR', curated: ['IR', 'RU'] },
            };
            // A member whose stored country is IR, and a mirror without a choice.
            for (const a of [
              assignEndpoints(keyOf(k), edges, { ...base, edgeCountry: 'IR' }),
              assignEndpoints(keyOf(k), edges, { ...base, avoidBlockedIn: ['IR', 'RU'] }),
            ]) {
              if (a.primary) expect(a.primary.edge.edgeId).not.toBe(c.edgeId);
              // Where the backup is handed out first it must not be the chosen edge either.
              if (path.backupFirst && a.backup) expect(a.backup.edge.edgeId).not.toBe(c.edgeId);
            }
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(10);
  });
});
