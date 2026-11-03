/**
 * Locations meant for a country in the assignment (docs/edges.md "Locations
 * meant for a country"): the rank key inside "not blocked there", the backup
 * key, the exclusivity floor, and that nothing moves without it: no country,
 * no meant-for edge, or every edge equally meant gives exactly today's walk.
 * The detector's `country_scoped` proof (`steeringAvoids`) is cross-checked
 * against the assignment with meant-for edges in the pool.
 */
import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  fnv1a32,
  steeringAvoids,
  type Assignment,
  type AssignOptions,
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
const IR = { ...OPTS, edgeCountry: 'IR', where: { country: 'IR', curated: ['IR', 'RU'] } };
const PATHS: DeliveryPath[] = [
  { format: 'links', canEmitV6: false },
  { format: 'singbox', canEmitV6: true },
  { format: 'links', canEmitV6: true, backupFirst: true },
];

/** Pools like the country corpus, with some locations meant for a country. */
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
      ...(rnd() < 0.2 ? { lane: 'trusted' as const } : {}),
      ...(rnd() < 0.4 ? { meantFor: rnd() < 0.5 ? ['IR'] : ['RU', 'IR'] } : {}),
    }));
    out.push({ edges, rnd });
  }
  return out;
}

/** What a member is handed, without the edge objects (they carry the input's `meantFor`) or the flags. */
const shape = (a: Assignment) => {
  const end = (e: Assignment['primary']) =>
    e
      ? { id: e.edge.edgeId, role: e.role, sni: e.sni, host: e.hostHeader, alt: e.alternates }
      : null;
  return JSON.stringify({
    p: end(a.primary),
    b: end(a.backup),
    pt: a.primaryTier,
    bt: a.backupTier,
  });
};
const withoutMeant = (edges: readonly PublishedEdge[]) => edges.map(({ meantFor: _m, ...e }) => e);

function optsFor(rnd: () => number): AssignOptions {
  return {
    now: 1,
    preferDistinctProviders: rnd() < 0.7,
    includeBackup: rnd() < 0.8,
    canEmitV6: rnd() < 0.5,
    namesPerEndpoint: 1 + Math.floor(rnd() * 3),
    backupNames: 1 + Math.floor(rnd() * 2),
    minProvenForExclusive: 1 + Math.floor(rnd() * 3),
    ...(rnd() < 0.3 ? { memberLane: rnd() < 0.5 ? ('open' as const) : ('trusted' as const) } : {}),
    ...(rnd() < 0.5 ? { edgePick: 'hrw1' as const } : {}),
  };
}

describe('nothing moves without the preference', () => {
  test('no country, a mirror without a choice, or another country: the same walk as without it', () => {
    let n = 0;
    for (const { edges, rnd } of corpus(23, 300)) {
      const plain = withoutMeant(edges);
      for (let k = 0; k < 20; k++) {
        const o = optsFor(rnd);
        const key = keyOf(k);
        for (const extra of [
          { edgeCountry: null },
          { edgeCountry: null, avoidBlockedIn: ['IR', 'RU'] },
          { edgeCountry: 'TR', where: { country: 'TR', curated: ['IR', 'RU', 'TR'] } },
        ]) {
          const a = assignEndpoints(key, edges, { ...o, ...extra });
          expect(a.primaryMeantFor).toBeUndefined();
          expect(a.backupMeantFor).toBeUndefined();
          expect(shape(a)).toBe(shape(assignEndpoints(key, plain, { ...o, ...extra })));
          n++;
        }
      }
    }
    expect(n).toBeGreaterThan(10_000);
  });

  test('every edge meant for the member’s country: the same walk as none (only the flags differ)', () => {
    for (const { edges, rnd } of corpus(29, 300)) {
      const all = edges.map((e) => ({ ...e, meantFor: ['IR'] }));
      const none = withoutMeant(edges);
      for (let k = 0; k < 20; k++) {
        const o = { ...optsFor(rnd), edgeCountry: 'IR', where: { country: 'IR', curated: ['IR'] } };
        expect(shape(assignEndpoints(keyOf(k), all, o))).toBe(
          shape(assignEndpoints(keyOf(k), none, o)),
        );
      }
    }
  });

  test('the exclusivity floor is today’s while the preference is inactive (the lanes case)', () => {
    // A trusted member: one proven and one not-known trusted address, two proven
    // open ones, a floor of 3. The floor counts proven addresses across lanes
    // (3), so tier 0 is exclusive and only the proven trusted address is handed
    // out first, exactly as before.
    const pool = [
      edge({ edgeId: 'tp', poolIndex: 0, lane: 'trusted', provenIn: ['IR'] }),
      edge({ edgeId: 'tu', poolIndex: 1, lane: 'trusted' }),
      edge({ edgeId: 'op1', poolIndex: 2, provenIn: ['IR'] }),
      edge({ edgeId: 'op2', poolIndex: 3, provenIn: ['IR'] }),
    ];
    const firsts = new Set<string>();
    for (let k = 0; k < 200; k++) {
      const a = assignEndpoints(keyOf(k), pool, {
        ...IR,
        memberLane: 'trusted',
        minProvenForExclusive: 3,
        edgePick: 'hrw1',
      });
      firsts.add(a.primary!.edge.edgeId);
    }
    expect([...firsts]).toEqual(['tp']);
  });
});

describe('meant for the member’s country', () => {
  test('a not-known address there comes before a proven one elsewhere', () => {
    const pool = [
      edge({ edgeId: 'proven', poolIndex: 0, provenIn: ['IR'] }),
      edge({ edgeId: 'meant', poolIndex: 1, provider: 'p2', meantFor: ['IR', 'RU'] }),
    ];
    for (let k = 0; k < 100; k++) {
      const a = assignEndpoints(keyOf(k), pool, IR);
      expect(a.primary!.edge.edgeId).toBe('meant');
      expect(a.primaryMeantFor).toBe(true);
      expect(a.backup!.edge.edgeId).toBe('proven');
      expect(a.backupMeantFor).toBeUndefined();
      expect(a.primaryTier).toBe(1);
      expect(a.backupTier).toBe(0);
    }
  });

  test('blocked there, it sinks below every address that is not', () => {
    const pool = [
      edge({ edgeId: 'meant', poolIndex: 0, meantFor: ['IR'], blockedIn: ['IR'] }),
      edge({ edgeId: 'other', poolIndex: 1, provider: 'p2' }),
    ];
    for (let k = 0; k < 100; k++) {
      const a = assignEndpoints(keyOf(k), pool, IR);
      expect(a.primary!.edge.edgeId).toBe('other');
      // A backup blocked there behind a primary that is not adds nothing.
      expect(a.backup).toBeNull();
    }
  });

  test('a member in another country ranks it like any other address', () => {
    const pool = [
      edge({ edgeId: 'a', poolIndex: 0, meantFor: ['IR'] }),
      edge({ edgeId: 'b', poolIndex: 1 }),
    ];
    const ru = { ...OPTS, edgeCountry: 'RU', where: { country: 'RU', curated: ['IR', 'RU'] } };
    const firsts = new Set<string>();
    for (let k = 0; k < 200; k++) {
      const a = assignEndpoints(keyOf(k), pool, ru);
      firsts.add(a.primary!.edge.edgeId);
      expect(a.primaryMeantFor).toBeUndefined();
    }
    expect([...firsts].sort()).toEqual(['a', 'b']);
  });

  test('the backup leaves the primary’s provider before it prefers a meant-for address', () => {
    const pool = [
      edge({ edgeId: 'm1', poolIndex: 0, meantFor: ['IR'] }),
      edge({ edgeId: 'm2', poolIndex: 1, meantFor: ['IR'] }),
      edge({ edgeId: 'x', poolIndex: 2, provider: 'p2' }),
    ];
    for (let k = 0; k < 100; k++) {
      const a = assignEndpoints(keyOf(k), pool, IR);
      expect(['m1', 'm2']).toContain(a.primary!.edge.edgeId);
      expect(a.backup!.edge.edgeId).toBe('x');
    }
  });

  test('among the backups of the same provider class it prefers the meant-for one', () => {
    const pool = [
      edge({ edgeId: 'm1', poolIndex: 0, meantFor: ['IR'] }),
      edge({ edgeId: 'm2', poolIndex: 1, provider: 'p2', meantFor: ['IR'] }),
      edge({ edgeId: 'x', poolIndex: 2, provider: 'p3', provenIn: ['IR'] }),
    ];
    for (let k = 0; k < 100; k++) {
      const a = assignEndpoints(keyOf(k), pool, IR);
      const pair = [a.primary!.edge.edgeId, a.backup!.edge.edgeId].sort();
      expect(pair).toEqual(['m1', 'm2']);
    }
  });

  test('while it acts, the floor counts the proven meant-for addresses only', () => {
    // A floor of 2: one proven and one not-known address meant for IR, two
    // proven elsewhere. Counted over the whole pool (3) tier 0 would be
    // exclusive and stack every member on the one proven meant-for address;
    // counted among the meant-for ones (1) both share the first tier.
    const pool = [
      edge({ edgeId: 'mp', poolIndex: 0, meantFor: ['IR'], provenIn: ['IR'] }),
      edge({ edgeId: 'mu', poolIndex: 1, meantFor: ['IR'] }),
      edge({ edgeId: 'p1', poolIndex: 2, provider: 'p2', provenIn: ['IR'] }),
      edge({ edgeId: 'p2', poolIndex: 3, provider: 'p3', provenIn: ['IR'] }),
    ];
    const firsts = new Set<string>();
    for (let k = 0; k < 200; k++)
      firsts.add(
        assignEndpoints(keyOf(k), pool, { ...IR, minProvenForExclusive: 2, edgePick: 'hrw1' })
          .primary!.edge.edgeId,
      );
    expect([...firsts].sort()).toEqual(['mp', 'mu']);
  });

  test('lanes still come first: a trusted member takes a trusted address over an open meant-for one', () => {
    const pool = [
      edge({ edgeId: 'open-meant', poolIndex: 0, meantFor: ['IR'] }),
      edge({ edgeId: 'trusted', poolIndex: 1, lane: 'trusted', provider: 'p2' }),
    ];
    for (let k = 0; k < 50; k++)
      expect(
        assignEndpoints(keyOf(k), pool, { ...IR, memberLane: 'trusted' }).primary!.edge.edgeId,
      ).toBe('trusted');
  });
});

describe('steeringAvoids with meant-for locations in the pool', () => {
  test.each([
    ['legacy', undefined],
    ['hrw1', 'hrw1'],
  ] as const)(
    'cross-check (%s pick): whenever it says yes, no member in that country gets the chosen edge first',
    (_name, edgePick) => {
      let checked = 0;
      for (const { edges } of corpus(31, 400)) {
        const plain = edges.map(({ lane: _l, ...e }) => e);
        for (const c of plain) {
          if (!steeringAvoids(c, plain, 'IR', PATHS, ['IR', 'RU'], { universal: true })) continue;
          checked++;
          for (const path of PATHS) {
            for (let k = 0; k < 60; k++) {
              const a = assignEndpoints(keyOf(k), plain, {
                ...IR,
                canEmitV6: path.canEmitV6,
                ...(edgePick ? { edgePick } : {}),
              });
              if (a.primary) expect(a.primary.edge.edgeId).not.toBe(c.edgeId);
              if (path.backupFirst && a.backup) expect(a.backup.edge.edgeId).not.toBe(c.edgeId);
            }
          }
        }
      }
      expect(checked).toBeGreaterThan(10);
    },
  );
});
