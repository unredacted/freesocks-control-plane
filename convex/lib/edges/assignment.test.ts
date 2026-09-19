import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  edgeAssignable,
  pickSni,
  rankSniHrw,
  type PublishedEdge,
} from './assignment';
import type { ListenerProto } from './protocols';

const NOW = 1_700_000_000_000;
const sha = (i: number) => ((i * 2654435761) >>> 0).toString(16).padStart(8, '0') + 'ab'.repeat(28);

const snis = (...names: string[]) => names.map((sni) => ({ sni, status: 'active' as const }));

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const TLS: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'tls' };
const WS: ListenerProto = { protocol: 'vless', streamTransport: 'ws', security: 'tls' };
const HTTPUPGRADE: ListenerProto = {
  protocol: 'vless',
  streamTransport: 'httpupgrade',
  security: 'tls',
};
const GRPC: ListenerProto = { protocol: 'vless', streamTransport: 'grpc', security: 'tls' };
const SS: ListenerProto = { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none' };

const edge = (
  over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number },
): PublishedEdge => ({
  provider: 'gcore',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'node-a-relay-a1' },
  edgePort: 443,
  addresses: { v4: `203.0.113.${over.poolIndex + 1}` },
  proto: REALITY,
  serverNames: snis('a.example', 'b.example', 'c.example'),
  ...over,
});

const opts = { now: NOW, preferDistinctProviders: true, includeBackup: true };

describe('assignEndpoints', () => {
  test('distributes 10k subscribers across published edges within tolerance and is stable', () => {
    const edges = [
      edge({ edgeId: 'e0', poolIndex: 0, provider: 'gcore' }),
      edge({ edgeId: 'e1', poolIndex: 1, provider: 'scaleway' }),
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'upcloud' }),
    ];
    const counts = new Map<string, number>();
    const sniCounts = new Map<string, number>();
    for (let i = 0; i < 10_000; i++) {
      const a = assignEndpoints(sha(i), edges, opts);
      counts.set(a.primary!.edge.edgeId, (counts.get(a.primary!.edge.edgeId) ?? 0) + 1);
      const sni = a.primary!.sni!;
      sniCounts.set(sni, (sniCounts.get(sni) ?? 0) + 1);
      expect(a.backup!.edge.edgeId).not.toBe(a.primary!.edge.edgeId);
      expect(a.backup!.edge.provider).not.toBe(a.primary!.edge.provider);
      // Stable across repeated renders.
      const again = assignEndpoints(sha(i), edges, opts);
      expect(again.primary!.edge.edgeId).toBe(a.primary!.edge.edgeId);
      expect(again.primary!.sni).toBe(a.primary!.sni);
    }
    for (const c of counts.values()) expect(Math.abs(c / 10_000 - 1 / 3)).toBeLessThan(0.1);
    for (const c of sniCounts.values()) expect(Math.abs(c / 10_000 - 1 / 3)).toBeLessThan(0.15);
  });

  test('replacing the edge at index k moves only subscribers whose primary or backup was k', () => {
    const before = [
      edge({ edgeId: 'e0', poolIndex: 0 }),
      edge({ edgeId: 'e1', poolIndex: 1, provider: 'ovh' }),
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'upcloud' }),
    ];
    const after = [before[0], edge({ edgeId: 'e1-new', poolIndex: 1, provider: 'ovh' }), before[2]];
    for (let i = 0; i < 2000; i++) {
      const a = assignEndpoints(sha(i), before, opts);
      const b = assignEndpoints(sha(i), after, opts);
      const touched = a.primary!.edge.edgeId === 'e1' || a.backup!.edge.edgeId === 'e1';
      if (!touched) {
        expect(b.primary!.edge.edgeId).toBe(a.primary!.edge.edgeId);
        expect(b.backup!.edge.edgeId).toBe(a.backup!.edge.edgeId);
        expect(b.primary!.sni).toBe(a.primary!.sni);
      } else if (a.primary!.edge.edgeId === 'e1') {
        expect(b.primary!.edge.edgeId).toBe('e1-new');
      }
    }
  });

  test('single published edge → backup null; no edges → nothing; unaddressed/no-SNI edges are skipped', () => {
    const one = assignEndpoints(sha(1), [edge({ edgeId: 'e0', poolIndex: 0 })], opts);
    expect(one.primary?.edge.edgeId).toBe('e0');
    expect(one.backup).toBeNull();
    expect(assignEndpoints(sha(1), [], opts)).toEqual({ primary: null, backup: null });
    const skipped = assignEndpoints(
      sha(1),
      [
        edge({ edgeId: 'e0', poolIndex: 0, addresses: {} }),
        edge({ edgeId: 'e1', poolIndex: 1, serverNames: [] }),
      ],
      opts,
    );
    expect(skipped.primary).toBeNull();
  });

  test('backup falls back to a same-provider edge when no other provider is published; includeBackup:false yields none', () => {
    const edges = [edge({ edgeId: 'e0', poolIndex: 0 }), edge({ edgeId: 'e1', poolIndex: 1 })];
    const a = assignEndpoints(sha(3), edges, opts);
    expect(a.backup).not.toBeNull();
    expect(a.backup!.edge.provider).toBe('gcore');
    expect(assignEndpoints(sha(3), edges, { ...opts, includeBackup: false }).backup).toBeNull();
  });

  test('an edge turning unassignable moves ONLY its own subscribers (pool-index compaction)', () => {
    const before = [
      edge({ edgeId: 'e0', poolIndex: 0, provider: 'gcore' }),
      edge({ edgeId: 'e1', poolIndex: 1, provider: 'ovh' }),
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'upcloud' }),
    ];
    // Three ways an edge stops being assignable while staying in the pool.
    const variants = [
      [before[0], { ...before[1], eligible: false }, before[2]], // listener disabled / retired / no template entry
      [before[0], { ...before[1], serverNames: [] }, before[2]], // no active name
      [before[0], { ...before[1], addresses: {} }, before[2]], // no address
    ];
    for (const after of variants) {
      let moved = 0;
      for (let i = 0; i < 2000; i++) {
        const a = assignEndpoints(sha(i), before, opts);
        const b = assignEndpoints(sha(i), after, opts);
        expect(b.primary!.edge.edgeId).not.toBe('e1');
        expect(b.backup?.edge.edgeId).not.toBe('e1');
        if (a.primary!.edge.edgeId !== 'e1') {
          expect(b.primary!.edge.edgeId).toBe(a.primary!.edge.edgeId);
          expect(b.primary!.sni).toBe(a.primary!.sni);
        } else {
          moved++;
          // Walk-forward: the seeded index 1 lands on the next assignable (e2).
          expect(b.primary!.edge.edgeId).toBe('e2');
        }
      }
      expect(moved).toBeGreaterThan(0);
    }
  });

  test('an IPv6-only edge is assignable only when the render can emit IPv6', () => {
    const v6 = edge({ edgeId: 'e6', poolIndex: 0, addresses: { v6: '2001:db8::6' } });
    expect(assignEndpoints(sha(1), [v6], opts).primary?.edge.edgeId).toBe('e6');
    expect(assignEndpoints(sha(1), [v6], { ...opts, canEmitV6: true }).primary?.edge.edgeId).toBe(
      'e6',
    );
    expect(assignEndpoints(sha(1), [v6], { ...opts, canEmitV6: false }).primary).toBeNull();
    // With a dual-stack neighbour the v6-only edge is skipped, not the render.
    const dual = edge({ edgeId: 'e4', poolIndex: 1 });
    for (let i = 0; i < 200; i++) {
      const a = assignEndpoints(sha(i), [v6, dual], { ...opts, canEmitV6: false });
      expect(a.primary?.edge.edgeId).toBe('e4');
      expect(a.backup).toBeNull();
    }
  });

  test('a pool whose every name is retired yields no assignment (nothing renders)', () => {
    const retired = [
      { sni: 'a.example', status: 'retired' as const, retiredAt: NOW - 1, drainUntil: NOW + 1e6 },
    ];
    const e = edge({ edgeId: 'e0', poolIndex: 0, serverNames: retired });
    expect(assignEndpoints(sha(1), [e], opts)).toEqual({ primary: null, backup: null });
  });

  test('every endpoint carries the listener it was assigned on (the renderer clones that template)', () => {
    const pool = [
      edge({ edgeId: 'e0', poolIndex: 0, listenerId: 'l1', listenerKey: 'a' }),
      edge({
        edgeId: 'e1',
        poolIndex: 1,
        provider: 'ovh',
        listenerId: 'l2',
        listenerKey: 's',
        matchRule: { kind: 'address' },
        proto: SS,
        serverNames: [],
      }),
    ];
    for (let i = 0; i < 200; i++) {
      const a = assignEndpoints(sha(i), pool, opts);
      const keys = new Set([a.primary!.edge.listenerKey, a.backup!.edge.listenerKey]);
      expect(keys).toEqual(new Set(['a', 's']));
      const ss = [a.primary!, a.backup!].find((ep) => ep.edge.listenerKey === 's')!;
      expect(ss.sni).toBeNull();
      expect(ss.edge.matchRule).toEqual({ kind: 'address' });
    }
  });
});

describe('pickSni', () => {
  const list = [
    { sni: 'a.example', status: 'active' as const },
    { sni: 'b.example', status: 'active' as const },
    { sni: 'c.example', status: 'active' as const },
  ];

  test('stable, and retiring one name moves only its holders', () => {
    const picks = new Map<number, string>();
    for (let i = 0; i < 3000; i++) picks.set(i, pickSni(sha(i), 'e0', list)!);
    const retired = list.map((s) =>
      s.sni === 'b.example'
        ? { ...s, status: 'retired' as const, retiredAt: NOW - 1000, drainUntil: NOW - 1 }
        : s,
    );
    for (let i = 0; i < 3000; i++) {
      const after = pickSni(sha(i), 'e0', retired)!;
      if (picks.get(i) !== 'b.example') expect(after).toBe(picks.get(i));
      else expect(['a.example', 'c.example']).toContain(after);
    }
  });

  test('a retired name is NEVER selected for a render, drain or not, held before or not', () => {
    const retired = [
      { sni: 'a.example', status: 'active' as const },
      {
        sni: 'b.example',
        status: 'retired' as const,
        retiredAt: NOW - 1000,
        drainUntil: NOW + 60_000, // still inside the drain: the node ACCEPTS it, we do not HAND IT OUT
      },
    ];
    // Find a key that lands on index 1 while both names are active.
    let h = sha(0);
    for (let i = 0; i < 500; i++) {
      h = sha(i);
      if (pickSni(h, 'e0', [retired[0], { sni: 'b.example', status: 'active' }]) === 'b.example')
        break;
    }
    expect(pickSni(h, 'e0', retired)).toBe('a.example');
    for (let i = 0; i < 500; i++) expect(pickSni(sha(i), 'e0', retired)).toBe('a.example');
    // The legacy "held it" option is accepted and ignored.
    const e = edge({ edgeId: 'e0', poolIndex: 0, serverNames: retired });
    const a = assignEndpoints(h, [e], { ...opts, subscriberLastContentAt: NOW - 5000 });
    expect(a.primary?.sni).toBe('a.example');
  });

  test('no active names → null (the edge is then not assignable)', () => {
    const allRetired = [
      { sni: 'x', status: 'retired' as const, retiredAt: NOW - 1, drainUntil: NOW + 1e6 },
    ];
    expect(pickSni(sha(1), 'e0', allRetired)).toBeNull();
    expect(pickSni(sha(1), 'e0', [])).toBeNull();
    const e = edge({ edgeId: 'e0', poolIndex: 0, serverNames: allRetired });
    expect(assignEndpoints(sha(1), [e], opts).primary).toBeNull();
  });
});

describe('pickSni legacy PRF is frozen', () => {
  // Golden vector: the legacy (version-less) pick must never change, because
  // every listener that has not opted into `hrw1` still renders with it.
  test('byte-identical picks for a fixed key set', () => {
    const list = snis('a.example', 'b.example', 'c.example', 'd.example', 'e.example');
    const picks = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((i) => pickSni(sha(i), 'e0', list));
    expect(picks).toMatchInlineSnapshot(`
      [
        "d.example",
        "b.example",
        "a.example",
        "a.example",
        "d.example",
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
      ]
    `);
  });

  test('legacy growth reshuffles most subscribers (why hrw1 exists)', () => {
    const before = snis(...Array.from({ length: 20 }, (_, i) => `n${i}.example`));
    const after = [...before, ...snis('n20.example')];
    let moved = 0;
    for (let i = 0; i < 5000; i++)
      if (pickSni(sha(i), 'e0', before) !== pickSni(sha(i), 'e0', after)) moved++;
    expect(moved / 5000).toBeGreaterThan(0.8);
  });
});

describe('pickSni hrw1 (rendezvous)', () => {
  const names = (n: number) => snis(...Array.from({ length: n }, (_, i) => `n${i}.example`));
  const N = 10_000;

  test('adding one name moves only the subscribers it wins, about 1/(N+1)', () => {
    const before = names(20);
    const after = [...before, ...snis('fresh.example')];
    let moved = 0;
    for (let i = 0; i < N; i++) {
      const a = pickSni(sha(i), 'e0', before, 'hrw1');
      const b = pickSni(sha(i), 'e0', after, 'hrw1');
      if (a !== b) {
        moved++;
        // Anyone who moved moved TO the new name, never between old ones.
        expect(b).toBe('fresh.example');
      }
    }
    expect(moved / N).toBeLessThan(2 / 21);
    expect(moved).toBeGreaterThan(0);
  });

  test('retiring a name moves only its holders', () => {
    const before = names(12);
    const after = before.map((s) =>
      s.sni === 'n3.example'
        ? { ...s, status: 'retired' as const, retiredAt: NOW - 1000, drainUntil: NOW + 60_000 }
        : s,
    );
    for (let i = 0; i < N; i++) {
      const a = pickSni(sha(i), 'e0', before, 'hrw1');
      const b = pickSni(sha(i), 'e0', after, 'hrw1');
      if (a === 'n3.example') expect(b).not.toBe('n3.example');
      else expect(b).toBe(a);
    }
  });

  test('order and removed entries do not matter (compaction moves nobody)', () => {
    const list = names(9);
    const shuffled = [...list].reverse();
    const withRetired = [
      { sni: 'gone.example', status: 'retired' as const, retiredAt: NOW - 1, drainUntil: NOW - 1 },
      ...list,
    ];
    for (let i = 0; i < 2000; i++) {
      const a = pickSni(sha(i), 'e0', list, 'hrw1');
      expect(pickSni(sha(i), 'e0', shuffled, 'hrw1')).toBe(a);
      expect(pickSni(sha(i), 'e0', withRetired, 'hrw1')).toBe(a);
    }
  });

  test('spreads subscribers across the names, and differs per edge', () => {
    const list = names(8);
    const counts = new Map<string, number>();
    let differs = 0;
    for (let i = 0; i < N; i++) {
      const a = pickSni(sha(i), 'e0', list, 'hrw1')!;
      counts.set(a, (counts.get(a) ?? 0) + 1);
      if (pickSni(sha(i), 'e1', list, 'hrw1') !== a) differs++;
    }
    expect(counts.size).toBe(8);
    for (const c of counts.values()) expect(c).toBeGreaterThan(N / 8 / 2);
    expect(differs).toBeGreaterThan(N / 2);
  });

  test('a retired name is never ranked; no active name is null', () => {
    const retired = { status: 'retired' as const, retiredAt: NOW - 1, drainUntil: NOW + 1e6 };
    const list = [{ sni: 'x.example', ...retired }, ...snis('y.example')];
    expect(rankSniHrw(sha(1), 'e0', list)).toEqual(['y.example']);
    expect(pickSni(sha(1), 'e0', [{ sni: 'x.example', ...retired }], 'hrw1')).toBeNull();
    expect(pickSni(sha(1), 'e0', [], 'hrw1')).toBeNull();
  });

  test('the ranking is a stable total order with no duplicates', () => {
    const list = [...names(6), ...snis('n2.example')];
    const r = rankSniHrw(sha(7), 'e0', list);
    expect(r).toHaveLength(6);
    expect(new Set(r).size).toBe(6);
    expect(rankSniHrw(sha(7), 'e0', [...list].reverse())).toEqual(r);
  });

  test('assignment uses the edge version; an L7 edge ignores it', () => {
    const list = names(10);
    const l4 = edge({ edgeId: 'e0', poolIndex: 0, serverNames: list, sniPick: 'hrw1' });
    for (let i = 0; i < 200; i++)
      expect(assignEndpoints(sha(i), [l4], opts).primary?.sni).toBe(
        pickSni(sha(i), 'e0', list, 'hrw1'),
      );
    const l7 = edge({
      edgeId: 'e7',
      poolIndex: 0,
      layer: 'l7',
      proto: WS,
      addresses: { hostname: 'front.example' },
      serverNames: list,
      sniPick: 'hrw1',
    });
    expect(assignEndpoints(sha(1), [l7], opts).primary?.sni).toBe('front.example');
  });
});

// An L7 edge is a hostname fronted by a CDN: the hostname is the address, the
// SNI and the Host header at once, so the listener's (origin-facing) server
// names play no part in it.
describe('hostname (L7) edges', () => {
  const l7 = (over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number }) =>
    edge({
      layer: 'l7',
      proto: WS,
      serverNames: [],
      addresses: { hostname: `front-${over.poolIndex}.example` },
      ...over,
    });

  test('assignable without any listener server name; the hostname is the SNI and the Host header', () => {
    const e = l7({ edgeId: 'h0', poolIndex: 0 });
    const a = assignEndpoints(sha(1), [e], opts);
    expect(a.primary).toMatchObject({
      edge: { edgeId: 'h0' },
      sni: 'front-0.example',
      hostHeader: 'front-0.example',
    });
    // The rendering rule's IPv6 mode is irrelevant: there is no address family.
    expect(assignEndpoints(sha(1), [e], { ...opts, canEmitV6: false }).primary?.sni).toBe(
      'front-0.example',
    );
    // Retired origin names do not make it unassignable either.
    const retired = l7({
      edgeId: 'h1',
      poolIndex: 0,
      serverNames: [{ sni: 'x.example', status: 'retired', retiredAt: NOW - 1 }],
    });
    expect(assignEndpoints(sha(1), [retired], opts).primary?.sni).toBe('front-0.example');
    // An L7 edge whose hostname is not provisioned yet is NOT assignable.
    expect(edgeAssignable(l7({ edgeId: 'h2', poolIndex: 0, addresses: {} }))).toBe(false);
  });

  test('hostHeader follows the listener: the hostname for L7, the selected name for L4 ws/httpupgrade, null otherwise', () => {
    for (const proto of [WS, HTTPUPGRADE, GRPC, REALITY, TLS, SS]) {
      const hosted = assignEndpoints(sha(1), [l7({ edgeId: 'h0', poolIndex: 0, proto })], opts);
      expect(hosted.primary!.hostHeader).toBe('front-0.example');
      expect(hosted.primary!.sni).toBe('front-0.example');
    }
    const expected: Array<[ListenerProto, 'sni' | null]> = [
      [WS, 'sni'],
      [HTTPUPGRADE, 'sni'],
      [GRPC, null],
      [REALITY, null],
      [TLS, null],
    ];
    for (const [proto, want] of expected) {
      const a = assignEndpoints(sha(1), [edge({ edgeId: 'e0', poolIndex: 0, proto })], opts);
      expect(a.primary!.hostHeader).toBe(want === 'sni' ? a.primary!.sni : null);
    }
    const plain = assignEndpoints(
      sha(1),
      [edge({ edgeId: 'e0', poolIndex: 0, proto: SS, serverNames: [] })],
      opts,
    );
    expect(plain.primary!.hostHeader).toBeNull();
    // A v6-only L4 ws edge still gets its Host header (assignment is family agnostic).
    const v6 = assignEndpoints(
      sha(1),
      [edge({ edgeId: 'e6', poolIndex: 0, proto: WS, addresses: { v6: '2001:db8::6' } })],
      opts,
    );
    expect(v6.primary!.hostHeader).toBe(v6.primary!.sni);
  });

  test('a mixed L4 + L7 pool walks in pool order and the backup still prefers another provider', () => {
    const pool = [
      edge({ edgeId: 'e0', poolIndex: 0, provider: 'gcore' }),
      l7({ edgeId: 'h1', poolIndex: 1, provider: 'cdn-one' }),
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'upcloud' }),
    ];
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const a = assignEndpoints(sha(i), pool, opts);
      seen.add(a.primary!.edge.edgeId);
      expect(a.backup!.edge.provider).not.toBe(a.primary!.edge.provider);
      // Each endpoint carries the tuple of ITS own layer.
      for (const ep of [a.primary!, a.backup!]) {
        if (ep.edge.edgeId === 'h1') {
          expect(ep.sni).toBe('front-1.example');
          expect(ep.hostHeader).toBe('front-1.example');
        } else {
          expect(['a.example', 'b.example', 'c.example']).toContain(ep.sni);
          expect(ep.hostHeader).toBeNull();
        }
      }
      // Stable across renders.
      expect(assignEndpoints(sha(i), pool, opts).primary!.edge.edgeId).toBe(a.primary!.edge.edgeId);
    }
    expect(seen).toEqual(new Set(['e0', 'h1', 'e2']));
    // An L7 edge is never skipped by an ipv6Mode:'off' rule, and a v6-only L4
    // neighbour is: only the neighbour's subscribers move.
    const withV6 = [
      pool[0],
      pool[1],
      edge({ edgeId: 'e2', poolIndex: 2, provider: 'upcloud', addresses: { v6: '2001:db8::2' } }),
    ];
    for (let i = 0; i < 500; i++) {
      const a = assignEndpoints(sha(i), withV6, { ...opts, canEmitV6: false });
      expect(a.primary!.edge.edgeId).not.toBe('e2');
    }
  });

  test('an L4 ws/httpupgrade/grpc edge behaves exactly like a tls one (names picked the same way)', () => {
    const names = snis('a.example', 'b.example', 'c.example');
    for (const proto of [WS, HTTPUPGRADE, GRPC]) {
      const tls = edge({ edgeId: 'e0', poolIndex: 0, proto: TLS, serverNames: names });
      const http = edge({ edgeId: 'e0', poolIndex: 0, proto, serverNames: names });
      for (let i = 0; i < 200; i++) {
        expect(assignEndpoints(sha(i), [http], opts).primary!.sni).toBe(
          assignEndpoints(sha(i), [tls], opts).primary!.sni,
        );
      }
      // …and stays unassignable without an active name, like tls.
      expect(
        assignEndpoints(
          sha(1),
          [edge({ edgeId: 'e0', poolIndex: 0, proto, serverNames: [] })],
          opts,
        ).primary,
      ).toBeNull();
    }
  });

  test('a no-name listener (shadowsocks) is assignable without server names and carries a null sni', () => {
    const tcp = edge({ edgeId: 't1', poolIndex: 0, proto: SS, serverNames: [] });
    const a = assignEndpoints(sha(1), [tcp], opts);
    expect(a.primary).toMatchObject({ edge: { edgeId: 't1' }, sni: null });
    // A REALITY edge without an active name stays unassignable.
    const bare = edge({ edgeId: 'r1', poolIndex: 0, serverNames: [] });
    expect(assignEndpoints(sha(1), [bare], opts).primary).toBeNull();
  });
});
