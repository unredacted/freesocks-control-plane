import { describe, expect, test } from 'vitest';
import { assignEndpoints, pickSni, type PublishedEdge } from './assignment';

const NOW = 1_700_000_000_000;
const sha = (i: number) => ((i * 2654435761) >>> 0).toString(16).padStart(8, '0') + 'ab'.repeat(28);

const snis = (...names: string[]) => names.map((sni) => ({ sni, status: 'active' as const }));

const edge = (
  over: Partial<PublishedEdge> & { edgeId: string; poolIndex: number },
): PublishedEdge => ({
  provider: 'gcore',
  slotId: 's1',
  slotRemark: 'node-a-relay-a1',
  edgePort: 443,
  addresses: { v4: `203.0.113.${over.poolIndex + 1}` },
  protocol: 'reality',
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
      [before[0], { ...before[1], eligible: false }, before[2]], // profile disabled / slot retired
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

  test('a pool whose every name is retired yields no assignment (nothing renders, templates drop)', () => {
    const retired = [
      { sni: 'a.example', status: 'retired' as const, retiredAt: NOW - 1, drainUntil: NOW + 1e6 },
    ];
    const e = edge({ edgeId: 'e0', poolIndex: 0, serverNames: retired });
    expect(assignEndpoints(sha(1), [e], opts)).toEqual({ primary: null, backup: null });
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

  test('a plain-protocol edge is assignable without server names and carries a null sni', () => {
    const tcp = edge({ edgeId: 't1', poolIndex: 0, protocol: 'plain', serverNames: [] });
    const a = assignEndpoints(sha(1), [tcp], opts);
    expect(a.primary).toMatchObject({ edge: { edgeId: 't1' }, sni: null });
    // A REALITY edge without an active name stays unassignable.
    const bare = edge({ edgeId: 'r1', poolIndex: 0, serverNames: [] });
    expect(assignEndpoints(sha(1), [bare], opts).primary).toBeNull();
  });
});
