/**
 * Address lanes (docs/edges.md "Address enumeration"): the pure rules, and the
 * promises the assignment keeps with them, checked over a seeded corpus.
 */
import { describe, expect, test } from 'vitest';
import {
  assignEndpoints,
  fnv1a32,
  steeringAvoids,
  type DeliveryPath,
  type PublishedEdge,
} from './assignment';
import {
  isPaidMember,
  laneAtPublish,
  laneBook,
  laneDesired,
  mayBeTrusted,
  memberLane,
  openToRetire,
} from './lanes';
import type { ListenerProto } from './protocols';

const DAY = 86_400_000;
const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };

const keyOf = (i: number) =>
  (fnv1a32(`m:${i}`) >>> 0).toString(16).padStart(8, '0') +
  (fnv1a32(`r:${i}`) >>> 0).toString(16).padStart(8, '0').repeat(7);

function corpus(seed0: number, pools: number): PublishedEdge[][] {
  let seed = seed0;
  const rnd = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
  const out: PublishedEdge[][] = [];
  for (let p = 0; p < pools; p++) {
    const n = 1 + Math.floor(rnd() * 7);
    out.push(
      Array.from({ length: n }, (_, i) => ({
        edgeId: `e${p}-${i}`,
        poolIndex: i,
        provider: ['p1', 'p2'][Math.floor(rnd() * 2)]!,
        listenerId: 'l1',
        listenerKey: 'k',
        matchRule: { kind: 'remark', remark: 'r' },
        proto: REALITY,
        edgePort: 443,
        addresses: rnd() < 0.15 ? { v6: '2001:db8::1' } : { v4: `203.0.113.${i + 1}` },
        serverNames: [{ sni: 'a.example', status: 'active' as const }],
        ...(rnd() < 0.5 ? { lane: 'trusted' as const } : {}),
        ...(rnd() < 0.3 ? { blockedIn: ['IR'] } : {}),
        ...(rnd() < 0.3 ? { provenIn: ['IR'] } : {}),
        ...(rnd() < 0.1 ? { eligible: false } : {}),
      })),
    );
  }
  return out;
}

const variants = (rnd: number) => [
  { now: 1, preferDistinctProviders: true, includeBackup: true, edgePick: 'hrw1' as const },
  {
    now: 1,
    preferDistinctProviders: rnd > 0.5,
    includeBackup: true,
    edgePick: 'hrw1' as const,
    edgeCountry: 'IR',
    canEmitV6: false,
  },
  {
    now: 1,
    preferDistinctProviders: true,
    includeBackup: true,
    edgePick: 'hrw1' as const,
    avoidBlockedIn: ['IR'],
  },
];

describe('the assignment with lanes', () => {
  test('an open member is never handed a trusted address, primary or backup', () => {
    let served = 0;
    for (const [p, pool] of corpus(3, 300).entries())
      for (const o of variants(p / 300))
        for (let k = 0; k < 20; k++) {
          const a = assignEndpoints(keyOf(k), pool, { ...o, memberLane: 'open' });
          for (const x of [a.primary, a.backup]) if (x) expect(x.edge.lane).toBeUndefined();
          if (a.primary) served++;
        }
    expect(served).toBeGreaterThan(1000);
  });

  test('a trusted member gets a trusted primary whenever one is usable where they are', () => {
    let fellBack = 0;
    for (const [p, pool] of corpus(5, 300).entries())
      for (const o of variants(p / 300))
        for (let k = 0; k < 20; k++) {
          const a = assignEndpoints(keyOf(k), pool, { ...o, memberLane: 'trusted' });
          if (!a.primary || a.primary.edge.lane === 'trusted') continue;
          fellBack++;
          // An open primary only when no trusted edge would do at least as well here.
          const usable = pool.filter((e) => {
            if (e.lane !== 'trusted' || e.eligible === false) return false;
            if (!e.addresses.v4 && 'canEmitV6' in o && o.canEmitV6 === false) return false;
            const blocked =
              ('edgeCountry' in o && (e.blockedIn ?? []).includes(o.edgeCountry!)) ||
              ('avoidBlockedIn' in o &&
                (e.blockedIn ?? []).some((c) => o.avoidBlockedIn!.includes(c)));
            return !blocked;
          });
          expect(usable).toEqual([]);
        }
    expect(fellBack).toBeGreaterThan(0);
  });

  test('without a member lane nothing changes (the lanes on edges are ignored)', () => {
    for (const pool of corpus(9, 100))
      for (let k = 0; k < 10; k++) {
        const stripped = pool.map(({ lane: _lane, ...e }) => e);
        const o = { now: 1, preferDistinctProviders: true, includeBackup: true };
        expect(JSON.stringify(assignEndpoints(keyOf(k), pool, o).primary?.edge.edgeId)).toBe(
          JSON.stringify(assignEndpoints(keyOf(k), stripped, o).primary?.edge.edgeId),
        );
      }
  });

  test('the trusted backup comes from the trusted lane while one is left, else an open one', () => {
    const base = {
      poolIndex: 0,
      provider: 'p1',
      listenerId: 'l1',
      listenerKey: 'k',
      matchRule: { kind: 'remark', remark: 'r' } as const,
      proto: REALITY,
      edgePort: 443,
      serverNames: [{ sni: 'a.example', status: 'active' as const }],
    };
    const t1 = {
      ...base,
      edgeId: 't1',
      addresses: { v4: '203.0.113.1' },
      lane: 'trusted' as const,
    };
    const t2 = {
      ...base,
      edgeId: 't2',
      addresses: { v4: '203.0.113.2' },
      lane: 'trusted' as const,
    };
    const o1 = { ...base, edgeId: 'o1', addresses: { v4: '203.0.113.3' }, provider: 'p2' };
    const opts = {
      now: 1,
      preferDistinctProviders: true,
      includeBackup: true,
      edgePick: 'hrw1' as const,
      memberLane: 'trusted' as const,
    };
    for (let k = 0; k < 50; k++) {
      const two = assignEndpoints(keyOf(k), [t1, t2, o1], opts);
      expect([two.primary!.edge.edgeId, two.backup!.edge.edgeId].sort()).toEqual(['t1', 't2']);
      const one = assignEndpoints(keyOf(k), [t1, o1], opts);
      expect([one.primary!.edge.edgeId, one.backup!.edge.edgeId]).toEqual(['t1', 'o1']);
    }
  });

  test('the country veto with lanes: whenever it says yes, no member there gets the chosen edge first', () => {
    const paths: DeliveryPath[] = [
      { format: 'links', canEmitV6: false },
      { format: 'singbox', canEmitV6: true },
      { format: 'links', canEmitV6: true, backupFirst: true },
    ];
    let checked = 0;
    for (const pool of corpus(11, 400))
      for (const c of pool) {
        if (!steeringAvoids(c, pool, 'IR', paths, ['IR'], { lanes: true })) continue;
        checked++;
        for (const path of paths)
          for (const memberLane of ['open', 'trusted'] as const)
            for (let k = 0; k < 30; k++) {
              const a = assignEndpoints(keyOf(k), pool, {
                now: 1,
                preferDistinctProviders: true,
                includeBackup: true,
                canEmitV6: path.canEmitV6,
                edgePick: 'hrw1',
                edgeCountry: 'IR',
                memberLane,
              });
              if (a.primary) expect(a.primary.edge.edgeId).not.toBe(c.edgeId);
              if (path.backupFirst && a.backup) expect(a.backup.edge.edgeId).not.toBe(c.edgeId);
            }
      }
    expect(checked).toBeGreaterThan(10);
  });
});

describe('the lane rules', () => {
  const now = 100 * DAY;
  test('who is trusted', () => {
    const lane = (o: Partial<Parameters<typeof memberLane>[0]>) =>
      memberLane({
        paid: false,
        createdAt: now,
        suspected: false,
        now,
        promoteAfterDays: 14,
        ...o,
      });
    expect(lane({})).toBe('open');
    expect(lane({ createdAt: now - 14 * DAY })).toBe('trusted');
    expect(lane({ createdAt: now - 13 * DAY })).toBe('open');
    expect(lane({ paid: true })).toBe('trusted');
    expect(lane({ paid: true, suspected: true })).toBe('open');
    expect(lane({ createdAt: 0, suspected: true })).toBe('open');
    expect(lane({ promoteAfterDays: 0 })).toBe('trusted');
  });

  test('paid: a tier other than the free one, while the membership runs', () => {
    expect(isPaidMember({}, { isDefaultFree: true }, now)).toBe(false);
    expect(isPaidMember({}, null, now)).toBe(false);
    expect(isPaidMember({}, { isDefaultFree: false }, now)).toBe(true);
    expect(isPaidMember({ membershipExpiresAt: now + 1 }, { isDefaultFree: false }, now)).toBe(
      true,
    );
    expect(isPaidMember({ membershipExpiresAt: now }, { isDefaultFree: false }, now)).toBe(false);
  });

  test('the taint rule', () => {
    const relay = { lanes: { open: 1, trusted: 4 }, lanesSince: 50 };
    const fresh = { _creationTime: 60, resources: [{ ownership: 'fcp' }] };
    expect(mayBeTrusted(fresh, relay, false)).toBe(true);
    expect(mayBeTrusted(fresh, {}, false)).toBe(false);
    expect(mayBeTrusted({ ...fresh, _creationTime: 40 }, relay, false)).toBe(false);
    expect(mayBeTrusted({ ...fresh, _creationTime: 50 }, relay, false)).toBe(false);
    expect(mayBeTrusted({ ...fresh, publishedAt: 55 }, relay, false)).toBe(false);
    expect(mayBeTrusted({ ...fresh, resources: [{ ownership: 'adopted' }] }, relay, false)).toBe(
      false,
    );
    expect(mayBeTrusted(fresh, relay, true)).toBe(false);
  });

  test('which lane an address takes at its first publication', () => {
    const targets = { open: 1, trusted: 2 };
    const at = (o: Partial<Parameters<typeof laneAtPublish>[0]>) =>
      laneAtPublish({ mayBeTrusted: true, targets, inUse: { open: 1, trusted: 0 }, ...o });
    expect(at({})).toBe('trusted');
    expect(at({ inUse: { open: 0, trusted: 0 } })).toBe('open');
    expect(at({ inUse: { open: 1, trusted: 2 } })).toBe('open');
    expect(at({ replacing: 'open' })).toBe('open');
    expect(at({ replacing: 'trusted', inUse: { open: 1, trusted: 2 } })).toBe('trusted');
    expect(at({ mayBeTrusted: false, replacing: 'trusted' })).toBe('open');
  });

  test('the book, the pool size during a switch-on, and which open address leaves', () => {
    const targets = { open: 1, trusted: 2 };
    // Switch-on: three old addresses, all open now.
    const before: Array<{
      edgeId: string;
      listenerId: string;
      publishedAt: number;
      lane?: 'trusted';
    }> = [
      { edgeId: 'a', listenerId: 'l', publishedAt: 3 },
      { edgeId: 'b', listenerId: 'l', publishedAt: 1 },
      { edgeId: 'c', listenerId: 'l', publishedAt: 2 },
    ];
    const b0 = laneBook(['l'], before, targets);
    expect(b0.get('l')).toEqual({
      open: 3,
      trusted: 0,
      openDeficit: 0,
      trustedDeficit: 2,
      openExcess: 2,
    });
    expect(laneDesired(b0, targets)).toBe(5);
    expect(openToRetire(b0, before, new Set())).toBeNull();
    const filled = [
      ...before,
      { edgeId: 't1', listenerId: 'l', lane: 'trusted' as const, publishedAt: 9 },
      { edgeId: 't2', listenerId: 'l', lane: 'trusted' as const, publishedAt: 9 },
    ];
    const b1 = laneBook(['l'], filled, targets);
    // Oldest first, never the template address.
    expect(openToRetire(b1, filled, new Set())!.edgeId).toBe('b');
    expect(openToRetire(b1, filled, new Set(['b']))!.edgeId).toBe('c');
    const done = laneBook(
      ['l'],
      filled.filter((e) => e.edgeId === 'a' || e.lane),
      targets,
    );
    expect(laneDesired(done, targets)).toBe(3);
    expect(openToRetire(done, filled, new Set())).toBeNull();
  });
});
