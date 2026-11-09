/**
 * A country on its own addresses, the pure half (lib/edges/ownPools.ts, the
 * assignment's `ownPool`, the detector's `own_pool` veto): who is handed what,
 * the budget's inheritance and count, the rehearsal.
 */
import { describe, expect, test } from 'vitest';
import { assignEndpoints, type AssignOptions, type PublishedEdge } from './assignment';
import type { ListenerProto } from './protocols';
import { steeringVeto } from './scoring';
import {
  cutoverRehearsal,
  isOwnAddress,
  ownBudgetKey,
  ownBudgetPerDay,
  ownCodesOf,
  ownReplacesToday,
  settledOwnCodes,
  withOwnReplace,
} from './ownPools';

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };

const edge = (id: string, i: number, over: Partial<PublishedEdge> = {}): PublishedEdge => ({
  edgeId: id,
  poolIndex: i,
  provider: 'p1',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'r' },
  edgePort: 443,
  layer: 'l4',
  addresses: { v4: `203.0.113.${i + 1}` },
  proto: REALITY,
  serverNames: ['a.example', 'b.example'].map((sni) => ({ sni, status: 'active' as const })),
  ...over,
});

const base: AssignOptions = {
  now: 1,
  preferDistinctProviders: true,
  includeBackup: true,
  edgePick: 'hrw1',
  edgeCountry: 'IR',
};
const seats = Array.from({ length: 200 }, (_, i) => `${(i * 2654435761) >>> 0}`.padStart(16, '0'));
const handed = (pool: PublishedEdge[], opts: AssignOptions) =>
  seats.map((s) => {
    const a = assignEndpoints(s, pool, opts);
    return [a.primary?.edge.edgeId ?? null, a.backup?.edge.edgeId ?? null] as const;
  });

describe('who a cut-over country is handed', () => {
  test('two of its own (CDN fronts): both, for the primary and the backup, over another provider', () => {
    // Shared ones on another provider would win the backup today (another failure domain).
    const pool = [
      edge('s0', 0, { provider: 'p2' }),
      edge('s1', 1, { provider: 'p2' }),
      edge('i0', 2, { audience: ['IR'], meantFor: ['IR'] }),
      edge('i1', 3, { audience: ['IR'], meantFor: ['IR'] }),
    ];
    const today = handed(pool, base);
    expect(today.every(([p, b]) => p?.startsWith('i') && b?.startsWith('s'))).toBe(true);
    const own = handed(pool, { ...base, ownPool: true });
    expect(own.every(([p, b]) => p?.startsWith('i') && b?.startsWith('i') && p !== b)).toBe(true);
  });

  test('one of its own (a load balancer): it first, a shared one as the backup', () => {
    const pool = [
      edge('s0', 0),
      edge('s1', 1),
      edge('i0', 2, { audience: ['IR'], meantFor: ['IR'] }),
    ];
    for (const [p, b] of handed(pool, { ...base, ownPool: true })) {
      expect(p).toBe('i0');
      expect(b?.startsWith('s')).toBe(true);
    }
  });

  test('its own blocked there: a shared one first (the fallback)', () => {
    const pool = [
      edge('s0', 0),
      edge('s1', 1),
      edge('i0', 2, { audience: ['IR'], meantFor: ['IR'], blockedIn: ['IR'] }),
    ];
    for (const [p] of handed(pool, { ...base, ownPool: true }))
      expect(p?.startsWith('s')).toBe(true);
  });

  test('another country, or no cutover: exactly as before', () => {
    const pool = [
      edge('s0', 0),
      edge('s1', 1),
      edge('i0', 2, { audience: ['IR'], meantFor: ['IR'] }),
    ];
    const ru = { ...base, edgeCountry: 'RU' };
    expect(handed(pool, { ...ru, ownPool: true })).toEqual(handed(pool, ru));
    expect(handed(pool, { ...base, ownPool: false })).toEqual(handed(pool, base));
  });
});

describe("the detector's veto for a shared address", () => {
  const paths = [{ format: 'links' as const, canEmitV6: false }];
  const steering = (published: PublishedEdge[], own?: string[]) => ({
    published,
    paths,
    checked: ['IR', 'RU'],
    curated: ['IR', 'RU'],
    held: [],
    freedomListeners: ['a1'],
    ...(own ? { own } : {}),
  });
  const shared = edge('s0', 0, { blockedIn: ['IR', 'RU'] });

  test('evidence only from a country on its own addresses here: never replaced', () => {
    expect(
      steeringVeto({ edgeId: 's0', countries: ['IR'] }, steering([shared, edge('s1', 1)], ['IR'])),
    ).toBe('own_pool');
  });

  test('mixed evidence judges the rest; none of it settled, as before', () => {
    // Russia is blocked on every shared address: nothing routes around it there.
    const blockedEverywhere = [shared, edge('s1', 1, { blockedIn: ['RU'] })];
    expect(
      steeringVeto({ edgeId: 's0', countries: ['IR', 'RU'] }, steering(blockedEverywhere, ['IR'])),
    ).toBeNull();
    const onlyIr = edge('s0', 0, { blockedIn: ['IR'] });
    expect(
      steeringVeto({ edgeId: 's0', countries: ['IR'] }, steering([onlyIr, edge('s1', 1)])),
    ).toBe('country_scoped');
    // Evidence naming no country (down everywhere) still replaces it.
    expect(steeringVeto({ edgeId: 's0', countries: [] }, steering([shared], ['IR']))).toBeNull();
  });

  test("a country's own address is never vetoed for its own country", () => {
    const own = edge('i0', 0, { audience: ['IR'], blockedIn: ['IR'] });
    expect(
      steeringVeto({ edgeId: 'i0', countries: ['IR'] }, steering([own, edge('s1', 1)], ['IR'])),
    ).toBeNull();
  });
});

describe('the budget', () => {
  const cfg = { replacesPerDay: 1, replacesPerDayByCountry: { RU: 3, BY: 2 } };

  test("the node's value, else the strictest of its countries', else the fleet's", () => {
    expect(ownBudgetPerDay({}, ['IR'], cfg)).toBe(1);
    expect(ownBudgetPerDay({}, ['RU'], cfg)).toBe(3);
    expect(ownBudgetPerDay({}, ['RU', 'BY'], cfg)).toBe(2);
    expect(ownBudgetPerDay({ audienceReplacesPerDay: 0 }, ['RU'], cfg)).toBe(0);
  });

  test('counted per countries and transport, per UTC day', () => {
    const key = ownBudgetKey(['RU', 'IR', 'IR'], 'l1');
    expect(key).toBe('IR RU|l1');
    let o: { audienceReplaces?: Array<{ key: string; day: string; count: number }> } = {};
    o = { audienceReplaces: withOwnReplace(o, key, '2026-11-09') };
    o = { audienceReplaces: withOwnReplace(o, key, '2026-11-09') };
    o = { audienceReplaces: withOwnReplace(o, 'IR|l2', '2026-11-09') };
    expect(ownReplacesToday(o, key, '2026-11-09')).toBe(2);
    expect(ownReplacesToday(o, 'IR|l2', '2026-11-09')).toBe(1);
    // Yesterday's counts go with the next one.
    o = { audienceReplaces: withOwnReplace(o, key, '2026-11-10') };
    expect(o.audienceReplaces).toEqual([{ key, day: '2026-11-10', count: 1 }]);
  });

  test('cut over, settled, and which addresses are theirs', () => {
    const o = {
      ownPools: [
        { code: 'IR', since: 1_000 },
        { code: 'RU', since: 9_000 },
      ],
    };
    expect(ownCodesOf(o)).toEqual(['IR', 'RU']);
    expect(settledOwnCodes(o, 5_000, 10_000)).toEqual(['IR']);
    expect(isOwnAddress({ audience: ['IR', 'BY'] }, ['IR'])).toBe(true);
    expect(isOwnAddress({ audience: ['BY'] }, ['IR'])).toBe(false);
    expect(isOwnAddress({}, ['IR'])).toBe(false);
  });
});

describe('the rehearsal', () => {
  test('says how many seats move and how many keep a shared address', () => {
    const pool = [
      edge('s0', 0, { provider: 'p2' }),
      edge('s1', 1, { provider: 'p2' }),
      edge('i0', 2, { audience: ['IR'], meantFor: ['IR'] }),
      edge('i1', 3, { audience: ['IR'], meantFor: ['IR'] }),
    ];
    const r = cutoverRehearsal(
      pool,
      'IR',
      { now: 1, preferDistinctProviders: true, includeBackup: true, edgePick: 'hrw1' },
      100,
    );
    expect(r).toEqual({ sampled: 100, moved: 100, sharedBefore: 100, sharedAfter: 0 });
    // One of its own: the backup stays shared, nothing moves.
    const one = cutoverRehearsal(
      pool.slice(0, 3),
      'IR',
      { now: 1, preferDistinctProviders: true, includeBackup: true, edgePick: 'hrw1' },
      100,
    );
    expect(one).toMatchObject({ sampled: 100, moved: 0, sharedAfter: 100 });
  });
});
