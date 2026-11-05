import { describe, expect, test } from 'vitest';
import {
  bodyGroups,
  countDeficit,
  coverTargets,
  coverageDeficit,
  groupOf,
  keepsCounts,
  resilienceExpectation,
  removableUnder,
  requirementOf,
  type PublishedRef,
  type Requirement,
  type SetListener,
  type SetPick,
} from './providerSet';

const pick = (id: string, provider: string, place = id): SetPick => ({
  locationId: id,
  provider,
  locationKey: `${provider}:${place}`,
});
const pub = (listenerKey: string, p: SetPick | null): PublishedRef => ({
  listenerKey,
  locationId: p?.locationId ?? null,
  provider: p?.provider ?? null,
  locationKey: p?.locationKey ?? null,
});

const X = pick('x', 'acme');
const Y = pick('y', 'globex');
const Y2 = pick('y2', 'globex', 'y-two');
const Z = pick('z', 'initech');

describe('requirementOf', () => {
  test('groups are providers; one provider among the carriers groups by location', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['y', 'y2'] },
        { listenerKey: 'c', carriers: ['x'] },
      ],
      [X, Y, Y2],
    );
    const [a, b, c] = req.listeners;
    expect(a!.groupBy).toBe('provider');
    expect([...a!.groups.keys()]).toEqual(['acme', 'globex']);
    expect(a!.required).toBe(2);
    expect(b!.groupBy).toBe('location');
    expect([...b!.groups.keys()]).toEqual(['globex:y', 'globex:y-two']);
    expect(b!.required).toBe(2);
    expect(c!.required).toBe(1);
    expect(req.reduced).toEqual([{ listenerKey: 'c', reason: 'one_group' }]);
    expect(req.picks).toEqual(['x', 'y', 'y2']);
  });

  test('a cooling pick does not count toward G and is not a pick demand; only-cooling is reported', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['y'] },
      ],
      [X, Y],
      new Set(['y']),
    );
    expect(req.listeners[0]!.required).toBe(1);
    expect(req.listeners[1]!.coolingOnly).toBe(true);
    expect(req.coolingOnly).toEqual(['b']);
    expect(req.picks).toEqual(['x']);
    // Reduced is about the set, not about what cools right now.
    expect(req.reduced.map((r) => r.listenerKey)).toEqual(['b']);
    // A cooling-only shortfall is not part of the deficit.
    expect(coverTargets(req, [])).toEqual([
      { listenerKey: 'a', locationId: 'x', coversListener: true },
    ]);
  });

  test('without a set: basic coverage from any location', () => {
    const req = requirementOf([{ listenerKey: 'a', carriers: [] }], null);
    expect(coverTargets(req, [])).toEqual([
      { listenerKey: 'a', locationId: null, coversListener: true },
    ]);
    expect(coverageDeficit(req, [pub('a', null)])).toBe(0);
  });

  test('a listener no pick carries still needs basic coverage, reported as uncarried', () => {
    const req = requirementOf([{ listenerKey: 'a', carriers: [] }], [X]);
    expect(req.uncarried).toEqual(['a']);
    expect(coverTargets(req, [])).toEqual([
      { listenerKey: 'a', locationId: null, coversListener: true },
    ]);
  });
});

describe('coverTargets', () => {
  test('two listeners on two picks of two providers: two targets do double duty', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['x', 'y'] },
      ],
      [X, Y],
    );
    const t = coverTargets(req, []);
    // Each listener needs both providers: four targets, every pick covered by them.
    expect(t).toHaveLength(4);
    expect(new Set(t.map((x) => `${x.listenerKey}@${x.locationId}`))).toEqual(
      new Set(['a@x', 'a@y', 'b@x', 'b@y']),
    );
  });

  test('a pick that adds no group still gets one address, published after the listener targets', () => {
    const req = requirementOf([{ listenerKey: 'a', carriers: ['x', 'y', 'z'] }], [X, Y, Z]);
    const t = coverTargets(req, []);
    expect(t).toHaveLength(3);
    expect(t.filter((x) => x.coversListener)).toHaveLength(2);
    expect(t.at(-1)!.coversListener).toBe(false);
  });

  test('what is published counts: a node live on X needs Y only', () => {
    const req = requirementOf([{ listenerKey: 'a', carriers: ['x', 'y'] }], [X, Y]);
    expect(coverTargets(req, [pub('a', X)])).toEqual([
      { listenerKey: 'a', locationId: 'y', coversListener: true },
    ]);
  });

  test('the matching beats a greedy pick (a listener with two groups yields its shared pick)', () => {
    // a can use x (acme) or y (globex); b only y. One unit each, picks x and y both unpublished.
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['y'] },
      ],
      [X, Y],
    );
    const t = coverTargets(req, [pub('a', Y)]);
    // a still needs acme (x); b needs any (y); both picks covered by those two.
    expect(t).toHaveLength(2);
  });

  test('matches brute force on random small instances', () => {
    let seed = 7;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const pool = [X, Y, Y2, Z];
    for (let round = 0; round < 300; round++) {
      const picks = pool.filter(() => rnd() < 0.7);
      if (picks.length === 0) continue;
      const listeners: SetListener[] = ['a', 'b', 'c']
        .slice(0, 1 + Math.floor(rnd() * 3))
        .map((k) => ({
          listenerKey: k,
          carriers: picks.filter(() => rnd() < 0.7).map((p) => p.locationId),
        }));
      const cooling = new Set(picks.filter(() => rnd() < 0.15).map((p) => p.locationId));
      const published: PublishedRef[] = [];
      for (const l of listeners)
        for (const id of l.carriers)
          if (rnd() < 0.2)
            published.push(
              pub(
                l.listenerKey,
                picks.find((p) => p.locationId === id)!,
              ),
            );
      const req = requirementOf(listeners, picks, cooling);
      const got = coverTargets(req, published);
      const ctx = JSON.stringify({ picks, listeners, cooling: [...cooling], published, got });
      expect(satisfied(req, published, got), ctx).toBe(true);
      expect(got.length, ctx).toBe(bruteForce(req, published));
    }
  });
});

describe('removableUnder', () => {
  const full = [pub('a', X), pub('a', Y), pub('b', X), pub('b', Y)];

  test('A on X and Y, B on X and Y with both listeners needing two groups: nothing is removable', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['x', 'y'] },
      ],
      [X, Y],
    );
    expect(full.map((_, i) => removableUnder(req, full, i))).toEqual([false, false, false, false]);
  });

  test('the same pool where each listener needs one group: two edges go, one at a time', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x'] },
        { listenerKey: 'b', carriers: ['y'] },
      ],
      [X, Y],
    );
    // Rebalance takes the highest removable index each time, until none is left.
    let pool = [...full];
    let removed = 0;
    for (;;) {
      const i = [...pool.keys()].reverse().find((k) => removableUnder(req, pool, k));
      if (i === undefined) break;
      pool = pool.filter((_, k) => k !== i);
      removed++;
    }
    expect(removed).toBe(2);
    expect(coverageDeficit(req, pool)).toBe(0);
  });

  test('removing a redundant copy is allowed while another listener is short (the deficit does not grow)', () => {
    const req = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x'] },
        { listenerKey: 'b', carriers: ['x'] },
      ],
      [X],
    );
    const pool = [pub('a', X), pub('a', X)];
    expect(coverageDeficit(req, pool)).toBe(1);
    expect(removableUnder(req, pool, 1)).toBe(true);
  });
});

// --- brute force -----------------------------------------------------------------------------------

function liveGroups(req: Requirement, key: string): Set<string> {
  return new Set(req.listeners.find((l) => l.listenerKey === key)!.groups.keys());
}

function satisfied(
  req: Requirement,
  published: readonly PublishedRef[],
  targets: ReadonlyArray<{ listenerKey: string; locationId: string | null }>,
): boolean {
  const pickOf = (id: string | null) => {
    for (const l of req.listeners)
      for (const [g, ps] of l.groups) if (id && ps.includes(id)) return { l, g };
    return null;
  };
  for (const l of req.listeners) {
    const have = new Set(
      published
        .filter((p) => p.listenerKey === l.listenerKey)
        .map((p) => groupOf(l.groupBy, p))
        .filter((g): g is string => g !== null),
    );
    const after = new Set(have);
    for (const t of targets) {
      if (t.listenerKey !== l.listenerKey || !t.locationId) continue;
      const g = [...l.groups.entries()].find(([, ps]) => ps.includes(t.locationId!))?.[0];
      if (g) after.add(g);
    }
    const reachable = new Set([...have, ...liveGroups(req, l.listenerKey)]);
    if (after.size < Math.min(l.required, reachable.size)) return false;
  }
  for (const p of req.picks) {
    const covered =
      published.some((x) => x.locationId === p) || targets.some((t) => t.locationId === p);
    if (!covered && pickOf(p)) return false;
  }
  return true;
}

function bruteForce(req: Requirement, published: readonly PublishedRef[]): number {
  const pairs: Array<{ listenerKey: string; locationId: string }> = [];
  for (const l of req.listeners)
    for (const ps of l.groups.values())
      for (const p of ps) pairs.push({ listenerKey: l.listenerKey, locationId: p });
  let best = Infinity;
  for (let mask = 0; mask < 1 << pairs.length; mask++) {
    const chosen = pairs.filter((_, i) => mask & (1 << i));
    if (chosen.length >= best) continue;
    if (satisfied(req, published, chosen)) best = chosen.length;
  }
  // A listener no pick carries asks for one address from anywhere.
  return (
    best +
    req.listeners.filter(
      (l) => l.uncarried && !published.some((p) => p.listenerKey === l.listenerKey),
    ).length
  );
}

describe('resilienceExpectation and bodyGroups', () => {
  const on = {
    style: 'subscription' as const,
    includeBackup: true,
    maxEntries: 0,
    preferDistinct: true,
    groupsOffered: 2,
  };
  test('a backup in another group is expected only under the effective rule', () => {
    expect(resilienceExpectation(on)).toEqual({ on: true });
    expect(resilienceExpectation({ ...on, style: 'single-key' })).toEqual({
      on: false,
      reason: 'single_key',
    });
    expect(resilienceExpectation({ ...on, includeBackup: false })).toEqual({
      on: false,
      reason: 'backup_disabled',
    });
    expect(resilienceExpectation({ ...on, maxEntries: 1 })).toEqual({
      on: false,
      reason: 'max_entries',
    });
    expect(resilienceExpectation({ ...on, maxEntries: 2 })).toEqual({ on: true });
    expect(resilienceExpectation({ ...on, preferDistinct: false })).toEqual({
      on: false,
      reason: 'distinct_off',
    });
    expect(resilienceExpectation({ ...on, groupsOffered: 1 })).toEqual({
      on: false,
      reason: 'one_group',
    });
  });

  test('groups are providers among the body listeners, or locations of one provider', () => {
    const edges = [
      { listenerKey: 'a', provider: 'acme', locationKey: 'acme:1' },
      { listenerKey: 'a', provider: 'acme', locationKey: 'acme:2' },
      { listenerKey: 'b', provider: 'globex', locationKey: 'globex:1' },
      { listenerKey: 'b', provider: 'initech', locationKey: 'initech:1', eligible: false },
    ];
    expect(bodyGroups(edges, ['a']).count).toBe(2);
    expect(bodyGroups(edges, ['a']).groupOf(edges[0]!)).toBe('acme:1');
    expect(bodyGroups(edges, ['a', 'b']).count).toBe(2);
    expect(bodyGroups(edges, ['a', 'b']).groupOf(edges[0]!)).toBe('acme');
    expect(bodyGroups(edges, ['b']).count).toBe(1);
  });
});

describe('addresses per location (a pick count)', () => {
  const both: SetListener[] = [
    { listenerKey: 'a', carriers: ['x', 'y'] },
    { listenerKey: 'b', carriers: ['x', 'y'] },
  ];
  const counted = (want: number | undefined, at = X) => [{ ...at, want }, Y];

  test('without a count the targets are exactly the ones before', () => {
    const plain = requirementOf(both, [X, Y]);
    const absent = requirementOf(both, counted(undefined));
    expect(absent.wants).toEqual([]);
    for (const published of [[], [pub('a', X)], [pub('a', X), pub('b', Y)]])
      expect(coverTargets(absent, published)).toEqual(coverTargets(plain, published));
  });

  test('a count asks for that many of each transport the pick carries, after the cover', () => {
    const req = requirementOf(both, counted(2));
    expect(req.wants).toEqual([{ locationId: 'x', want: 2, listenerKeys: ['a', 'b'] }]);
    const published = [pub('a', X), pub('b', Y)];
    const plain = coverTargets(requirementOf(both, [X, Y]), published);
    const targets = coverTargets(req, published);
    // The cover first, unchanged (it already puts one `b` at x for diversity);
    // then the count: one more `a` and one more `b` at x.
    expect(targets.slice(0, plain.length)).toEqual(plain);
    expect(plain).toContainEqual({ listenerKey: 'b', locationId: 'x', coversListener: true });
    expect(targets.slice(plain.length)).toEqual([
      { listenerKey: 'a', locationId: 'x', coversListener: false, count: true },
      { listenerKey: 'b', locationId: 'x', coversListener: false, count: true },
    ]);
    // Met: no count target is left, and the deficit is what the plain cover says.
    const met = [...published, pub('a', X), pub('b', X), pub('b', X)];
    expect(coverTargets(req, met).filter((t) => t.count)).toEqual([]);
  });

  test('targets the cover already puts at the pick count toward it', () => {
    const req = requirementOf(both, counted(1));
    // Nothing published: the cover asks for `a` and `b` somewhere, one of them at x.
    const targets = coverTargets(req, []);
    for (const key of ['a', 'b'])
      expect(targets.filter((t) => t.listenerKey === key && t.locationId === 'x').length).toBe(1);
  });

  test('a cooling pick asks for nothing; a transport the pick does not carry is not counted', () => {
    expect(requirementOf(both, counted(3), new Set(['x'])).wants).toEqual([]);
    const narrow = requirementOf(
      [
        { listenerKey: 'a', carriers: ['x', 'y'] },
        { listenerKey: 'b', carriers: ['y'] },
      ],
      counted(2),
    );
    expect(narrow.wants).toEqual([{ locationId: 'x', want: 2, listenerKeys: ['a'] }]);
  });

  test('out-of-range counts are none', () => {
    for (const want of [0, 9, 1.5, -1])
      expect(requirementOf(both, counted(want)).wants).toEqual([]);
  });

  test('lane cleanup keeps what a count needs; rebalance too', () => {
    const req = requirementOf(both, counted(2));
    const published = [
      pub('a', X),
      pub('a', X),
      pub('b', X),
      pub('b', X),
      pub('a', Y),
      pub('b', Y),
    ];
    expect(countDeficit(req, published)).toBe(0);
    // An address at x is counted: removing it raises the count deficit.
    expect(keepsCounts(req, published, 0)).toBe(false);
    expect(removableUnder(req, published, 0)).toBe(false);
    // One more than the count at x is free to go.
    const extra = [...published, pub('a', X)];
    expect(keepsCounts(req, extra, 6)).toBe(true);
    // Without counts nothing is held.
    expect(keepsCounts(requirementOf(both, [X, Y]), published, 0)).toBe(true);
    // A count of one: the location's only address of a transport is kept, though
    // the cover would name its gap as a pick target rather than a count one.
    const one = requirementOf(both, counted(1));
    const single = [pub('a', X), pub('b', X), pub('a', Y), pub('b', Y)];
    expect(keepsCounts(one, single, 0)).toBe(false);
    expect(keepsCounts(one, [...single, pub('a', X)], 0)).toBe(true);
  });
});

describe('addresses only for some countries in the requirement', () => {
  const both: SetListener[] = [{ listenerKey: 'a', carriers: ['x', 'y'] }];
  const onlyX = { ...X, onlyCodes: ['IR'] };
  const contained = (p: SetPick, audience: string[]): PublishedRef => ({
    ...pub('a', p),
    audience,
  });

  test('an only location is no carrier of coverage or diversity, and asks for nothing without a count', () => {
    const req = requirementOf(both, [onlyX, Y]);
    expect(req.picks).toEqual(['y']);
    expect(req.listeners[0]!.required).toBe(1);
    // A contained address covers nobody: the transport still needs one for everyone.
    expect(coverTargets(req, [contained(onlyX, ['IR'])])).toEqual([
      { listenerKey: 'a', locationId: 'y', coversListener: true },
    ]);
  });

  test('its count counts the addresses contained there, an out-of-date one too', () => {
    const req = requirementOf(both, [{ ...onlyX, want: 2 }, Y]);
    // One current, one out of date: it holds its place until it is renewed in
    // its own slot, so nothing more is asked for (the pool never grows for it).
    const published = [pub('a', Y), contained(onlyX, ['IR']), contained(onlyX, ['IR', 'RU'])];
    expect(coverTargets(req, published).filter((t) => t.count)).toEqual([]);
    expect(keepsCounts(req, published, 1)).toBe(false);
    expect(keepsCounts(req, published, 2)).toBe(false);
    // An address there for everyone (in use before the switch) does not count.
    const withEveryone = [pub('a', Y), contained(onlyX, ['IR']), pub('a', onlyX)];
    expect(coverTargets(req, withEveryone).filter((t) => t.count)).toEqual([
      { listenerKey: 'a', locationId: 'x', coversListener: false, count: true },
    ]);
  });
});
