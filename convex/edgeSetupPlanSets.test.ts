/**
 * What a chosen set of picks makes in the setup plan (`setOfPicks`, pure over
 * the plan): the targets of a fresh protection, the transports left with no
 * backup elsewhere, and what keeps a pick from being used. Fixtures only.
 */
import { describe, expect, test } from 'vitest';
import { refuseSet, setOfPicks } from './edgeSetupPlan';
import type { SetupPlanAccount, SetupPlanInbound } from './lib/edges/setupRuns';

const inbound = (listenerKey: string): SetupPlanInbound => ({
  listenerKey,
  sourceTag: listenerKey.toUpperCase(),
  listenerSpec: {},
  layers: ['l4'],
  frontable: true,
  formats: { links: true, singbox: true, clash: true },
  needsName: false,
});
const loc = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  label: `Region ${id}`,
  placeKey: id,
  isDefault: false,
  qualified: true,
  compatible: true,
  reasons: [],
  ...over,
});
const account = (
  id: string,
  provider: string,
  locations: ReturnType<typeof loc>[],
  carries: string[],
): SetupPlanAccount => ({
  id,
  name: id,
  provider,
  layer: 'l4',
  compatible: true,
  reasons: [],
  locations,
  carries,
});
const usage = (id: string, live = 0, max = 10, locs: Array<{ id: string }> = []) => ({
  id,
  live,
  maxLiveEdges: max,
  dailyAllocationBudget: 0,
  allocationsToday: 0,
  locations: locs.map((l) => ({ id: l.id, live: 0, maxLiveEdges: null })),
});

describe('setOfPicks', () => {
  const a = account('acct-a', 'acme', [loc('x1'), loc('x2')], ['main', 'ws']);
  const b = account('acct-b', 'globex', [loc('y1')], ['main']);
  const required = [inbound('main'), inbound('ws')];

  test('two providers: main gets both, ws its only carrier; every pick holds an address', () => {
    const set = setOfPicks(['x1', 'y1'], [a, b], required, [usage('acct-a'), usage('acct-b')]);
    expect(set.targets).toEqual(
      expect.arrayContaining([
        { listenerKey: 'main', locationId: 'x1' },
        { listenerKey: 'main', locationId: 'y1' },
        { listenerKey: 'ws', locationId: 'x1' },
      ]),
    );
    expect(set.targets).toHaveLength(3);
    // ws is carried by one provider only: no backup elsewhere for it.
    expect(set.reduced).toEqual([{ listenerKey: 'ws', reason: 'one_group' }]);
    expect(set.uncovered).toEqual([]);
    expect(() => refuseSet(set)).not.toThrow();
  });

  test('a transport no pick carries is refused; so is a pick over its account capacity', () => {
    const uncovered = setOfPicks(['y1'], [a, b], required, [usage('acct-b')]);
    expect(uncovered.uncovered).toEqual(['ws']);
    expect(() => refuseSet(uncovered)).toThrow(/set_uncovered_listener/);
    const full = setOfPicks(['x1', 'x2'], [a, b], required, [usage('acct-a', 9, 10)]);
    expect(full.problems).toContainEqual({ locationId: 'x1', reason: 'account_capacity_reached' });
    expect(() => refuseSet(full)).toThrow(/account_incompatible/);
  });

  test('a location picked twice, or more picks than a set holds, is refused', () => {
    expect(() => setOfPicks(['x1', 'x1'], [a, b], required, [])).toThrow(/picked twice/);
    expect(() =>
      setOfPicks(['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7'], [a, b], required, []),
    ).toThrow(/set_too_large/);
  });
});

describe('setOfPicks with a transport on a network (docs/edges.md "Networks")', () => {
  test('only a pick on the transport’s network carries it', () => {
    const scoped = { ...inbound('reality'), networkId: 'net-1' };
    const a = account('acct-a', 'acme', [loc('x1', { networkId: 'net-1' })], ['reality']);
    const b = account(
      'acct-b',
      'globex',
      [loc('y1', { networkId: 'net-2' }), loc('y2')],
      ['reality'],
    );
    const set = setOfPicks(
      ['x1', 'y1', 'y2'],
      [a, b],
      [scoped],
      [usage('acct-a'), usage('acct-b')],
    );
    expect(set.targets).toEqual([{ listenerKey: 'reality', locationId: 'x1' }]);
    // Off its network, no pick carries it at all.
    const none = setOfPicks(['y1', 'y2'], [a, b], [scoped], [usage('acct-b')]);
    expect(none.uncovered).toEqual(['reality']);
    // A transport on no network: carried as before.
    const plain = setOfPicks(['y1'], [a, b], [inbound('reality')], [usage('acct-b')]);
    expect(plain.targets).toEqual([{ listenerKey: 'reality', locationId: 'y1' }]);
  });
});
