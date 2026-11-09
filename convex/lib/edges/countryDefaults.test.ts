/**
 * A country's default picks, the pure planner (lib/edges/countryDefaults.ts):
 * what it writes on a node, what it leaves alone, and what it takes away.
 */
import { describe, expect, test } from 'vitest';
import { defaultsPlan, handCodesOf, type DefaultsPick } from './countryDefaults';

const NOW = 5_000;
const IR = { codes: ['IR'], picks: [{ locationId: 'L1', want: 1 }, { locationId: 'L2' }] };
const plan = (
  providerSet: DefaultsPick[],
  over: Partial<Parameters<typeof defaultsPlan>[0]> = {},
) =>
  defaultsPlan({
    providerSet,
    defaults: [IR],
    optOut: [],
    carries: () => true,
    liveAt: () => false,
    now: NOW,
    ...over,
  });

describe('writing the defaults on a node', () => {
  test('an entry on a location the node picks; a pick serving them only where it does not', () => {
    const out = plan([{ locationId: 'L1', addedAt: 1 }]);
    expect(out.changed).toBe(true);
    expect(out.added).toEqual(['IR']);
    expect(out.providerSet).toEqual([
      {
        locationId: 'L1',
        addedAt: 1,
        audiences: [{ codes: ['IR'], want: 1, addedAt: NOW, fromDefault: true }],
      },
      {
        locationId: 'L2',
        addedAt: NOW,
        audiences: [{ codes: ['IR'], addedAt: NOW, fromDefault: true }],
        audienceOnly: true,
        fromDefault: true,
      },
    ]);
  });

  test('written once: the same set again is no change, whatever its key order', () => {
    const once = plan([{ locationId: 'L1', addedAt: 1 }]).providerSet;
    const reordered = once.map((p) =>
      Object.fromEntries(Object.entries(p).reverse()),
    ) as DefaultsPick[];
    expect(plan(reordered).changed).toBe(false);
  });

  test('only locations carrying one of its freedom transports', () => {
    const out = plan([], { carries: (id) => id === 'L2' });
    expect(out.providerSet.map((p) => p.locationId)).toEqual(['L2']);
  });

  test("a country it keeps by hand, or opted out of, is the node's own", () => {
    const hand: DefaultsPick[] = [
      { locationId: 'L9', addedAt: 1, audiences: [{ codes: ['IR', 'RU'], want: 2, addedAt: 1 }] },
    ];
    expect(handCodesOf(hand)).toEqual(['IR', 'RU']);
    expect(plan(hand).changed).toBe(false);
    expect(plan([], { optOut: ['IR'] }).changed).toBe(false);
  });

  test('a count changed follows; a default removed takes its entries and the pick it added away', () => {
    const once = plan([{ locationId: 'L1', addedAt: 1 }]).providerSet;
    const more = plan(once, {
      defaults: [{ codes: ['IR'], picks: [{ locationId: 'L1', want: 2 }, { locationId: 'L2' }] }],
    });
    expect(more.providerSet[0]!.audiences).toEqual([
      { codes: ['IR'], want: 2, addedAt: NOW, fromDefault: true },
    ]);
    const gone = plan(once, { defaults: [] });
    expect(gone.removed).toEqual(['IR']);
    expect(gone.providerSet).toEqual([{ locationId: 'L1', addedAt: 1 }]);
  });

  test('a pick it added stays while an address is live there, serving them only', () => {
    const once = plan([]).providerSet;
    const gone = plan(once, { defaults: [], liveAt: (id) => id === 'L2' });
    expect(gone.providerSet).toEqual([
      { locationId: 'L2', addedAt: NOW, audienceOnly: true, fromDefault: true },
    ]);
  });

  test("the node's own entries stay as they are", () => {
    const set: DefaultsPick[] = [
      { locationId: 'L1', addedAt: 1, audiences: [{ codes: ['RU'], want: 1, addedAt: 2 }] },
    ];
    const out = plan(set);
    expect(out.providerSet[0]!.audiences).toEqual([
      { codes: ['RU'], want: 1, addedAt: 2 },
      { codes: ['IR'], want: 1, addedAt: NOW, fromDefault: true },
    ]);
  });
});
