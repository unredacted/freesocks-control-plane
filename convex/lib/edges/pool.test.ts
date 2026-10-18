import { describe, expect, test } from 'vitest';
import {
  allocatePoolIndex,
  coverageListeners,
  freeSlotCount,
  nextFreePoolIndex,
  uncoveredListeners,
  withEdgeAt,
  withoutEdge,
  type PoolListener,
} from './pool';

const L = (id: string, over: Partial<PoolListener> = {}): PoolListener => ({
  id,
  templateEdgeId: null,
  deployed: true,
  enabled: true,
  retired: false,
  ...over,
});

describe('pool: free slots and coverage', () => {
  test('freeSlotCount counts gaps and missing tail slots under desired only', () => {
    expect(freeSlotCount([], 2)).toBe(2);
    expect(freeSlotCount(['e1'], 2)).toBe(1);
    expect(freeSlotCount(['e1', null, 'e3'], 2)).toBe(1);
    expect(freeSlotCount(['e1', 'e2', 'e3'], 2)).toBe(0);
    expect(nextFreePoolIndex(['e1', null, 'e3'], 3)).toBe(1);
  });

  test('coverage excludes undeployed, disabled and retired listeners; uncovered = no template edge', () => {
    const rows = [
      L('a', { templateEdgeId: 'e1' }),
      L('b'),
      L('c', { deployed: false }),
      L('d', { enabled: false }),
      L('e', { retired: true }),
    ];
    expect(coverageListeners(rows).map((l) => l.id)).toEqual(['a', 'b']);
    expect(uncoveredListeners(rows).map((l) => l.id)).toEqual(['b']);
  });
});

describe('allocatePoolIndex: reserved allocation', () => {
  const lowers = { lowersDeficit: true, deficit: 1 };
  const extra = { lowersDeficit: false, deficit: 1 };

  test('an edge that lowers the deficit always takes the lowest free index', () => {
    expect(allocatePoolIndex(['e1'], 2, lowers)).toEqual({ index: 1 });
  });

  test('any other edge is refused while the free slots are held for the deficit', () => {
    // One free slot, a deficit of one: an extra copy may not take it.
    expect(allocatePoolIndex(['e1'], 2, extra)).toEqual({ refused: 'pool_reserved' });
    // Two free slots, a deficit of one: it may take one.
    expect(allocatePoolIndex(['e1'], 3, extra)).toEqual({ index: 1 });
  });

  test('no free slot at all is pool_full, whatever the edge', () => {
    expect(allocatePoolIndex(['e1', 'e2'], 2, lowers)).toEqual({ refused: 'pool_full' });
    expect(allocatePoolIndex(['e1', 'e2'], 2, extra)).toEqual({ refused: 'pool_full' });
  });

  test('with no deficit the pool behaves as before', () => {
    const none = { lowersDeficit: false, deficit: 0 };
    expect(allocatePoolIndex(['e1', 'e2'], 4, none)).toEqual({ index: 2 });
    expect(allocatePoolIndex(['e1', null, 'e2'], 4, none)).toEqual({ index: 1 });
  });

  test('pool helpers round-trip an edge in and out of a slot', () => {
    const p = withEdgeAt<string>([], 2, 'e3');
    expect(p).toEqual([null, null, 'e3']);
    expect(withoutEdge(p, 'e3')).toEqual([]);
  });
});
