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
  test('an uncovered listener always takes the lowest free index', () => {
    const rows = [L('a', { templateEdgeId: 'e1' }), L('b')];
    expect(allocatePoolIndex(['e1'], 2, 'b', rows)).toEqual({ index: 1 });
  });

  test('an extra copy for a covered listener is refused while free slots are reserved', () => {
    const rows = [L('a', { templateEdgeId: 'e1' }), L('b')];
    // One free slot, one uncovered listener: A may not take it.
    expect(allocatePoolIndex(['e1'], 2, 'a', rows)).toEqual({ refused: 'pool_reserved' });
    // Two free slots, one uncovered: A may take one.
    expect(allocatePoolIndex(['e1'], 3, 'a', rows)).toEqual({ index: 1 });
  });

  test('no free slot at all is pool_full, whatever the listener', () => {
    const rows = [L('a', { templateEdgeId: 'e1' }), L('b')];
    expect(allocatePoolIndex(['e1', 'e2'], 2, 'b', rows)).toEqual({ refused: 'pool_full' });
    expect(allocatePoolIndex(['e1', 'e2'], 2, 'a', rows)).toEqual({ refused: 'pool_full' });
  });

  test('a listener that is not a coverage listener (disabled) is treated as covered', () => {
    const rows = [L('a', { templateEdgeId: 'e1' }), L('b'), L('c', { enabled: false })];
    expect(allocatePoolIndex(['e1'], 2, 'c', rows)).toEqual({ refused: 'pool_reserved' });
  });

  test('with every listener covered the pool behaves as before', () => {
    const rows = [L('a', { templateEdgeId: 'e1' }), L('b', { templateEdgeId: 'e2' })];
    expect(allocatePoolIndex(['e1', 'e2'], 4, 'a', rows)).toEqual({ index: 2 });
    expect(allocatePoolIndex(['e1', null, 'e2'], 4, 'b', rows)).toEqual({ index: 1 });
  });

  test('pool helpers round-trip an edge in and out of a slot', () => {
    const p = withEdgeAt<string>([], 2, 'e3');
    expect(p).toEqual([null, null, 'e3']);
    expect(withoutEdge(p, 'e3')).toEqual([]);
  });
});
