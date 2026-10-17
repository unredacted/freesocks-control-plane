import { describe, expect, it } from 'vitest';
import { collapseRepeats } from './collapseRepeats';

describe('collapseRepeats', () => {
  it('folds neighbours with the same key and keeps the order of events', () => {
    const out = collapseRepeats(['a1', 'a2', 'a3', 'b1', 'a4'], (s) => s[0]!);
    expect(out.map((g) => [g.item, g.last, g.count])).toEqual([
      ['a1', 'a3', 3],
      ['b1', 'b1', 1],
      ['a4', 'a4', 1],
    ]);
  });
  it('never folds an entry whose key is null', () => {
    const out = collapseRepeats(['x', 'x', 'x'], () => null);
    expect(out.map((g) => g.count)).toEqual([1, 1, 1]);
  });
  it('an empty list stays empty', () => {
    expect(collapseRepeats([], () => 'k')).toEqual([]);
  });
});
