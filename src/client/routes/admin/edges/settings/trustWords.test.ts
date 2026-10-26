import { describe, expect, test } from 'vitest';
import { trustCountsLine } from './trustWords';

describe('trustCountsLine', () => {
  test('counts only', () => {
    expect(
      trustCountsLine({
        suspected: 1,
        withStrikes: 3,
        strikesToday: 2,
        demotionsToday: 1,
        since: null,
      }),
    ).toBe(
      'Suspected now: 1 account (3 accounts with a strike). Today: 2 strikes, 1 account moved to open addresses.',
    );
    expect(
      trustCountsLine({
        suspected: 0,
        withStrikes: 0,
        strikesToday: 1,
        demotionsToday: 0,
        since: null,
      }),
    ).not.toMatch(/—/);
  });
});
