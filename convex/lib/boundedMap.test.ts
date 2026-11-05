import { describe, expect, test } from 'vitest';
import { mapBounded } from './boundedMap';

describe('mapBounded', () => {
  test('keeps input order and never runs more than the limit at once', async () => {
    let inFlight = 0;
    let most = 0;
    const out = await mapBounded([5, 1, 4, 2, 3, 0, 6], 3, async (n, i) => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise((r) => setTimeout(r, n));
      inFlight--;
      return `${i}:${n}`;
    });
    expect(out).toEqual(['0:5', '1:1', '2:4', '3:2', '4:3', '5:0', '6:6']);
    expect(most).toBe(3);
  });

  test('an empty list, and a limit below one still runs one at a time', async () => {
    expect(await mapBounded([], 4, async (x) => x)).toEqual([]);
    let inFlight = 0;
    let most = 0;
    await mapBounded([1, 2, 3], 0, async (x) => {
      inFlight++;
      most = Math.max(most, inFlight);
      await Promise.resolve();
      inFlight--;
      return x;
    });
    expect(most).toBe(1);
  });

  test('a failure rejects the whole map', async () => {
    await expect(
      mapBounded([1, 2], 2, async (x) => {
        if (x === 2) throw new Error('no');
        return x;
      }),
    ).rejects.toThrow('no');
  });
});
