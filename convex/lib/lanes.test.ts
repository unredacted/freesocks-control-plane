import { describe, expect, test } from 'vitest';
import { inLanes } from './lanes';

const tick = () => new Promise<void>((r) => setTimeout(r, 1));

describe('inLanes', () => {
  test('never more than the lanes in flight, every item once, in order of start', async () => {
    let inFlight = 0;
    let most = 0;
    const started: number[] = [];
    const items = Array.from({ length: 9 }, (_, i) => i);
    const res = await inLanes(items, 3, async (i) => {
      started.push(i);
      inFlight++;
      most = Math.max(most, inFlight);
      await tick();
      inFlight--;
    });
    expect(most).toBe(3);
    expect(started).toEqual(items);
    expect(res).toEqual({ done: 9, failed: 0, rest: [] });
  });

  test('an item that throws is counted and the rest still run', async () => {
    const seen: number[] = [];
    const res = await inLanes([1, 2, 3, 4], 2, async (i) => {
      seen.push(i);
      if (i === 2) throw new Error('boom');
    });
    expect(seen.sort()).toEqual([1, 2, 3, 4]);
    expect(res).toEqual({ done: 4, failed: 1, rest: [] });
  });

  test('nothing starts after the deadline: the rest is handed back', async () => {
    const res = await inLanes([1, 2, 3], 2, async () => {}, Date.now() - 1);
    expect(res).toEqual({ done: 0, failed: 0, rest: [1, 2, 3] });
  });

  test('an empty list or zero lanes still finishes', async () => {
    expect(await inLanes([], 4, async () => {})).toEqual({ done: 0, failed: 0, rest: [] });
    expect((await inLanes([1, 2], 0, async () => {})).done).toBe(2);
  });
});
