/**
 * Bounded fan-out for background work (docs/convex-self-hosting.md "Background
 * work in lanes"). The backend has 16 permits per kind of function, shared with member
 * requests, and runs at most a handful of scheduled jobs at once; a cron that
 * schedules one job per row fills both with a burst. Instead, one driver works
 * through the rows with a few in flight (`inLanes`), within a time budget, and
 * schedules itself again for what is left.
 *
 * One item that throws is counted and skipped; the rest still run (a job per
 * row had the same isolation).
 */

export interface LaneResult<T> {
  /** Items whose work finished (including the ones that threw). */
  done: number;
  /** Items whose work threw. */
  failed: number;
  /** Items not started before the deadline: the caller's next run takes them. */
  rest: T[];
}

/**
 * Run `work` over `items` with at most `lanes` in flight, starting none after
 * `deadline` (epoch ms). Order of starts follows `items`.
 */
export async function inLanes<T>(
  items: readonly T[],
  lanes: number,
  work: (item: T) => Promise<unknown>,
  deadline?: number,
): Promise<LaneResult<T>> {
  let next = 0;
  let done = 0;
  let failed = 0;
  const worker = async () => {
    while (next < items.length && (deadline === undefined || Date.now() < deadline)) {
      const item = items[next++]!;
      try {
        await work(item);
      } catch {
        failed++;
      }
      done++;
    }
  };
  const n = Math.max(1, Math.min(Math.floor(lanes), items.length));
  await Promise.all(Array.from({ length: n }, worker));
  return { done, failed, rest: items.slice(next) };
}
