/**
 * Fold runs of identical neighbours into one entry with a count (pure). A list
 * flooded by the same retry ("Add address x: never sent", forty times) reads as
 * one line that says how often it happened. Only NEIGHBOURS fold: an entry that
 * recurs after something else stays its own line, so the order of events holds.
 *
 * `key` decides what "identical" means; `null` means "never fold this one" (an
 * entry with its own buttons). Each group keeps its first item (the newest, in a
 * newest-first list) and the last one (the oldest) for a time range.
 */
export interface Repeated<T> {
  item: T;
  /** The last item folded in (the item itself when `count` is 1). */
  last: T;
  count: number;
}

export function collapseRepeats<T>(
  items: readonly T[],
  key: (item: T) => string | null,
): Repeated<T>[] {
  const out: Repeated<T>[] = [];
  let prevKey: string | null = null;
  for (const item of items) {
    const k = key(item);
    const prev = out.at(-1);
    if (prev && k !== null && k === prevKey) {
      prev.count += 1;
      prev.last = item;
    } else {
      out.push({ item, last: item, count: 1 });
    }
    prevKey = k;
  }
  return out;
}
