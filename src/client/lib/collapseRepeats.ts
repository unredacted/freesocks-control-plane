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

/**
 * When two audit rows are the same event for folding: same action, actor,
 * target and payload. A server change (`panel_op`) folds across targets: each
 * retry of the same change is a new op, so its id says nothing new, while two
 * different records (two orders, two members) never fold into one row.
 */
export function auditRepeatKey(e: {
  action: string;
  actorType: string;
  actorId: string | null;
  targetType: string | null;
  targetId: string | null;
  payload: unknown;
}): string {
  const target = e.targetType === 'panel_op' ? '' : (e.targetId ?? '');
  return [
    e.action,
    e.actorType,
    e.actorId ?? '',
    e.targetType ?? '',
    target,
    JSON.stringify(e.payload),
  ].join('\u0000');
}
