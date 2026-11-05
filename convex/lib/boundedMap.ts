/**
 * Run `fn` over `items` with at most `limit` calls in flight, keeping the
 * results in input order (pure; unit-tested). The admin routes that read one
 * query per item (the countries summary) use it so a long list never fills
 * the backend's query pool at once.
 */
export async function mapBounded<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  };
  const width = Math.max(1, Math.min(Math.floor(limit), items.length));
  await Promise.all(Array.from({ length: width }, worker));
  return out;
}
