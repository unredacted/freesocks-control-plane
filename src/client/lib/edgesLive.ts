/**
 * Admin -> Edges live refresh: an origin that changed refreshes its lists.
 *
 * The origin lookup, the fleet summary and the attention list are cheap reads
 * that poll on their own; each notes a stamp per origin it lists
 * (lib/livePoll.ts `originStamp` / `originStatusStamp`, called from the query
 * functions in edgesApi.ts). When a source's stamp for an origin moved since
 * that source last read it, the origin's lists are invalidated: the mounted
 * ones are fetched again at once, the rest only marked stale. So a detector
 * rotation that starts and ends between two polls of the node page's lists
 * shows within one summary read.
 *
 * Keys are matched by their shape (`edgesApi.ts` `edgeKeys`: everything under
 * `['admin', 'edges']`, per origin under `[…, 'relay', slug]`, per edge under
 * `[…, 'edge', edgeId]`); this module imports no query code of its own.
 *
 * Exports:
 *   OriginStampSource                    'lookup' | 'summary' | 'attention'
 *   originDependent(key, slug, source)   what one origin's change makes stale
 *   noteOrigins(qc, source, stamps)      record a reading; invalidate what moved
 */
import type { QueryClient } from '@tanstack/svelte-query';
import { OriginStamps } from './livePoll';

/** Which read noted the stamps (each source is compared with its own previous reading). */
export type OriginStampSource = 'lookup' | 'summary' | 'attention';

/**
 * The queries an origin's change makes stale: everything under its slug, the
 * edge drawers, the fleet summary and attention. Never the source's own query
 * (it is the read that just ran) and never forms, catalogs, runs or test links
 * (a test link is a POST that mints a credential).
 */
export function originDependent(
  key: readonly unknown[],
  slug: string,
  source: OriginStampSource,
): boolean {
  if (key[0] !== 'admin' || key[1] !== 'edges') return false;
  const [, , kind, sub, leaf] = key;
  if (kind === 'relay') return sub === slug && !(source === 'lookup' && leaf === 'lookup');
  if (kind === 'summary') return source !== 'summary';
  if (kind === 'attention') return source !== 'attention';
  return kind === 'edge';
}

const stampBooks = new WeakMap<QueryClient, OriginStamps>();

/**
 * Record one source's stamps per origin and invalidate the lists of every
 * origin whose stamp moved (debounced per origin). Returns those origins.
 *
 * One invalidation for all of them: the fleet lists and the edge drawers are
 * shared, and a second invalidation of a query that has data cancels and
 * restarts its fetch (the request itself is not aborted), so one call per
 * origin would read the fleet once per changed origin.
 */
export function noteOrigins(
  qc: QueryClient,
  source: OriginStampSource,
  stamps: Iterable<readonly [string, string]>,
  now = Date.now(),
): string[] {
  let book = stampBooks.get(qc);
  if (!book) stampBooks.set(qc, (book = new OriginStamps()));
  const changed = book.observe(source, stamps, now);
  if (changed.length > 0)
    void qc.invalidateQueries({
      predicate: (q) => changed.some((slug) => originDependent(q.queryKey, slug, source)),
    });
  return changed;
}
