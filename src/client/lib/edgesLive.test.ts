import { QueryClient, QueryObserver, type QueryKey } from '@tanstack/query-core';
import { describe, expect, it, vi } from 'vitest';
import { noteOrigins, originDependent } from './edgesLive';

// edgesApi's wrappers need the Svelte adapter; its key tree and helpers do not.
vi.mock('@tanstack/svelte-query', () => ({ createQuery: () => ({}) }));
const { edgeKeys, setEdgeLiveSnapshot } = await import('./edgesApi');

const tick = () => new Promise((r) => setTimeout(r, 0));

/** A cache holding one of every key an origin's change could touch. */
function seeded() {
  const qc = new QueryClient();
  const keys = {
    lookup: edgeKeys.relayLookup('node-a'),
    edges: edgeKeys.relayEdges('node-a'),
    listeners: edgeKeys.relayListeners('node-a'),
    timeline: edgeKeys.relayTimeline('node-a'),
    simulations: edgeKeys.relaySimulations('node-a'),
    otherEdges: edgeKeys.relayEdges('node-b'),
    summary: edgeKeys.summary,
    attention: edgeKeys.attention,
    drawer: edgeKeys.edgeDetail('e1'),
    config: edgeKeys.config,
    templates: edgeKeys.templates,
    testLinks: edgeKeys.testLinks(['e1']),
    setupRun: edgeKeys.setupRun('run1'),
    servers: ['admin', 'servers', 'summary'] as const,
  };
  for (const key of Object.values(keys)) qc.setQueryData(key, { seeded: true });
  const stale = () =>
    Object.fromEntries(
      Object.entries(keys).map(([name, key]) => [name, !!qc.getQueryState(key)?.isInvalidated]),
    );
  return { qc, stale };
}

describe('originDependent', () => {
  it('is the origin subtree, its edge drawers and the fleet lists, never the source', () => {
    const k = (...rest: unknown[]) => ['admin', 'edges', ...rest];
    expect(originDependent(k('relay', 'node-a', 'edges'), 'node-a', 'summary')).toBe(true);
    expect(originDependent(k('relay', 'node-a', 'lookup'), 'node-a', 'summary')).toBe(true);
    expect(originDependent(k('relay', 'node-a', 'lookup'), 'node-a', 'lookup')).toBe(false);
    expect(originDependent(k('relay', 'node-b', 'edges'), 'node-a', 'lookup')).toBe(false);
    expect(originDependent(k('summary'), 'node-a', 'summary')).toBe(false);
    expect(originDependent(k('summary'), 'node-a', 'lookup')).toBe(true);
    expect(originDependent(k('attention'), 'node-a', 'attention')).toBe(false);
    expect(originDependent(k('attention'), 'node-a', 'summary')).toBe(true);
    expect(originDependent(k('edge', 'e1', 'detail'), 'node-a', 'attention')).toBe(true);
    // Forms, catalogs, runs and test links (a POST that mints a credential) are never touched.
    for (const key of [k('config'), k('templates'), k('test-links', 'e1'), k('setup-runs')])
      expect(originDependent(key, 'node-a', 'lookup')).toBe(false);
    expect(originDependent(['admin', 'servers', 'summary'], 'node-a', 'lookup')).toBe(false);
    expect(originDependent(['account'], 'node-a', 'lookup')).toBe(false);
  });
});

describe('noteOrigins', () => {
  it('a first reading changes nothing', () => {
    const { qc, stale } = seeded();
    expect(noteOrigins(qc, 'lookup', [['node-a', 'epoch-4']], 0)).toEqual([]);
    expect(Object.values(stale()).some(Boolean)).toBe(false);
  });

  it('a moved stamp invalidates that origin lists, never the source or static reads', () => {
    const { qc, stale } = seeded();
    noteOrigins(qc, 'lookup', [['node-a', 'epoch-4']], 0);
    expect(noteOrigins(qc, 'lookup', [['node-a', 'epoch-5']], 30_000)).toEqual(['node-a']);
    expect(stale()).toEqual({
      lookup: false,
      edges: true,
      listeners: true,
      timeline: true,
      simulations: true,
      otherEdges: false,
      summary: true,
      attention: true,
      drawer: true,
      config: false,
      templates: false,
      testLinks: false,
      setupRun: false,
      servers: false,
    });
  });

  it('the summary and attention reads catch a change for every origin they list', () => {
    const { qc, stale } = seeded();
    noteOrigins(
      qc,
      'attention',
      [
        ['node-a', 'protected|2|1'],
        ['node-b', 'protected|2|1'],
      ],
      0,
    );
    // A spare of node-b was used by an automatic replacement between two list polls.
    expect(
      noteOrigins(
        qc,
        'attention',
        [
          ['node-a', 'protected|2|1'],
          ['node-b', 'protected|2|0'],
        ],
        15_000,
      ),
    ).toEqual(['node-b']);
    const s = stale();
    expect(s.otherEdges).toBe(true);
    expect(s.edges).toBe(false);
    expect(s.attention).toBe(false);
    expect(s.summary).toBe(true);
  });

  it('keeps one book per client', () => {
    const a = new QueryClient();
    const b = new QueryClient();
    noteOrigins(a, 'summary', [['node-a', '1']], 0);
    // b has never seen node-a: a first sighting there.
    expect(noteOrigins(b, 'summary', [['node-a', '2']], 10_000)).toEqual([]);
    expect(noteOrigins(a, 'summary', [['node-a', '2']], 10_000)).toEqual(['node-a']);
  });
});

describe('noteOrigins with mounted queries', () => {
  it('a fleet read that moved several origins fetches each shared query once', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const calls: Record<string, number> = {};
    // Mounted, holding data, never settling: a second invalidation of such a
    // query cancels and restarts its fetch, so every extra call would show.
    const mount = (name: string, queryKey: QueryKey) => {
      qc.setQueryData(queryKey, { seeded: true });
      const observer = new QueryObserver(qc, {
        queryKey,
        queryFn: () => {
          calls[name] = (calls[name] ?? 0) + 1;
          return new Promise<never>(() => {});
        },
        staleTime: Infinity,
      });
      return observer.subscribe(() => {});
    };
    const slugs = ['node-a', 'node-b', 'node-c'];
    const unmount = [
      mount('summary', edgeKeys.summary),
      mount('drawer', edgeKeys.edgeDetail('e1')),
      mount('config', edgeKeys.config),
      ...slugs.map((s) => mount(`edges:${s}`, edgeKeys.relayEdges(s))),
    ];
    noteOrigins(
      qc,
      'attention',
      slugs.map((s) => [s, '1'] as const),
      0,
    );
    expect(
      noteOrigins(
        qc,
        'attention',
        slugs.map((s) => [s, '2'] as const),
        15_000,
      ),
    ).toEqual(slugs);
    await tick();
    expect(calls).toEqual({
      summary: 1,
      drawer: 1,
      'edges:node-a': 1,
      'edges:node-b': 1,
      'edges:node-c': 1,
    });
    for (const u of unmount) u();
    qc.clear();
  });
});

describe('the edge drawer live snapshot', () => {
  const detail = (snapshot: string | null) =>
    ({
      edge: { id: 'e1' },
      live: snapshot === null ? null : { summary: { status: snapshot } },
      probes: [],
    }) as never;
  const statusOf = (data: unknown) =>
    (data as { live: { summary: { status: string } } | null }).live?.summary.status ?? null;

  it('lives in the detail: a refresh shows at once, a newer detail poll supersedes it', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const key = edgeKeys.edgeDetail('e1');
    const polls = ['A', 'C'];
    const observer = new QueryObserver(qc, {
      queryKey: key,
      queryFn: async () => detail(polls.shift() ?? null),
    });
    const unsubscribe = observer.subscribe(() => {});
    await tick();
    expect(statusOf(observer.getCurrentResult().data)).toBe('A');
    // "Refresh live" returned snapshot B: it replaces A in the same cache.
    setEdgeLiveSnapshot(qc, 'e1', { summary: { status: 'B' } } as never);
    expect(statusOf(observer.getCurrentResult().data)).toBe('B');
    // Another admin refreshed it again; the next detail poll carries C and wins.
    await qc.invalidateQueries({ queryKey: key });
    expect(statusOf(observer.getCurrentResult().data)).toBe('C');
    // No second cache for the drawer to fall back on.
    expect(qc.getQueryData(edgeKeys.edgeLive('e1'))).toBeUndefined();
    unsubscribe();
    qc.clear();
  });

  it('leaves an edge whose detail was never read alone', () => {
    const qc = new QueryClient();
    setEdgeLiveSnapshot(qc, 'e2', null);
    expect(qc.getQueryData(edgeKeys.edgeDetail('e2'))).toBeUndefined();
  });
});
