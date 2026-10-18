import { QueryClient } from '@tanstack/query-core';
import { describe, expect, it, vi } from 'vitest';
import { noteOrigins, originDependent } from './edgesLive';

// edgesApi's wrappers need the Svelte adapter; its key tree does not.
vi.mock('@tanstack/svelte-query', () => ({ createQuery: () => ({}) }));
const { edgeKeys } = await import('./edgesApi');

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
