import { describe, expect, it } from 'vitest';
import {
  EdgeSummary,
  OriginAdmin,
  OriginStatus,
  type OriginStatusRow,
} from '../../../../../shared/contracts/edges';
import {
  DELIVERY_LABELS,
  filterRelays,
  fleetTiles,
  parseFilter,
  parseLayer,
  statusIndex,
  suspicionChip,
  type OriginRow,
} from './derive';

const NOW = '2026-09-18T00:00:00.000Z';

function relay(slug: string, over: Record<string, unknown> = {}) {
  return OriginAdmin.parse({
    id: `id-${slug}`,
    slug,
    origin: { kind: 'manual' },
    originAddress: '198.51.100.10',
    locationCode: null,
    hostMode: 'none',
    delivery: 'edge-required',
    enabled: true,
    autoRotate: false,
    providerPreference: null,
    desiredPublished: 2,
    standbyPerRelay: 0,
    cooldownMinutes: 120,
    maxRotationsPerDay: 3,
    drainMinutes: 60,
    publicationEpoch: 1,
    publishedEdgeIds: [],
    publishedCount: 0,
    standbyEdgeIds: [],
    activeRotationId: null,
    cooldownUntil: null,
    rotationsToday: 0,
    lastRotatedAt: null,
    quarantine: null,
    deleting: false,
    suspicion: null,
    updatedAt: NOW,
    ...over,
  });
}
const entry = (edgeId: string, layer: 'l4' | 'l7', health = 'online') => ({
  poolIndex: 0,
  edgeId,
  provider: null,
  managed: true,
  addresses: { v4: '198.51.100.20', v6: null, hostname: null },
  layer,
  health,
  status: 'active',
  unreachableIn: [],
  mixedIn: [],
});
function row(slug: string, pool: ReturnType<typeof entry>[], over: Record<string, unknown> = {}) {
  return {
    relay: relay(slug, {
      publishedCount: pool.length,
      publishedEdgeIds: pool.map((p) => p.edgeId),
      ...over,
    }),
    pool,
    standbys: 0,
    draining: 0,
    needsOperator: 0,
    rotation: null,
  };
}
/** The server's status of an origin (convex/lib/edges/originStatus.ts), as the attention response carries it. */
const status = (slug: string, over: Partial<OriginStatus>): OriginStatusRow => ({
  relayId: `id-${slug}`,
  relaySlug: slug,
  status: OriginStatus.parse({
    kind: 'protected',
    dot: 'green',
    code: null,
    runId: null,
    runKind: null,
    step: null,
    published: 1,
    standbys: 0,
    offline: 0,
    worstHealth: 'online',
    layers: ['l4'],
    attention: false,
    delivery: { kind: 'serving', code: null },
    failedRunId: null,
    fronted: false,
    ...over,
  }),
});

const rows = [
  row('alpha', [entry('e1', 'l4'), entry('e2', 'l7', 'degraded')]),
  row('bravo', []),
  row('charlie', [entry('e3', 'l4', 'offline')], {
    quarantine: { rotationId: 'r1', since: NOW, reason: 'rollback_failed' },
  }),
];
const summary = EdgeSummary.parse({
  counts: {
    relays: 3,
    published: 3,
    suspected: 0,
    rotating: 1,
    quarantined: 1,
    unreachableEdges: 0,
    needsOperator: 0,
  },
  relays: rows.map((r, i) => ({ ...r, standbys: i === 0 ? 2 : 0 })),
  generatedAt: NOW,
});
const parsedRows: OriginRow[] = summary.relays;
const statuses = statusIndex([
  status('alpha', { layers: ['l4', 'l7'], published: 2, worstHealth: 'degraded' }),
  status('bravo', {
    kind: 'unprotected',
    dot: 'red',
    published: 0,
    layers: [],
    worstHealth: null,
    attention: true,
    delivery: { kind: 'dark', code: 'empty_pool' },
  }),
  status('charlie', { kind: 'paused', dot: 'red', attention: true, worstHealth: 'offline' }),
]);

describe('overview derive', () => {
  it('parses URL state with a safe fallback', () => {
    expect(parseFilter('dark')).toBe('dark');
    expect(parseFilter('x')).toBe('all');
    expect(parseLayer('l7')).toBe('l7');
    expect(parseLayer(null)).toBe('all');
  });

  it('words every delivery kind the server judges', () => {
    expect(DELIVERY_LABELS.dark).toBe('Members dark');
    expect(DELIVERY_LABELS.direct).toBe('Direct address');
    expect(Object.keys(DELIVERY_LABELS).sort()).toEqual(
      ['dark', 'degraded', 'direct', 'manual', 'serving'].sort(),
    );
  });

  it('filters by the server status: problem and layer', () => {
    const slugs = (f: Parameters<typeof filterRelays>[1], l: Parameters<typeof filterRelays>[2]) =>
      filterRelays(parsedRows, f, l, statuses).map((r) => r.relay.slug);
    expect(slugs('all', 'all')).toEqual(['alpha', 'bravo', 'charlie']);
    expect(slugs('attention', 'all')).toEqual(['bravo', 'charlie']);
    expect(slugs('dark', 'all')).toEqual(['bravo']);
    expect(slugs('quarantined', 'all')).toEqual(['charlie']);
    expect(slugs('unpublished', 'all')).toEqual(['bravo']);
    expect(slugs('all', 'l7')).toEqual(['alpha']);
    expect(slugs('quarantined', 'l7')).toEqual([]);
    // No status yet (the attention response is loading): only `all` matches.
    expect(
      filterRelays(parsedRows, 'dark', 'all', statusIndex([])).map((r) => r.relay.slug),
    ).toEqual([]);
    expect(filterRelays(parsedRows, 'all', 'all', statusIndex(undefined))).toHaveLength(3);
  });

  it('derives the tiles the summary has no figure for', () => {
    const tiles = fleetTiles(summary, statuses, {
      usedLastHour: 180,
      hourlyBudget: 200,
      enabled: true,
    });
    const by = Object.fromEntries(tiles.map((t) => [t.id, t]));
    expect(tiles).toHaveLength(9);
    expect(by['published-l4']!.value).toBe('2');
    expect(by['published-l7']!.value).toBe('1');
    expect(by['standbys']!.value).toBe('2');
    expect(by['dark']!.value).toBe('1');
    expect(by['dark']!.filter).toBe('dark');
    expect(by['quarantined']!.filter).toBe('quarantined');
    expect(by['needs-operator']!.filter).toBeNull();
    expect(by['probe-budget']!.value).toBe('180 of 200');
    expect(by['probe-budget']!.tone).toBe('warning');
  });

  it('says so when probes are off or the budget is unknown', () => {
    const none = statusIndex([]);
    const off = fleetTiles(summary, none, {
      usedLastHour: null,
      hourlyBudget: 200,
      enabled: false,
    });
    expect(off.find((t) => t.id === 'probe-budget')!.value).toBe('Off');
    const unknown = fleetTiles(summary, none, {
      usedLastHour: null,
      hourlyBudget: null,
      enabled: null,
    });
    expect(unknown.find((t) => t.id === 'probe-budget')!.value).toBe('Unknown');
  });

  it('puts a veto ahead of a suspicion in the detector chip', () => {
    const suspicion = {
      state: 'suspected',
      hintLevel: 'corroborated',
      score: 0.8,
      reportScore: 0.5,
      loadScore: 0.2,
      probeScore: 0.1,
      scope: 'regional',
      countries: [{ code: 'IR', count: 4 }],
      edgeEvidence: [],
      firstSeenAt: NOW,
      lastEvalAt: NOW,
      quietEvals: 0,
      baselineWarm: true,
      veto: null,
    };
    const suspected = row('echo', [], { suspicion }) as OriginRow;
    expect(suspicionChip(suspected)?.label).toBe('Block suspected in IR');
    const vetoed = row('foxtrot', [], {
      suspicion: { ...suspicion, veto: 'node_offline' },
    }) as OriginRow;
    expect(suspicionChip(vetoed)?.tone).toBe('info');
    expect(suspicionChip(parsedRows[0]!)).toBeNull();
  });
});
