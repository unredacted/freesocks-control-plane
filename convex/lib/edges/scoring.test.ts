import { describe, expect, test } from 'vitest';
import { EDGE_DEFAULTS } from '../edgeConfig';
import { autoRotateDecision, evaluate, type EdgeProbeState, type EvaluationInput } from './scoring';

const cfg = { detect: EDGE_DEFAULTS.detect, probe: { ...EDGE_DEFAULTS.probe, enabled: true } };
const now = 1_800_000_000_000;

function warmBaseline(reports = 1, usersOnline: number | null = 100, n = 80) {
  return Array.from({ length: n }, () => ({ reports, distinctReporters: reports, usersOnline }));
}

function input(over: Partial<EvaluationInput> = {}): EvaluationInput {
  return {
    now,
    window: { reports: 0, distinctReporters: 0, countries: {}, byEdge: {} },
    baseline: warmBaseline(),
    usersOnline: 100,
    loadStale: false,
    edges: [],
    cfg,
    prev: null,
    ...over,
  };
}

const edge = (edgeId: string, over: Partial<EdgeProbeState> = {}): EdgeProbeState => ({
  edgeId,
  byCountry: [],
  internalVerdict: 'reachable',
  providerHealth: 'online',
  probeAgeMs: 60_000,
  ...over,
});

describe('evaluate', () => {
  test('quiet window scores zero and stays clear', () => {
    const ev = evaluate(input());
    expect(ev.state).toBe('clear');
    expect(ev.score).toBe(0);
    expect(ev.hintLevel).toBe('none');
    expect(ev.transition).toBeNull();
    expect(ev.baselineWarm).toBe(true);
  });

  test('fewer than minReporters contributes nothing, however many raw reports', () => {
    const ev = evaluate(
      input({ window: { reports: 40, distinctReporters: 3, countries: { IR: 40 }, byEdge: {} } }),
    );
    expect(ev.reportScore).toBe(0);
  });

  test('a report spike with a load drop (corroboration required) suspects; probes-off evidence is origin-level only', () => {
    const ev = evaluate(
      input({
        window: { reports: 12, distinctReporters: 10, countries: { IR: 10, RU: 2 }, byEdge: {} },
        usersOnline: 20,
      }),
    );
    expect(ev.reportScore).toBe(1);
    expect(ev.loadScore).toBe(1);
    expect(ev.score).toBe(1);
    expect(ev.state).toBe('suspected');
    expect(ev.transition).toBe('suspected');
    expect(ev.hintLevel).toBe('reports');
    expect(ev.scope).toBe('regional');
    expect(ev.countries[0]).toEqual({ code: 'IR', count: 10 });
    expect(ev.edgeEvidence).toEqual([]);
    expect(ev.firstSeenAt).toBe(now);
  });

  test('reports without a load drop stay a hint when load corroboration is required', () => {
    const ev = evaluate(
      input({ window: { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} } }),
    );
    expect(ev.reportScore).toBe(1);
    expect(ev.loadScore).toBe(0);
    expect(ev.score).toBe(0.5);
    expect(ev.state).toBe('clear');
    expect(ev.hintLevel).toBe('reports');
  });

  test('stale load is down-weighted; cold baseline uses reporters only, weakly', () => {
    const stale = evaluate(
      input({
        window: { reports: 12, distinctReporters: 10, countries: {}, byEdge: {} },
        usersOnline: 20,
        loadStale: true,
      }),
    );
    expect(stale.loadScore).toBeCloseTo(EDGE_DEFAULTS.detect.staleWeight);
    const cold = evaluate(
      input({
        baseline: warmBaseline(1, 100, 5),
        window: { reports: 6, distinctReporters: 6, countries: {}, byEdge: {} },
      }),
    );
    expect(cold.baselineWarm).toBe(false);
    expect(cold.reportScore).toBeCloseTo(6 / 8);
    expect(cold.loadScore).toBe(0); // baseline too short to know the load
  });

  test('probe evidence: unreachable countries on a healthy edge score and name the edge', () => {
    const ev = evaluate(
      input({
        edges: [
          edge('e1', {
            byCountry: [
              { country: 'IR', verdict: 'unreachable' },
              { country: 'RU', verdict: 'reachable' },
              { country: 'CN', verdict: 'mixed' },
            ],
          }),
          edge('e2', { byCountry: [{ country: 'IR', verdict: 'reachable' }] }),
        ],
      }),
    );
    expect(ev.probeScore).toBeCloseTo(1.5 / 7);
    expect(ev.hintLevel).toBe('probes');
    expect(ev.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'probes', countries: ['IR'] }]);
    expect(ev.state).toBe('clear'); // 0.5 * 0.21 < suspectAt
  });

  test('an edge that is down for everyone (internal probe / provider offline) is an outage, not a block', () => {
    const ev = evaluate(
      input({
        window: { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} },
        usersOnline: 10,
        edges: [
          edge('down', {
            internalVerdict: 'unreachable',
            byCountry: EDGE_DEFAULTS.probe.countries.map((c) => ({
              country: c,
              verdict: 'unreachable' as const,
            })),
          }),
          edge('off', { providerHealth: 'offline' }),
        ],
      }),
    );
    expect(ev.outageEdges).toEqual(['down', 'off']);
    expect(ev.probeScore).toBe(0);
    expect(ev.edgeEvidence).toEqual([]);
    expect(ev.state).toBe('suspected'); // reports + load still raise the origin-level hint
  });

  test('member "which connection" reports become edge evidence only with enough share', () => {
    const ev = evaluate(
      input({
        window: {
          reports: 10,
          distinctReporters: 8,
          countries: { IR: 10 },
          byEdge: {
            e1: { count: 4, countries: { IR: 4 } },
            e2: { count: 1, countries: { IR: 1 } },
          },
        },
        usersOnline: 0,
      }),
    );
    expect(ev.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'reports', countries: ['IR'] }]);
    const split = evaluate(
      input({
        window: {
          reports: 10,
          distinctReporters: 8,
          countries: {},
          byEdge: { e1: { count: 3, countries: {} }, e2: { count: 3, countries: {} } },
        },
      }),
    );
    expect(split.edgeEvidence).toEqual([]);
  });

  test('corroborated when members and probes agree; probeSourcesDown when every summary is stale', () => {
    const ev = evaluate(
      input({
        window: { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} },
        edges: [
          edge('e1', {
            byCountry: [{ country: 'IR', verdict: 'unreachable' }],
            probeAgeMs: 10 * 60 * 60_000,
          }),
        ],
      }),
    );
    expect(ev.hintLevel).toBe('corroborated');
    expect(ev.probeSourcesDown).toBe(true);
    const fresh = evaluate(input({ edges: [edge('e1', { probeAgeMs: 60_000 })] }));
    expect(fresh.probeSourcesDown).toBe(false);
    const never = evaluate(input({ edges: [edge('e1', { probeAgeMs: null })] }));
    expect(never.probeSourcesDown).toBe(true);
  });

  test('clearing needs clearAfterEvals quiet evaluations; a loud one resets the count', () => {
    const suspected = { state: 'suspected' as const, firstSeenAt: now - 60_000, quietEvals: 0 };
    const q1 = evaluate(input({ prev: suspected }));
    expect(q1.state).toBe('suspected');
    expect(q1.quietEvals).toBe(1);
    expect(q1.firstSeenAt).toBe(now - 60_000);
    const loud = evaluate(
      input({
        prev: { ...suspected, quietEvals: 2 },
        window: { reports: 12, distinctReporters: 10, countries: {}, byEdge: {} },
        usersOnline: 0,
      }),
    );
    expect(loud.quietEvals).toBe(0);
    const cleared = evaluate(input({ prev: { ...suspected, quietEvals: 2 } }));
    expect(cleared.state).toBe('clear');
    expect(cleared.transition).toBe('cleared');
    expect(cleared.firstSeenAt).toBeNull();
  });
});

describe('autoRotateDecision', () => {
  const suspectedEv = evaluate(
    input({
      window: { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} },
      usersOnline: 0,
      edges: [edge('e1', { byCountry: [{ country: 'IR', verdict: 'unreachable' }] }), edge('e2')],
    }),
  );
  const origin = {
    autoRotate: true,
    quarantined: false,
    rotationActive: false,
    cooldownUntil: null,
    rotationsToday: 0,
    maxRotationsPerDay: 3,
    hostManaged: true,
  };
  const on = { enabled: true, autoRotate: true, detect: EDGE_DEFAULTS.detect };
  const published = [
    { edgeId: 'e1', poolIndex: 0 },
    { edgeId: 'e2', poolIndex: 1 },
  ];

  test('every gate must be open, in order', () => {
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: { ...on, enabled: false },
        origin,
        published,
        now,
      }),
    ).toEqual({ veto: 'edge_disabled' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, autoRotate: false },
        published,
        now,
      }),
    ).toEqual({ veto: 'auto_rotate_off' });
    expect(
      autoRotateDecision({ evaluation: evaluate(input()), cfg: on, origin, published, now }),
    ).toEqual({ veto: 'not_suspected' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, quarantined: true },
        published,
        now,
      }),
    ).toEqual({ veto: 'quarantined' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, rotationActive: true },
        published,
        now,
      }),
    ).toEqual({ veto: 'rotation_active' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, cooldownUntil: now + 1 },
        published,
        now,
      }),
    ).toEqual({ veto: 'cooldown' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, rotationsToday: 3 },
        published,
        now,
      }),
    ).toEqual({ veto: 'daily_cap' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin: { ...origin, hostManaged: false },
        published,
        now,
      }),
    ).toEqual({ veto: 'hosts_unmanaged' });
    expect(
      autoRotateDecision({ evaluation: suspectedEv, cfg: on, origin, published, now }),
    ).toEqual({ edgeId: 'e1', source: 'probes' });
  });

  test('origin-level suspicion alone never rotates; probe-only evidence needs the allow flag and live sources', () => {
    const originOnly = evaluate(
      input({
        window: { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} },
        usersOnline: 0,
      }),
    );
    expect(autoRotateDecision({ evaluation: originOnly, cfg: on, origin, published, now })).toEqual(
      { veto: 'no_edge_evidence' },
    );
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: { ...on, detect: { ...on.detect, allowProbeOnlyAutoRotate: false } },
        origin,
        published,
        now,
      }),
    ).toEqual({ veto: 'probe_only_disallowed' });
    expect(
      autoRotateDecision({
        evaluation: { ...suspectedEv, probeSourcesDown: true },
        cfg: on,
        origin,
        published,
        now,
      }),
    ).toEqual({ veto: 'probe_sources_down' });
  });

  test('outage edges and unpublished edges are never rotation targets; member evidence is preferred', () => {
    expect(
      autoRotateDecision({
        evaluation: { ...suspectedEv, outageEdges: ['e1'] },
        cfg: on,
        origin,
        published,
        now,
      }),
    ).toEqual({ veto: 'edge_outage' });
    expect(
      autoRotateDecision({
        evaluation: suspectedEv,
        cfg: on,
        origin,
        published: [{ edgeId: 'e2', poolIndex: 0 }],
        now,
      }),
    ).toEqual({ veto: 'target_not_published' });
    const both = {
      ...suspectedEv,
      edgeEvidence: [
        { edgeId: 'e1', source: 'probes' as const, countries: ['IR'] },
        { edgeId: 'e2', source: 'reports' as const, countries: ['IR'] },
      ],
    };
    expect(autoRotateDecision({ evaluation: both, cfg: on, origin, published, now })).toEqual({
      edgeId: 'e2',
      source: 'reports',
    });
  });
});
