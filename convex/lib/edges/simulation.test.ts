import { describe, expect, test } from 'vitest';
import { EDGE_DEFAULTS } from '../edgeConfig';
import { autoRotateDecision, evaluate, type EdgeProbeState, type WindowReports } from './scoring';
import {
  applySimulatedEvidence,
  blockSimulatorAllowedIn,
  defaultSimulatedReporters,
} from './simulation';

const NOW = 1_800_000_000_000;

const emptyWindow = (): WindowReports => ({
  reports: 0,
  distinctReporters: 0,
  countries: {},
  byEdge: {},
});
const edge = (edgeId: string, over: Partial<EdgeProbeState> = {}): EdgeProbeState => ({
  edgeId,
  byCountry: [],
  internalVerdict: 'unknown',
  providerHealth: 'unknown',
  probeAgeMs: null,
  ...over,
});

describe('the block simulator gate', () => {
  test('only local development or the explicit opt-in value; ENVIRONMENT=production alone is never enough', () => {
    expect(blockSimulatorAllowedIn({})).toBe(false);
    expect(blockSimulatorAllowedIn({ ENVIRONMENT: 'production' })).toBe(false);
    expect(
      blockSimulatorAllowedIn({ ENVIRONMENT: 'production', EDGE_SIMULATOR_ALLOW: 'yes' }),
    ).toBe(false);
    expect(blockSimulatorAllowedIn({ EDGE_SIMULATOR_ALLOW: 'simulate-blocks' })).toBe(true);
    expect(
      blockSimulatorAllowedIn({
        ENVIRONMENT: 'production',
        EDGE_SIMULATOR_ALLOW: 'simulate-blocks',
      }),
    ).toBe(true);
    expect(blockSimulatorAllowedIn({ ENVIRONMENT: 'development' })).toBe(true);
  });

  test('the default reporters are twice the detector minimum, within bounds', () => {
    expect(defaultSimulatedReporters(4)).toBe(8);
    expect(defaultSimulatedReporters(0)).toBe(1);
    expect(defaultSimulatedReporters(400)).toBe(50);
  });
});

describe('the simulated evidence overlay', () => {
  test('adds reporters for the country and the edge, and reads that edge unreachable there; the inputs are untouched', () => {
    const window: WindowReports = {
      reports: 3,
      distinctReporters: 2,
      countries: { RU: 2 },
      byEdge: { b: { count: 1, countries: { RU: 1 } } },
    };
    const edges = [
      edge('a', {
        byCountry: [
          { country: 'IR', verdict: 'reachable', wasReachable: true, ageMs: 600_000 },
          { country: 'RU', verdict: 'reachable', wasReachable: true, ageMs: 600_000 },
        ],
        probeAgeMs: 600_000,
      }),
      edge('b'),
    ];
    const before = JSON.stringify({ window, edges });
    const out = applySimulatedEvidence(window, edges, [
      { edgeId: 'a', country: 'IR', reporters: 8 },
    ]);
    expect(JSON.stringify({ window, edges })).toBe(before);
    expect(out.window).toEqual({
      reports: 11,
      distinctReporters: 10,
      countries: { RU: 2, IR: 8 },
      byEdge: { b: { count: 1, countries: { RU: 1 } }, a: { count: 8, countries: { IR: 8 } } },
    });
    const a = out.edges.find((e) => e.edgeId === 'a')!;
    expect(a.probeAgeMs).toBe(0);
    expect(a.byCountry).toContainEqual({
      country: 'IR',
      verdict: 'unreachable',
      wasReachable: true,
      ageMs: 0,
    });
    // Only that (edge, country) is overridden.
    expect(a.byCountry).toContainEqual({
      country: 'RU',
      verdict: 'reachable',
      wasReachable: true,
      ageMs: 600_000,
    });
    expect(out.edges.find((e) => e.edgeId === 'b')).toEqual(edges[1]);
  });

  test('a simulation for an edge that is no longer published adds nothing', () => {
    const out = applySimulatedEvidence(
      emptyWindow(),
      [edge('a')],
      [{ edgeId: 'gone', country: 'IR', reporters: 8 }],
    );
    expect(out.window).toEqual(emptyWindow());
    expect(out.edges).toEqual([edge('a')]);
  });

  test('with the shipped detection settings the default simulation reaches suspicion, corroborated, on its edge', () => {
    const cfg = { ...EDGE_DEFAULTS, enabled: true, autoRotate: true };
    cfg.probe = { ...EDGE_DEFAULTS.probe, enabled: true, countries: ['IR', 'RU'] };
    // Nothing real at all: cold baseline, no load signal, no probe rows yet.
    const real = { window: emptyWindow(), edges: [edge('a'), edge('b')] };
    const sims = [
      {
        edgeId: 'a',
        country: 'IR',
        reporters: defaultSimulatedReporters(cfg.detect.minReporters),
      },
    ];
    const overlaid = applySimulatedEvidence(real.window, real.edges, sims);
    const ev = evaluate({
      now: NOW,
      window: overlaid.window,
      baseline: [],
      usersOnline: null,
      loadStale: true,
      nodeOnline: null,
      edges: overlaid.edges,
      cfg,
      prev: null,
    });
    expect(ev.state).toBe('suspected');
    expect(ev.hintLevel).toBe('corroborated');
    expect(ev.score).toBeCloseTo(0.75, 3);
    expect(ev.edgeEvidence).toEqual(
      expect.arrayContaining([
        { edgeId: 'a', source: 'reports', countries: ['IR'] },
        { edgeId: 'a', source: 'probes', countries: ['IR'] },
      ]),
    );
    const decision = autoRotateDecision({
      evaluation: ev,
      cfg,
      origin: {
        autoRotate: true,
        quarantined: false,
        rotationActive: false,
        cooldownUntil: null,
        rotationsToday: 0,
        maxRotationsPerDay: 3,
        hostManaged: true,
      },
      published: [
        { edgeId: 'a', poolIndex: 0 },
        { edgeId: 'b', poolIndex: 1 },
      ],
      now: NOW,
    });
    expect(decision).toEqual({ edgeId: 'a', source: 'reports' });
    // Without the overlay the same inputs score nothing.
    const quiet = evaluate({
      now: NOW,
      window: real.window,
      baseline: [],
      usersOnline: null,
      loadStale: true,
      nodeOnline: null,
      edges: real.edges,
      cfg,
      prev: null,
    });
    expect(quiet.state).toBe('clear');
  });
});
