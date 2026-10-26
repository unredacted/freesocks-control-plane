import { describe, expect, test } from 'vitest';
import { EDGE_DEFAULTS } from '../edgeConfig';
import {
  autoRotateDecision,
  evaluate,
  loadBaseline,
  type EdgeProbeState,
  type EvaluationInput,
  type SteeringInput,
} from './scoring';
import type { DeliveryPath, PublishedEdge } from './assignment';
import type { Verdict } from './probes/verdict';

// Probe-only evidence is opted IN here (the shipped default is off) so the probe path is exercised.
const cfg = {
  detect: { ...EDGE_DEFAULTS.detect, allowProbeOnlyAutoRotate: true },
  probe: { ...EDGE_DEFAULTS.probe, enabled: true },
};
const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
const now = 1_800_000_000_000;

/**
 * A warm baseline spread over the past week, one sample every two hours, so
 * time-of-day matching finds the same clock hour on each previous day (7
 * samples ≥ 22h old within ±1h).
 */
function warmBaseline(reports = 1, usersOnline: number | null = 100, n = 84) {
  return Array.from({ length: n }, (_, i) => ({
    at: now - (i + 1) * 2 * HOUR,
    reports,
    distinctReporters: reports,
    usersOnline,
  }));
}

function input(over: Partial<EvaluationInput> = {}): EvaluationInput {
  return {
    now,
    window: { reports: 0, distinctReporters: 0, countries: {}, byEdge: {} },
    baseline: warmBaseline(),
    usersOnline: 100,
    loadStale: false,
    nodeOnline: true,
    edges: [],
    cfg,
    prev: null,
    ...over,
  };
}

/** A country verdict the edge was reachable from before (the normal case). */
const c = (
  country: string,
  verdict: Verdict,
  over: Partial<EdgeProbeState['byCountry'][0]> = {},
) => ({
  country,
  verdict,
  wasReachable: true,
  ...over,
});

const edge = (edgeId: string, over: Partial<EdgeProbeState> = {}): EdgeProbeState => ({
  edgeId,
  byCountry: [],
  internalVerdict: 'reachable',
  providerHealth: 'online',
  probeAgeMs: 60_000,
  ...over,
});

const loud = { reports: 12, distinctReporters: 10, countries: { IR: 12 }, byEdge: {} };

describe('evaluate', () => {
  test('quiet window scores zero and stays clear', () => {
    const ev = evaluate(input());
    expect(ev.state).toBe('clear');
    expect(ev.score).toBe(0);
    expect(ev.hintLevel).toBe('none');
    expect(ev.transition).toBeNull();
    expect(ev.baselineWarm).toBe(true);
    expect(ev.loadBaseline).toBe('time_of_day');
    expect(ev.nodeOffline).toBe(false);
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
    const ev = evaluate(input({ window: loud }));
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

  describe('time-of-day baseline (fix: a flat weekly mean mistakes a quiet afternoon for a block)', () => {
    /** Diurnal week: 200 users in the night half of the UTC day, 40 in the day half, every 30 min. */
    const diurnal = (at: number) => ((at % DAY) / HOUR < 12 ? 200 : 40);
    const week = Array.from({ length: (7 * DAY) / (30 * 60_000) }, (_, i) => {
      const at = now - (i + 1) * 30 * 60_000;
      return { at, reports: 0, distinctReporters: 0, usersOnline: diurnal(at) };
    });
    const dayHour = now - (now % DAY) + 15 * HOUR; // 15:00 UTC → baseline 40
    const nightHour = now - (now % DAY) + 3 * HOUR; // 03:00 UTC → baseline 200

    test('the same clock hour on previous days is the baseline', () => {
      expect(loadBaseline(week, dayHour)).toEqual({ value: 40, kind: 'time_of_day' });
      expect(loadBaseline(week, nightHour)).toEqual({ value: 200, kind: 'time_of_day' });
    });

    test('normal daytime load is NOT a drop (the flat mean of 120 would have said 67%)', () => {
      const ev = evaluate(input({ now: dayHour, baseline: week, usersOnline: 40, window: loud }));
      expect(ev.loadBaseline).toBe('time_of_day');
      expect(ev.loadScore).toBe(0);
      expect(ev.state).toBe('clear');
    });

    test('a halved night load IS a full drop (the flat mean would have seen 17%)', () => {
      const ev = evaluate(
        input({ now: nightHour, baseline: week, usersOnline: 100, window: loud }),
      );
      expect(ev.loadScore).toBe(1);
      expect(ev.state).toBe('suspected');
    });

    test('too few same-hour samples → flat mean, dampened like a stale reading', () => {
      const short = week.filter((s) => nightHour - s.at < 20 * HOUR); // nothing ≥ 22h old
      expect(loadBaseline(short, nightHour).kind).toBe('flat');
      const ev = evaluate(input({ now: nightHour, baseline: short, usersOnline: 0, window: loud }));
      expect(ev.loadBaseline).toBe('flat');
      expect(ev.loadScore).toBeCloseTo(EDGE_DEFAULTS.detect.staleWeight);
      expect(loadBaseline([], now)).toEqual({ value: 0, kind: 'none' });
    });
  });

  test('probe evidence: one agreed unreachable country on a once-reachable edge is edge evidence AND, probe-only allowed, reaches suspicion alone', () => {
    const ev = evaluate(
      input({
        edges: [
          edge('e1', {
            byCountry: [c('IR', 'unreachable'), c('RU', 'reachable'), c('CN', 'mixed')],
          }),
          edge('e2', { byCountry: [c('IR', 'reachable')] }),
        ],
      }),
    );
    expect(ev.probeScore).toBe(1);
    expect(ev.hintLevel).toBe('probes');
    expect(ev.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'probes', countries: ['IR'] }]);
    expect(ev.score).toBe(1);
    expect(ev.state).toBe('suspected');
    expect(ev.transition).toBe('suspected');
    // With probe-only rotations disallowed the verdict is weighed, not decisive.
    const weighed = evaluate(
      input({
        cfg: { ...cfg, detect: { ...cfg.detect, allowProbeOnlyAutoRotate: false } },
        edges: [edge('e1', { byCountry: [c('IR', 'unreachable')] })],
      }),
    );
    expect(weighed.probeScore).toBe(1);
    expect(weighed.score).toBeCloseTo(EDGE_DEFAULTS.detect.probeWeight);
    expect(weighed.state).toBe('clear');
    expect(weighed.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'probes', countries: ['IR'] }]);
  });

  test('a country that has ALWAYS been unreachable for the edge is not block evidence', () => {
    const ev = evaluate(
      input({
        edges: [
          edge('e1', {
            byCountry: [c('IR', 'unreachable', { wasReachable: false }), c('RU', 'reachable')],
          }),
        ],
      }),
    );
    expect(ev.probeScore).toBe(0);
    expect(ev.edgeEvidence).toEqual([]);
    expect(ev.hintLevel).toBe('none');
    expect(ev.state).toBe('clear');
  });

  test('an edge that is down for everyone (internal probe / provider offline) is an outage, not a block', () => {
    const ev = evaluate(
      input({
        window: loud,
        usersOnline: 10,
        edges: [
          edge('down', {
            internalVerdict: 'unreachable',
            byCountry: EDGE_DEFAULTS.probe.countries.map((x) => c(x, 'unreachable')),
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

  test('an OFFLINE node is an outage for every edge: no probe evidence, nodeOffline flagged', () => {
    const ev = evaluate(
      input({
        window: loud,
        usersOnline: 0,
        nodeOnline: false,
        edges: [edge('e1', { byCountry: [c('IR', 'unreachable')] }), edge('e2')],
      }),
    );
    expect(ev.nodeOffline).toBe(true);
    expect(ev.outageEdges).toEqual(['e1', 'e2']);
    expect(ev.probeScore).toBe(0);
    expect(ev.edgeEvidence).toEqual([]);
    // Unknown online bit (no inventory row) is not an outage claim.
    expect(evaluate(input({ nodeOnline: null })).nodeOffline).toBe(false);
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

  test('corroborated when members and FRESH probes agree; stale or probes-off evidence is ignored per edge', () => {
    const unreachableIr = [c('IR', 'unreachable')];
    const ev = evaluate(
      input({
        window: loud,
        edges: [edge('e1', { byCountry: unreachableIr, probeAgeMs: 60_000 })],
      }),
    );
    expect(ev.hintLevel).toBe('corroborated');
    expect(ev.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'probes', countries: ['IR'] }]);
    expect(ev.probeSourcesDown).toBe(false);
    // A stale summary on one edge next to a fresh one on another: the stale edge
    // is neither evidence nor a rotation candidate, and the sources are not "down".
    const mixed = evaluate(
      input({
        window: loud,
        edges: [
          edge('stale', { byCountry: unreachableIr, probeAgeMs: 10 * HOUR }),
          edge('fresh', { probeAgeMs: 60_000 }),
        ],
      }),
    );
    expect(mixed.hintLevel).toBe('reports');
    expect(mixed.probeScore).toBe(0);
    expect(mixed.edgeEvidence).toEqual([]);
    expect(mixed.probeSourcesDown).toBe(false);
    // Every summary stale → sources down (and still no edge evidence from the stale rows).
    const allStale = evaluate(
      input({
        window: loud,
        edges: [edge('e1', { byCountry: unreachableIr, probeAgeMs: 10 * HOUR })],
      }),
    );
    expect(allStale.hintLevel).toBe('reports');
    expect(allStale.probeSourcesDown).toBe(true);
    const never = evaluate(input({ edges: [edge('e1', { probeAgeMs: null })] }));
    expect(never.probeSourcesDown).toBe(true);
    // Probes disabled: whatever the summaries say, they carry no weight and there is no veto.
    const off = evaluate(
      input({
        window: loud,
        cfg: { ...cfg, probe: { ...cfg.probe, enabled: false } },
        edges: [edge('e1', { byCountry: unreachableIr, probeAgeMs: 60_000 })],
      }),
    );
    expect(off.hintLevel).toBe('reports');
    expect(off.edgeEvidence).toEqual([]);
    expect(off.probeSourcesDown).toBe(false);
  });

  test('freshness is per COUNTRY: a stale country row inside a fresh summary is not evidence', () => {
    const staleAfter = 2 * cfg.probe.intervalMinutes * 60_000;
    const ev = evaluate(
      input({
        edges: [
          edge('e1', {
            probeAgeMs: 60_000, // RU was refreshed a minute ago...
            byCountry: [
              c('IR', 'unreachable', { ageMs: staleAfter + 1 }), // ...but IR's verdict is old
              c('RU', 'reachable', { ageMs: 60_000 }),
            ],
          }),
        ],
      }),
    );
    expect(ev.probeScore).toBe(0);
    expect(ev.edgeEvidence).toEqual([]);
    expect(ev.probeSourcesDown).toBe(false);
    const fresh = evaluate(
      input({
        edges: [edge('e1', { byCountry: [c('IR', 'unreachable', { ageMs: staleAfter })] })],
      }),
    );
    expect(fresh.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'probes', countries: ['IR'] }]);
  });

  test('clearing needs clearAfterEvals quiet evaluations; a loud one resets the count', () => {
    const suspected = { state: 'suspected' as const, firstSeenAt: now - 60_000, quietEvals: 0 };
    const q1 = evaluate(input({ prev: suspected }));
    expect(q1.state).toBe('suspected');
    expect(q1.quietEvals).toBe(1);
    expect(q1.firstSeenAt).toBe(now - 60_000);
    const loudEv = evaluate(
      input({
        prev: { ...suspected, quietEvals: 2 },
        window: { reports: 12, distinctReporters: 10, countries: {}, byEdge: {} },
        usersOnline: 0,
      }),
    );
    expect(loudEv.quietEvals).toBe(0);
    const cleared = evaluate(input({ prev: { ...suspected, quietEvals: 2 } }));
    expect(cleared.state).toBe('clear');
    expect(cleared.transition).toBe('cleared');
    expect(cleared.firstSeenAt).toBeNull();
  });
});

describe('autoRotateDecision', () => {
  const suspectedEv = evaluate(
    input({
      window: loud,
      usersOnline: 0,
      edges: [edge('e1', { byCountry: [c('IR', 'unreachable')] }), edge('e2')],
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
  const on = {
    enabled: true,
    autoRotate: true,
    detect: { ...EDGE_DEFAULTS.detect, allowProbeOnlyAutoRotate: true },
  };
  const published = [
    { edgeId: 'e1', poolIndex: 0 },
    { edgeId: 'e2', poolIndex: 1 },
  ];
  const decide = (over: Partial<Parameters<typeof autoRotateDecision>[0]> = {}) =>
    autoRotateDecision({ evaluation: suspectedEv, cfg: on, origin, published, now, ...over });

  describe('with address lanes on', () => {
    // e1 carries the evidence. Open: it has its own budget and skips the caps.
    test('an open address is replaced on its own budget, past the cap and the cooldown', () => {
      const capped = {
        ...origin,
        rotationsToday: 3,
        cooldownUntil: now + 60_000,
      };
      expect(
        decide({ origin: capped, lanes: { openEdgeIds: ['e1'], openBudgetLeft: true } }),
      ).toMatchObject({ edgeId: 'e1' });
      expect(
        decide({
          origin: capped,
          lanes: { openEdgeIds: ['e1'], openBudgetLeft: true },
          fleet: { brakeEngaged: false, rotationsToday: 99, rotationsPerDay: 12 },
        }),
      ).toMatchObject({ edgeId: 'e1' });
      // The fleet brake (a mass block) still holds it.
      expect(
        decide({
          lanes: { openEdgeIds: ['e1'], openBudgetLeft: true },
          fleet: { brakeEngaged: true, rotationsToday: 0, rotationsPerDay: 12 },
        }),
      ).toEqual({ veto: 'fleet_brake' });
    });

    test('its budget spent: vetoed, never taken from the trusted lane', () => {
      expect(decide({ lanes: { openEdgeIds: ['e1'], openBudgetLeft: false } })).toEqual({
        veto: 'open_lane_budget',
      });
    });

    test('a trusted address keeps the caps', () => {
      expect(
        decide({
          origin: { ...origin, rotationsToday: 3 },
          lanes: { openEdgeIds: [], openBudgetLeft: true },
        }),
      ).toEqual({ veto: 'daily_cap' });
    });
  });

  describe('with delivery by country on (steering vetoes)', () => {
    const REALITY = { protocol: 'vless', streamTransport: 'raw', security: 'reality' } as const;
    const pub = (
      edgeId: string,
      poolIndex: number,
      over: Partial<PublishedEdge> = {},
    ): PublishedEdge => ({
      edgeId,
      poolIndex,
      provider: 'p1',
      listenerId: 'l1',
      listenerKey: 'a1',
      matchRule: { kind: 'remark', remark: 'r' },
      proto: REALITY,
      edgePort: 443,
      addresses: { v4: `203.0.113.${poolIndex + 1}` },
      serverNames: [{ sni: 'a.example', status: 'active' }],
      ...over,
    });
    const paths: DeliveryPath[] = [
      { format: 'links', canEmitV6: true },
      { format: 'clash', canEmitV6: false },
    ];
    const steer = (edges: PublishedEdge[], over: Partial<SteeringInput> = {}): SteeringInput => ({
      published: edges,
      paths,
      checked: ['IR', 'RU'],
      curated: ['IR', 'RU'],
      held: [],
      freedomListeners: ['a1'],
      ...over,
    });
    const blockedE1 = pub('e1', 0, { blockedIn: ['IR'] });

    test('steering off: rotates as today', () => {
      expect(decide()).toEqual({ edgeId: 'e1', source: 'probes' });
    });

    test('blocked in IR only, with a distinct IR-unblocked alternative on every path: country_scoped', () => {
      expect(decide({ steering: steer([blockedE1, pub('e2', 1)]) })).toEqual({
        veto: 'country_scoped',
      });
    });

    test('only NOT KNOWN in IR, beside another not-known edge: rotates (equal tiers)', () => {
      expect(decide({ steering: steer([pub('e1', 0), pub('e2', 1)]) })).toEqual({
        edgeId: 'e1',
        source: 'probes',
      });
    });

    test('self-selection: the only unblocked edge for IR is the chosen one: rotates', () => {
      expect(decide({ steering: steer([blockedE1, pub('e2', 1, { blockedIn: ['IR'] })]) })).toEqual(
        { edgeId: 'e1', source: 'probes' },
      );
    });

    test('an alternative unsuitable for a path rotates: another listener, or IPv6 only where a path cannot emit it', () => {
      expect(decide({ steering: steer([blockedE1, pub('e2', 1, { listenerKey: 'b2' })]) })).toEqual(
        { edgeId: 'e1', source: 'probes' },
      );
      expect(
        decide({
          steering: steer([blockedE1, pub('e2', 1, { addresses: { v6: '2001:db8::2' } })]),
        }),
      ).toEqual({ edgeId: 'e1', source: 'probes' });
      // Every name blocked in IR on an hrw1 listener.
      const names = [{ sni: 'a.example', status: 'active' as const, blockedIn: ['IR'] }];
      expect(
        decide({
          steering: steer([
            { ...blockedE1, sniPick: 'hrw1' },
            pub('e2', 1, { sniPick: 'hrw1', serverNames: names }),
          ]),
        }),
      ).toEqual({ edgeId: 'e1', source: 'probes' });
    });

    test('blocked in every checked country: rotates (it would only serve members outside the list)', () => {
      expect(
        decide({
          steering: steer([pub('e1', 0, { blockedIn: ['IR', 'RU'] }), pub('e2', 1)]),
        }),
      ).toEqual({ edgeId: 'e1', source: 'probes' });
    });

    test('the country-wide guard holds every evidence country: country_wide', () => {
      expect(decide({ steering: steer([pub('e1', 0), pub('e2', 1)], { held: ['IR'] }) })).toEqual({
        veto: 'country_wide',
      });
    });

    test('a held country and a routed-around one together still veto (neither justifies a burn)', () => {
      const both = { ...blockedE1, blockedIn: ['RU'] };
      const ev = evaluate(
        input({
          window: loud,
          usersOnline: 0,
          edges: [
            edge('e1', { byCountry: [c('IR', 'unreachable'), c('RU', 'unreachable')] }),
            edge('e2'),
          ],
        }),
      );
      // RU: routed around (e1 blocked there, e2 not); IR: under the country-wide guard.
      expect(
        decide({ evaluation: ev, steering: steer([both, pub('e2', 1)], { held: ['IR'] }) }),
      ).toEqual({ veto: 'country_scoped' });
      // Neither covered for IR (not held, not blocked on e1): rotates.
      expect(decide({ evaluation: ev, steering: steer([both, pub('e2', 1)]) })).toEqual({
        edgeId: 'e1',
        source: 'probes',
      });
    });

    test('a path that hands out the backup first needs two edges that are not blocked there', () => {
      const backupFirst: DeliveryPath[] = [{ format: 'links', canEmitV6: true, backupFirst: true }];
      // One alternative: the blocked edge would be the backup, the first address handed out.
      expect(
        decide({ steering: steer([blockedE1, pub('e2', 1)], { paths: backupFirst }) }),
      ).toEqual({ edgeId: 'e1', source: 'probes' });
      expect(
        decide({
          steering: steer([blockedE1, pub('e2', 1), pub('e3', 2)], { paths: backupFirst }),
        }),
      ).toEqual({ veto: 'country_scoped' });
    });

    test('mirrors without a choice avoid edges blocked anywhere: an alternative blocked elsewhere is not enough', () => {
      expect(decide({ steering: steer([blockedE1, pub('e2', 1, { blockedIn: ['RU'] })]) })).toEqual(
        { edgeId: 'e1', source: 'probes' },
      );
    });

    test('never on a listener that privacy-family members use (they are not steered)', () => {
      expect(
        decide({ steering: steer([blockedE1, pub('e2', 1)], { freedomListeners: [] }) }),
      ).toEqual({ edgeId: 'e1', source: 'probes' });
    });

    test('evidence from a country edges are not checked from changes nothing', () => {
      expect(decide({ steering: steer([blockedE1, pub('e2', 1)], { checked: ['RU'] }) })).toEqual({
        edgeId: 'e1',
        source: 'probes',
      });
    });
  });

  test('every gate must be open, in the documented order', () => {
    expect(decide({ cfg: { ...on, enabled: false } })).toEqual({ veto: 'edge_disabled' });
    expect(decide({ origin: { ...origin, autoRotate: false } })).toEqual({
      veto: 'auto_rotate_off',
    });
    // An origin a guided setup owns is never replaced automatically, whatever the evidence.
    expect(decide({ origin: { ...origin, setupOwned: true } })).toEqual({ veto: 'setup_owned' });
    // Nor is the leftover of a cancelled or failed one: it never went live.
    expect(decide({ origin: { ...origin, notLive: true } })).toEqual({ veto: 'not_live' });
    expect(decide({ evaluation: evaluate(input()) })).toEqual({ veto: 'not_suspected' });
    // Evidence + outage gates come BEFORE the operational ones: a quarantined
    // origin without evidence reports the missing evidence, not the quarantine.
    const originOnly = evaluate(input({ window: loud, usersOnline: 0 }));
    expect(decide({ evaluation: originOnly, origin: { ...origin, quarantined: true } })).toEqual({
      veto: 'no_edge_evidence',
    });
    expect(decide({ origin: { ...origin, quarantined: true } })).toEqual({ veto: 'quarantined' });
    expect(decide({ origin: { ...origin, rotationActive: true } })).toEqual({
      veto: 'rotation_active',
    });
    expect(decide({ origin: { ...origin, cooldownUntil: now + 1 } })).toEqual({ veto: 'cooldown' });
    expect(decide({ origin: { ...origin, rotationsToday: 3 } })).toEqual({ veto: 'daily_cap' });
    expect(decide({ origin: { ...origin, hostManaged: false } })).toEqual({
      veto: 'hosts_unmanaged',
    });
    expect(decide()).toEqual({ edgeId: 'e1', source: 'probes' });
  });

  test('a truncated report window never rotates, whatever the evidence says', () => {
    const incompleteEv = evaluate(
      input({
        window: { ...loud, incomplete: true },
        usersOnline: 0,
        edges: [edge('e1', { byCountry: [c('IR', 'unreachable')] }), edge('e2')],
      }),
    );
    expect(incompleteEv.windowIncomplete).toBe(true);
    // Same inputs, complete window: this one rotates.
    expect(decide()).toEqual({ edgeId: 'e1', source: 'probes' });
    expect(decide({ evaluation: incompleteEv })).toEqual({ veto: 'evidence_incomplete' });
    // It is still only a veto: an origin that is not suspected reports that first.
    expect(decide({ evaluation: { ...evaluate(input()), windowIncomplete: true } })).toEqual({
      veto: 'not_suspected',
    });
    // A complete window keeps the flag off.
    expect(suspectedEv.windowIncomplete).toBe(false);
  });

  test('origin-level suspicion alone never rotates; probe-only evidence needs the allow flag and live sources', () => {
    const originOnly = evaluate(input({ window: loud, usersOnline: 0 }));
    expect(decide({ evaluation: originOnly })).toEqual({ veto: 'no_edge_evidence' });
    expect(
      decide({ cfg: { ...on, detect: { ...on.detect, allowProbeOnlyAutoRotate: false } } }),
    ).toEqual({ veto: 'probe_only_disallowed' });
    expect(decide({ evaluation: { ...suspectedEv, probeSourcesDown: true } })).toEqual({
      veto: 'probe_sources_down',
    });
  });

  test('outage edges and unpublished edges are never rotation targets; member evidence is preferred', () => {
    expect(decide({ evaluation: { ...suspectedEv, outageEdges: ['e1'] } })).toEqual({
      veto: 'edge_outage',
    });
    expect(decide({ published: [{ edgeId: 'e2', poolIndex: 0 }] })).toEqual({
      veto: 'target_not_published',
    });
    const both = {
      ...suspectedEv,
      edgeEvidence: [
        { edgeId: 'e1', source: 'probes' as const, countries: ['IR'] },
        { edgeId: 'e2', source: 'reports' as const, countries: ['IR'] },
      ],
    };
    expect(decide({ evaluation: both })).toEqual({ edgeId: 'e2', source: 'reports' });
  });

  test('an offline node vetoes as node_offline even with member edge evidence (an outage, never a block)', () => {
    const ev = evaluate(
      input({
        window: { ...loud, byEdge: { e1: { count: 6, countries: { IR: 6 } } } },
        usersOnline: 0,
        nodeOnline: false,
        edges: [edge('e1', { byCountry: [c('IR', 'unreachable')] }), edge('e2')],
      }),
    );
    expect(ev.state).toBe('suspected');
    expect(ev.edgeEvidence).toEqual([{ edgeId: 'e1', source: 'reports', countries: ['IR'] }]);
    expect(decide({ evaluation: ev })).toEqual({ veto: 'node_offline' });
  });

  test('every published edge equally unreachable = a protocol-level block: rotation would change nothing', () => {
    const both = evaluate(
      input({
        edges: [
          edge('e1', { byCountry: [c('IR', 'unreachable'), c('RU', 'unreachable')] }),
          edge('e2', { byCountry: [c('RU', 'unreachable'), c('IR', 'unreachable')] }),
        ],
      }),
    );
    expect(both.state).toBe('suspected');
    expect(decide({ evaluation: both })).toEqual({ veto: 'protocol_level_block' });
    // Different country sets → an address-level block on one edge → rotate it.
    const differ = evaluate(
      input({
        edges: [
          edge('e1', { byCountry: [c('IR', 'unreachable'), c('RU', 'unreachable')] }),
          edge('e2', { byCountry: [c('IR', 'unreachable'), c('RU', 'reachable')] }),
        ],
      }),
    );
    expect(decide({ evaluation: differ })).toEqual({ edgeId: 'e1', source: 'probes' });
    // A single published edge cannot be told apart from a protocol block: it rotates.
    expect(decide({ evaluation: both, published: [{ edgeId: 'e1', poolIndex: 0 }] })).toEqual({
      edgeId: 'e1',
      source: 'probes',
    });
  });
});
