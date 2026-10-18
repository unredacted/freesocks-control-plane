/**
 * The block simulator (docs/edges.md "Simulating a block on a test
 * deployment"): a beta or local deployment cannot produce real censorship, so
 * an operator can make the block detector believe one published edge is
 * blocked in one country, and watch the real path run end to end (scoring,
 * suspicion, the fleet guards, the start checks, the rotation machine, the burn
 * drain, the epoch, the member's subscription).
 *
 * Nothing fake is ever written to the detector's real inputs (member reports,
 * probe rows, baseline samples): a live simulation is overlaid on a COPY of
 * them right before `evaluate`. Pure; the table and the mutations live in
 * convex/edgeSimulations.ts.
 */
import type { EdgeProbeState, WindowReports } from './scoring';

/**
 * Whether this deployment accepts test block evidence. `ENVIRONMENT` alone
 * cannot tell a beta stack from production (beta runs `production`), so it
 * takes an explicit opt-in value, read on every call: removing it silences
 * every live simulation at the next detector pass. Local development needs none.
 */
export function blockSimulatorAllowedIn(env: Record<string, string | undefined>): boolean {
  return env.ENVIRONMENT === 'development' || env.EDGE_SIMULATOR_ALLOW === 'simulate-blocks';
}

/** How long a simulation lasts when the operator does not say (minutes), and the bounds. */
export const SIMULATION_DEFAULT_MINUTES = 60;
export const SIMULATION_MINUTES = { min: 15, max: 360 } as const;
/** Simulated reporters: at least one, at most a crowd no beta needs. */
export const SIMULATION_REPORTERS = { min: 1, max: 50 } as const;
/** Live simulations per deployment (a test, not a fleet event). */
export const MAX_LIVE_SIMULATIONS = 3;
/** Ended simulations are kept this long for the record, then deleted. */
export const SIMULATION_RETENTION_MS = 30 * 24 * 60 * 60_000;

/**
 * The default number of simulated reporters: twice the detector's minimum. With
 * the shipped detection settings (load corroboration on, a cold or quiet warm
 * baseline) that scores 0.5 x 1 + 0.5 x 0.5 = 0.75 against a 0.6 threshold
 * once the probe side reads unreachable, so no detector setting has to change.
 */
export function defaultSimulatedReporters(minReporters: number): number {
  return Math.min(SIMULATION_REPORTERS.max, Math.max(SIMULATION_REPORTERS.min, 2 * minReporters));
}

/** One live simulation as the detector consumes it (the shared input of a per-country detector, too). */
export interface SimulatedEvidence {
  edgeId: string;
  country: string;
  reporters: number;
}

/**
 * The detector's inputs with the simulations laid over them, as NEW objects
 * (the originals are never touched, so the real counts still reach the
 * baseline sample). For each simulation:
 *  - reports: `reporters` more distinct reporters and reports in the window,
 *    counted for its country and attributed to its edge, so the per-edge
 *    evidence rule (enough reporters, 60 % of the attributed ones) holds;
 *  - probes: its edge reads `unreachable` from its country, once reachable and
 *    measured just now, and the edge itself counts as freshly probed (the
 *    detector drops an edge with no fresh probe before it reads any country).
 *    Only that (edge, country) is overridden; every other row stays real.
 * Simulations for an edge that is not in `edges` (no longer published) add
 * nothing.
 */
export function applySimulatedEvidence(
  window: WindowReports,
  edges: EdgeProbeState[],
  sims: ReadonlyArray<SimulatedEvidence>,
): { window: WindowReports; edges: EdgeProbeState[] } {
  const out: WindowReports = {
    ...window,
    countries: { ...window.countries },
    byEdge: Object.fromEntries(
      Object.entries(window.byEdge).map(([id, e]) => [
        id,
        { count: e.count, countries: { ...e.countries } },
      ]),
    ),
  };
  const outEdges: EdgeProbeState[] = edges.map((e) => ({
    ...e,
    byCountry: e.byCountry.map((c) => ({ ...c })),
  }));
  for (const sim of sims) {
    const edge = outEdges.find((e) => e.edgeId === sim.edgeId);
    if (!edge) continue;
    out.reports += sim.reporters;
    out.distinctReporters += sim.reporters;
    out.countries[sim.country] = (out.countries[sim.country] ?? 0) + sim.reporters;
    const attributed = (out.byEdge[sim.edgeId] ??= { count: 0, countries: {} });
    attributed.count += sim.reporters;
    attributed.countries[sim.country] = (attributed.countries[sim.country] ?? 0) + sim.reporters;
    edge.byCountry = [
      ...edge.byCountry.filter((c) => c.country !== sim.country),
      { country: sim.country, verdict: 'unreachable', wasReachable: true, ageMs: 0 },
    ];
    edge.probeAgeMs = 0;
  }
  return { window: out, edges: outEdges };
}
