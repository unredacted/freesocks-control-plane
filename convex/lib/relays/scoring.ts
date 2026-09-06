/**
 * Block-detector scoring (pure). One evaluation per origin per tick combines:
 *  - member reports attributed to the origin inside the detector window (a
 *    deduplicated contribution per member per window, `detectorWeight`);
 *  - the node's live user count against its own baseline (a block empties a
 *    node; an outage does too, which is why probes and provider health veto);
 *  - external probe verdicts per published edge (edge-level evidence).
 * Origin-level evidence can only HINT. Edge-level evidence (probes, or members
 * who said which connection failed) is what an automatic rotation needs.
 */
import type { RelayConfig } from '../relayConfig';
import { probeScore as probeScoreOf, unreachableCountries, type Verdict } from './probes/verdict';

export interface WindowReports {
  reports: number;
  /** Σ detectorWeight: deduplicated member contributions. */
  distinctReporters: number;
  countries: Record<string, number>;
  /** Reports whose member said which connection failed, per edge. */
  byEdge: Record<string, { count: number; countries: Record<string, number> }>;
}

export interface BaselineSample {
  reports: number;
  distinctReporters: number;
  usersOnline: number | null;
}

export interface EdgeProbeState {
  edgeId: string;
  byCountry: Array<{ country: string; verdict: Verdict }>;
  /** The FCP-side probe ('XX'): unreachable = the edge is down for everyone. */
  internalVerdict: Verdict;
  providerHealth: string;
  /** Age of the newest probe summary, ms; null when never probed. */
  probeAgeMs: number | null;
}

export interface PrevSuspicion {
  state: 'clear' | 'suspected';
  firstSeenAt: number | null;
  quietEvals: number;
}

export interface EvaluationInput {
  now: number;
  window: WindowReports;
  baseline: BaselineSample[];
  usersOnline: number | null;
  loadStale: boolean;
  edges: EdgeProbeState[];
  cfg: Pick<RelayConfig, 'detect' | 'probe'>;
  prev: PrevSuspicion | null;
}

export type HintLevel = 'none' | 'reports' | 'probes' | 'corroborated';

export interface EdgeEvidence {
  edgeId: string;
  source: 'reports' | 'probes';
  countries: string[];
}

export interface Evaluation {
  state: 'clear' | 'suspected';
  hintLevel: HintLevel;
  score: number;
  reportScore: number;
  loadScore: number;
  probeScore: number;
  scope: 'global' | 'regional' | null;
  countries: Array<{ code: string; count: number }>;
  edgeEvidence: EdgeEvidence[];
  firstSeenAt: number | null;
  quietEvals: number;
  baselineWarm: boolean;
  /** 'suspected' | 'cleared' when the state flipped this evaluation. */
  transition: 'suspected' | 'cleared' | null;
  /** Edges whose probes look like an outage rather than a block (never rotate for these). */
  outageEdges: string[];
  probeSourcesDown: boolean;
}

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
const mean = (xs: number[]) => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);

export function evaluate(input: EvaluationInput): Evaluation {
  const { detect, probe } = input.cfg;
  const { window: w } = input;
  const baselineWarm = input.baseline.length >= detect.minBaselineSamples;

  // --- reports -----------------------------------------------------------------------------
  let reportScore = 0;
  if (w.distinctReporters >= detect.minReporters) {
    if (baselineWarm) {
      const baseReports = mean(input.baseline.map((s) => s.reports));
      const threshold = Math.max(detect.minReporters, baseReports * detect.spikeFactor);
      reportScore = clamp01(w.reports / threshold);
    } else {
      // Cold baseline: reporters alone, weakly.
      reportScore = clamp01(w.distinctReporters / (detect.minReporters * 2));
    }
  }

  // --- load --------------------------------------------------------------------------------
  let loadScore = 0;
  const baseLoad = mean(
    input.baseline.map((s) => s.usersOnline).filter((x): x is number => typeof x === 'number'),
  );
  if (input.usersOnline !== null && baseLoad >= detect.minLoadUsers) {
    const drop = 1 - input.usersOnline / baseLoad;
    loadScore = clamp01(drop / (detect.loadDropPct / 100));
    if (input.loadStale) loadScore *= detect.staleWeight;
  }

  // --- probes ------------------------------------------------------------------------------
  const outageEdges = input.edges
    .filter((e) => e.internalVerdict === 'unreachable' || e.providerHealth === 'offline')
    .map((e) => e.edgeId);
  const probeEdges = input.edges.filter((e) => !outageEdges.includes(e.edgeId));
  const probeScore = probeEdges.length
    ? Math.max(...probeEdges.map((e) => probeScoreOf(e.byCountry, probe.countries)))
    : 0;
  const probeSourcesDown =
    probe.enabled &&
    input.edges.length > 0 &&
    input.edges.every(
      (e) => e.probeAgeMs === null || e.probeAgeMs > 2 * probe.intervalMinutes * 60_000,
    );

  // --- combine -----------------------------------------------------------------------------
  const base = detect.requireLoadCorroboration
    ? 0.5 * reportScore + 0.5 * loadScore
    : clamp01(reportScore + 0.5 * loadScore);
  const score = clamp01(
    Math.max(base, detect.probeWeight * probeScore + (1 - detect.probeWeight) * base),
  );

  // --- evidence ----------------------------------------------------------------------------
  const edgeEvidence: EdgeEvidence[] = [];
  for (const e of probeEdges) {
    const countries = unreachableCountries(e.byCountry);
    if (countries.length > 0) edgeEvidence.push({ edgeId: e.edgeId, source: 'probes', countries });
  }
  const attributed = Object.values(w.byEdge).reduce((a, b) => a + b.count, 0);
  for (const [edgeId, v] of Object.entries(w.byEdge)) {
    if (v.count >= detect.minEdgeReporters && v.count / Math.max(1, attributed) >= 0.6) {
      edgeEvidence.push({
        edgeId,
        source: 'reports',
        countries: Object.entries(v.countries)
          .sort((a, b) => b[1] - a[1])
          .map(([c]) => c),
      });
    }
  }
  const reportsHint = reportScore > 0 || edgeEvidence.some((e) => e.source === 'reports');
  const probesHint = probeScore > 0 || edgeEvidence.some((e) => e.source === 'probes');
  const hintLevel: HintLevel =
    reportsHint && probesHint
      ? 'corroborated'
      : probesHint
        ? 'probes'
        : reportsHint
          ? 'reports'
          : 'none';

  // --- geography ---------------------------------------------------------------------------
  const countries = Object.entries(w.countries)
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);
  const totalC = countries.reduce((a, c) => a + c.count, 0);
  const scope: Evaluation['scope'] =
    totalC === 0 ? null : countries[0].count / totalC >= 0.6 ? 'regional' : 'global';

  // --- state -------------------------------------------------------------------------------
  const prev = input.prev ?? { state: 'clear' as const, firstSeenAt: null, quietEvals: 0 };
  let state = prev.state;
  let quietEvals = prev.quietEvals;
  let firstSeenAt = prev.firstSeenAt;
  let transition: Evaluation['transition'] = null;
  if (prev.state === 'suspected') {
    if (score < detect.clearBelow) {
      quietEvals += 1;
      if (quietEvals >= detect.clearAfterEvals) {
        state = 'clear';
        firstSeenAt = null;
        quietEvals = 0;
        transition = 'cleared';
      }
    } else {
      quietEvals = 0;
    }
  } else if (score >= detect.suspectAt) {
    state = 'suspected';
    firstSeenAt = input.now;
    quietEvals = 0;
    transition = 'suspected';
  }

  return {
    state,
    hintLevel,
    score,
    reportScore,
    loadScore,
    probeScore,
    scope,
    countries,
    edgeEvidence,
    firstSeenAt,
    quietEvals,
    baselineWarm,
    transition,
    outageEdges,
    probeSourcesDown,
  };
}

export type AutoRotateVeto =
  | 'relay_disabled'
  | 'auto_rotate_off'
  | 'not_suspected'
  | 'no_edge_evidence'
  | 'probe_only_disallowed'
  | 'probe_sources_down'
  | 'edge_outage'
  | 'quarantined'
  | 'rotation_active'
  | 'cooldown'
  | 'daily_cap'
  | 'hosts_unmanaged'
  | 'target_not_published';

/** Pick the edge an automatic rotation should replace, or the reason it must not run. */
export function autoRotateDecision(args: {
  evaluation: Evaluation;
  cfg: Pick<RelayConfig, 'enabled' | 'autoRotate' | 'detect'>;
  origin: {
    autoRotate: boolean;
    quarantined: boolean;
    rotationActive: boolean;
    cooldownUntil: number | null;
    rotationsToday: number;
    maxRotationsPerDay: number;
    hostManaged: boolean;
  };
  published: Array<{ edgeId: string; poolIndex: number }>;
  now: number;
}): { edgeId: string; source: 'reports' | 'probes' } | { veto: AutoRotateVeto } {
  const { evaluation: ev, cfg, origin } = args;
  if (!cfg.enabled || !cfg.autoRotate) return { veto: 'relay_disabled' };
  if (!origin.autoRotate) return { veto: 'auto_rotate_off' };
  if (ev.state !== 'suspected') return { veto: 'not_suspected' };
  if (origin.quarantined) return { veto: 'quarantined' };
  if (origin.rotationActive) return { veto: 'rotation_active' };
  if (origin.cooldownUntil !== null && origin.cooldownUntil > args.now) return { veto: 'cooldown' };
  if (origin.rotationsToday >= origin.maxRotationsPerDay) return { veto: 'daily_cap' };
  const publishedIds = new Set(args.published.map((p) => p.edgeId));
  const candidates = ev.edgeEvidence.filter(
    (e) => publishedIds.has(e.edgeId) && !ev.outageEdges.includes(e.edgeId),
  );
  if (candidates.length === 0) {
    if (
      ev.edgeEvidence.length > 0 &&
      ev.edgeEvidence.every((e) => ev.outageEdges.includes(e.edgeId))
    ) {
      return { veto: 'edge_outage' };
    }
    return { veto: ev.edgeEvidence.length > 0 ? 'target_not_published' : 'no_edge_evidence' };
  }
  const reportBacked = candidates.find((c) => c.source === 'reports');
  const chosen = reportBacked ?? candidates[0];
  if (chosen.source === 'probes' && !reportBacked) {
    if (!cfg.detect.allowProbeOnlyAutoRotate) return { veto: 'probe_only_disallowed' };
    if (ev.probeSourcesDown) return { veto: 'probe_sources_down' };
  }
  const idx = args.published.find((p) => p.edgeId === chosen.edgeId)?.poolIndex ?? -1;
  if (idx === 0 && !origin.hostManaged) return { veto: 'hosts_unmanaged' };
  return { edgeId: chosen.edgeId, source: chosen.source };
}
