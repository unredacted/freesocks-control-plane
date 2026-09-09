/**
 * Block-detector scoring (pure). One evaluation per origin per tick combines:
 *  - member reports attributed to the origin inside the detector window (a
 *    deduplicated contribution per member per window, `detectorWeight`);
 *  - the node's live user count against its own baseline (a block empties a
 *    node; an outage does too, which is why probes, provider health and the
 *    node's own online bit veto);
 *  - external probe verdicts per published edge (edge-level evidence).
 * Origin-level evidence can only HINT. Edge-level evidence (probes, or members
 * who said which connection failed) is what an automatic rotation needs.
 */
import type { EdgeConfig } from '../edgeConfig';
import {
  probeScore as probeScoreOf,
  unreachableCountries,
  type CountryVerdict,
} from './probes/verdict';

export interface WindowReports {
  reports: number;
  /** Σ detectorWeight: deduplicated member contributions. */
  distinctReporters: number;
  countries: Record<string, number>;
  /** Deduplicated (Σ detectorWeight) reports whose member said which connection failed, per edge. */
  byEdge: Record<string, { count: number; countries: Record<string, number> }>;
}

export interface BaselineSample {
  /** When the sample was taken (epoch ms); drives time-of-day matching. */
  at: number;
  reports: number;
  distinctReporters: number;
  usersOnline: number | null;
}

export interface EdgeProbeState {
  edgeId: string;
  byCountry: Array<
    CountryVerdict & {
      /** Age of THIS country's newest contributing row, ms; absent = use `probeAgeMs`. */
      ageMs?: number;
    }
  >;
  /** The FCP-side probe ('XX'): unreachable = the edge is down for everyone. */
  internalVerdict: Verdict;
  providerHealth: string;
  /**
   * Age of the newest EXTERNAL (country) probe row, ms; null when never probed
   * from any country. The internal probe alone never makes an edge "fresh".
   */
  probeAgeMs: number | null;
}

export type Verdict = CountryVerdict['verdict'];

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
  /** The panel's online bit for the relay node; null = unknown. false = an outage, never a block. */
  nodeOnline: boolean | null;
  edges: EdgeProbeState[];
  cfg: Pick<EdgeConfig, 'detect' | 'probe'>;
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
  /** The relay node itself is offline per the panel: whatever else says, an outage. */
  nodeOffline: boolean;
  /** Which baseline the load score used. */
  loadBaseline: 'time_of_day' | 'flat' | 'none';
}

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
/** Time-of-day matching: same clock hour ±1h on PREVIOUS days (≥ 22h old, so yesterday's +1h side counts). */
const TOD_TOLERANCE_MS = HOUR;
const TOD_MIN_AGE_MS = 22 * HOUR;
const TOD_MIN_SAMPLES = 3;

const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
const mean = (xs: number[]) => (xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length);

/** Circular distance between two instants' times of day, ms. */
function timeOfDayDistance(a: number, b: number): number {
  const d = Math.abs((a % DAY) - (b % DAY));
  return Math.min(d, DAY - d);
}

/**
 * The load baseline: the mean of samples taken at the same time of day on
 * previous days when there are enough of them (load is diurnal: a quiet
 * afternoon is not a block), else the flat mean of every sample (dampened by
 * the caller, like a stale reading).
 */
export function loadBaseline(
  baseline: readonly BaselineSample[],
  now: number,
): { value: number; kind: 'time_of_day' | 'flat' | 'none' } {
  const withLoad = baseline.filter(
    (s): s is BaselineSample & { usersOnline: number } => typeof s.usersOnline === 'number',
  );
  if (withLoad.length === 0) return { value: 0, kind: 'none' };
  const sameHour = withLoad.filter(
    (s) => now - s.at >= TOD_MIN_AGE_MS && timeOfDayDistance(s.at, now) <= TOD_TOLERANCE_MS,
  );
  if (sameHour.length >= TOD_MIN_SAMPLES) {
    return { value: mean(sameHour.map((s) => s.usersOnline)), kind: 'time_of_day' };
  }
  return { value: mean(withLoad.map((s) => s.usersOnline)), kind: 'flat' };
}

export function evaluate(input: EvaluationInput): Evaluation {
  const { detect, probe } = input.cfg;
  const { window: w } = input;
  const baselineWarm = input.baseline.length >= detect.minBaselineSamples;
  const nodeOffline = input.nodeOnline === false;

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
  const base = loadBaseline(input.baseline, input.now);
  if (input.usersOnline !== null && base.value >= detect.minLoadUsers) {
    const drop = 1 - input.usersOnline / base.value;
    loadScore = clamp01(drop / (detect.loadDropPct / 100));
    // A stale reading, or a baseline that could not match the time of day, is
    // weaker evidence: the same dampening for both.
    if (input.loadStale || base.kind === 'flat') loadScore *= detect.staleWeight;
  }

  // --- probes ------------------------------------------------------------------------------
  // Probe evidence is per edge AND per country, and must be FRESH: a row older
  // than two intervals (or one left over from before probes were disabled) says
  // nothing about the edge now, so it neither scores nor counts as evidence.
  // The internal probe alone never makes an edge fresh (it is not a country).
  const staleAfterMs = 2 * probe.intervalMinutes * 60_000;
  const probeFresh = (e: EdgeProbeState) =>
    probe.enabled && e.probeAgeMs !== null && e.probeAgeMs <= staleAfterMs;
  const freshCountries = (e: EdgeProbeState): CountryVerdict[] =>
    e.byCountry.filter((c) => (c.ageMs ?? e.probeAgeMs ?? Infinity) <= staleAfterMs);
  // An offline node is an outage for every edge in front of it.
  const outageEdges = input.edges
    .filter(
      (e) => nodeOffline || e.internalVerdict === 'unreachable' || e.providerHealth === 'offline',
    )
    .map((e) => e.edgeId);
  const probeEdges = input.edges.filter((e) => !outageEdges.includes(e.edgeId) && probeFresh(e));
  const probeScore = probeEdges.length
    ? Math.max(...probeEdges.map((e) => probeScoreOf(freshCountries(e), probe.countries)))
    : 0;
  const probeSourcesDown = probe.enabled && input.edges.length > 0 && !input.edges.some(probeFresh);

  // --- evidence ----------------------------------------------------------------------------
  const edgeEvidence: EdgeEvidence[] = [];
  for (const e of probeEdges) {
    const countries = unreachableCountries(freshCountries(e));
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

  // --- combine -----------------------------------------------------------------------------
  const originBase = detect.requireLoadCorroboration
    ? 0.5 * reportScore + 0.5 * loadScore
    : clamp01(reportScore + 0.5 * loadScore);
  let score = clamp01(
    Math.max(originBase, detect.probeWeight * probeScore + (1 - detect.probeWeight) * originBase),
  );
  // A fresh, agreed probe verdict on a once-reachable edge is edge-level
  // evidence on its own: when the operator allows probe-only rotations it may
  // reach suspicion without members or load saying anything.
  if (detect.allowProbeOnlyAutoRotate && edgeEvidence.some((e) => e.source === 'probes')) {
    score = clamp01(Math.max(score, probeScore));
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
    nodeOffline,
    loadBaseline: base.kind,
  };
}

export type AutoRotateVeto =
  | 'edge_disabled'
  | 'auto_rotate_off'
  | 'not_suspected'
  | 'no_edge_evidence'
  | 'target_not_published'
  | 'node_offline'
  | 'edge_outage'
  | 'protocol_level_block'
  | 'probe_only_disallowed'
  | 'probe_sources_down'
  | 'quarantined'
  | 'rotation_active'
  | 'cooldown'
  | 'daily_cap'
  | 'hosts_unmanaged';

/**
 * Pick the edge an automatic rotation should replace, or the reason it must not
 * run. Gate order follows docs/edges.md § Detector: enabled, autoRotate (global
 * + relay), suspected, edge-level evidence, not an outage, no quarantine, no
 * running rotation, cooldown, daily cap, manageable Host.
 */
export function autoRotateDecision(args: {
  evaluation: Evaluation;
  cfg: Pick<EdgeConfig, 'enabled' | 'autoRotate' | 'detect'>;
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
  // 1. enabled  2. autoRotate (global, then the relay's own opt-in)
  if (!cfg.enabled || !cfg.autoRotate) return { veto: 'edge_disabled' };
  if (!origin.autoRotate) return { veto: 'auto_rotate_off' };
  // 3. suspected
  if (ev.state !== 'suspected') return { veto: 'not_suspected' };
  // 4. edge-level evidence on a published edge
  if (ev.edgeEvidence.length === 0) return { veto: 'no_edge_evidence' };
  const publishedIds = new Set(args.published.map((p) => p.edgeId));
  const evidence = ev.edgeEvidence.filter((e) => publishedIds.has(e.edgeId));
  if (evidence.length === 0) return { veto: 'target_not_published' };
  // 5. not an outage: the node is up, the edge itself answers, and the block is
  //    not on every published edge alike (then it is the protocol, not an address).
  if (ev.nodeOffline) return { veto: 'node_offline' };
  const candidates = evidence.filter((e) => !ev.outageEdges.includes(e.edgeId));
  if (candidates.length === 0) return { veto: 'edge_outage' };
  if (allPublishedEquallyUnreachable(ev, args.published)) return { veto: 'protocol_level_block' };
  const reportBacked = candidates.find((c) => c.source === 'reports');
  const chosen = reportBacked ?? candidates[0];
  if (chosen.source === 'probes' && !reportBacked) {
    if (!cfg.detect.allowProbeOnlyAutoRotate) return { veto: 'probe_only_disallowed' };
    if (ev.probeSourcesDown) return { veto: 'probe_sources_down' };
  }
  // 6. no quarantine  7. no running rotation  8. cooldown  9. daily cap
  if (origin.quarantined) return { veto: 'quarantined' };
  if (origin.rotationActive) return { veto: 'rotation_active' };
  if (origin.cooldownUntil !== null && origin.cooldownUntil > args.now) return { veto: 'cooldown' };
  if (origin.rotationsToday >= origin.maxRotationsPerDay) return { veto: 'daily_cap' };
  // 10. a manageable Host when the target holds index 0
  const idx = args.published.find((p) => p.edgeId === chosen.edgeId)?.poolIndex ?? -1;
  if (idx === 0 && !origin.hostManaged) return { veto: 'hosts_unmanaged' };
  return { edgeId: chosen.edgeId, source: chosen.source };
}

/**
 * Every published edge (≥2) shows probe evidence with the SAME unreachable
 * country set: the censor is matching the protocol, not an address, and a
 * replacement address would be blocked the same way. With one published edge
 * nothing can be told apart.
 */
function allPublishedEquallyUnreachable(
  ev: Evaluation,
  published: Array<{ edgeId: string }>,
): boolean {
  if (published.length < 2) return false;
  const sets: string[] = [];
  for (const p of published) {
    const probes = ev.edgeEvidence.find((e) => e.edgeId === p.edgeId && e.source === 'probes');
    if (!probes || probes.countries.length === 0) return false;
    sets.push([...probes.countries].sort().join(','));
  }
  return sets.every((s) => s === sets[0]);
}
