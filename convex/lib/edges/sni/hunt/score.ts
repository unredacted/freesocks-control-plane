/**
 * How a candidate name is judged and ranked (pure; unit-tested; docs/edges.md
 * "Finding names").
 *
 * The GATE is qualification itself: a candidate passes only with the `q_*`
 * verdict FCP's own qualification would give it (`judgeHandshake` plus the
 * network check), so nothing ranks a name that could not be added. Then a
 * score out of 100:
 *
 *  - `baseScore`: what every checked candidate has (popularity, how many
 *    passing names its address serves, ML-KEM and h2, stability). The
 *    shortlist that gets evidence is chosen by it, never by `score`, so
 *    evidence a few candidates already have cannot keep the others out.
 *  - `score`: `baseScore` plus the evidence parts (near the node, standing per
 *    country). Missing or expired evidence counts as HALF its part, so a
 *    measured good candidate ranks above an unmeasured one and a measured bad
 *    one below it. Penalties (a block signal) come off last.
 */

export const SCORE_PARTS = {
  popularity: 25,
  cluster: 10,
  tls: 10,
  stability: 5,
  near: 30,
  country: 20,
} as const;

/** Points for popularity by rank in the top-sites list (unknown: none). */
export function popularityPoints(rank: number | undefined): number {
  if (!rank || rank < 1) return 0;
  const share = Math.max(0.1, Math.min(1, (6 - Math.log10(rank)) / 2.5));
  return Math.round(share * SCORE_PARTS.popularity * 10) / 10;
}

/** Points for how near the node the endpoint answers (connect ms from the node's place). */
export function nearPoints(connectMs: number): number {
  if (connectMs <= 15) return 30;
  if (connectMs <= 35) return 22;
  if (connectMs <= 80) return 12;
  if (connectMs <= 150) return 4;
  return 0;
}

/** Points for stability: passing checks at least a day apart. */
export function stabilityPoints(passes: number): number {
  return [0, 1, 3, 5][Math.max(0, Math.min(3, Math.floor(passes)))]!;
}

export interface ScoreInput {
  rank?: number;
  /** Qualification's verdict: null when the candidate passed, a `q_*` code when it did not. */
  code: string | null | undefined;
  alpn?: string;
  mlkem?: boolean;
  passes: number;
  /** Passing candidates of the scope on its first address, itself included. */
  cluster: number;
  /** Fresh near-the-node points (0..30), or undefined when not measured or expired. */
  near?: number;
  /** Fresh per-country points (0..20), or undefined. */
  country?: number;
  /** Points to take off (a block signal). */
  penalty?: number;
}

export interface ScoreParts {
  popularity: number;
  cluster: number;
  tls: number;
  stability: number;
  near: number | null;
  country: number | null;
  penalty: number;
}

export function scoreCandidate(i: ScoreInput): {
  passed: boolean;
  baseScore: number;
  score: number;
  parts: ScoreParts;
} {
  const passed = i.code === null;
  const popularity = popularityPoints(i.rank);
  if (!passed) {
    // Not addable: ranked under every passing candidate, by popularity only.
    const parts: ScoreParts = {
      popularity,
      cluster: 0,
      tls: 0,
      stability: 0,
      near: null,
      country: null,
      penalty: 0,
    };
    return { passed, baseScore: 0, score: 0, parts };
  }
  const cluster = Math.min(SCORE_PARTS.cluster, Math.max(0, i.cluster));
  const tls = (i.mlkem ? 5 : 0) + (i.alpn === 'h2' ? 5 : 0);
  const stability = stabilityPoints(i.passes);
  const base = round(popularity + cluster + tls + stability);
  const near = i.near === undefined ? null : Math.max(0, Math.min(SCORE_PARTS.near, i.near));
  const country =
    i.country === undefined ? null : Math.max(0, Math.min(SCORE_PARTS.country, i.country));
  const penalty = Math.max(0, i.penalty ?? 0);
  const evidence = (near ?? SCORE_PARTS.near / 2) + (country ?? SCORE_PARTS.country / 2);
  const score = round(Math.max(0, Math.min(100, base + evidence - penalty)));
  return {
    passed,
    baseScore: base,
    score,
    parts: { popularity, cluster, tls, stability, near, country, penalty },
  };
}

function round(x: number): number {
  return Math.round(x * 10) / 10;
}

// --- states -------------------------------------------------------------------------------------

export type CandidateState = 'new' | 'added' | 'ignored' | 'gone' | 'failing';

/**
 * A candidate's state after a check. An operator's `ignored` and an `added`
 * candidate keep theirs. A candidate that was on its network and now resolves
 * off it is `gone` (the upkeep deletes it after a while); any other failure is
 * `failing`, and a pass makes it `new` (ready) again.
 */
export function stateAfterCheck(
  prev: CandidateState,
  code: string | null,
  wasOnNetwork: boolean,
): CandidateState {
  if (prev === 'ignored' || prev === 'added') return prev;
  if (code === null) return 'new';
  if (code === 'q_off_network' && wasOnNetwork) return 'gone';
  if (code === 'q_off_network' && prev === 'gone') return 'gone';
  return 'failing';
}

/** A pass counts towards stability only a day after the last one that did. */
export const PASS_SPACING_MS = 24 * 3_600_000;

export function passesAfterCheck(
  prev: { passes: number; lastPassAt?: number },
  passed: boolean,
  now: number,
): { passes: number; lastPassAt?: number } {
  if (!passed) return { passes: 0 };
  if (prev.lastPassAt === undefined || now - prev.lastPassAt >= PASS_SPACING_MS)
    return { passes: prev.passes + 1, lastPassAt: now };
  return { passes: prev.passes, lastPassAt: prev.lastPassAt };
}
