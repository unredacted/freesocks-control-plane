/**
 * Reachability verdicts. Per (edge, country, SOURCE) first, then across
 * sources per country. `unreachable` is deliberately hard to reach: it needs
 * agreement (≥ `agreementVantages` distinct failing networks within a source,
 * and either a second source or ≥2 networks overall) with NO success anywhere;
 * `reachable` needs one eyeball success or two datacenter successes.
 */
import type { ProbeResult, ProbeSource } from './types';

export type Verdict = 'reachable' | 'unreachable' | 'mixed' | 'unknown';

export interface SourceSummary {
  source: ProbeSource;
  verdict: Verdict;
  okVantages: number;
  failVantages: number;
  /** Distinct failing networks (ASN, else network name, else one shared "unknown" bucket). */
  failNetworks: string[];
}

/**
 * The failing network a result belongs to. A result that identifies neither an
 * ASN nor a network is NOT its own network: counting one bucket per result
 * would let a single source fabricate agreement out of N vantages that may all
 * sit in the same AS, so every such result collapses into `<source>:unknown`.
 */
function networkKey(r: ProbeResult, source: ProbeSource): string {
  return r.asn ?? r.network ?? `${source}:unknown`;
}

/** One country, one source, results inside the window. */
export function sourceVerdict(
  source: ProbeSource,
  results: readonly ProbeResult[],
  agreementVantages: number,
): SourceSummary {
  const ok = results.filter((r) => r.ok);
  const fail = results.filter((r) => !r.ok);
  const failNetworks = [...new Set(fail.map((r) => networkKey(r, source)))];
  let verdict: Verdict = 'unknown';
  if (ok.length === 0 && fail.length > 0 && failNetworks.length >= Math.max(1, agreementVantages)) {
    verdict = 'unreachable';
  } else if (
    ok.some((r) => r.vantageClass === 'eyeball') ||
    ok.filter((r) => r.vantageClass !== 'eyeball').length >= 2
  ) {
    verdict = fail.length > 0 && fail.length >= ok.length ? 'mixed' : 'reachable';
  } else if (ok.length > 0 && fail.length > 0) {
    verdict = 'mixed';
  } else if (ok.length === 1 && fail.length === 0) {
    // A single non-eyeball success is weak evidence; still not "unreachable".
    verdict = 'unknown';
  }
  return { source, verdict, okVantages: ok.length, failVantages: fail.length, failNetworks };
}

/** Across sources for one country. */
export function countryVerdict(perSource: readonly SourceSummary[]): Verdict {
  const withData = perSource.filter((s) => s.okVantages + s.failVantages > 0);
  if (withData.length === 0) return 'unknown';
  const reachable = withData.filter((s) => s.verdict === 'reachable');
  const unreachable = withData.filter((s) => s.verdict === 'unreachable');
  const anyOk = withData.some((s) => s.okVantages > 0);
  if (reachable.length > 0) return unreachable.length > 0 ? 'mixed' : 'reachable';
  if (unreachable.length > 0 && !anyOk) {
    const networks = new Set(unreachable.flatMap((s) => s.failNetworks));
    if (unreachable.length >= 2 || networks.size >= 2) return 'unreachable';
  }
  if (withData.some((s) => s.verdict === 'mixed') || (unreachable.length > 0 && anyOk))
    return 'mixed';
  return 'unknown';
}

/**
 * One country across a target's listener PORTS (each port's verdict is the
 * cross-source `countryVerdict` of that port's rows). A blocked listener
 * blocks that slot, so any `unreachable` port makes the country unreachable;
 * `mixed` passes through next (a single-port target keeps its verdict);
 * `reachable` needs every port with a verdict to be reachable; otherwise
 * `unknown`. Ports without a verdict (`unknown`) never veto the others.
 */
export function portRollup(perPort: readonly Verdict[]): Verdict {
  const decided = perPort.filter((v) => v !== 'unknown');
  if (decided.length === 0) return 'unknown';
  if (decided.includes('unreachable')) return 'unreachable';
  if (decided.includes('mixed')) return 'mixed';
  return 'reachable';
}

/** One country's cross-source verdict plus whether the target was ever reachable from there. */
export interface CountryVerdict {
  country: string;
  verdict: Verdict;
  /**
   * The target had a `reachable` verdict from this country earlier. A
   * TRANSITION reachable → unreachable is block evidence. A country that has
   * never reached the target says nothing on its own (a provider range the
   * country never carried, a fresh edge nobody has tried yet), unless the
   * failure is `sustained`.
   */
  wasReachable: boolean;
  /**
   * Never reached from this country, and held unreachable long enough while
   * the node's other addresses reach it from there (`sustainedCountries`):
   * block evidence like a transition.
   */
  sustained?: boolean;
}

/** A country whose verdict is block evidence: a transition, or sustained unreachability. */
const blockEvidence = (b: CountryVerdict) => b.wasReachable || b.sustained === true;

/**
 * Worst configured country: 1 when any configured country the target was once
 * reachable from (or is sustained-unreachable from) is now `unreachable` (an
 * agreed verdict IS the block signal; a share across countries would only
 * dilute a single-country block), 0.5 when the worst is `mixed`, else 0.
 * Countries without a verdict count as nothing.
 */
export function probeScore(
  byCountry: ReadonlyArray<CountryVerdict>,
  configured: readonly string[],
): number {
  let worst = 0;
  for (const c of configured) {
    const b = byCountry.find((x) => x.country === c);
    if (!b || !blockEvidence(b)) continue;
    if (b.verdict === 'unreachable') return 1;
    if (b.verdict === 'mixed') worst = Math.max(worst, 0.5);
  }
  return worst;
}

/**
 * Countries where the target is unreachable as block evidence (the detector's
 * edge-level evidence): once reachable from there, or sustained-unreachable.
 */
export function unreachableCountries(byCountry: ReadonlyArray<CountryVerdict>): string[] {
  return byCountry
    .filter((b) => b.verdict === 'unreachable' && blockEvidence(b))
    .map((b) => b.country);
}

// --- sustained unreachability ------------------------------------------------------------------

/** What sustained unreachability needs (`edge.detect.sustained*`). */
export interface SustainedRule {
  /** Failing checks (vantage answers) on record. */
  checks: number;
  /** Distinct networks among them. */
  networks: number;
  /** Between the first of them and the newest. */
  minutes: number;
}

/** A summary's record of a country that never reached the target (probes.ts `refreshTargetSummary`). */
export interface NeverReached {
  checks: number;
  networks: number;
  /** The first failing check on record. */
  since: number;
  /** The newest. */
  lastAt: number;
}

/** One country of a target's summary (`edges.reachability.byCountry`), as the rule reads it. */
export interface SummaryCountry {
  country: string;
  verdict: Verdict;
  wasReachable?: boolean;
  neverReached?: NeverReached;
  /** The country's newest contributing row. */
  lastAt: number;
}

/**
 * The address's own half of sustained unreachability, from one country: its
 * sources agree it is unreachable now, nothing ever reached it from there over
 * the member-facing path, and the failing checks on record meet the rule.
 */
export function sustainedBlock(
  c: Pick<SummaryCountry, 'verdict' | 'wasReachable' | 'neverReached'>,
  rule: SustainedRule,
): boolean {
  const n = c.neverReached;
  if (c.verdict !== 'unreachable' || c.wasReachable || !n) return false;
  return (
    n.checks >= rule.checks &&
    n.networks >= rule.networks &&
    n.lastAt - n.since >= rule.minutes * 60_000
  );
}

/**
 * Sustained unreachability: the block evidence for an address that has NEVER
 * been reached from a country, where the transition rule cannot fire (an
 * address blocked there from the first probe on). A listed country counts when,
 * all of:
 *
 *  - the address's own fresh verdict there is `unreachable`, nothing ever
 *    reached it from there, and the failing checks meet the rule
 *    (`sustainedBlock`; never the IPv6 path, never a check that could not test);
 *  - the address is reached from ELSEWHERE (another country's fresh verdict is
 *    `reachable`): one nobody reaches is broken, not blocked;
 *  - ANOTHER address of the same node and listener (`siblings`) is reached from
 *    THAT country (fresh): the vantages there work, and the listener's port and
 *    protocol get through. A vantage outage, or a block on the protocol, fails
 *    every such address alike.
 *
 * An outage (the node offline, the address's own internal check failing, its
 * provider down) is the caller's veto, as for any probe evidence.
 */
export function sustainedCountries(
  own: readonly SummaryCountry[],
  siblings: ReadonlyArray<readonly SummaryCountry[]>,
  listed: readonly string[],
  rule: SustainedRule,
  isFresh: (c: SummaryCountry) => boolean,
): string[] {
  const fresh = (xs: readonly SummaryCountry[]) =>
    xs.filter((c) => c.country !== 'XX' && isFresh(c));
  const mine = fresh(own);
  const others = siblings.map(fresh);
  return listed.filter((country) => {
    const c = mine.find((x) => x.country === country);
    if (!c || !sustainedBlock(c, rule)) return false;
    if (!mine.some((x) => x.country !== country && x.verdict === 'reachable')) return false;
    return others.some((s) => s.some((x) => x.country === country && x.verdict === 'reachable'));
  });
}
