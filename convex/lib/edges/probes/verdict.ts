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
  /** Distinct failing networks (ASN, else network name, else a per-result key). */
  failNetworks: string[];
}

function networkKey(r: ProbeResult, i: number): string {
  return r.asn ?? r.network ?? `v${i}`;
}

/** One country, one source, results inside the window. */
export function sourceVerdict(
  source: ProbeSource,
  results: readonly ProbeResult[],
  agreementVantages: number,
): SourceSummary {
  const ok = results.filter((r) => r.ok);
  const fail = results.filter((r) => !r.ok);
  const failNetworks = [...new Set(fail.map((r, i) => networkKey(r, i)))];
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
   * The target had a `reachable` verdict from this country earlier. Only a
   * TRANSITION reachable → unreachable is block evidence: a country that has
   * never reached the target says nothing about a block (a provider range the
   * country never carried, a fresh edge nobody has tried yet).
   */
  wasReachable: boolean;
}

/**
 * Worst configured country: 1 when any configured country the target was once
 * reachable from is now `unreachable` (an agreed verdict IS the block signal; a
 * share across countries would only dilute a single-country block), 0.5 when
 * the worst is `mixed`, else 0. Countries without a verdict count as nothing.
 */
export function probeScore(
  byCountry: ReadonlyArray<CountryVerdict>,
  configured: readonly string[],
): number {
  let worst = 0;
  for (const c of configured) {
    const b = byCountry.find((x) => x.country === c);
    if (!b || !b.wasReachable) continue;
    if (b.verdict === 'unreachable') return 1;
    if (b.verdict === 'mixed') worst = Math.max(worst, 0.5);
  }
  return worst;
}

/** Countries where a once-reachable target is now unreachable (the detector's edge-level evidence). */
export function unreachableCountries(byCountry: ReadonlyArray<CountryVerdict>): string[] {
  return byCountry
    .filter((b) => b.verdict === 'unreachable' && b.wasReachable)
    .map((b) => b.country);
}
