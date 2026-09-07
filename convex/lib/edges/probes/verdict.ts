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
 * Share of the configured countries where the edge is unreachable (mixed
 * counts half). Countries without a verdict count as nothing (not as ok).
 */
export function probeScore(
  byCountry: ReadonlyArray<{ country: string; verdict: Verdict }>,
  configured: readonly string[],
): number {
  if (configured.length === 0) return 0;
  let acc = 0;
  for (const c of configured) {
    const v = byCountry.find((b) => b.country === c)?.verdict;
    if (v === 'unreachable') acc += 1;
    else if (v === 'mixed') acc += 0.5;
  }
  return Math.min(1, acc / configured.length);
}

/** Countries where the edge is unreachable (the detector's edge-level evidence). */
export function unreachableCountries(
  byCountry: ReadonlyArray<{ country: string; verdict: Verdict }>,
): string[] {
  return byCountry.filter((b) => b.verdict === 'unreachable').map((b) => b.country);
}
