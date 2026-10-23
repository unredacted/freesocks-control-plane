/**
 * Sustained unreachability over stored edges (the rule itself is
 * `sustainedCountries` in ./verdict.ts): the listed countries an edge has
 * never been reached from, held unreachable long enough while another address
 * of its node is reached from there. The detector (edgeDetector.ts) reads it
 * as probe evidence, the per-country checks (edgeCountry.ts) as a block on the
 * address track. docs/edges.md "Block evidence from probes".
 */
import type { Doc } from '../../../_generated/dataModel';
import type { EdgeConfig } from '../../edgeConfig';
import { probeStaleAfterMs } from '../scoring';
import { sustainedCountries, type SummaryCountry, type Verdict } from './verdict';

type SummaryHolder = Pick<Doc<'edges'>, '_id' | 'reachability'>;

function summaryOf(e: SummaryHolder): SummaryCountry[] {
  return (e.reachability?.byCountry ?? []).map((c) => ({
    country: c.country,
    verdict: c.verdict as Verdict,
    ...(c.wasReachable !== undefined ? { wasReachable: c.wasReachable } : {}),
    ...(c.neverReached ? { neverReached: c.neverReached } : {}),
    lastAt: c.lastAt,
  }));
}

/**
 * The listed countries (`cfg.probe.countries`) `edge` is sustained-unreachable
 * from, against `siblings` (the other live addresses of its node; the edge
 * itself is ignored if passed). Only fresh verdicts count (two probe
 * intervals, like every probe evidence); nothing while probes are off.
 */
export function sustainedCountriesOf(
  edge: SummaryHolder,
  siblings: readonly SummaryHolder[],
  cfg: Pick<EdgeConfig, 'probe' | 'detect'>,
  now: number,
): string[] {
  if (!cfg.probe.enabled) return [];
  const staleAfterMs = probeStaleAfterMs(cfg.probe);
  return sustainedCountries(
    summaryOf(edge),
    siblings.filter((s) => s._id !== edge._id).map(summaryOf),
    cfg.probe.countries,
    {
      checks: cfg.detect.sustainedChecks,
      networks: cfg.detect.sustainedNetworks,
      minutes: cfg.detect.sustainedMinutes,
    },
    (c) => now - c.lastAt <= staleAfterMs,
  );
}

/**
 * The address itself is out (not a block): its provider reports it offline,
 * or FCP's own check of it fails. The detector's `outageEdges` rule, for the
 * callers that read evidence outside the detector.
 */
export function edgeOutage(e: Pick<Doc<'edges'>, 'health' | 'reachability'>): boolean {
  if (e.health === 'offline') return true;
  return (e.reachability?.byCountry ?? []).some(
    (c) => c.country === 'XX' && c.verdict === 'unreachable',
  );
}
