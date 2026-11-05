/**
 * The name checks' part of `probe.globalpingTestsPerHour` as configured now
 * (lib/edges/probes/globalpingAccount.ts `namesShare`): read by the probe
 * rounds (what they leave free), the checks of names from inside countries
 * and the hunt's timing (their budgets under the cap).
 */
import type { DatabaseReader } from '../../../_generated/server';
import { resolveEdgeConfig, resolveEdgeSecrets } from '../../edgeConfig';
import {
  resolveSniConfig,
  resolveSniHuntConfig,
  resolveSniVantageConfig,
  usableSources,
  vantageCountries,
} from '../../sniConfig';
import { namesShare, type NamesShare } from './globalpingAccount';

export async function resolveGlobalpingShare(db: DatabaseReader): Promise<NamesShare> {
  const [edge, sni, vantage, hunt, secrets] = await Promise.all([
    resolveEdgeConfig(db),
    resolveSniConfig(db),
    resolveSniVantageConfig(db),
    resolveSniHuntConfig(db),
    resolveEdgeSecrets(db),
  ]);
  const sources = usableSources(vantage, secrets);
  return namesShare({
    perHour: edge.probe.globalpingTestsPerHour,
    vantage: {
      on:
        sni.enabled &&
        vantage.enabled &&
        sources.includes('globalping') &&
        vantageCountries(vantage, sni.curatedCountries).length > 0,
      hourlyBudget: vantage.hourlyBudget,
      perCountryLimit: vantage.perCountryLimit,
      sources: sources.length,
    },
    huntChecks: hunt.enabled,
    huntTiming: { on: hunt.enabled, perHour: hunt.timingPerHour },
  });
}
