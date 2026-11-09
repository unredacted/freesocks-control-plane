'use node';
/**
 * Gandi LiveDNS adapter: a DNS ACCOUNT only (`role: 'dns'`, `dnsOnly`).
 *
 * LiveDNS is plain DNS: nothing it serves is proxied, so a Gandi account never
 * fronts member traffic. It holds the records FCP writes for other fronts (a
 * Fastly or CloudFront front's certificate challenge and traffic name, a front
 * node's origin name, a load balancer address's name), which go through
 * `./dns/gandiDns.ts` like Cloudflare's go through `./dns/cloudflareDns.ts`.
 *
 * What this adapter itself answers is the account's half: the credential test,
 * the domains the token reaches (its locations, named by the domain itself:
 * LiveDNS has no zone ids) and a location's check. The edge lifecycle is never
 * reached (no edge is planned on a DNS-only account: `frontsAllowed` is false
 * and `l7Transports` is empty); its methods refuse, or answer that nothing
 * exists, so a stray call can neither build nor destroy anything.
 */
import { credentialTestFailure, EdgeProviderError, noteDiscoverError } from './http';
import {
  gandiDnsClient,
  gandiTokenRefused,
  gandiTokenRejected,
  listGandiDomains,
  normalizeDnsName,
} from './dns/gandiDns';
import { GandiTemplate, GANDI_TEMPLATE_FIELDS, type GandiTemplateParams } from './templates';
import type {
  CredentialTestResult,
  DiscoverResult,
  EdgeProvider,
  GandiConfig,
  LocationCheckResult,
} from './types';

function dnsOnly(step: string): EdgeProviderError {
  return new EdgeProviderError(`gandi builds no edge (${step})`, {
    provider: 'gandi',
    step,
    code: 'dns_only_provider',
    retryable: false,
    timedOut: false,
  });
}

/** The domains, with a refused token reported as `token_rejected`. */
async function domainsOf(apiToken: string, step: string) {
  try {
    return await listGandiDomains(apiToken, step);
  } catch (e) {
    if (gandiTokenRefused(e)) throw gandiTokenRejected(step, e as EdgeProviderError);
    throw e;
  }
}

export const gandiProvider: EdgeProvider<GandiConfig, GandiTemplateParams> = {
  id: 'gandi',
  templateSchema: GandiTemplate,
  templateFields: GANDI_TEMPLATE_FIELDS,
  defaultTemplate: GandiTemplate.parse({}),

  /**
   * The token is accepted by LiveDNS and reaches at least one domain. Which
   * domain holds a record is a location's, checked by `checkLocation`. A token
   * without the LiveDNS permission is refused (403) like a wrong one.
   */
  async testCredentials(cfg): Promise<CredentialTestResult> {
    try {
      const { domains, truncated } = await domainsOf(cfg.apiToken, 'test');
      if (domains.length === 0) return { ok: false, code: 'no_zones', detail: 'zones_none' };
      return {
        ok: true,
        detail: truncated ? `zones_${domains.length}_plus` : `zones_${domains.length}`,
      };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  /**
   * One domain (the location's) is usable: readable with this token, the name
   * the location recorded, and served by LiveDNS (`readZone` answers
   * `not_delegated` when the public NS records name other servers: records
   * written there would never resolve).
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    try {
      const zone = await gandiDnsClient({ ...cfg, accountId: '' }).readZone();
      const observed = { zoneStatus: zone.status };
      const out = (code?: string): LocationCheckResult => ({
        ok: !code,
        ...(code ? { code } : {}),
        detail: code ?? `zone_${zone.status}`,
        observed,
        label: zone.name,
        zoneName: zone.name,
      });
      if (cfg.zoneName && zone.name !== normalizeDnsName(cfg.zoneName))
        return out('zone_name_mismatch');
      if (zone.status !== 'active') return out('zone_not_active');
      return out();
    } catch (e) {
      if (gandiTokenRefused(e)) {
        const refused = gandiTokenRejected('location', e as EdgeProviderError);
        return { ok: false, code: 'zone_unreadable', detail: refused.meta.detail };
      }
      // A domain this token does not see: unreadable, not an outage.
      if (e instanceof EdgeProviderError && e.meta.status === 404)
        return { ok: false, code: 'zone_unreadable' };
      throw e;
    }
  },

  /** No regions: the places it offers are the domains the token reaches. */
  async listRegions(cfg) {
    return (await domainsOf(cfg.apiToken, 'zones')).domains.map((d) => ({ id: d, label: d }));
  },

  async discoverOptions(partial): Promise<DiscoverResult> {
    const apiToken = typeof partial.apiToken === 'string' ? partial.apiToken : '';
    if (!apiToken) return {};
    try {
      const { domains, truncated } = await domainsOf(apiToken, 'zones');
      return {
        zones: domains.map((d) => ({ id: d, label: d })),
        ...(truncated ? { truncated: ['zones'] } : {}),
      };
    } catch (e) {
      const out: DiscoverResult = {};
      noteDiscoverError(out, 'zones', e);
      return out;
    }
  },

  // --- the edge lifecycle: never reached on a DNS-only account ----------------------------
  planProvision() {
    throw dnsOnly('plan');
  },
  async runStep() {
    throw dnsOnly('run');
  },
  async discover() {
    return { status: 'confirmed_absent' };
  },
  async describe() {
    return { state: 'gone', addresses: {}, health: 'unknown' };
  },
  async inspect() {
    throw dnsOnly('inspect');
  },
  async inventory() {
    return { loadBalancers: [], ips: [], flavors: [] };
  },
  planDestroy: () => [],
  async runDestroy() {
    return { status: 'confirmed_gone' };
  },
};
