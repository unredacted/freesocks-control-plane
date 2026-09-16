/**
 * Cloudflare L7 edge adapter: PLACEHOLDER. One proxied DNS record in the
 * account's zone (+ an Origin Rule when the origin port is not the zone
 * mode's default). Replaced by the full adapter in this change; every method
 * refuses with `not_implemented` until then so nothing can allocate.
 */
import type {
  CloudflareConfig,
  Discovery,
  EdgeDescription,
  EdgeProvider,
  StepOutcome,
} from './types';
import { EdgeProviderError } from './http';
import { CloudflareTemplate, CLOUDFLARE_TEMPLATE_FIELDS, type CloudflareTemplateParams } from './templates';

export { CloudflareTemplate, CLOUDFLARE_TEMPLATE_FIELDS } from './templates';
export type { CloudflareTemplateParams } from './templates';

function notImplemented(step: string): EdgeProviderError {
  return new EdgeProviderError(`cloudflare ${step}: not implemented`, {
    provider: 'cloudflare',
    step,
    code: 'not_implemented',
    retryable: false,
    timedOut: false,
  });
}

export const cloudflareProvider: EdgeProvider<CloudflareConfig, CloudflareTemplateParams> = {
  id: 'cloudflare',
  templateSchema: CloudflareTemplate,
  templateFields: CLOUDFLARE_TEMPLATE_FIELDS,
  defaultTemplate: CloudflareTemplate.parse({}),
  async testCredentials() {
    return { ok: false, code: 'not_implemented' };
  },
  planProvision() {
    throw notImplemented('plan');
  },
  async runStep(): Promise<StepOutcome> {
    throw notImplemented('step');
  },
  async discover(): Promise<Discovery> {
    return { status: 'unresolved' };
  },
  async describe(): Promise<EdgeDescription> {
    return { state: 'pending', addresses: {}, health: 'unknown', code: 'not_implemented' };
  },
  async inspect() {
    throw notImplemented('inspect');
  },
  async inventory() {
    return { loadBalancers: [], ips: [], flavors: [] };
  },
  planDestroy: () => [],
  async runDestroy() {
    return { status: 'unresolved' };
  },
};
