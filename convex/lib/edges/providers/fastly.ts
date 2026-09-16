/**
 * Fastly L7 edge adapter: PLACEHOLDER. A service + backend + WebSockets
 * snippet/product + domain + TLS subscription, with DNS records written into
 * the referenced Cloudflare account. Replaced by the full adapter in this
 * change; every method refuses with `not_implemented` until then.
 */
import type { Discovery, EdgeDescription, EdgeProvider, FastlyConfig, StepOutcome } from './types';
import { EdgeProviderError } from './http';
import { FastlyTemplate, FASTLY_TEMPLATE_FIELDS, type FastlyTemplateParams } from './templates';

export { FastlyTemplate, FASTLY_TEMPLATE_FIELDS } from './templates';
export type { FastlyTemplateParams } from './templates';

function notImplemented(step: string): EdgeProviderError {
  return new EdgeProviderError(`fastly ${step}: not implemented`, {
    provider: 'fastly',
    step,
    code: 'not_implemented',
    retryable: false,
    timedOut: false,
  });
}

export const fastlyProvider: EdgeProvider<FastlyConfig, FastlyTemplateParams> = {
  id: 'fastly',
  templateSchema: FastlyTemplate,
  templateFields: FASTLY_TEMPLATE_FIELDS,
  defaultTemplate: FastlyTemplate.parse({}),
  async testCredentials() {
    return { ok: false, code: 'not_implemented' };
  },
  planProvision() {
    throw notImplemented('plan');
  },
  async runStep(): Promise<StepOutcome> {
    throw notImplemented('step');
  },
  async pollStep(): Promise<StepOutcome> {
    throw notImplemented('poll');
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
  async confirmDestroyed() {
    return { status: 'unresolved' };
  },
};
