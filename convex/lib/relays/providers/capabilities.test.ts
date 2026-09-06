/**
 * Drift guard between the relay capability record and the adapters: async
 * providers must expose pollStep, async-delete providers confirmDestroyed; every
 * planned step must be discoverable and uniquely named; template schemas must
 * default a fully valid params object.
 */
import { describe, expect, test } from 'vitest';
import { RELAY_PROVIDER_IDS } from '../../relayProviderIds';
import { RELAY_CAPABILITIES } from './capabilities';
import { RELAY_PROVIDERS } from './registry';
import type { EdgeSpec, RelayProviderConfig } from './types';

const spec: EdgeSpec = {
  name: 'fcp-relay-test-0123abcd',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};

const CONFIGS: Record<(typeof RELAY_PROVIDER_IDS)[number], RelayProviderConfig> = {
  gcore: { type: 'gcore', apiKey: 'k', projectId: 1, regionId: 2 },
  upcloud: { type: 'upcloud', token: 't', zone: 'de-fra1' },
  scaleway: {
    type: 'scaleway',
    accessKey: 'SCW1',
    secretKey: 's',
    projectId: 'p',
    zone: 'fr-par-1',
  },
  ovh: {
    type: 'ovh',
    applicationKey: 'ak',
    applicationSecret: 'as',
    consumerKey: 'ck',
    endpoint: 'ovh-eu',
    serviceName: 'svc',
    regionName: 'GRA9',
    networkId: 'n',
    subnetId: 's',
    gatewayId: 'g',
  },
};

describe('relay capability record ⇔ adapters', () => {
  test('every provider id has a capability row and an adapter', () => {
    for (const id of RELAY_PROVIDER_IDS) {
      expect(RELAY_CAPABILITIES[id]).toBeDefined();
      expect(RELAY_PROVIDERS[id].id).toBe(id);
    }
  });

  test.each([...RELAY_PROVIDER_IDS])('%s: async flags mirror optional methods', (id) => {
    const caps = RELAY_CAPABILITIES[id];
    const p = RELAY_PROVIDERS[id];
    expect(caps.asyncOps).toBe(!!p.pollStep);
    expect(caps.asyncDelete).toBe(!!p.confirmDestroyed);
  });

  test.each([...RELAY_PROVIDER_IDS])(
    '%s: default template validates and steps are well-formed',
    (id) => {
      const p = RELAY_PROVIDERS[id];
      const tpl = p.templateSchema.parse(p.defaultTemplate);
      expect(tpl).toEqual(p.defaultTemplate);
      // Field descriptors point at real template keys.
      for (const f of p.templateFields) {
        const head = f.key.split('.')[0];
        expect(Object.keys(tpl as Record<string, unknown>)).toContain(head);
      }
      // OVH's default lacks the required flavor; give it one for planning.
      const planTpl =
        id === 'ovh' ? { ...(tpl as Record<string, unknown>), flavorId: 'small' } : tpl;
      const steps = p.planProvision(CONFIGS[id], spec, planTpl);
      expect(steps.length).toBeGreaterThan(0);
      expect(new Set(steps.map((s) => s.id)).size).toBe(steps.length);
      for (const s of steps) {
        expect(['by_name', 'by_tag', 'none']).toContain(s.discoverability);
        expect(s.resourceName.startsWith(spec.name)).toBe(true);
      }
      // At most one undiscoverable allocating step per plan (operator-resolved).
      expect(steps.filter((s) => s.discoverability === 'none').length).toBeLessThanOrEqual(1);
    },
  );
});
