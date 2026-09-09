/**
 * Drift guard between the relay capability record and the adapters. Every flag
 * with an observable adapter counterpart is cross-checked here: async flags
 * against the optional methods, `needsPrivateNetwork` against the settings
 * schema, `ipv6`/`idleTimeoutConfigurable` against the template fields,
 * `memberHealth` against what describe() reports for a healthy balancer,
 * `discoverySettleMs` against a first-look absence, `udp` against the
 * transport refusal. Plus: every planned step is discoverable and uniquely
 * named; template schemas default a fully valid params object.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../../edgeProviderIds';
import { EDGE_SETTINGS_SCHEMAS } from '../accountSettings';
import { jsonRes, mockFetch } from '../testing/mockFetch';
import {
  EDGE_PROVIDER_CAPABILITIES,
  discoveryMaySettle,
  unsupportedTransport,
} from './capabilities';
import { EDGE_PROVIDERS } from './registry';
import { __setScalewayApiFactory } from './scaleway';
import { __resetOvhSkewCache } from './ovh';
import type { EdgeSpec, EdgeProviderConfig, Ledger } from './types';

afterEach(() => {
  vi.unstubAllGlobals();
  __setScalewayApiFactory(null);
  __resetOvhSkewCache();
});

const spec: EdgeSpec = {
  name: 'fcp-relay-test-0123abcd',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};

const CONFIGS: Record<(typeof EDGE_PROVIDER_IDS)[number], EdgeProviderConfig> = {
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

/** Valid settings per provider WITH a private network where the schema knows one. */
const SETTINGS_WITH_NETWORK: Record<(typeof EDGE_PROVIDER_IDS)[number], Record<string, unknown>> = {
  gcore: { projectId: 1, regionId: 2, networkId: 'n', subnetId: 's' },
  upcloud: { zone: 'de-fra1' },
  scaleway: { accessKey: 'SCWXXXXXXXXXXXXXXXXX', zone: 'fr-par-1' },
  ovh: {
    applicationKey: 'ak',
    endpoint: 'ovh-eu',
    serviceName: 'svc',
    regionName: 'GRA9',
    networkId: 'n',
    subnetId: 's',
  },
};

const lbLedger: Ledger = {
  steps: [],
  resources: [
    { stepId: 'lb', kind: 'lb', resourceId: 'lb-1', ownership: 'created', deleteState: 'present' },
  ],
};

/** One JSON object that reads as a healthy, active balancer under every adapter's field names. */
const HEALTHY_LB = {
  id: 'lb-1',
  uuid: 'lb-1',
  name: spec.name,
  provisioning_status: 'ACTIVE',
  operating_status: 'ONLINE',
  provisioningStatus: 'ACTIVE',
  operatingStatus: 'ONLINE',
  operational_state: 'running',
  nodes: [{ operational_state: 'running' }],
  vip_address: '203.0.113.5',
  floatingIp: { id: 'fip', ip: '203.0.113.5' },
};

function healthyScalewayApi() {
  const list = (items: unknown[]) => Object.assign(Promise.resolve({}), { all: async () => items });
  __setScalewayApiFactory(
    () =>
      ({
        getLb: async () => ({
          id: 'lb-1',
          status: 'ready',
          ip: [{ id: 'ip', ipAddress: '203.0.113.5' }],
        }),
        getLbStats: async () => ({
          backendServersStats: [{ ip: '198.51.100.7', lastHealthCheckStatus: 'passed' }],
        }),
        listLbs: () => list([]),
        listIPs: () => list([]),
      }) as never,
  );
}

describe('relay capability record ⇔ adapters', () => {
  test('every provider id has a capability row and an adapter', () => {
    for (const id of EDGE_PROVIDER_IDS) {
      expect(EDGE_PROVIDER_CAPABILITIES[id]).toBeDefined();
      expect(EDGE_PROVIDERS[id].id).toBe(id);
    }
  });

  test.each([...EDGE_PROVIDER_IDS])('%s: async flags mirror optional methods', (id) => {
    const caps = EDGE_PROVIDER_CAPABILITIES[id];
    const p = EDGE_PROVIDERS[id];
    expect(caps.asyncOps).toBe(!!p.pollStep);
    expect(caps.asyncDelete).toBe(!!p.confirmDestroyed);
  });

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: needsPrivateNetwork mirrors the settings schema requiring network + subnet',
    (id) => {
      const { networkId: _n, subnetId: _s, ...without } = SETTINGS_WITH_NETWORK[id];
      expect(
        EDGE_SETTINGS_SCHEMAS[id].safeParse({ ...SETTINGS_WITH_NETWORK[id], type: id }).success,
      ).toBe(true);
      const okWithout = EDGE_SETTINGS_SCHEMAS[id].safeParse({ ...without, type: id }).success;
      expect(okWithout).toBe(!EDGE_PROVIDER_CAPABILITIES[id].needsPrivateNetwork);
    },
  );

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: ipv6 + idleTimeoutConfigurable mirror the template fields',
    (id) => {
      const keys = EDGE_PROVIDERS[id].templateFields.map((f) => f.key);
      expect(keys.some((k) => /ipv6|ipFamily/i.test(k))).toBe(EDGE_PROVIDER_CAPABILITIES[id].ipv6);
      expect(keys.some((k) => /timeoutClient/i.test(k))).toBe(
        EDGE_PROVIDER_CAPABILITIES[id].idleTimeoutConfigurable,
      );
    },
  );

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: memberHealth mirrors whether describe() reports a healthy balancer as online',
    async (id) => {
      mockFetch((c) =>
        c.path.endsWith('/auth/time') ? jsonRes(1_700_000_000) : jsonRes(HEALTHY_LB),
      );
      healthyScalewayApi();
      const d = await EDGE_PROVIDERS[id].describe(CONFIGS[id], lbLedger);
      expect(d.state).toBe('active');
      expect(d.health === 'online').toBe(EDGE_PROVIDER_CAPABILITIES[id].memberHealth);
    },
  );

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: discoverySettleMs > 0 mirrors a first-look absence being unresolved (listing not authoritative)',
    async (id) => {
      // Empty listings under every shape: gcore `{results}`, others arrays.
      mockFetch((c) =>
        c.path.endsWith('/auth/time')
          ? jsonRes(1_700_000_000)
          : c.path.startsWith('/cloud/v1/')
            ? jsonRes({ results: [] })
            : c.path.includes('/ip_address')
              ? jsonRes({ ip_addresses: { ip_address: [] } })
              : jsonRes([]),
      );
      healthyScalewayApi();
      const p = EDGE_PROVIDERS[id];
      const caps = EDGE_PROVIDER_CAPABILITIES[id];
      const planTpl =
        id === 'ovh'
          ? { ...(p.defaultTemplate as Record<string, unknown>), flavorId: 'small' }
          : p.defaultTemplate;
      const lbStep = p
        .planProvision(CONFIGS[id], spec, planTpl)
        .find((s) => s.kind === 'create_lb')!;
      const first = await p.discover(
        CONFIGS[id],
        lbStep,
        spec,
        {
          steps: [
            {
              ...lbStep,
              stepId: lbStep.id,
              state: 'unresolved',
              attempt: 1,
              startedAt: Date.now(),
            },
          ],
          resources: [],
        },
        1,
      );
      expect(first.status === 'unresolved').toBe(caps.discoverySettleMs > 0);
      expect(caps.discoverySettleMs).toBeLessThanOrEqual(caps.typicalProvisionMs);
    },
  );

  test.each([...EDGE_PROVIDER_IDS])('%s: udp mirrors the transport refusal', (id) => {
    const udpSpec: EdgeSpec = {
      ...spec,
      listeners: [{ ...spec.listeners[0], transport: 'udp' }],
    };
    expect(unsupportedTransport(id, udpSpec)).toBe(
      EDGE_PROVIDER_CAPABILITIES[id].udp ? null : 'udp',
    );
    expect(unsupportedTransport(id, spec)).toBeNull();
    expect(
      unsupportedTransport(id, {
        ...spec,
        listeners: [{ ...spec.listeners[0], transport: 'tcp' }],
      }),
    ).toBeNull();
  });

  test('discoveryMaySettle needs two looks and the settle floor; a missing startedAt keeps the look count only', () => {
    const now = 10_000_000;
    const settle = EDGE_PROVIDER_CAPABILITIES.gcore.discoverySettleMs;
    expect(discoveryMaySettle('gcore', 1, now - settle * 2, now)).toBe(false);
    expect(discoveryMaySettle('gcore', 2, now - settle + 1, now)).toBe(false);
    expect(discoveryMaySettle('gcore', 2, now - settle, now)).toBe(true);
    expect(discoveryMaySettle('gcore', 2, undefined, now)).toBe(true);
    // A zero floor (authoritative listings) settles on the look count alone.
    expect(discoveryMaySettle('scaleway', 2, now, now)).toBe(true);
  });

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: default template validates and steps are well-formed',
    (id) => {
      const p = EDGE_PROVIDERS[id];
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
