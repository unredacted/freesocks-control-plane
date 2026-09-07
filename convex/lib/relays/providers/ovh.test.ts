import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { OvhTemplate, __resetOvhSkewCache, ovhLbBody, ovhProvider } from './ovh';
import type { Ledger, OvhConfig } from './types';
import { errorBlob, jsonRes, mockFetch, type Captured } from '../testing/mockFetch';

beforeEach(() => __resetOvhSkewCache());
afterEach(() => vi.unstubAllGlobals());

const cfg: OvhConfig = {
  type: 'ovh',
  applicationKey: 'AK-public',
  applicationSecret: 'SECRET_OVH_AS',
  consumerKey: 'SECRET_OVH_CK',
  endpoint: 'ovh-eu',
  serviceName: 'svc-1',
  regionName: 'GRA9',
  networkId: 'net-1',
  subnetId: 'sub-1',
  gatewayId: 'gw-1',
};
const spec = {
  name: 'fcp-relay-o1-feedface',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
const tpl = OvhTemplate.parse({ flavorId: 'small' });
const base = '/1.0/cloud/project/svc-1/region/GRA9/loadbalancing';

/** Route: /auth/time answers the clock; everything else goes to `rest`. */
const withTime = (rest: (c: Captured) => Response) => (c: Captured) =>
  c.path.endsWith('/auth/time') ? jsonRes(1_700_000_000) : rest(c);

describe('ovh: body + signing', () => {
  test('body: private network + existing gateway + minted floating ip + inline tcp listener/pool', () => {
    const body = ovhLbBody(cfg, spec, tpl);
    expect(body).toMatchObject({
      flavorId: 'small',
      name: spec.name,
      network: {
        private: {
          network: { id: 'net-1', subnetId: 'sub-1' },
          floatingIpCreate: { description: spec.name },
          gateway: { id: 'gw-1' },
        },
      },
    });
    expect(body.network.private).not.toHaveProperty('gatewayCreate');
    expect(body.listeners[0]).toMatchObject({ port: 443, protocol: 'tcp' });
    expect(body.listeners[0].pool).toMatchObject({
      algorithm: 'roundRobin',
      protocol: 'tcp',
      healthMonitor: { monitorType: 'tcp', delay: 5, timeout: 3, maxRetries: 3 },
      members: [{ address: '198.51.100.7', protocolPort: 443 }],
    });
    const noGw = ovhLbBody({ ...cfg, gatewayId: undefined }, spec, tpl);
    expect(noGw.network.private).toMatchObject({ gatewayCreate: { model: 's' } });
    expect(() => ovhLbBody(cfg, spec, OvhTemplate.parse({}))).toThrow(/flavorId/);
  });

  test('every call is signed and the secrets never appear in error text', async () => {
    const stub = mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'created' })));
    const [step] = ovhProvider.planProvision(cfg, spec, tpl);
    const out = await ovhProvider.runStep(cfg, step, spec, tpl, { steps: [], resources: [] });
    expect(out).toEqual({ status: 'requested', opRef: 'op-1', resources: [] });
    const post = stub.calls.find((c) => c.method === 'POST')!;
    expect(post.path).toBe(`${base}/loadbalancer`);
    expect(post.headers['x-ovh-application']).toBe('AK-public');
    expect(post.headers['x-ovh-consumer']).toBe('SECRET_OVH_CK');
    expect(post.headers['x-ovh-signature']).toMatch(/^\$1\$[0-9a-f]{40}$/);
    expect(post.headers['x-ovh-timestamp']).toBe('1700000000');
    // Clock is fetched once and cached.
    expect(stub.calls.filter((c) => c.path.endsWith('/auth/time'))).toHaveLength(1);

    mockFetch(
      withTime(() =>
        jsonRes({ class: 'Client::Forbidden', message: `bad sig for SECRET_OVH_AS` }, 403),
      ),
    );
    let err: unknown;
    try {
      await ovhProvider.testCredentials(cfg).then((r) => {
        if (!r.ok) throw new Error(`code=${r.code}`);
      });
    } catch (e) {
      err = e;
    }
    expect(errorBlob(err)).not.toContain('SECRET_OVH');
    expect(errorBlob(err)).toContain('Client::Forbidden');
  });
});

describe('ovh: polling, discovery, describe, destroy', () => {
  const [step] = ovhProvider.planProvision(cfg, spec, tpl);

  test('pollStep: completed → done with the lb id; in-error → partial; else requested', async () => {
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'completed', resourceId: 'lb-1' })));
    expect(await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] })).toEqual({
      status: 'done',
      resources: [{ kind: 'lb', resourceId: 'lb-1', ownership: 'created' }],
    });
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'in-error' })));
    expect(
      await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({ status: 'partial', code: 'operation_error' });
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'in-progress' })));
    expect(
      await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({ status: 'requested' });
  });

  test('discover: by name adopts lb + floating ip; absence confirmed on the second attempt', async () => {
    const empty: Ledger = { steps: [], resources: [] };
    mockFetch(
      withTime(() =>
        jsonRes([{ id: 'lb-2', name: spec.name, floatingIp: { id: 'fip-2', ip: '203.0.113.2' } }]),
      ),
    );
    expect(await ovhProvider.discover(cfg, step, spec, empty, 1)).toMatchObject({
      status: 'found',
      resources: [
        { kind: 'lb', resourceId: 'lb-2', ownership: 'adopted' },
        { kind: 'floating_ip', resourceId: 'fip-2' },
      ],
      addresses: { v4: '203.0.113.2' },
    });
    mockFetch(withTime(() => jsonRes([])));
    expect(await ovhProvider.discover(cfg, step, spec, empty, 1)).toEqual({ status: 'unresolved' });
    expect(await ovhProvider.discover(cfg, step, spec, empty, 2)).toEqual({
      status: 'confirmed_absent',
    });
  });

  test('describe adopts the minted floating ip and maps statuses; destroy requests an operation', async () => {
    const ledger: Ledger = {
      steps: [],
      resources: [
        {
          stepId: 'lb',
          kind: 'lb',
          resourceId: 'lb-1',
          ownership: 'created',
          deleteState: 'present',
        },
      ],
    };
    mockFetch(
      withTime(() =>
        jsonRes({
          id: 'lb-1',
          provisioningStatus: 'ACTIVE',
          operatingStatus: 'ONLINE',
          floatingIp: { id: 'fip-1', ip: '203.0.113.1' },
        }),
      ),
    );
    expect(await ovhProvider.describe(cfg, ledger)).toMatchObject({
      state: 'active',
      health: 'online',
      addresses: { v4: '203.0.113.1' },
      resources: [{ kind: 'floating_ip', resourceId: 'fip-1' }],
    });
    const stub = mockFetch(withTime(() => jsonRes({ id: 'op-del', status: 'created' })));
    expect(await ovhProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'delete_requested',
      opRef: 'op-del',
    });
    expect(stub.calls.find((c) => c.method === 'DELETE')?.path).toBe(`${base}/loadbalancer/lb-1`);
    mockFetch(withTime(() => jsonRes({ message: 'gone' }, 404)));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('discoverOptions: projects from the keys; regions + private networks (subnets filtered to the region) once a project is set', async () => {
    mockFetch(
      withTime((c) => {
        if (c.path === '/1.0/cloud/project') return jsonRes(['svc-a']);
        if (c.path === '/1.0/cloud/project/svc-a') return jsonRes({ description: 'Prod' });
        if (c.path === '/1.0/cloud/project/svc-a/region') return jsonRes(['GRA9', 'SBG5']);
        if (c.path === '/1.0/cloud/project/svc-a/network/private')
          return jsonRes([
            { id: 'pn-1', name: 'vrack-a', regions: [{ region: 'GRA9' }] },
            { id: 'pn-2', name: 'vrack-b', regions: [{ region: 'SBG5' }] },
          ]);
        if (c.path === '/1.0/cloud/project/svc-a/network/private/pn-1/subnet')
          return jsonRes([
            { id: 'sn-1', cidr: '10.1.0.0/24', ipPools: [{ region: 'GRA9' }] },
            { id: 'sn-2', cidr: '10.2.0.0/24', ipPools: [{ region: 'SBG5' }] },
          ]);
        throw new Error(`unexpected ${c.method} ${c.url}`);
      }),
    );
    const keysOnly = await ovhProvider.discoverOptions!({
      type: 'ovh',
      applicationKey: cfg.applicationKey,
      applicationSecret: cfg.applicationSecret,
      consumerKey: cfg.consumerKey,
      endpoint: 'ovh-eu',
    });
    expect(keysOnly.projects).toEqual([{ id: 'svc-a', label: 'Prod (svc-a)' }]);
    expect(keysOnly.regions).toBeUndefined();
    const withProject = await ovhProvider.discoverOptions!({
      ...cfg,
      serviceName: 'svc-a',
      regionName: 'GRA9',
    });
    expect(withProject.regions).toEqual([
      { id: 'GRA9', label: 'GRA9' },
      { id: 'SBG5', label: 'SBG5' },
    ]);
    expect(withProject.networks).toEqual([
      { id: 'pn-1', label: 'vrack-a', subnets: [{ id: 'sn-1', label: '10.1.0.0/24' }] },
    ]);
  });
});
