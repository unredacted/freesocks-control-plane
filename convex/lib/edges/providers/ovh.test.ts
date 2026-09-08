import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { OvhTemplate, __resetOvhSkewCache, ovhGatewayName, ovhLbBody, ovhProvider } from './ovh';
import type { Ledger, OvhConfig } from './types';
import { EDGE_PROVIDER_CAPABILITIES } from './capabilities';
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
    // Completed but no resourceId on the wire: never "done with nothing" — hand
    // the step to name-based discovery instead.
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'completed' })));
    expect(
      await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({ status: 'partial', code: 'operation_completed_without_resource' });
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'in-error' })));
    expect(
      await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({ status: 'partial', code: 'operation_error' });
    mockFetch(withTime(() => jsonRes({ id: 'op-1', status: 'in-progress' })));
    expect(
      await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({ status: 'requested' });
  });

  const region = '/1.0/cloud/project/svc-1/region/GRA9';
  const settle = EDGE_PROVIDER_CAPABILITIES.ovh.discoverySettleMs;
  const ledgerAt = (startedAt: number, opRef?: string): Ledger => ({
    steps: [
      {
        stepId: 'lb',
        kind: 'create_lb',
        resourceName: spec.name,
        state: 'unresolved',
        opRef,
        attempt: 1,
        startedAt,
      },
    ],
    resources: [],
  });
  /** Empty project: no balancer, no floating ip, no gateway, no operation. */
  const emptyProject = (c: Captured) => {
    if (c.path === `${base}/loadbalancer`) return jsonRes([]);
    if (c.path === `${region}/floatingip`) return jsonRes([]);
    if (c.path === `${region}/gateway`) return jsonRes([]);
    if (c.path === '/1.0/cloud/project/svc-1/operation') return jsonRes([]);
    throw new Error(`unexpected ${c.method} ${c.url}`);
  };

  test('discover: by name adopts lb + floating ip (+ the FCP-named gateway when none is configured)', async () => {
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
    const noGw = { ...cfg, gatewayId: undefined };
    mockFetch(
      withTime((c) => {
        if (c.path === `${base}/loadbalancer`)
          return jsonRes([{ id: 'lb-2', name: spec.name, floatingIp: { id: 'fip-2' } }]);
        if (c.path === `${region}/gateway`)
          return jsonRes([
            { id: 'gw-other', name: 'someone-else-gw' },
            { id: 'gw-2', name: ovhGatewayName(spec.name), status: 'active' },
          ]);
        throw new Error(`unexpected ${c.method} ${c.url}`);
      }),
    );
    expect(await ovhProvider.discover(noGw, step, spec, empty, 1)).toMatchObject({
      status: 'found',
      resources: [
        { kind: 'lb', resourceId: 'lb-2' },
        { kind: 'floating_ip', resourceId: 'fip-2' },
        { kind: 'gateway', resourceId: 'gw-2', ownership: 'adopted' },
      ],
    });
  });

  test('discover: absence needs two quiet looks AND the settle floor; an in-flight balancer operation blocks it', async () => {
    mockFetch(withTime(emptyProject));
    // Legacy ledger without startedAt: the look count alone applies.
    const noStart: Ledger = { steps: [], resources: [] };
    expect(await ovhProvider.discover(cfg, step, spec, noStart, 1)).toEqual({
      status: 'unresolved',
    });
    expect(await ovhProvider.discover(cfg, step, spec, noStart, 2)).toEqual({
      status: 'confirmed_absent',
    });
    // Two looks 40 s after the request: too early.
    expect(await ovhProvider.discover(cfg, step, spec, ledgerAt(Date.now() - 40_000), 2)).toEqual({
      status: 'unresolved',
    });
    expect(
      await ovhProvider.discover(cfg, step, spec, ledgerAt(Date.now() - settle - 1000), 2),
    ).toEqual({ status: 'confirmed_absent' });
    // The project still runs a balancer operation started after our step: unresolved.
    mockFetch(
      withTime((c) =>
        c.path === '/1.0/cloud/project/svc-1/operation'
          ? jsonRes([
              {
                id: 'op-x',
                status: 'in-progress',
                action: 'loadbalancer#create',
                createdAt: new Date().toISOString(),
              },
            ])
          : emptyProject(c),
      ),
    );
    expect(
      await ovhProvider.discover(cfg, step, spec, ledgerAt(Date.now() - settle - 1000), 3),
    ).toEqual({ status: 'unresolved' });
    // A completed or unrelated operation does not block.
    mockFetch(
      withTime((c) =>
        c.path === '/1.0/cloud/project/svc-1/operation'
          ? jsonRes([
              { id: 'op-y', status: 'completed', action: 'loadbalancer#create' },
              { id: 'op-z', status: 'in-progress', action: 'instance#create' },
            ])
          : emptyProject(c),
      ),
    );
    expect(
      await ovhProvider.discover(cfg, step, spec, ledgerAt(Date.now() - settle - 1000), 3),
    ).toEqual({ status: 'confirmed_absent' });
  });

  test('discover: FCP-named children without their balancer are ambiguous (ledgered for the operator, never re-run)', async () => {
    const noGw = { ...cfg, gatewayId: undefined };
    mockFetch(
      withTime((c) => {
        if (c.path === `${region}/floatingip`)
          return jsonRes([
            { id: 'fip-orphan', ip: '203.0.113.7', description: spec.name },
            { id: 'fip-else', ip: '203.0.113.8', description: 'other' },
          ]);
        if (c.path === `${region}/gateway`)
          return jsonRes([{ id: 'gw-orphan', name: ovhGatewayName(spec.name) }]);
        return emptyProject(c);
      }),
    );
    expect(
      await ovhProvider.discover(noGw, step, spec, ledgerAt(Date.now() - settle - 1000), 2),
    ).toEqual({
      status: 'ambiguous',
      candidates: [
        {
          kind: 'floating_ip',
          resourceId: 'fip-orphan',
          ownership: 'adopted',
          meta: { address: '203.0.113.7' },
        },
        { kind: 'gateway', resourceId: 'gw-orphan', ownership: 'adopted' },
      ],
    });
  });

  test('gateway ledger: a completed create lists the gateway it minted; describe adopts one the ledger lacks', async () => {
    const noGw = { ...cfg, gatewayId: undefined };
    const gwList = jsonRes([{ id: 'gw-new', name: ovhGatewayName(spec.name), status: 'active' }]);
    mockFetch(
      withTime((c) => {
        if (c.path.endsWith('/operation/op-1'))
          return jsonRes({ id: 'op-1', status: 'completed', resourceId: 'lb-1' });
        if (c.path === `${region}/gateway`) return gwList.clone();
        throw new Error(`unexpected ${c.method} ${c.url}`);
      }),
    );
    expect(await ovhProvider.pollStep!(noGw, step, 'op-1', { steps: [], resources: [] })).toEqual({
      status: 'done',
      resources: [
        { kind: 'lb', resourceId: 'lb-1', ownership: 'created' },
        { kind: 'gateway', resourceId: 'gw-new', ownership: 'created' },
      ],
    });
    // With a configured gateway nothing is looked up or ledgered.
    const stub = mockFetch(
      withTime(() => jsonRes({ id: 'op-1', status: 'completed', resourceId: 'lb-1' })),
    );
    expect(await ovhProvider.pollStep!(cfg, step, 'op-1', { steps: [], resources: [] })).toEqual({
      status: 'done',
      resources: [{ kind: 'lb', resourceId: 'lb-1', ownership: 'created' }],
    });
    expect(stub.calls.some((c) => c.path === `${region}/gateway`)).toBe(false);
    // An errored operation reports the FCP-named leftovers as a partial result.
    mockFetch(
      withTime((c) => {
        if (c.path.endsWith('/operation/op-1')) return jsonRes({ id: 'op-1', status: 'in-error' });
        if (c.path === `${region}/floatingip`)
          return jsonRes([{ id: 'fip-left', ip: '203.0.113.9', description: spec.name }]);
        if (c.path === `${region}/gateway`) return gwList.clone();
        throw new Error(`unexpected ${c.method} ${c.url}`);
      }),
    );
    expect(
      await ovhProvider.pollStep!(noGw, step, 'op-1', { steps: [], resources: [] }),
    ).toMatchObject({
      status: 'partial',
      code: 'operation_error',
      resources: [
        { kind: 'floating_ip', resourceId: 'fip-left' },
        { kind: 'gateway', resourceId: 'gw-new' },
      ],
    });
    // describe: the ledger holds only the lb → the floating ip AND the gateway are adopted.
    const ledger: Ledger = {
      steps: [
        { stepId: 'lb', kind: 'create_lb', resourceName: spec.name, state: 'done', attempt: 1 },
      ],
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
      withTime((c) => {
        if (c.path === `${base}/loadbalancer/lb-1`)
          return jsonRes({
            id: 'lb-1',
            name: spec.name,
            provisioningStatus: 'ACTIVE',
            operatingStatus: 'ONLINE',
            floatingIp: { id: 'fip-1', ip: '203.0.113.1' },
          });
        if (c.path === `${region}/gateway`) return gwList.clone();
        throw new Error(`unexpected ${c.method} ${c.url}`);
      }),
    );
    expect(await ovhProvider.describe(noGw, ledger)).toMatchObject({
      state: 'active',
      resources: [
        { kind: 'floating_ip', resourceId: 'fip-1' },
        { kind: 'gateway', resourceId: 'gw-new', ownership: 'created' },
      ],
    });
    // Once ledgered, describe stops looking the gateway up.
    ledger.resources.push({
      stepId: 'lb',
      kind: 'gateway',
      resourceId: 'gw-new',
      ownership: 'created',
      deleteState: 'present',
    });
    const s3 = mockFetch(
      withTime(() => jsonRes({ id: 'lb-1', name: spec.name, provisioningStatus: 'ACTIVE' })),
    );
    await ovhProvider.describe(noGw, ledger);
    expect(s3.calls.some((c) => c.path === `${region}/gateway`)).toBe(false);
  });

  test('destroy walks lb → floating ip → gateway by kind; every kind is read back; unknown kinds are unresolved', async () => {
    const mk = (kind: string, resourceId: string) => ({
      stepId: 'x',
      kind,
      resourceId,
      ownership: 'created' as const,
      deleteState: 'present' as const,
    });
    // Ledger order is gateway, fip, lb (describe-appended children first): the plan reorders.
    const ledger: Ledger = {
      steps: [],
      resources: [mk('gateway', 'gw-1'), mk('floating_ip', 'fip-1'), mk('lb', 'lb-1')],
    };
    expect(ovhProvider.planDestroy(cfg, ledger).map((r) => r.kind)).toEqual([
      'lb',
      'floating_ip',
      'gateway',
    ]);
    const stub = mockFetch(withTime(() => jsonRes({ id: 'op-gw', status: 'created' })));
    expect(await ovhProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'delete_requested',
      opRef: 'op-gw',
    });
    expect(stub.calls.find((c) => c.method === 'DELETE')?.path).toBe(`${region}/gateway/gw-1`);
    mockFetch(withTime(() => jsonRes({ id: 'gw-1', status: 'deleting' })));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'unresolved',
    });
    mockFetch(withTime(() => jsonRes({ id: 'gw-1', status: 'active' })));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'still_present',
    });
    // The balancer: PENDING_DELETE → unresolved; ACTIVE → still_present; 404 → gone.
    mockFetch(withTime(() => jsonRes({ id: 'lb-1', provisioningStatus: 'PENDING_DELETE' })));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[2], ledger)).toEqual({
      status: 'unresolved',
    });
    mockFetch(withTime(() => jsonRes({ id: 'lb-1', provisioningStatus: 'ACTIVE' })));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[2], ledger)).toEqual({
      status: 'still_present',
    });
    mockFetch(withTime(() => jsonRes({ message: 'gone' }, 404)));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[2], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    // DELETE throws (unknown outcome) → the next confirm reads 404 → gone.
    mockFetch(withTime(() => jsonRes({ class: 'Server::InternalServerError' }, 500)));
    await expect(ovhProvider.runDestroy(cfg, ledger.resources[2], ledger)).rejects.toMatchObject({
      meta: { status: 500, retryable: true },
    });
    mockFetch(withTime(() => jsonRes({}, 404)));
    expect(await ovhProvider.confirmDestroyed!(cfg, ledger.resources[2], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    const odd = mk('mystery', 'm-1');
    expect(await ovhProvider.runDestroy(cfg, odd, ledger)).toEqual({ status: 'unresolved' });
    expect(await ovhProvider.confirmDestroyed!(cfg, odd, ledger)).toEqual({ status: 'unresolved' });
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
    // The floating ip is read back too.
    const fip = { ...ledger.resources[0], kind: 'floating_ip', resourceId: 'fip-1' };
    mockFetch(withTime(() => jsonRes({ id: 'fip-1', ip: '203.0.113.1', status: 'active' })));
    expect(await ovhProvider.confirmDestroyed!(cfg, fip, ledger)).toEqual({
      status: 'still_present',
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
