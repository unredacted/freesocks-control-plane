import { afterEach, describe, expect, test, vi } from 'vitest';
import { GcoreTemplate, gcoreLbBody, gcoreProvider } from './gcore';
import type { GcoreConfig, Ledger } from './types';
import { errorBlob, jsonRes, mockFetch } from '../testing/mockFetch';

afterEach(() => vi.unstubAllGlobals());

const cfg: GcoreConfig = { type: 'gcore', apiKey: 'SECRET_GCORE_KEY', projectId: 11, regionId: 22 };
const spec = {
  name: 'fcp-relay-o1-deadbeef',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
const tpl = GcoreTemplate.parse({});
const emptyLedger: Ledger = { steps: [], resources: [] };

describe('gcore: request shapes', () => {
  test('create body: one TCP listener with an inline pool + TCP health monitor, tagged with the edge name', () => {
    const body = gcoreLbBody(cfg, spec, tpl);
    expect(body).toMatchObject({
      name: spec.name,
      flavor: 'lb1-1-2',
      vip_ip_family: 'dual',
      tags: { fcp_edge: spec.name },
    });
    expect(body).not.toHaveProperty('vip_network_id');
    const l = body.listeners[0];
    expect(l).toMatchObject({ protocol: 'TCP', protocol_port: 443 });
    expect(l.pools[0]).toMatchObject({
      protocol: 'TCP',
      lb_algorithm: 'ROUND_ROBIN',
      members: [{ address: '198.51.100.7', protocol_port: 443, weight: 1 }],
      healthmonitor: { type: 'TCP', delay: 10, timeout: 5, max_retries: 3, max_retries_down: 3 },
    });
  });

  test('private VIP mode requires a network + subnet and adds a new floating ip', () => {
    const priv = GcoreTemplate.parse({ vipMode: 'private' });
    expect(() => gcoreLbBody(cfg, spec, priv)).toThrow(/networkId/);
    const body = gcoreLbBody({ ...cfg, networkId: 'net', subnetId: 'sub' }, spec, priv);
    expect(body).toMatchObject({
      vip_network_id: 'net',
      vip_subnet_id: 'sub',
      floating_ip: { source: 'new' },
    });
  });
});

describe('gcore: provisioning steps', () => {
  test('runStep POSTs with the APIKey header and returns the task as opRef', async () => {
    const stub = mockFetch(() => jsonRes({ tasks: ['task-1'] }));
    const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
    const out = await gcoreProvider.runStep(cfg, step, spec, tpl, emptyLedger);
    expect(out).toEqual({ status: 'requested', opRef: 'task-1', resources: [] });
    expect(stub.calls[0]).toMatchObject({ path: '/cloud/v1/loadbalancers/11/22', method: 'POST' });
    expect(stub.calls[0].headers.authorization).toBe('APIKey SECRET_GCORE_KEY');
  });

  test('pollStep maps FINISHED → done with every created resource, ERROR → partial, else requested', async () => {
    const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
    mockFetch(() =>
      jsonRes({
        id: 't',
        state: 'FINISHED',
        created_resources: { loadbalancers: ['lb-1'], floatingips: ['fip-1'] },
      }),
    );
    expect(await gcoreProvider.pollStep!(cfg, step, 't', emptyLedger)).toEqual({
      status: 'done',
      resources: [
        { kind: 'lb', resourceId: 'lb-1', ownership: 'created' },
        { kind: 'floating_ip', resourceId: 'fip-1', ownership: 'created' },
      ],
    });
    mockFetch(() =>
      jsonRes({ id: 't', state: 'ERROR', created_resources: { loadbalancers: ['lb-1'] } }),
    );
    expect(await gcoreProvider.pollStep!(cfg, step, 't', emptyLedger)).toMatchObject({
      status: 'partial',
      code: 'task_error',
      resources: [{ resourceId: 'lb-1' }],
    });
    mockFetch(() => jsonRes({ id: 't', state: 'RUNNING' }));
    expect(await gcoreProvider.pollStep!(cfg, step, 't', emptyLedger)).toMatchObject({
      status: 'requested',
      opRef: 't',
    });
  });
});

describe('gcore: discovery', () => {
  const [step] = gcoreProvider.planProvision(cfg, spec, tpl);

  test('with a known task: running → unresolved, finished → found', async () => {
    const ledger: Ledger = {
      steps: [
        {
          stepId: 'lb',
          kind: 'create_lb',
          resourceName: spec.name,
          state: 'unresolved',
          opRef: 'task-9',
          attempt: 1,
        },
      ],
      resources: [],
    };
    mockFetch(() => jsonRes({ id: 'task-9', state: 'RUNNING' }));
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toEqual({
      status: 'unresolved',
    });
    mockFetch(() =>
      jsonRes({ id: 'task-9', state: 'FINISHED', created_resources: { loadbalancers: ['lb-7'] } }),
    );
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toMatchObject({
      status: 'found',
      resources: [{ resourceId: 'lb-7' }],
    });
  });

  test('without a task: name match → found (adopted); absence is unresolved first, confirmed on the second look', async () => {
    mockFetch(() =>
      jsonRes({
        results: [{ id: 'lb-x', name: spec.name, vip_address: '203.0.113.9', floating_ips: [] }],
      }),
    );
    const found = await gcoreProvider.discover(cfg, step, spec, emptyLedger, 1);
    expect(found).toMatchObject({
      status: 'found',
      resources: [{ kind: 'lb', resourceId: 'lb-x', ownership: 'adopted' }],
      addresses: { v4: '203.0.113.9' },
    });
    mockFetch(() => jsonRes({ results: [{ id: 'other', name: 'someone-else' }] }));
    expect(await gcoreProvider.discover(cfg, step, spec, emptyLedger, 1)).toEqual({
      status: 'unresolved',
    });
    expect(await gcoreProvider.discover(cfg, step, spec, emptyLedger, 2)).toEqual({
      status: 'confirmed_absent',
    });
  });
});

describe('gcore: describe / destroy', () => {
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

  test('describe maps statuses, splits v4/v6 and adopts a floating ip the ledger lacks', async () => {
    mockFetch(() =>
      jsonRes({
        id: 'lb-1',
        provisioning_status: 'ACTIVE',
        operating_status: 'ONLINE',
        vip_address: '203.0.113.5',
        vip_ipv6_address: '2001:db8::5',
        floating_ips: [{ id: 'fip-2', floating_ip_address: '203.0.113.50' }],
      }),
    );
    const d = await gcoreProvider.describe(cfg, ledger);
    expect(d).toMatchObject({
      state: 'active',
      health: 'online',
      addresses: { v4: '203.0.113.50', v6: '2001:db8::5' },
      resources: [{ kind: 'floating_ip', resourceId: 'fip-2' }],
    });
    mockFetch(() =>
      jsonRes({ id: 'lb-1', provisioning_status: 'PENDING_CREATE', operating_status: 'OFFLINE' }),
    );
    expect(await gcoreProvider.describe(cfg, ledger)).toMatchObject({
      state: 'pending',
      health: 'offline',
    });
    mockFetch(() => jsonRes({ message: 'nope' }, 404));
    expect(await gcoreProvider.describe(cfg, ledger)).toMatchObject({ state: 'gone' });
  });

  test('destroy requests a delete task; confirmDestroyed reads 404 as gone', async () => {
    const stub = mockFetch(() => jsonRes({ tasks: ['del-1'] }));
    const out = await gcoreProvider.runDestroy(cfg, ledger.resources[0], ledger);
    expect(out).toEqual({ status: 'delete_requested', opRef: 'del-1' });
    expect(stub.calls[0]).toMatchObject({
      method: 'DELETE',
      path: '/cloud/v1/loadbalancers/11/22/lb-1',
    });
    mockFetch(() => jsonRes({ id: 'lb-1' }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'unresolved',
    });
    mockFetch(() => jsonRes({}, 404));
    expect(await gcoreProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('errors never leak the api key or host', async () => {
    mockFetch(() => jsonRes({ message: 'bad key SECRET_GCORE_KEY' }, 401));
    let err: unknown;
    try {
      await gcoreProvider.describe(cfg, ledger);
    } catch (e) {
      err = e;
    }
    const blob = errorBlob(err);
    expect(blob).not.toContain('SECRET_GCORE_KEY');
    expect(blob).not.toContain('api.gcore.com');
    expect(blob).toContain('401');
  });
});
