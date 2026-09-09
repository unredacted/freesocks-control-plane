import { afterEach, describe, expect, test, vi } from 'vitest';
import { GcoreTemplate, gcoreLbAddresses, gcoreLbBody, gcoreProvider } from './gcore';
import { EDGE_PROVIDER_CAPABILITIES } from './capabilities';
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

  test('an IPv6-only family is refused at template validation (publishing needs an IPv4)', () => {
    expect(GcoreTemplate.safeParse({ ipFamily: 'ipv6' }).success).toBe(false);
    expect(GcoreTemplate.safeParse({ ipFamily: 'ipv4' }).success).toBe(true);
    expect(GcoreTemplate.safeParse({ ipFamily: 'dual' }).success).toBe(true);
  });

  test('a private VIP is never surfaced as the public v4; the floating ip is', () => {
    expect(gcoreLbAddresses({ vip_address: '10.0.0.5', vip_ipv6_address: '2001:db8::5' })).toEqual({
      v6: '2001:db8::5',
    });
    expect(
      gcoreLbAddresses({
        vip_address: '10.0.0.5',
        floating_ips: [{ floating_ip_address: '203.0.113.50' }],
      }),
    ).toEqual({ v4: '203.0.113.50' });
    expect(gcoreLbAddresses({ vip_address: '203.0.113.9', vip_ipv6_address: 'fd00::1' })).toEqual({
      v4: '203.0.113.9',
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

  test('absence needs BOTH two quiet looks AND the settle floor since the step started', async () => {
    const settle = EDGE_PROVIDER_CAPABILITIES.gcore.discoverySettleMs;
    const ledgerAt = (startedAt: number): Ledger => ({
      steps: [
        {
          stepId: 'lb',
          kind: 'create_lb',
          resourceName: spec.name,
          state: 'unresolved',
          attempt: 1,
          startedAt,
        },
      ],
      resources: [],
    });
    mockFetch(() => jsonRes({ results: [] }));
    // Two looks ~40s apart are not enough: the create may still be registering.
    expect(await gcoreProvider.discover(cfg, step, spec, ledgerAt(Date.now() - 40_000), 2)).toEqual(
      { status: 'unresolved' },
    );
    expect(await gcoreProvider.discover(cfg, step, spec, ledgerAt(Date.now() - 40_000), 5)).toEqual(
      { status: 'unresolved' },
    );
    // Enough wall clock but only one look: still unresolved.
    expect(
      await gcoreProvider.discover(cfg, step, spec, ledgerAt(Date.now() - settle - 1000), 1),
    ).toEqual({ status: 'unresolved' });
    expect(
      await gcoreProvider.discover(cfg, step, spec, ledgerAt(Date.now() - settle - 1000), 2),
    ).toEqual({ status: 'confirmed_absent' });
  });

  test('a task in ERROR with no created resources still consults the by-name listing', async () => {
    const ledger: Ledger = {
      steps: [
        {
          stepId: 'lb',
          kind: 'create_lb',
          resourceName: spec.name,
          state: 'unresolved',
          opRef: 'task-err',
          attempt: 1,
          startedAt: Date.now(),
        },
      ],
      resources: [],
    };
    const stub = mockFetch((c) => {
      if (c.path === '/cloud/v1/tasks/task-err')
        return jsonRes({ id: 'task-err', state: 'ERROR', created_resources: {} });
      if (c.path === '/cloud/v1/loadbalancers/11/22')
        return jsonRes({
          results: [{ id: 'lb-late', name: spec.name, vip_address: '203.0.113.11' }],
        });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toMatchObject({
      status: 'found',
      resources: [{ kind: 'lb', resourceId: 'lb-late', ownership: 'adopted' }],
    });
    expect(stub.calls.map((c) => c.path)).toEqual([
      '/cloud/v1/tasks/task-err',
      '/cloud/v1/loadbalancers/11/22',
    ]);
    // Same errored task, nothing listed, just started: unresolved (not absent).
    mockFetch((c) =>
      c.path === '/cloud/v1/tasks/task-err'
        ? jsonRes({ id: 'task-err', state: 'ERROR' })
        : jsonRes({ results: [] }),
    );
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toEqual({
      status: 'unresolved',
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

  test('planDestroy: the lb goes before a floating ip describe() appended after it', () => {
    const l: Ledger = {
      steps: [],
      resources: [
        ledger.resources[0],
        {
          stepId: 'describe',
          kind: 'floating_ip',
          resourceId: 'fip-2',
          ownership: 'created',
          deleteState: 'present',
        },
      ],
    };
    expect(gcoreProvider.planDestroy(cfg, l).map((r) => r.resourceId)).toEqual(['lb-1', 'fip-2']);
  });

  test('destroy requests a delete task; confirm reads PENDING_DELETE as unresolved, ACTIVE as still_present, 404 as gone', async () => {
    const stub = mockFetch(() => jsonRes({ tasks: ['del-1'] }));
    const out = await gcoreProvider.runDestroy(cfg, ledger.resources[0], ledger);
    expect(out).toEqual({ status: 'delete_requested', opRef: 'del-1' });
    expect(stub.calls[0]).toMatchObject({
      method: 'DELETE',
      path: '/cloud/v1/loadbalancers/11/22/lb-1',
    });
    mockFetch(() => jsonRes({ id: 'lb-1', provisioning_status: 'PENDING_DELETE' }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'unresolved',
    });
    // Still ACTIVE after the request: the delete never landed → re-issue.
    mockFetch(() => jsonRes({ id: 'lb-1', provisioning_status: 'ACTIVE' }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'still_present',
    });
    mockFetch(() => jsonRes({}, 404));
    expect(await gcoreProvider.confirmDestroyed!(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    // A floating ip is read back the same way.
    const fip = {
      stepId: 'lb',
      kind: 'floating_ip',
      resourceId: 'fip-1',
      ownership: 'created' as const,
      deleteState: 'delete_requested' as const,
    };
    const s2 = mockFetch(() => jsonRes({ id: 'fip-1', status: 'ACTIVE' }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, fip, ledger)).toEqual({
      status: 'still_present',
    });
    expect(s2.calls[0].path).toBe('/cloud/v1/floatingips/11/22/fip-1');
    // Unknown kinds are never assumed gone.
    const odd = { ...fip, kind: 'mystery' };
    expect(await gcoreProvider.runDestroy(cfg, odd, ledger)).toEqual({ status: 'unresolved' });
    expect(await gcoreProvider.confirmDestroyed!(cfg, odd, ledger)).toEqual({
      status: 'unresolved',
    });
  });

  test('destroy: DELETE throws (unknown outcome), then confirm reads 404 → gone', async () => {
    mockFetch(() => jsonRes({ message: 'busy' }, 503));
    await expect(gcoreProvider.runDestroy(cfg, ledger.resources[0], ledger)).rejects.toMatchObject({
      meta: { status: 503, retryable: true },
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

  test('discoverOptions lists projects + regions from the key alone, and networks with their subnets once both are chosen', async () => {
    mockFetch((c) => {
      if (c.path === '/cloud/v1/projects')
        return jsonRes({
          results: [
            { id: 11, name: 'Project A' },
            { id: 12, name: 'Project B' },
          ],
        });
      if (c.path === '/cloud/v1/regions')
        return jsonRes({ results: [{ id: 22, display_name: 'Region X' }] });
      if (c.path === '/cloud/v1/networks/11/22')
        return jsonRes({ results: [{ id: 'net-1', name: 'private' }] });
      if (c.path === '/cloud/v1/subnets/11/22')
        return jsonRes({
          results: [{ id: 'sub-1', name: 's', network_id: 'net-1', cidr: '10.0.0.0/24' }],
        });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const keyOnly = await gcoreProvider.discoverOptions!({
      type: 'gcore',
      apiKey: 'SECRET_GCORE_KEY',
    });
    expect(keyOnly.projects).toEqual([
      { id: '11', label: 'Project A' },
      { id: '12', label: 'Project B' },
    ]);
    expect(keyOnly.regions).toEqual([{ id: '22', label: 'Region X' }]);
    expect(keyOnly.networks).toBeUndefined();
    const full = await gcoreProvider.discoverOptions!({ ...cfg });
    expect(full.networks).toEqual([
      { id: 'net-1', label: 'private', subnets: [{ id: 'sub-1', label: 's (10.0.0.0/24)' }] },
    ]);
  });

  test('discoverOptions reports a failing list as a code and still returns the others', async () => {
    mockFetch((c) => {
      if (c.path === '/cloud/v1/projects') return jsonRes({ message: 'nope' }, 403);
      if (c.path === '/cloud/v1/regions')
        return jsonRes({ results: [{ id: 22, display_name: 'R' }] });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const r = await gcoreProvider.discoverOptions!({ type: 'gcore', apiKey: 'k' });
    expect(r.projects).toBeUndefined();
    expect(r.regions).toEqual([{ id: '22', label: 'R' }]);
    expect(r.errors?.projects).toBeDefined();
  });
});
