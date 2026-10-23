import { afterEach, describe, expect, test, vi } from 'vitest';
import { UpcloudTemplate, upcloudLbBody, upcloudProvider } from './upcloud';
import type { Ledger, UpcloudConfig } from './types';
import { emptyRes, errorBlob, jsonRes, mockFetch } from '../testing/mockFetch';

afterEach(() => vi.unstubAllGlobals());

const cfg: UpcloudConfig = { type: 'upcloud', token: 'SECRET_UC_TOKEN', zone: 'de-fra1' };
const spec = {
  name: 'fcp-relay-o1-cafebabe',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
const tpl = UpcloudTemplate.parse({});

describe('upcloud: request shapes + plan', () => {
  test('create body: public IPv4 network, tcp frontend on the edge port, static member backend', () => {
    const body = upcloudLbBody(cfg, spec, tpl);
    expect(body).toMatchObject({
      name: spec.name,
      plan: 'development',
      zone: 'de-fra1',
      configured_status: 'started',
      networks: [{ name: 'public', type: 'public', family: 'IPv4' }],
    });
    expect(body.frontends[0]).toMatchObject({
      mode: 'tcp',
      port: 443,
      default_backend: 'origin-443',
    });
    expect(body.backends[0].members[0]).toMatchObject({
      type: 'static',
      ip: '198.51.100.7',
      port: 443,
      enabled: true,
    });
    expect(body.backends[0].properties).toMatchObject({
      health_check_type: 'tcp',
      health_check_interval: 10,
    });
  });

  test('options left unset send exactly what FCP sent before options existed', () => {
    const body = upcloudLbBody(cfg, spec, tpl);
    expect(body.backends[0].members[0]!.max_sessions).toBe(1000);
    expect(body.backends[0].properties).toEqual({
      timeout_server: 300,
      timeout_tunnel: 3600,
      health_check_type: 'tcp',
      health_check_interval: 10,
      health_check_fall: 3,
      health_check_rise: 3,
    });
    expect(body).not.toHaveProperty('maintenance_dow');
    expect(body).not.toHaveProperty('labels');
  });

  test('each option reaches its API field', () => {
    const body = upcloudLbBody(
      cfg,
      spec,
      UpcloudTemplate.parse({
        maxSessions: 25_000,
        closeOnFailure: true,
        maintenanceDow: 'sunday',
        maintenanceTime: '03:00:00Z',
        labels: [{ key: 'team', value: 'edge' }],
      }),
    );
    expect(body.backends[0].members[0]!.max_sessions).toBe(25_000);
    expect(body.backends[0].properties).toMatchObject({
      health_check_on_down: 'shutdown-sessions',
    });
    expect(body).toMatchObject({
      maintenance_dow: 'sunday',
      maintenance_time: '03:00:00Z',
      labels: [{ key: 'team', value: 'edge' }],
    });
  });

  test('plan: lb, then a floating ip (undiscoverable) and its attach when delegation is on', () => {
    const steps = upcloudProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => [s.kind, s.discoverability])).toEqual([
      ['create_lb', 'by_name'],
      ['allocate_ip', 'none'],
      ['attach_ip', 'by_name'],
    ]);
    const noIp = upcloudProvider.planProvision(
      cfg,
      spec,
      UpcloudTemplate.parse({ delegateFloatingIp: false }),
    );
    expect(noIp.map((s) => s.kind)).toEqual(['create_lb']);
  });
});

describe('upcloud: steps', () => {
  const steps = upcloudProvider.planProvision(cfg, spec, tpl);

  test('create_lb → done with the service uuid; bearer header', async () => {
    const stub = mockFetch(() =>
      jsonRes({ uuid: 'lb-uuid', name: spec.name, operational_state: 'pending' }),
    );
    const out = await upcloudProvider.runStep(cfg, steps[0], spec, tpl, {
      steps: [],
      resources: [],
    });
    expect(out).toEqual({
      status: 'done',
      resources: [{ kind: 'lb', resourceId: 'lb-uuid', ownership: 'created' }],
    });
    expect(stub.calls[0]).toMatchObject({ path: '/1.3/load-balancer', method: 'POST' });
    expect(stub.calls[0].headers.authorization).toBe('Bearer SECRET_UC_TOKEN');
  });

  test('allocate_ip → done with the address as both id and v4; attach_ip posts to the service', async () => {
    mockFetch(() => jsonRes({ ip_address: { address: '203.0.113.20', floating: 'yes' } }));
    const out = await upcloudProvider.runStep(cfg, steps[1], spec, tpl, {
      steps: [],
      resources: [],
    });
    expect(out).toMatchObject({
      status: 'done',
      resources: [{ kind: 'floating_ip', resourceId: '203.0.113.20' }],
      addresses: { v4: '203.0.113.20' },
    });
    const ledger: Ledger = {
      steps: [],
      resources: [
        {
          stepId: 'lb',
          kind: 'lb',
          resourceId: 'lb-uuid',
          ownership: 'created',
          deleteState: 'present',
        },
        {
          stepId: 'ip',
          kind: 'floating_ip',
          resourceId: '203.0.113.20',
          ownership: 'created',
          deleteState: 'present',
        },
      ],
    };
    const stub = mockFetch(() => jsonRes({ uuid: 'lb-uuid' }));
    const att = await upcloudProvider.runStep(cfg, steps[2], spec, tpl, ledger);
    expect(att).toEqual({ status: 'done', resources: [], addresses: { v4: '203.0.113.20' } });
    expect(stub.calls[0]).toMatchObject({
      path: '/1.3/load-balancer/lb-uuid/ip-addresses',
      method: 'POST',
      body: { address: '203.0.113.20', network_name: 'public' },
    });
  });
});

describe('upcloud: discovery', () => {
  const steps = upcloudProvider.planProvision(cfg, spec, tpl);
  const empty: Ledger = { steps: [], resources: [] };

  /** The step as a lost create left it: requested `agoMs` ago, outcome unknown. */
  const lost = (stepId: string, kind: string, agoMs: number): Ledger => ({
    steps: [
      {
        stepId,
        kind,
        resourceName: spec.name,
        state: 'unresolved',
        attempt: 0,
        startedAt: Date.now() - agoMs,
      },
    ],
    resources: [],
  });

  test('service list is authoritative: found by exact name, else confirmed absent once settled', async () => {
    mockFetch(() =>
      jsonRes([
        { uuid: 'u1', name: spec.name },
        { uuid: 'u2', name: 'other' },
      ]),
    );
    expect(await upcloudProvider.discover(cfg, steps[0], spec, empty, 1)).toEqual({
      status: 'found',
      resources: [{ kind: 'lb', resourceId: 'u1', ownership: 'adopted' }],
    });
    mockFetch(() => jsonRes([{ uuid: 'u2', name: 'other' }]));
    expect(
      await upcloudProvider.discover(cfg, steps[0], spec, lost('lb', 'create_lb', 5 * 60_000), 2),
    ).toEqual({ status: 'confirmed_absent' });
  });

  test('one quiet look, or a look too soon after the create, is not proof that it never happened', async () => {
    mockFetch((c) =>
      c.path === '/1.3/ip_address' ? jsonRes({ ip_addresses: { ip_address: [] } }) : jsonRes([]),
    );
    // A create that outlived its timeout may land a little later: look again.
    const old = lost('lb', 'create_lb', 5 * 60_000);
    expect(await upcloudProvider.discover(cfg, steps[0], spec, old, 1)).toEqual({
      status: 'unresolved',
    });
    expect(
      await upcloudProvider.discover(cfg, steps[0], spec, lost('lb', 'create_lb', 10_000), 2),
    ).toEqual({ status: 'unresolved' });
    expect(await upcloudProvider.discover(cfg, steps[0], spec, old, 2)).toEqual({
      status: 'confirmed_absent',
    });
    // The same for a floating IP that might still appear.
    expect(
      await upcloudProvider.discover(cfg, steps[1], spec, lost('ip', 'allocate_ip', 5 * 60_000), 1),
    ).toEqual({ status: 'unresolved' });
  });

  test('the service list is read page by page: a service past the first page is found', async () => {
    // UpCloud answers 10 services by default, at most 100 a page.
    const services = Array.from({ length: 205 }, (_, i) => ({
      uuid: `u${i}`,
      name: i === 204 ? spec.name : `other-${i}`,
    }));
    const stub = mockFetch((c) => {
      const q = new URLSearchParams(c.query);
      const limit = Math.min(Number(q.get('limit') ?? 10), 100);
      const offset = Number(q.get('offset') ?? 0);
      return jsonRes(services.slice(offset, offset + limit));
    });
    expect(
      await upcloudProvider.discover(cfg, steps[0], spec, lost('lb', 'create_lb', 5 * 60_000), 2),
    ).toEqual({
      status: 'found',
      resources: [{ kind: 'lb', resourceId: 'u204', ownership: 'adopted' }],
    });
    expect(stub.calls).toHaveLength(3);
    stub.calls.length = 0;
    const inv = await upcloudProvider.inventory!(cfg);
    expect(inv.loadBalancers).toHaveLength(205);
  });

  test('floating ips carry no identity: unattached candidates are ambiguous, none is confirmed absent', async () => {
    mockFetch(() =>
      jsonRes({
        ip_addresses: {
          ip_address: [
            {
              address: '203.0.113.20',
              floating: 'yes',
              family: 'IPv4',
              zone: 'de-fra1',
              server: null,
            },
            {
              address: '203.0.113.21',
              floating: 'yes',
              family: 'IPv4',
              zone: 'de-fra1',
              server: 'srv-1',
            },
            { address: '198.51.100.9', floating: 'no', family: 'IPv4', zone: 'de-fra1' },
          ],
        },
      }),
    );
    const d = await upcloudProvider.discover(cfg, steps[1], spec, empty, 1);
    expect(d).toMatchObject({ status: 'ambiguous', candidates: [{ resourceId: '203.0.113.20' }] });
    mockFetch(() =>
      jsonRes({
        ip_addresses: {
          ip_address: [{ address: '203.0.113.21', floating: 'yes', server: 'srv-1' }],
        },
      }),
    );
    expect(
      await upcloudProvider.discover(cfg, steps[1], spec, lost('ip', 'allocate_ip', 5 * 60_000), 2),
    ).toEqual({ status: 'confirmed_absent' });
  });
});

describe('upcloud: describe / destroy', () => {
  const ledger: Ledger = {
    steps: [
      { stepId: 'lb', kind: 'create_lb', resourceName: spec.name, state: 'done', attempt: 1 },
      { stepId: 'ip', kind: 'allocate_ip', resourceName: spec.name, state: 'done', attempt: 1 },
      { stepId: 'attach', kind: 'attach_ip', resourceName: spec.name, state: 'done', attempt: 1 },
    ],
    resources: [
      {
        stepId: 'lb',
        kind: 'lb',
        resourceId: 'lb-uuid',
        ownership: 'created',
        deleteState: 'present',
      },
      {
        stepId: 'ip',
        kind: 'floating_ip',
        resourceId: '203.0.113.20',
        ownership: 'created',
        deleteState: 'present',
        meta: '{"address":"203.0.113.20"}',
      },
    ],
  };

  test('running → active with the delegated floating ip as the address; health is never online (no member health on the wire)', async () => {
    mockFetch(() =>
      jsonRes({
        uuid: 'lb-uuid',
        operational_state: 'running',
        nodes: [{ operational_state: 'running' }, { operational_state: 'running' }],
      }),
    );
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({
      state: 'active',
      health: 'unknown',
      addresses: { v4: '203.0.113.20' },
    });
    mockFetch(() =>
      jsonRes({
        uuid: 'lb-uuid',
        operational_state: 'running',
        nodes: [{ operational_state: 'running' }, { operational_state: 'setup-lb' }],
      }),
    );
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ health: 'degraded' });
    mockFetch(() =>
      jsonRes({
        uuid: 'lb-uuid',
        operational_state: 'running',
        nodes: [{ operational_state: 'error' }],
      }),
    );
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ health: 'offline' });
    mockFetch(() => jsonRes({ uuid: 'lb-uuid', operational_state: 'setup-lb' }));
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ state: 'pending' });
    mockFetch(() => emptyRes(404));
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ state: 'gone' });
  });

  test('planDestroy: the service before the floating ip, whatever the ledger order', () => {
    const swapped: Ledger = {
      steps: [],
      resources: [ledger.resources[1], ledger.resources[0]],
    };
    expect(upcloudProvider.planDestroy(cfg, swapped).map((r) => r.kind)).toEqual([
      'lb',
      'floating_ip',
    ]);
  });

  test('destroy: a 2xx is only delete_requested; the re-issued DELETE reading 404 confirms; unknown kinds are unresolved', async () => {
    const stub = mockFetch(() => emptyRes(204));
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(stub.calls[0]).toMatchObject({ method: 'DELETE', path: '/1.3/load-balancer/lb-uuid' });
    mockFetch(() => emptyRes(404));
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[1], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(
      await upcloudProvider.runDestroy(cfg, { ...ledger.resources[1], kind: 'mystery' }, ledger),
    ).toEqual({ status: 'unresolved' });
  });

  test('destroy: DELETE throws (unknown outcome), then the re-issue reads 404 → gone; errors carry no token', async () => {
    mockFetch(() => jsonRes({ error: { error_code: 'SERVER_ERROR' } }, 500));
    await expect(
      upcloudProvider.runDestroy(cfg, ledger.resources[0], ledger),
    ).rejects.toMatchObject({ meta: { status: 500, retryable: true } });
    mockFetch(() => emptyRes(404));
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    mockFetch(() =>
      jsonRes(
        { error: { error_code: 'AUTHENTICATION_FAILED', error_message: 'token SECRET_UC_TOKEN' } },
        401,
      ),
    );
    let err: unknown;
    try {
      await upcloudProvider.describe(cfg, ledger);
    } catch (e) {
      err = e;
    }
    expect(errorBlob(err)).not.toContain('SECRET_UC_TOKEN');
    expect(errorBlob(err)).toContain('AUTHENTICATION_FAILED');
  });

  test('discoverOptions lists the zones from the token alone', async () => {
    mockFetch((c) => {
      if (c.path === '/1.3/zone')
        return jsonRes({ zones: { zone: [{ id: 'de-fra1', description: 'Frankfurt #1' }] } });
      throw new Error(`unexpected ${c.method} ${c.url}`);
    });
    const r = await upcloudProvider.discoverOptions!({ type: 'upcloud', token: 'SECRET_UC_TOKEN' });
    expect(r.regions).toEqual([{ id: 'de-fra1', label: 'Frankfurt #1' }]);
  });
});
