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
      body: { ip_addresses: [{ address: '203.0.113.20', listen: true }] },
    });
  });
});

describe('upcloud: discovery', () => {
  const steps = upcloudProvider.planProvision(cfg, spec, tpl);
  const empty: Ledger = { steps: [], resources: [] };

  test('service list is authoritative: found by exact name, else confirmed absent', async () => {
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
    expect(await upcloudProvider.discover(cfg, steps[0], spec, empty, 1)).toEqual({
      status: 'confirmed_absent',
    });
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
    expect(await upcloudProvider.discover(cfg, steps[1], spec, empty, 1)).toEqual({
      status: 'confirmed_absent',
    });
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

  test('running → active/online with the delegated floating ip as the address', async () => {
    mockFetch(() => jsonRes({ uuid: 'lb-uuid', operational_state: 'running', nodes: [] }));
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({
      state: 'active',
      health: 'online',
      addresses: { v4: '203.0.113.20' },
    });
    mockFetch(() => jsonRes({ uuid: 'lb-uuid', operational_state: 'setup-lb' }));
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ state: 'pending' });
    mockFetch(() => emptyRes(404));
    expect(await upcloudProvider.describe(cfg, ledger)).toMatchObject({ state: 'gone' });
  });

  test('destroy is synchronous; 404 is gone; errors carry no token', async () => {
    const stub = mockFetch(() => emptyRes(204));
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[0], ledger)).toEqual({
      status: 'confirmed_gone',
    });
    expect(stub.calls[0]).toMatchObject({ method: 'DELETE', path: '/1.3/load-balancer/lb-uuid' });
    mockFetch(() => emptyRes(404));
    expect(await upcloudProvider.runDestroy(cfg, ledger.resources[1], ledger)).toEqual({
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
