import { afterEach, describe, expect, test, vi } from 'vitest';
import { ScalewayTemplate, __setScalewayApiFactory, scalewayProvider } from './scaleway';
import type { Ledger, ScalewayConfig } from './types';

afterEach(() => __setScalewayApiFactory(null));

const cfg: ScalewayConfig = {
  type: 'scaleway',
  accessKey: 'SCWXXXXXXXXXXXXXXXXX',
  secretKey: 'SECRET_SCW',
  projectId: 'proj',
  zone: 'fr-par-1',
};
const spec = {
  name: 'fcp-relay-o1-0badf00d',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
const tpl = ScalewayTemplate.parse({});

type Fake = Record<string, ReturnType<typeof vi.fn>>;

/** A fake ZonedAPI; list methods return `{ all }`-shaped promises like the SDK. */
function fakeApi(over: Partial<Fake> = {}): Fake {
  const list = (items: unknown[]) => Object.assign(Promise.resolve({}), { all: async () => items });
  const api: Fake = {
    createIp: vi.fn(async (r: { isIpv6: boolean }) => ({
      id: r.isIpv6 ? 'ip6-1' : 'ip4-1',
      ipAddress: r.isIpv6 ? '2001:db8::10' : '203.0.113.10',
      tags: [spec.name],
    })),
    createLb: vi.fn(async () => ({
      id: 'lb-1',
      name: spec.name,
      status: 'pending',
      ip: [{ id: 'ip4-1', ipAddress: '203.0.113.10', tags: [] }],
    })),
    createBackend: vi.fn(async () => ({ id: 'be-1', name: `${spec.name}-backend` })),
    createFrontend: vi.fn(async () => ({ id: 'fe-1', name: `${spec.name}-frontend` })),
    getLb: vi.fn(async () => ({
      id: 'lb-1',
      name: spec.name,
      status: 'ready',
      type: 'LB-S',
      zone: 'fr-par-1',
      ip: [
        { id: 'ip4-1', ipAddress: '203.0.113.10' },
        { id: 'ip6-1', ipAddress: '2001:db8::10' },
      ],
    })),
    getLbStats: vi.fn(async () => ({
      backendServersStats: [
        { ip: '198.51.100.7', lastHealthCheckStatus: 'passed', serverState: 'running' },
      ],
    })),
    listIPs: vi.fn(() => list([])),
    listLbs: vi.fn(() => list([])),
    listBackends: vi.fn(() => list([])),
    listFrontends: vi.fn(() => list([])),
    listLbTypes: vi.fn(() => list([{ name: 'LB-S' }])),
    deleteLb: vi.fn(async () => undefined),
    deleteBackend: vi.fn(async () => undefined),
    deleteFrontend: vi.fn(async () => undefined),
    releaseIp: vi.fn(async () => undefined),
    ...over,
  };
  __setScalewayApiFactory(() => api as never);
  return api;
}

describe('scaleway: plan + steps', () => {
  test('plan: v4 ip, v6 ip, lb, backend, frontend (all discoverable)', () => {
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual([
      'allocate_ip',
      'allocate_ipv6',
      'create_lb',
      'create_backend',
      'create_frontend',
    ]);
    expect(steps.every((s) => s.discoverability !== 'none')).toBe(true);
    const noV6 = scalewayProvider.planProvision(cfg, spec, ScalewayTemplate.parse({ ipv6: false }));
    expect(noV6.map((s) => s.kind)).not.toContain('allocate_ipv6');
  });

  test('steps call the SDK with tcp forwarding, tagged ips and the origin as the only server', async () => {
    const api = fakeApi();
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    const ledger: Ledger = { steps: [], resources: [] };
    const ip4 = await scalewayProvider.runStep(cfg, steps[0], spec, tpl, ledger);
    expect(ip4).toMatchObject({
      status: 'done',
      resources: [{ kind: 'ip', resourceId: 'ip4-1' }],
      addresses: { v4: '203.0.113.10' },
    });
    expect(api.createIp).toHaveBeenCalledWith({
      projectId: 'proj',
      isIpv6: false,
      tags: [spec.name],
    });
    ledger.resources.push({
      stepId: 'ip4',
      kind: 'ip',
      resourceId: 'ip4-1',
      ownership: 'created',
      deleteState: 'present',
    });
    const ip6 = await scalewayProvider.runStep(cfg, steps[1], spec, tpl, ledger);
    expect(ip6).toMatchObject({
      resources: [{ kind: 'ipv6', resourceId: 'ip6-1' }],
      addresses: { v6: '2001:db8::10' },
    });
    ledger.resources.push({
      stepId: 'ip6',
      kind: 'ipv6',
      resourceId: 'ip6-1',
      ownership: 'created',
      deleteState: 'present',
    });
    const lb = await scalewayProvider.runStep(cfg, steps[2], spec, tpl, ledger);
    expect(lb).toMatchObject({ status: 'done', resources: [{ kind: 'lb', resourceId: 'lb-1' }] });
    expect(api.createLb).toHaveBeenCalledWith(
      expect.objectContaining({
        name: spec.name,
        type: 'LB-S',
        ipIds: ['ip4-1', 'ip6-1'],
        assignFlexibleIp: false,
      }),
    );
    ledger.resources.push({
      stepId: 'lb',
      kind: 'lb',
      resourceId: 'lb-1',
      ownership: 'created',
      deleteState: 'present',
    });
    await scalewayProvider.runStep(cfg, steps[3], spec, tpl, ledger);
    expect(api.createBackend).toHaveBeenCalledWith(
      expect.objectContaining({
        lbId: 'lb-1',
        forwardProtocol: 'tcp',
        forwardPort: 443,
        serverIp: ['198.51.100.7'],
        proxyProtocol: 'proxy_protocol_none',
      }),
    );
    ledger.resources.push({
      stepId: 'backend',
      kind: 'backend',
      resourceId: 'be-1',
      ownership: 'created',
      deleteState: 'present',
    });
    await scalewayProvider.runStep(cfg, steps[4], spec, tpl, ledger);
    expect(api.createFrontend).toHaveBeenCalledWith(
      expect.objectContaining({
        lbId: 'lb-1',
        inboundPort: 443,
        backendId: 'be-1',
        timeoutClient: '600s',
      }),
    );
  });
});

describe('scaleway: discovery / describe / destroy', () => {
  const steps = scalewayProvider.planProvision(cfg, spec, tpl);

  test('listings are authoritative: found by tag/name, else confirmed absent', async () => {
    const list = (items: unknown[]) =>
      Object.assign(Promise.resolve({}), { all: async () => items });
    fakeApi({
      listIPs: vi.fn(() =>
        list([
          { id: 'ip4-9', ipAddress: '203.0.113.90', tags: [spec.name] },
          { id: 'ipx', ipAddress: '203.0.113.91', tags: ['other'] },
        ]),
      ),
      listLbs: vi.fn(() => list([])),
    });
    expect(
      await scalewayProvider.discover(cfg, steps[0], spec, { steps: [], resources: [] }, 1),
    ).toMatchObject({
      status: 'found',
      resources: [{ kind: 'ip', resourceId: 'ip4-9', ownership: 'adopted' }],
    });
    expect(
      await scalewayProvider.discover(cfg, steps[1], spec, { steps: [], resources: [] }, 1),
    ).toEqual({ status: 'confirmed_absent' });
    expect(
      await scalewayProvider.discover(cfg, steps[2], spec, { steps: [], resources: [] }, 1),
    ).toEqual({ status: 'confirmed_absent' });
  });

  test('describe maps ready→active with both families and health from stats; 404 → gone', async () => {
    const api = fakeApi();
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
    const d = await scalewayProvider.describe(cfg, ledger);
    expect(d).toMatchObject({
      state: 'active',
      health: 'online',
      addresses: { v4: '203.0.113.10', v6: '2001:db8::10' },
    });
    // IPs the LB reports but the ledger lacks are adopted.
    expect(d.resources?.map((r) => r.resourceId).sort()).toEqual(['ip4-1', 'ip6-1']);
    api.getLb = vi.fn(async () => {
      throw Object.assign(new Error('not found'), { status: 404, name: 'ResourceNotFoundError' });
    });
    expect(await scalewayProvider.describe(cfg, ledger)).toMatchObject({ state: 'gone' });
  });

  test('destroy: lb is requested then confirmed by 404; ips release synchronously; errors carry no secret', async () => {
    const api = fakeApi();
    const lb = {
      stepId: 'lb',
      kind: 'lb',
      resourceId: 'lb-1',
      ownership: 'created' as const,
      deleteState: 'present' as const,
    };
    const ip = {
      stepId: 'ip4',
      kind: 'ip',
      resourceId: 'ip4-1',
      ownership: 'created' as const,
      deleteState: 'present' as const,
    };
    const ledger: Ledger = { steps: [], resources: [lb, ip] };
    expect(await scalewayProvider.runDestroy(cfg, lb, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(api.deleteLb).toHaveBeenCalledWith({ lbId: 'lb-1', releaseIp: false });
    expect(await scalewayProvider.runDestroy(cfg, ip, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    api.getLb = vi.fn(async () => {
      throw Object.assign(new Error(`gone SECRET_SCW`), {
        status: 404,
        name: 'ResourceNotFoundError',
      });
    });
    expect(await scalewayProvider.confirmDestroyed!(cfg, lb, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    api.getLb = vi.fn(async () => {
      throw Object.assign(new Error(`denied for SECRET_SCW at https://api.scaleway.com`), {
        status: 403,
        name: 'PermissionsDeniedError',
      });
    });
    let err: unknown;
    try {
      await scalewayProvider.describe(cfg, ledger);
    } catch (e) {
      err = e;
    }
    const blob = `${(err as Error).message} ${JSON.stringify((err as { meta: unknown }).meta)}`;
    expect(blob).not.toContain('SECRET_SCW');
    expect(blob).not.toContain('api.scaleway.com');
    expect(blob).toContain('403');
  });
});
