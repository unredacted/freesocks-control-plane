import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  SCALEWAY_SETTLE,
  ScalewayTemplate,
  __setScalewayApiFactory,
  __setScalewayKeysFactory,
  __setScalewayPause,
  scalewayApi,
  scalewayProvider,
  scalewayTimings,
} from './scaleway';
import type { Ledger, ResourceStep, ScalewayConfig, StepOutcome } from './types';
import { fakeScaleway, type FakeScaleway } from '../testing/fakeScaleway';

afterEach(() => {
  __setScalewayApiFactory(null);
  __setScalewayKeysFactory(null);
});

/** The IAM read of the key's default project: a project, or a throw (an SDK-shaped error). */
function fakeKeys(answer: string | null | { status: number; name: string }) {
  const defaultProjectOf = vi.fn(async () => {
    if (answer && typeof answer === 'object')
      throw Object.assign(new Error('refused'), { status: answer.status, name: answer.name });
    return answer;
  });
  __setScalewayKeysFactory(() => ({ defaultProjectOf }));
  return defaultProjectOf;
}

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
    // A new LB is still being built: the step waits for it under the LB's id.
    const lb = await scalewayProvider.runStep(cfg, steps[2], spec, tpl, ledger);
    expect(lb).toMatchObject({
      status: 'requested',
      opRef: 'settle:lb-1',
      resources: [{ kind: 'lb', resourceId: 'lb-1' }],
    });
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
    expect(await scalewayProvider.runStep(cfg, steps[3], spec, tpl, ledger)).toMatchObject({
      status: 'requested',
      resources: [{ kind: 'backend', resourceId: 'be-1' }],
    });
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
    expect(await scalewayProvider.runStep(cfg, steps[4], spec, tpl, ledger)).toMatchObject({
      status: 'requested',
      resources: [{ kind: 'frontend', resourceId: 'fe-1' }],
    });
    expect(api.createFrontend).toHaveBeenCalledWith(
      expect.objectContaining({
        lbId: 'lb-1',
        inboundPort: 443,
        backendId: 'be-1',
        timeoutClient: 600_000,
      }),
    );
  });
});

describe('scaleway: timings on the wire', () => {
  // The real SDK over a recording fetch, so what is asserted is the JSON the API reads.
  const sdkCfg: ScalewayConfig = {
    ...cfg,
    // The SDK refuses a secret key or a project that is not a UUID.
    secretKey: '99999999-8888-4777-8666-555555555555',
    projectId: '11111111-2222-4333-8444-555555555555',
  };
  // A distinct value per field, so each one is seen landing in its own place.
  const t = ScalewayTemplate.parse({
    timeoutClient: '600s',
    timeoutServer: '300s',
    timeoutConnect: '4.5s',
    timeoutTunnel: '3600s',
    timeoutQueue: '2.5s',
    healthCheck: {
      checkDelay: '5s',
      checkTimeout: '0.75s',
      checkMaxRetries: 3,
      transientCheckDelay: '0.5s',
    },
  });
  // int64 milliseconds (the Go SDK's marshaler.Duration).
  const BACKEND_MS = { timeout_server: 300_000, timeout_connect: 4500, timeout_tunnel: 3_600_000 };
  const HEALTH_CHECK_MS = { check_delay: 5000, check_timeout: 750 };
  // Protobuf durations (the Go SDK's scw.Duration): strings in seconds.
  const BACKEND_DURATION = { timeout_queue: '2.5s' };
  const HEALTH_CHECK_DURATION = { transient_check_delay: '0.5s' };

  function recorder() {
    const calls: Array<{ method: string; path: string; raw: string; body: unknown }> = [];
    const fetchImpl = (async (req: Request) => {
      const raw = await req.text();
      calls.push({
        method: req.method,
        path: new URL(req.url).pathname,
        raw,
        body: raw ? JSON.parse(raw) : undefined,
      });
      // A ready LB for the settle reads; an id for every create.
      return new Response(JSON.stringify({ id: 'x-1', status: 'ready' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const sent = (method: string, path: RegExp) => {
      const hit = calls.find((c) => c.method === method && path.test(c.path));
      if (!hit) throw new Error(`no ${method} ${path} was sent`);
      return hit;
    };
    return { fetchImpl, sent };
  }

  const ledgerWith = (...kinds: Array<[string, string]>): Ledger => ({
    steps: [],
    resources: kinds.map(([kind, resourceId]) => ({
      stepId: kind,
      kind,
      resourceId,
      ownership: 'created' as const,
      deleteState: 'present' as const,
    })),
  });

  test('create: the six int64 fields carry JSON integers in milliseconds, the two durations stay strings', async () => {
    const { fetchImpl, sent } = recorder();
    __setScalewayApiFactory((c) => scalewayApi(c, fetchImpl));
    const steps = scalewayProvider.planProvision(sdkCfg, spec, t);
    const step = (kind: string) => steps.find((s) => s.kind === kind)!;
    await scalewayProvider.runStep(
      sdkCfg,
      step('create_backend'),
      spec,
      t,
      ledgerWith(['lb', 'lb-1']),
    );
    await scalewayProvider.runStep(
      sdkCfg,
      step('create_frontend'),
      spec,
      t,
      ledgerWith(['lb', 'lb-1'], ['backend', 'be-1']),
    );

    const backend = sent('POST', /\/lbs\/lb-1\/backends$/);
    expect(backend.body).toMatchObject({
      ...BACKEND_MS,
      ...BACKEND_DURATION,
      health_check: { ...HEALTH_CHECK_MS, ...HEALTH_CHECK_DURATION, check_max_retries: 3 },
    });
    // A bare integer in the text, never a quoted one (the refused `"5s"` sat here).
    expect(backend.raw).toContain('"check_delay":5000');
    expect(backend.raw).toContain('"timeout_server":300000');
    const frontend = sent('POST', /\/lbs\/lb-1\/frontends$/);
    expect(frontend.body).toMatchObject({ timeout_client: 600_000 });
    expect(frontend.raw).toContain('"timeout_client":600000');
  });

  test('update: the same builder puts the same encoding on the backend, health check and frontend updates', async () => {
    // FCP never changes a live edge today (a new one is built); this pins the
    // SDK's update marshalling for when it does.
    const { fetchImpl, sent } = recorder();
    const api = scalewayApi(sdkCfg, fetchImpl);
    const w = scalewayTimings(t, 'update');
    await api.updateBackend({
      backendId: 'be-1',
      name: `${spec.name}-backend`,
      forwardProtocol: 'tcp',
      forwardPort: 443,
      forwardPortAlgorithm: t.forwardPortAlgorithm,
      stickySessions: 'none',
      stickySessionsCookieName: '',
      ...w.backend,
    });
    await api.updateHealthCheck({
      backendId: 'be-1',
      port: 443,
      checkMaxRetries: t.healthCheck.checkMaxRetries,
      checkSendProxy: false,
      tcpConfig: {},
      ...w.healthCheck,
    });
    await api.updateFrontend({
      frontendId: 'fe-1',
      name: `${spec.name}-frontend`,
      inboundPort: 443,
      backendId: 'be-1',
      enableHttp3: false,
      ...w.frontend,
    });

    expect(sent('PUT', /\/backends\/be-1$/).body).toMatchObject({
      ...BACKEND_MS,
      ...BACKEND_DURATION,
    });
    expect(sent('PUT', /\/backends\/be-1\/healthcheck$/).body).toMatchObject({
      ...HEALTH_CHECK_MS,
      ...HEALTH_CHECK_DURATION,
    });
    expect(sent('PUT', /\/frontends\/fe-1$/).body).toMatchObject({ timeout_client: 600_000 });
  });

  test('defaults go out in milliseconds; unset durations are not sent', async () => {
    const w = scalewayTimings(tpl, 'plan');
    expect(w).toEqual({
      backend: { timeoutServer: 600_000, timeoutConnect: 5000, timeoutTunnel: 3_600_000 },
      healthCheck: { checkDelay: 5000, checkTimeout: 3000 },
      frontend: { timeoutClient: 600_000 },
    });
  });

  test('a stored value that is not whole milliseconds refuses the plan, before anything is created', () => {
    const odd = ScalewayTemplate.parse({ timeoutConnect: '1.5ms' });
    expect(() => scalewayProvider.planProvision(sdkCfg, spec, odd)).toThrow(
      expect.objectContaining({
        meta: expect.objectContaining({ code: 'template_invalid', retryable: false }),
      }),
    );
    // A stored duration in another unit is sent in the unit each field takes.
    const legacy = ScalewayTemplate.parse({
      timeoutQueue: '1500ms',
      healthCheck: { checkDelay: '1m', checkTimeout: '3s', checkMaxRetries: 3 },
    });
    const w = scalewayTimings(legacy, 'plan');
    expect(w.backend.timeoutQueue).toBe('1.5s');
    expect(w.healthCheck.checkDelay).toBe(60_000);
  });
});

describe('scaleway: options', () => {
  const ledgerWith = (...kinds: Array<[string, string]>): Ledger => ({
    steps: [],
    resources: kinds.map(([kind, resourceId]) => ({
      stepId: kind,
      kind,
      resourceId,
      ownership: 'created' as const,
      deleteState: 'present' as const,
    })),
  });

  test('options left unset send what FCP sent before options existed', async () => {
    const api = fakeApi();
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    await scalewayProvider.runStep(cfg, steps[3], spec, tpl, ledgerWith(['lb', 'lb-1']));
    const backend = api.createBackend.mock.calls[0]![0] as Record<string, unknown>;
    expect(backend.onMarkedDownAction).toBe('on_marked_down_action_none');
    for (const k of ['maxConnections', 'timeoutQueue', 'maxRetries'])
      expect(backend).not.toHaveProperty(k);
    expect(backend.healthCheck).not.toHaveProperty('transientCheckDelay');
    await scalewayProvider.runStep(
      cfg,
      steps[4],
      spec,
      tpl,
      ledgerWith(['lb', 'lb-1'], ['backend', 'be-1']),
    );
    expect(api.createFrontend.mock.calls[0]![0]).not.toHaveProperty('connectionRateLimit');
  });

  test('each option reaches its API field', async () => {
    const api = fakeApi();
    const t = ScalewayTemplate.parse({
      reverse: 'edge.example.org',
      description: 'spare',
      maxConnections: 5000,
      timeoutQueue: '2.5s',
      maxRetries: 2,
      closeOnFailure: true,
      connectionRateLimit: 100,
      healthCheck: {
        checkDelay: '5s',
        checkTimeout: '3s',
        checkMaxRetries: 3,
        transientCheckDelay: '0.5s',
      },
    });
    const steps = scalewayProvider.planProvision(cfg, spec, t);
    await scalewayProvider.runStep(cfg, steps[0], spec, t, ledgerWith());
    expect(api.createIp).toHaveBeenCalledWith(
      expect.objectContaining({ reverse: 'edge.example.org' }),
    );
    await scalewayProvider.runStep(cfg, steps[2], spec, t, ledgerWith(['ip', 'ip4-1']));
    expect(api.createLb).toHaveBeenCalledWith(expect.objectContaining({ description: 'spare' }));
    await scalewayProvider.runStep(cfg, steps[3], spec, t, ledgerWith(['lb', 'lb-1']));
    expect(api.createBackend).toHaveBeenCalledWith(
      expect.objectContaining({
        maxConnections: 5000,
        timeoutQueue: '2.5s',
        maxRetries: 2,
        onMarkedDownAction: 'shutdown_sessions',
        healthCheck: expect.objectContaining({ transientCheckDelay: '0.5s' }),
      }),
    );
    await scalewayProvider.runStep(
      cfg,
      steps[4],
      spec,
      t,
      ledgerWith(['lb', 'lb-1'], ['backend', 'be-1']),
    );
    expect(api.createFrontend).toHaveBeenCalledWith(
      expect.objectContaining({ connectionRateLimit: 100 }),
    );
  });
});

describe('scaleway: settling between steps', () => {
  // The fake LB reads `pending` for a while after every change and never
  // applies a change sent before it is `ready` again (testing/fakeScaleway.ts).
  const pauses: number[] = [];
  beforeEach(() => {
    pauses.length = 0;
    __setScalewayPause(async (ms) => {
      pauses.push(ms);
    });
  });
  afterEach(() => __setScalewayPause(null));

  const use = (fake: FakeScaleway) => __setScalewayApiFactory(() => fake.api as never);
  const steps = scalewayProvider.planProvision(cfg, spec, tpl);
  const stepOfKind = (kind: string) => steps.find((x) => x.kind === kind)!;

  /** What the rotation records of an outcome (settleOp: resources deduped, startedAt kept). */
  function record(ledger: Ledger, step: ResourceStep, out: StepOutcome, at = Date.now()): Ledger {
    const was = ledger.steps.find((x) => x.stepId === step.id);
    const known = new Set(ledger.resources.map((r) => `${r.kind}:${r.resourceId}`));
    return {
      steps: [
        ...ledger.steps.filter((x) => x.stepId !== step.id),
        {
          stepId: step.id,
          kind: step.kind,
          resourceName: step.resourceName,
          state: out.status === 'partial' ? 'unresolved' : out.status,
          attempt: 1,
          startedAt: was?.startedAt ?? at,
        },
      ],
      resources: [
        ...ledger.resources,
        ...out.resources
          .filter((r) => !known.has(`${r.kind}:${r.resourceId}`))
          .map((r) => ({
            stepId: step.id,
            kind: r.kind,
            resourceId: r.resourceId,
            ownership: r.ownership,
            deleteState: 'present' as const,
          })),
      ],
    };
  }

  /** The build the way the rotation drives it: each step run, then polled until done. */
  async function build(): Promise<{ ledger: Ledger; stoppedOn: StepOutcome | null }> {
    let ledger: Ledger = { steps: [], resources: [] };
    for (const step of steps) {
      let out = await scalewayProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = record(ledger, step, out);
      for (let i = 0; out.status === 'requested'; i++) {
        if (i > 50) throw new Error(`${step.id} never settled`);
        out = await scalewayProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = record(ledger, step, out);
      }
      if (out.status !== 'done') return { ledger, stoppedOn: out };
    }
    return { ledger, stoppedOn: null };
  }

  /** The ledger of a built edge (IPs, LB, backend, frontend). */
  const built = (...kinds: Array<[string, string]>): Ledger => ({
    steps: [],
    resources: kinds.map(([kind, resourceId]) => ({
      stepId: kind,
      kind,
      resourceId,
      ownership: 'created' as const,
      deleteState: 'present' as const,
    })),
  });

  test('sent back to back, the backend and frontend are accepted and never applied (what was observed)', async () => {
    const fake = fakeScaleway({ applyReads: 3 });
    await fake.api.createLb({ name: spec.name });
    await fake.api.createBackend({ name: `${spec.name}-backend` });
    await fake.api.createFrontend({ name: `${spec.name}-frontend`, backendId: 'be-1' });
    expect(fake.lost()).toEqual(['backend', 'frontend']);
    expect(fake.answers()).toBe(false);
  });

  test('every change waits for a ready LB, before and after: nothing is lost and the address answers', async () => {
    const fake = fakeScaleway({ applyReads: 3 });
    use(fake);
    const { ledger, stoppedOn } = await build();
    expect(stoppedOn).toBeNull();
    expect(fake.lost()).toEqual([]);
    expect(fake.answers()).toBe(true);
    // Each create goes out right after a READY read, and the build ends on one.
    for (const create of ['createBackend', 'createFrontend']) {
      const i = fake.calls.indexOf(create);
      expect(fake.calls[i - 1]).toBe('getLb:ready');
    }
    expect(fake.calls.at(-1)).toBe('getLb:ready');
    expect(fake.calls.filter((c) => c === 'getLb:pending').length).toBeGreaterThanOrEqual(9);
    // Done steps hold their resources, the LB step its addresses.
    expect(ledger.steps.every((x) => x.state === 'done')).toBe(true);
    expect(ledger.resources.map((r) => r.kind)).toEqual([
      'ip',
      'ipv6',
      'lb',
      'backend',
      'frontend',
    ]);
  });

  test('the LB step is done with its addresses once ready; a poll while it builds asks to be polled again', async () => {
    const fake = fakeScaleway({ applyReads: 2 });
    use(fake);
    const lbStep = stepOfKind('create_lb');
    await fake.api.createIp({ isIpv6: false, tags: [spec.name] });
    let ledger = built(['ip', 'ip4-1']);
    const out = await scalewayProvider.runStep(cfg, lbStep, spec, tpl, ledger);
    expect(out).toMatchObject({ status: 'requested', opRef: 'settle:lb-1' });
    ledger = record(ledger, lbStep, out);
    expect(await scalewayProvider.pollStep!(cfg, lbStep, 'settle:lb-1', ledger)).toEqual({
      status: 'requested',
      opRef: 'settle:lb-1',
      resources: [],
    });
    await scalewayProvider.pollStep!(cfg, lbStep, 'settle:lb-1', ledger);
    expect(await scalewayProvider.pollStep!(cfg, lbStep, 'settle:lb-1', ledger)).toMatchObject({
      status: 'done',
      resources: [{ kind: 'lb', resourceId: 'lb-1' }],
      addresses: { v4: '198.51.100.80' },
    });
  });

  test('a backend waits in place for the LB; still busy after the wait, it throws before sending anything', async () => {
    const fake = fakeScaleway({ applyReads: 0 });
    use(fake);
    const step = stepOfKind('create_backend');
    const ledger = built(['lb', 'lb-1']);
    fake.busyFor(4);
    expect(await scalewayProvider.runStep(cfg, step, spec, tpl, ledger)).toMatchObject({
      status: 'requested',
      resources: [{ kind: 'backend', resourceId: 'be-1' }],
    });
    expect(pauses).toEqual([3000, 3000, 3000, 3000]);
    expect(fake.lost()).toEqual([]);

    // Busy for longer than the wait in place: nothing is sent, and the throw
    // is retryable (discovery proves the absence, the step runs again).
    pauses.length = 0;
    fake.busyFor(1000);
    const err = await scalewayProvider.runStep(cfg, step, spec, tpl, ledger).catch((e) => e);
    expect(err.meta).toMatchObject({ code: 'lb_busy', retryable: true });
    expect(pauses.reduce((a, b) => a + b, 0)).toBe(SCALEWAY_SETTLE.inStepMs);
    expect(fake.calls.filter((c) => c === 'createBackend')).toHaveLength(1);
  });

  test('a frontend waits the same way, and is done only once the LB applied it', async () => {
    const fake = fakeScaleway({ applyReads: 2 });
    use(fake);
    await fake.api.createLb({ name: spec.name });
    const step = stepOfKind('create_frontend');
    let ledger = built(['lb', 'lb-1'], ['backend', 'be-1']);
    const out = await scalewayProvider.runStep(cfg, step, spec, tpl, ledger);
    expect(fake.calls.slice(-4)).toEqual([
      'getLb:pending',
      'getLb:pending',
      'getLb:ready',
      'createFrontend',
    ]);
    ledger = record(ledger, step, out);
    expect((await scalewayProvider.pollStep!(cfg, step, 'settle:lb-1', ledger)).status).toBe(
      'requested',
    );
    await scalewayProvider.pollStep!(cfg, step, 'settle:lb-1', ledger);
    expect(await scalewayProvider.pollStep!(cfg, step, 'settle:lb-1', ledger)).toEqual({
      status: 'done',
      resources: [{ kind: 'frontend', resourceId: 'fe-1', ownership: 'created' }],
    });
    expect(fake.answers()).toBe(false); // the backend was never sent here
    expect(fake.lost()).toEqual([]);
  });

  test('an LB in a state it does not leave stops the run at once, before or after a change', async () => {
    const fake = fakeScaleway();
    use(fake);
    fake.force('error');
    expect(
      await scalewayProvider.runStep(
        cfg,
        stepOfKind('create_backend'),
        spec,
        tpl,
        built(['lb', 'lb-1']),
      ),
    ).toEqual({
      status: 'partial',
      resources: [],
      code: 'lb_unusable',
      refused: true,
      detail: 'load balancer status error',
    });
    expect(fake.calls).not.toContain('createBackend');
    const lbStep = stepOfKind('create_lb');
    const ledger = record(built(), lbStep, {
      status: 'requested',
      opRef: 'settle:lb-1',
      resources: [{ kind: 'lb', resourceId: 'lb-1', ownership: 'created' }],
    });
    fake.force('locked');
    expect(await scalewayProvider.pollStep!(cfg, lbStep, 'settle:lb-1', ledger)).toMatchObject({
      status: 'partial',
      code: 'lb_unusable',
      refused: true,
    });
  });

  test("a poll gives up 15 minutes after the step's first request, never sooner", async () => {
    const fake = fakeScaleway();
    use(fake);
    fake.busyFor(1000);
    const step = stepOfKind('create_backend');
    const out: StepOutcome = {
      status: 'requested',
      opRef: 'settle:lb-1',
      resources: [{ kind: 'backend', resourceId: 'be-1', ownership: 'created' }],
    };
    const startedAgo = (ms: number) => record(built(['lb', 'lb-1']), step, out, Date.now() - ms);
    expect(
      (await scalewayProvider.pollStep!(cfg, step, 'settle:lb-1', startedAgo(14 * 60_000))).status,
    ).toBe('requested');
    expect(
      await scalewayProvider.pollStep!(cfg, step, 'settle:lb-1', startedAgo(16 * 60_000)),
    ).toMatchObject({ status: 'partial', code: 'lb_settle_timeout', refused: true });
  });

  test("a poll is done only with the step's own resource on the ledger", async () => {
    use(fakeScaleway());
    const err = await scalewayProvider.pollStep!(
      cfg,
      stepOfKind('create_backend'),
      'settle:lb-1',
      built(['lb', 'lb-1']),
    ).catch((e) => e);
    expect(err.meta).toMatchObject({ code: 'ledger_incomplete' });
  });

  test('discovery finds a step only once the LB has applied it', async () => {
    const fake = fakeScaleway({ applyReads: 1 });
    use(fake);
    await fake.api.createLb({ name: spec.name });
    // The LB listing itself says it is still being built.
    expect(await scalewayProvider.discover(cfg, stepOfKind('create_lb'), spec, built(), 1)).toEqual(
      { status: 'unresolved' },
    );
    await fake.api.getLb();
    await fake.api.createBackend({ name: `${spec.name}-backend` });
    const backendStep = stepOfKind('create_backend');
    expect(
      await scalewayProvider.discover(cfg, backendStep, spec, built(['lb', 'lb-1']), 1),
    ).toEqual({ status: 'unresolved' });
    expect(
      await scalewayProvider.discover(cfg, backendStep, spec, built(['lb', 'lb-1']), 2),
    ).toMatchObject({ status: 'found', resources: [{ kind: 'backend', resourceId: 'be-1' }] });
  });

  test('reapply saves the frontend again as read, on a ready LB: the lost frontend is served', async () => {
    const fake = fakeScaleway({ applyReads: 2 });
    use(fake);
    // As observed: the frontend went out while the LB was still applying the backend.
    await fake.api.createLb({ name: spec.name });
    await fake.api.getLb();
    await fake.api.getLb();
    await fake.api.createBackend({ name: `${spec.name}-backend` });
    await fake.api.createFrontend({
      name: `${spec.name}-frontend`,
      inboundPort: 443,
      backendId: 'be-1',
      timeoutClient: 600_000,
      enableHttp3: false,
      enableAccessLogs: false,
    });
    expect(fake.answers()).toBe(false);
    const update = vi.spyOn(fake.api, 'updateFrontend');
    const ledger = built(['lb', 'lb-1'], ['backend', 'be-1'], ['frontend', 'fe-1']);
    expect(await scalewayProvider.reapply!(cfg, ledger)).toEqual({
      status: 'sent',
      settled: true,
    });
    expect(update).toHaveBeenCalledWith({
      frontendId: 'fe-1',
      name: `${spec.name}-frontend`,
      inboundPort: 443,
      backendId: 'be-1',
      enableHttp3: false,
      timeoutClient: 600_000,
      enableAccessLogs: false,
    });
    // It waited for the LB before and after the save.
    expect(fake.calls.slice(-8)).toEqual([
      'getLb:pending',
      'getLb:pending',
      'getLb:ready',
      'getFrontend',
      'updateFrontend',
      'getLb:pending',
      'getLb:pending',
      'getLb:ready',
    ]);
    expect(fake.answers()).toBe(true);
    expect(fake.lost()).toEqual([]);
  });

  test('reapply sends nothing while the LB is busy or stuck, or with no frontend', async () => {
    const fake = fakeScaleway();
    use(fake);
    await fake.api.createLb({ name: spec.name });
    await fake.api.createFrontend({ name: `${spec.name}-frontend`, backendId: 'be-1' });
    const update = vi.spyOn(fake.api, 'updateFrontend');
    const ledger = built(['lb', 'lb-1'], ['backend', 'be-1'], ['frontend', 'fe-1']);
    fake.busyFor(1000);
    expect(await scalewayProvider.reapply!(cfg, ledger)).toEqual({
      status: 'skipped',
      code: 'lb_busy',
    });
    fake.force('locked');
    expect(await scalewayProvider.reapply!(cfg, ledger)).toEqual({
      status: 'skipped',
      code: 'lb_unusable',
    });
    expect(await scalewayProvider.reapply!(cfg, built(['lb', 'lb-1']))).toEqual({
      status: 'skipped',
      code: 'no_frontend',
    });
    expect(update).not.toHaveBeenCalled();
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
      await scalewayProvider.discover(cfg, steps[1], spec, { steps: [], resources: [] }, 2),
    ).toEqual({ status: 'confirmed_absent' });
    expect(
      await scalewayProvider.discover(cfg, steps[2], spec, { steps: [], resources: [] }, 2),
    ).toEqual({ status: 'confirmed_absent' });
  });

  test('one quiet look is not proof that a create never happened', async () => {
    const list = (items: unknown[]) =>
      Object.assign(Promise.resolve({}), { all: async () => items });
    fakeApi({ listIPs: vi.fn(() => list([])), listLbs: vi.fn(() => list([])) });
    for (const step of [steps[0], steps[2]])
      expect(
        await scalewayProvider.discover(cfg, step, spec, { steps: [], resources: [] }, 1),
      ).toEqual({ status: 'unresolved' });
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

  const notFound = (msg = 'not found') =>
    Object.assign(new Error(msg), { status: 404, name: 'ResourceNotFoundError' });
  const res = (stepId: string, kind: string, resourceId: string) => ({
    stepId,
    kind,
    resourceId,
    ownership: 'created' as const,
    deleteState: 'present' as const,
  });

  test('planDestroy orders by kind (frontend → backend → lb → ips), not by ledger position', () => {
    // An IP adopted by describe() lands AFTER the lb in the ledger; reverse order
    // would release it while the lb still holds it.
    const ledger: Ledger = {
      steps: [],
      resources: [
        res('lb', 'lb', 'lb-1'),
        res('backend', 'backend', 'be-1'),
        res('frontend', 'frontend', 'fe-1'),
        res('describe', 'ip', 'ip4-1'),
        { ...res('describe', 'ipv6', 'ip6-gone'), deleteState: 'confirmed_gone' },
        res('describe', 'ipv6', 'ip6-1'),
      ],
    };
    expect(scalewayProvider.planDestroy(cfg, ledger).map((r) => r.resourceId)).toEqual([
      'fe-1',
      'be-1',
      'lb-1',
      'ip4-1',
      'ip6-1',
    ]);
  });

  test('destroy: every delete is requested then read back; a ready lb is still_present, deleting is unresolved, 404 is gone', async () => {
    const api = fakeApi();
    const lb = res('lb', 'lb', 'lb-1');
    const ip = res('ip4', 'ip', 'ip4-1');
    const ledger: Ledger = { steps: [], resources: [lb, ip] };
    expect(await scalewayProvider.runDestroy(cfg, lb, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(api.deleteLb).toHaveBeenCalledWith({ lbId: 'lb-1', releaseIp: false });
    expect(await scalewayProvider.runDestroy(cfg, ip, ledger)).toEqual({
      status: 'delete_requested',
    });
    expect(api.releaseIp).toHaveBeenCalledWith({ ipId: 'ip4-1' });
    // The lb reads back `ready`: the delete never landed → still_present (re-issue).
    expect(await scalewayProvider.confirmDestroyed!(cfg, lb, ledger)).toEqual({
      status: 'still_present',
    });
    api.getLb = vi.fn(async () => ({ id: 'lb-1', status: 'deleting', ip: [] }));
    expect(await scalewayProvider.confirmDestroyed!(cfg, lb, ledger)).toEqual({
      status: 'unresolved',
    });
    api.getLb = vi.fn(async () => {
      throw notFound('gone SECRET_SCW');
    });
    expect(await scalewayProvider.confirmDestroyed!(cfg, lb, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    // IPs are read back too: present → still_present; 404 → gone.
    api.getIp = vi.fn(async () => ({ id: 'ip4-1', ipAddress: '203.0.113.10' }));
    expect(await scalewayProvider.confirmDestroyed!(cfg, ip, ledger)).toEqual({
      status: 'still_present',
    });
    api.getIp = vi.fn(async () => {
      throw notFound();
    });
    expect(await scalewayProvider.confirmDestroyed!(cfg, ip, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    // An unknown kind is never assumed gone (operator parks the edge).
    const odd = res('x', 'mystery', 'm-1');
    expect(await scalewayProvider.runDestroy(cfg, odd, ledger)).toEqual({ status: 'unresolved' });
    expect(await scalewayProvider.confirmDestroyed!(cfg, odd, ledger)).toEqual({
      status: 'unresolved',
    });
  });

  test('destroy: the DELETE throws (unknown outcome), then the confirm pass reads 404 → gone', async () => {
    const api = fakeApi({
      deleteLb: vi.fn(async () => {
        throw Object.assign(new Error('gateway timeout'), { status: 504, name: 'GatewayTimeout' });
      }),
    });
    const lb = res('lb', 'lb', 'lb-1');
    const ledger: Ledger = { steps: [], resources: [lb] };
    await expect(scalewayProvider.runDestroy(cfg, lb, ledger)).rejects.toMatchObject({
      meta: { status: 504, retryable: true },
    });
    api.getLb = vi.fn(async () => {
      throw notFound();
    });
    expect(await scalewayProvider.confirmDestroyed!(cfg, lb, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('a 400 on an address allocation ends the run on a known code; a create with no project is never sent', async () => {
    const api = fakeApi({
      createIp: vi.fn(async () => {
        throw Object.assign(new Error('invalid argument(s): project_id is required'), {
          status: 400,
          name: 'InvalidArgumentsError',
        });
      }),
    });
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    // With the provider's own words (redacted; the ops layer scrubs the edge's names).
    expect(await scalewayProvider.runStep(cfg, steps[0], spec, tpl, empty)).toEqual({
      status: 'partial',
      resources: [],
      code: 'ip_allocation_refused',
      refused: true,
      detail: 'invalid argument(s): project_id is required',
    });
    // A provider fault is not a refusal: it is thrown, and the step is looked for again.
    api.createIp = vi.fn(async () => {
      throw Object.assign(new Error('busy'), { status: 503, name: 'ScalewayError' });
    });
    await expect(scalewayProvider.runStep(cfg, steps[0], spec, tpl, empty)).rejects.toThrow(/503/);
    // No project from the location nor from the key: the run stops on it, nothing sent.
    api.createIp = vi.fn();
    const noProject = { ...cfg, projectId: undefined };
    expect(await scalewayProvider.runStep(noProject, steps[0], spec, tpl, empty)).toEqual({
      status: 'partial',
      resources: [],
      code: 'project_unresolved',
      refused: true,
    });
    expect(api.createIp).not.toHaveBeenCalled();
  });

  test('the LB, backend and frontend creates stop on a refusal for good; a busy LB (409, 412) stays unknown', async () => {
    const refusal = (status: number, name: string) =>
      vi.fn(async () => {
        throw Object.assign(new Error(`${name}: refused`), { status, name });
      });
    const api = fakeApi();
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    const ledger: Ledger = {
      steps: [],
      resources: [
        res('ip4', 'ip', 'ip4-1'),
        res('lb', 'lb', 'lb-1'),
        res('backend', 'backend', 'be-1'),
      ],
    };
    const byKind = (kind: string) => steps.find((s) => s.kind === kind)!;
    for (const [kind, method] of [
      ['create_lb', 'createLb'],
      ['create_backend', 'createBackend'],
      ['create_frontend', 'createFrontend'],
    ] as const) {
      api[method] = refusal(400, 'InvalidArgumentsError');
      expect(await scalewayProvider.runStep(cfg, byKind(kind), spec, tpl, ledger)).toMatchObject({
        status: 'partial',
        resources: [],
        code: 'create_refused',
        refused: true,
        detail: expect.stringContaining('refused'),
      });
      api[method] = refusal(403, 'QuotasExceededError');
      expect(await scalewayProvider.runStep(cfg, byKind(kind), spec, tpl, ledger)).toMatchObject({
        code: 'create_refused',
        refused: true,
      });
      for (const [status, name] of [
        [409, 'TransientStateError'],
        [412, 'PreconditionFailedError'],
      ] as const) {
        api[method] = refusal(status, name);
        await expect(
          scalewayProvider.runStep(cfg, byKind(kind), spec, tpl, ledger),
        ).rejects.toMatchObject({ meta: { status } });
      }
    }
  });

  test('errors carry no secret or host', async () => {
    const api = fakeApi();
    const lb = res('lb', 'lb', 'lb-1');
    const ledger: Ledger = { steps: [], resources: [lb] };
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

describe('scaleway: credential test and the default project', () => {
  const account: ScalewayConfig = { ...cfg, projectId: undefined, zone: '' };

  test("reads the key's default project as an observed fact, listing in no project", async () => {
    const api = fakeApi();
    const keys = fakeKeys('66666666-7777-4888-8999-000000000000');
    // A project an earlier test observed (now in the config) is not where the key is tested.
    expect(await scalewayProvider.testCredentials({ ...account, projectId: 'old' })).toEqual({
      ok: true,
      observed: { defaultProjectId: '66666666-7777-4888-8999-000000000000' },
    });
    expect(api.listLbs).toHaveBeenCalledWith({ pageSize: 1 });
    expect(keys).toHaveBeenCalledWith(cfg.accessKey);
  });

  test('a key that may not read it still passes (its locations need a Project id); a provider fault fails the test', async () => {
    fakeApi();
    for (const status of [401, 403, 404]) {
      fakeKeys({ status, name: 'PermissionsDeniedError' });
      expect(await scalewayProvider.testCredentials(account)).toEqual({ ok: true });
    }
    // A key with no default project at all.
    fakeKeys(null);
    expect(await scalewayProvider.testCredentials(account)).toEqual({ ok: true });
    fakeKeys({ status: 500, name: 'ScalewayError' });
    expect(await scalewayProvider.testCredentials(account)).toMatchObject({ ok: false });
  });
});
