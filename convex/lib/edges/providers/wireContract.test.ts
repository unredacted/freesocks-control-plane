// @vitest-environment node
/**
 * Wire contracts, one describe per provider (the CI workflow filters with
 * `-t <provider>`, so the names must stay recognisable).
 *
 * Each block drives the adapter's FULL lifecycle (credential test, option
 * discovery, plan, every step, every poll, discovery for every step, describe,
 * inspect, inventory, destroy planning, destroy and its confirmation) against a
 * RECORDING HTTP TRANSPORT, never against a stubbed adapter method, and then
 * asserts both directions of `WIRE_CONTRACTS`: nothing was requested that the
 * contract does not declare, and nothing is declared that the lifecycle never
 * requested. On top of that each block pins the credential header, the absence
 * of transport retries (a 429, a 500 and an aborted connection each produce
 * exactly one request), recovery from a lost response through `discover`
 * (never a second allocating call), the destroy order after a partial
 * provisioning, and that no error text carries a secret, the origin address or
 * the fronted hostname.
 *
 * Node environment: the Fastly SDK talks through superagent (node `http`), so
 * its traffic is observed with an in-process recorder rather than a `fetch`
 * stub; the other five adapters are observed through the global `fetch` stub in
 * the same environment, which keeps every provider under one `-t` filter.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { errorBlob, jsonRes, mockFetch, type Captured } from '../testing/mockFetch';
import { startHttpRecorder, type HttpRecorder, type RecordedCall } from '../testing/httpRecorder';
import { acmeChallengeName } from '../hostname';
import {
  WIRE_CONTRACTS,
  matchWireCall,
  tableRowCells,
  uncoveredEntries,
  unmatchedCalls,
  wireContractCells,
  WIRE_CONTRACT_HEADING,
  type ObservedCall,
} from './wireContract';
import type {
  ChildResource,
  CloudflareConfig,
  EdgeProvider,
  EdgeSpec,
  FastlyConfig,
  GcoreConfig,
  Ledger,
  LedgerResource,
  OvhConfig,
  ResourceStep,
  ScalewayConfig,
  StepOutcome,
  UpcloudConfig,
} from './types';
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { DnsClient, DnsCreateArgs, DnsRecord, DnsRecordType } from './dns/types';
import { gcoreProvider } from './gcore';
import { upcloudProvider } from './upcloud';
import { createAdvancedClient, withHTTPClient, withProfile } from '@scaleway/sdk-client';
import { Lbv1 } from '@scaleway/sdk-lb';
import { scalewayProvider, __setScalewayApiFactory } from './scaleway';
import { ovhProvider, __resetOvhSkewCache } from './ovh';
import { cloudflareProvider, __setCloudflareApiFactory } from './cloudflare';
import { cloudflareApi } from './dns/cloudflareDns';
import { fastlyProvider, __setFastlyDnsClientFactory } from './fastly';
import { __setFastlyBasePath } from './fastly/sdk';
import { readFileSync } from 'node:fs';

// --- shared plumbing -------------------------------------------------------------------

/** The origin every spec points at; it must never appear in an error. */
const ORIGIN_IP = '198.51.100.7';

function keysOf(body: unknown): string[] {
  return body && typeof body === 'object' && !Array.isArray(body) ? Object.keys(body) : [];
}

function fromCaptured(calls: readonly Captured[]): ObservedCall[] {
  return calls.map((c) => ({
    method: c.method,
    path: c.path,
    queryKeys: [...new URLSearchParams(c.query).keys()],
    bodyKeys: keysOf(c.body),
  }));
}

function fromRecorded(calls: readonly RecordedCall[]): ObservedCall[] {
  return calls.map((c) => ({
    method: c.method,
    path: c.path,
    queryKeys: Object.keys(c.query),
    bodyKeys: keysOf(c.body),
  }));
}

const show = (c: ObservedCall) =>
  `${c.method} ${c.path}${c.queryKeys?.length ? `?${c.queryKeys.join('&')}` : ''}`;

/** Every recorded call is declared (an undeclared endpoint fails here). */
function expectDeclared(id: EdgeProviderId, calls: readonly ObservedCall[]): void {
  expect(calls.length).toBeGreaterThan(0);
  expect(unmatchedCalls(id, calls).map(show)).toEqual([]);
}

/** ...and every declared call was exercised (a dead contract entry fails here). */
function expectContractCovered(id: EdgeProviderId, calls: readonly ObservedCall[]): void {
  expectDeclared(id, calls);
  expect(uncoveredEntries(id, calls).map((e) => `${e.method} ${e.path}`)).toEqual([]);
}

/** Fold a step outcome into the ledger the way the orchestrator's mutation does. */
function apply(ledger: Ledger, step: ResourceStep, out: StepOutcome): Ledger {
  const resources: ChildResource[] = 'resources' in out ? out.resources : [];
  return {
    steps: [
      ...ledger.steps.filter((s) => s.stepId !== step.id),
      {
        stepId: step.id,
        kind: step.kind,
        resourceName: step.resourceName,
        state:
          out.status === 'done' ? 'done' : out.status === 'requested' ? 'requested' : 'unresolved',
        attempt: 1,
        ...(out.status === 'requested' ? { opRef: out.opRef } : {}),
        startedAt: 1,
      },
    ],
    resources: [
      ...ledger.resources,
      ...resources.map((r) => ({
        stepId: step.id,
        kind: r.kind,
        resourceId: r.resourceId,
        ownership: r.ownership,
        deleteState: 'present' as const,
        ...(r.meta ? { meta: JSON.stringify(r.meta) } : {}),
      })),
    ],
  };
}

function resource(
  stepId: string,
  kind: string,
  resourceId: string,
  meta?: Record<string, unknown>,
): LedgerResource {
  return {
    stepId,
    kind,
    resourceId,
    ownership: 'created',
    deleteState: 'present',
    ...(meta ? { meta: JSON.stringify(meta) } : {}),
  };
}

/** Destroy everything the plan lists, in the adapter's own order. */
async function destroyAll(
  provider: EdgeProvider,
  cfg: never,
  ledger: Ledger,
  confirm = true,
): Promise<string[]> {
  const plan = provider.planDestroy(cfg, ledger);
  for (const r of plan) {
    await provider.runDestroy(cfg, r, ledger);
    if (confirm && provider.confirmDestroyed) await provider.confirmDestroyed(cfg, r, ledger);
  }
  return plan.map((r) => r.kind);
}

async function caught(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return undefined;
  } catch (e) {
    return e;
  }
}

/**
 * `discoverOptions` takes the account form's partial, index-signature state;
 * a fully typed config is not assignable to it without this widening.
 */
function partial<T extends object>(cfg: T): Partial<T> & Record<string, unknown> {
  return { ...cfg } as Partial<T> & Record<string, unknown>;
}

/** An aborted request, as `fetch` reports one. */
function abortError(): Error {
  const e = new Error('The operation was aborted');
  e.name = 'AbortError';
  return e;
}

// --- gcore ------------------------------------------------------------------------------

describe('wire contract: gcore', () => {
  afterEach(() => vi.unstubAllGlobals());

  const cfg: GcoreConfig = {
    type: 'gcore',
    apiKey: 'SECRET_GCORE_KEY',
    projectId: 11,
    regionId: 22,
    networkId: 'net-1',
    subnetId: 'sub-1',
  };
  const spec: EdgeSpec = {
    name: 'fcp-relay-o1-deadbeef',
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN_IP, port: 443 }] }],
  };
  const tpl = gcoreProvider.templateSchema.parse({}) as never;
  const SCOPE = '/cloud/v1/loadbalancers/11/22';
  const FIPS = '/cloud/v1/floatingips/11/22';

  // Shapes from https://api.gcore.com/docs/cloud (Cloud API v1), read 2026-09-16.
  const LB = {
    id: 'lb-1',
    name: spec.name,
    provisioning_status: 'ACTIVE',
    operating_status: 'ONLINE',
    vip_address: '203.0.113.50',
    floating_ips: [{ id: 'fip-1', floating_ip_address: '203.0.113.50' }],
    flavor: 'lb1-1-2',
    created_at: '2026-09-16T10:00:00Z',
    listeners: [{ id: 'lst-1', protocol_port: 443 }],
  };
  const TASK = {
    id: 'task-1',
    state: 'FINISHED',
    created_resources: { loadbalancers: ['lb-1'], floatingips: ['fip-1'] },
  };

  function route(over: { lbs?: unknown[] } = {}) {
    return (c: Captured): Response => {
      const p = c.path;
      if (p === '/cloud/v1/projects') return jsonRes({ results: [{ id: 11, name: 'project' }] });
      if (p === '/cloud/v1/regions')
        return jsonRes({ results: [{ id: 22, display_name: 'region' }] });
      if (p.startsWith('/cloud/v1/networks/'))
        return jsonRes({ results: [{ id: 'net-1', name: 'private' }] });
      if (p.startsWith('/cloud/v1/subnets/'))
        return jsonRes({
          results: [{ id: 'sub-1', name: 'sub', network_id: 'net-1', cidr: '10.0.0.0/24' }],
        });
      if (p.startsWith('/cloud/v1/tasks/')) return jsonRes(TASK);
      if (p === `/cloud/v1/lbflavors/11/22`)
        return jsonRes({ results: [{ flavor_name: 'lb1-1-2' }] });
      if (p === SCOPE)
        return c.method === 'POST'
          ? jsonRes({ tasks: ['task-1'] })
          : jsonRes({ results: over.lbs ?? [LB] });
      if (p === `${SCOPE}/lb-1`)
        return c.method === 'DELETE' ? jsonRes({ tasks: ['task-2'] }) : jsonRes(LB);
      if (p === FIPS)
        return jsonRes({ results: [{ id: 'fip-1', floating_ip_address: '203.0.113.50' }] });
      if (p === `${FIPS}/fip-1`)
        return c.method === 'DELETE'
          ? jsonRes({ tasks: ['task-3'] })
          : jsonRes({ id: 'fip-1', floating_ip_address: '203.0.113.50', status: 'ACTIVE' });
      return jsonRes({ message: 'not found' }, 404);
    };
  }

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const stub = mockFetch(route());
    await gcoreProvider.testCredentials(cfg);
    await gcoreProvider.listRegions!(cfg);
    await gcoreProvider.discoverOptions!(partial(cfg));

    const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
    let ledger: Ledger = { steps: [], resources: [] };
    const started = await gcoreProvider.runStep(cfg, step, spec, tpl, ledger);
    ledger = apply(ledger, step, started);
    expect(started.status).toBe('requested');
    const polled = await gcoreProvider.pollStep!(cfg, step, 'task-1', ledger);
    ledger = apply(ledger, step, polled);
    expect(polled.status).toBe('done');

    // Discovery twice: through the task the step recorded, and (with no opRef)
    // through the by-name listing.
    expect((await gcoreProvider.discover(cfg, step, spec, ledger, 1)).status).toBe('found');
    const listingOnly: Ledger = { steps: [], resources: ledger.resources };
    expect((await gcoreProvider.discover(cfg, step, spec, listingOnly, 1)).status).toBe('found');

    await gcoreProvider.describe(cfg, ledger);
    await gcoreProvider.inspect(cfg, ledger);
    await gcoreProvider.inventory(cfg);
    expect(await destroyAll(gcoreProvider as never, cfg as never, ledger)).toEqual([
      'lb',
      'floating_ip',
    ]);

    // An empty listing after the settle window is the only confirmed absence.
    stub.route(route({ lbs: [] }));
    const quiet: Ledger = {
      steps: [{ ...listingOnly.steps[0], ...ledger.steps[0], opRef: undefined, startedAt: 1 }],
      resources: [],
    };
    expect((await gcoreProvider.discover(cfg, step, spec, quiet, 3)).status).toBe(
      'confirmed_absent',
    );

    expectContractCovered('gcore', fromCaptured(stub.calls));
    expect(stub.calls.every((c) => c.headers.authorization === `APIKey ${cfg.apiKey}`)).toBe(true);
    expect(stub.calls.every((c) => c.redirect === 'manual')).toBe(true);
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    for (const reply of [429, 500] as const) {
      const stub = mockFetch(() => jsonRes({ message: 'busy' }, reply));
      const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
      expect(
        await caught(() => gcoreProvider.runStep(cfg, step, spec, tpl, emptyLedger)),
      ).toBeTruthy();
      expect(stub.calls).toHaveLength(1);
      vi.unstubAllGlobals();
    }
    const aborted = mockFetch(() => {
      throw abortError();
    });
    const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() => gcoreProvider.runStep(cfg, step, spec, tpl, emptyLedger));
    expect((err as { meta?: { timedOut?: boolean } }).meta?.timedOut).toBe(true);
    expect(aborted.calls).toHaveLength(1);
    vi.unstubAllGlobals();

    // The lost response is resolved by a READ, not by a second POST.
    const recovery = mockFetch(route());
    const lost: Ledger = {
      steps: [
        {
          stepId: 'lb',
          kind: 'create_lb',
          resourceName: spec.name,
          state: 'unresolved',
          attempt: 1,
          startedAt: 1,
        },
      ],
      resources: [],
    };
    const found = await gcoreProvider.discover(cfg, step, spec, lost, 1);
    expect(found.status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expectDeclared('gcore', fromCaptured(recovery.calls));
  });

  test('errors carry no key, no origin address and no response body', async () => {
    mockFetch(() => jsonRes({ message: `bad key ${cfg.apiKey} for ${ORIGIN_IP}` }, 403));
    const [step] = gcoreProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() => gcoreProvider.runStep(cfg, step, spec, tpl, emptyLedger));
    expect(errorBlob(err)).not.toContain('SECRET_');
    expect(errorBlob(err)).not.toContain(ORIGIN_IP);
  });

  const emptyLedger: Ledger = { steps: [], resources: [] };
});

// --- upcloud ------------------------------------------------------------------------------

describe('wire contract: upcloud', () => {
  afterEach(() => vi.unstubAllGlobals());

  const cfg: UpcloudConfig = { type: 'upcloud', token: 'SECRET_UPCLOUD_TOKEN', zone: 'fi-hel1' };
  const spec: EdgeSpec = {
    name: 'fcp-relay-o2-cafebabe',
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN_IP, port: 443 }] }],
  };
  const tpl = upcloudProvider.templateSchema.parse({}) as never;
  const FLOATING = '203.0.113.60';

  // Shapes from https://developers.upcloud.com/1.3/ (Managed Load Balancer), read 2026-09-16.
  const LB = {
    uuid: 'lb-uuid-1',
    name: spec.name,
    plan: 'development',
    zone: 'fi-hel1',
    operational_state: 'running',
    created_at: '2026-09-16T10:00:00Z',
    nodes: [
      {
        operational_state: 'running',
        networks: [{ type: 'public', ip_addresses: [{ address: FLOATING, listen: true }] }],
      },
    ],
    frontends: [{ port: 443, mode: 'tcp' }],
    backends: [{ members: [{ ip: ORIGIN_IP, port: 443 }] }],
  };

  const route = (c: Captured): Response => {
    const p = c.path;
    if (p === '/1.3/account') return jsonRes({ account: { username: 'automation' } });
    if (p === '/1.3/zone')
      return jsonRes({ zones: { zone: [{ id: 'fi-hel1', description: 'Helsinki' }] } });
    if (p === '/1.3/load-balancer/plans') return jsonRes({ plans: [{ name: 'development' }] });
    if (p === '/1.3/load-balancer') return c.method === 'POST' ? jsonRes(LB) : jsonRes([LB]);
    if (p === `/1.3/load-balancer/${LB.uuid}/ip-addresses`) return jsonRes({});
    if (p === `/1.3/load-balancer/${LB.uuid}`) return jsonRes(c.method === 'DELETE' ? {} : LB);
    if (p === '/1.3/ip_address')
      return c.method === 'POST'
        ? jsonRes({ ip_address: { address: FLOATING } })
        : jsonRes({
            ip_addresses: {
              ip_address: [{ address: FLOATING, floating: 'yes', family: 'IPv4', zone: 'fi-hel1' }],
            },
          });
    if (p === `/1.3/ip_address/${FLOATING}`) return jsonRes({});
    return jsonRes({ error: { error_code: 'NOT_FOUND' } }, 404);
  };

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const stub = mockFetch(route);
    await upcloudProvider.testCredentials(cfg);
    await upcloudProvider.listRegions!(cfg);
    await upcloudProvider.discoverOptions!(partial(cfg));

    let ledger: Ledger = { steps: [], resources: [] };
    const steps = upcloudProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual(['create_lb', 'allocate_ip', 'attach_ip']);
    for (const step of steps) {
      const out = await upcloudProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
    }
    for (const step of steps) await upcloudProvider.discover(cfg, step, spec, ledger, 1);

    await upcloudProvider.describe(cfg, ledger);
    await upcloudProvider.inspect(cfg, ledger);
    await upcloudProvider.inventory(cfg);
    // No confirmDestroyed: the idempotent DELETE is re-issued instead.
    expect(await destroyAll(upcloudProvider as never, cfg as never, ledger)).toEqual([
      'lb',
      'floating_ip',
    ]);

    expectContractCovered('upcloud', fromCaptured(stub.calls));
    expect(stub.calls.every((c) => c.headers.authorization === `Bearer ${cfg.token}`)).toBe(true);
    expect(stub.calls.every((c) => c.redirect === 'manual')).toBe(true);
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const [lbStep, ipStep] = upcloudProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    for (const status of [429, 500] as const) {
      const stub = mockFetch(() => jsonRes({ error: { error_code: 'BUSY' } }, status));
      expect(
        await caught(() => upcloudProvider.runStep(cfg, lbStep, spec, tpl, empty)),
      ).toBeTruthy();
      expect(stub.calls).toHaveLength(1);
      vi.unstubAllGlobals();
    }
    const aborted = mockFetch(() => {
      throw abortError();
    });
    expect(await caught(() => upcloudProvider.runStep(cfg, ipStep, spec, tpl, empty))).toBeTruthy();
    expect(aborted.calls).toHaveLength(1);
    vi.unstubAllGlobals();

    const recovery = mockFetch(route);
    expect((await upcloudProvider.discover(cfg, lbStep, spec, empty, 1)).status).toBe('found');
    // A floating IP carries no name: an unknown outcome is an operator decision,
    // never a second allocation.
    expect((await upcloudProvider.discover(cfg, ipStep, spec, empty, 1)).status).toBe('ambiguous');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expectDeclared('upcloud', fromCaptured(recovery.calls));
  });

  test('errors carry no token, no origin address and no response body', async () => {
    mockFetch(() =>
      jsonRes({ error: { error_message: `token ${cfg.token} / ${ORIGIN_IP}` } }, 401),
    );
    const [step] = upcloudProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() =>
      upcloudProvider.runStep(cfg, step, spec, tpl, { steps: [], resources: [] }),
    );
    expect(errorBlob(err)).not.toContain('SECRET_');
    expect(errorBlob(err)).not.toContain(ORIGIN_IP);
  });
});

// --- scaleway ------------------------------------------------------------------------------

describe('wire contract: scaleway', () => {
  afterEach(() => {
    __setScalewayApiFactory(null);
    vi.unstubAllGlobals();
  });

  const cfg: ScalewayConfig = {
    type: 'scaleway',
    accessKey: 'SCWXXXXXXXXXXXXXXXXX',
    // The SDK refuses a secret key that is not a UUID, so this one cannot carry
    // a `SECRET_` marker: the leak assertions below use its literal value.
    secretKey: '99999999-8888-4777-8666-555555555555',
    projectId: '11111111-2222-4333-8444-555555555555',
    zone: 'fr-par-1',
  };
  const spec: EdgeSpec = {
    name: 'fcp-relay-o3-0badf00d',
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN_IP, port: 443 }] }],
  };
  const tpl = scalewayProvider.templateSchema.parse({}) as never;
  const ZONE = '/lb/v1/zones/fr-par-1';

  // Shapes from https://www.scaleway.com/en/developers/api/load-balancer/zoned-api/, read 2026-09-16.
  const IP4 = { id: 'ip4-1', ip_address: '203.0.113.80', tags: [spec.name], lb_id: 'lb-1' };
  const IP6 = { id: 'ip6-1', ip_address: '2001:db8::10', tags: [spec.name], lb_id: 'lb-1' };
  const LB = {
    id: 'lb-1',
    name: spec.name,
    status: 'ready',
    type: 'LB-S',
    zone: 'fr-par-1',
    created_at: '2026-09-16T10:00:00Z',
    ip: [IP4, IP6],
    tags: [spec.name],
  };
  const BACKEND = {
    id: 'be-1',
    name: `${spec.name}-backend`,
    forward_port: 443,
    pool: [ORIGIN_IP],
  };
  const FRONTEND = { id: 'fe-1', name: `${spec.name}-frontend`, inbound_port: 443 };

  /**
   * The REAL SDK, pointed at the recording stub.
   *
   * `scalewayApi(cfg, fetchImpl)` cannot be used here: it passes `httpClient`
   * to `createClient`, and `createClient` runs the argument through
   * `withProfile`, which copies only the apiURL, the ids and the credentials
   * (node_modules/@scaleway/sdk-client/dist/scw/client-ini-factory.js). The
   * HTTP client is dropped and the client keeps the `fetch` captured in
   * `DEFAULT_SETTINGS` at import time, which no later stub can replace. The
   * client is therefore built the way the SDK documents an alternative HTTP
   * client (`withHTTPClient`), with the same profile the adapter passes, so
   * what the ZonedAPI puts on the wire is still the real thing.
   */
  function useStub() {
    __setScalewayApiFactory((c) => {
      const client = createAdvancedClient(
        withProfile({
          accessKey: c.accessKey,
          secretKey: c.secretKey,
          defaultProjectId: c.projectId,
          defaultZone: c.zone as never,
        }),
        withHTTPClient(globalThis.fetch as typeof fetch),
      );
      return new Lbv1.ZonedAPI(client);
    });
  }

  const route = (c: Captured): Response => {
    const p = c.path;
    const isIpv6 =
      c.body && typeof c.body === 'object' && (c.body as { is_ipv6?: boolean }).is_ipv6 === true;
    if (p === `${ZONE}/lbs`)
      return c.method === 'POST' ? jsonRes(LB) : jsonRes({ lbs: [LB], total_count: 1 });
    if (p === `${ZONE}/lbs/lb-1`) return jsonRes(c.method === 'DELETE' ? {} : LB);
    if (p === `${ZONE}/lbs/lb-1/stats`)
      return jsonRes({
        backend_servers_stats: [
          { ip: ORIGIN_IP, last_health_check_status: 'passed', server_state: 'stopped' },
        ],
        total_count: 1,
      });
    if (p === `${ZONE}/lbs/lb-1/backends`)
      return c.method === 'POST'
        ? jsonRes(BACKEND)
        : jsonRes({ backends: [BACKEND], total_count: 1 });
    if (p === `${ZONE}/lbs/lb-1/frontends`)
      return c.method === 'POST'
        ? jsonRes(FRONTEND)
        : jsonRes({ frontends: [FRONTEND], total_count: 1 });
    if (p === `${ZONE}/backends/be-1`) return jsonRes(c.method === 'DELETE' ? {} : BACKEND);
    if (p === `${ZONE}/frontends/fe-1`) return jsonRes(c.method === 'DELETE' ? {} : FRONTEND);
    if (p === `${ZONE}/ips`)
      return c.method === 'POST'
        ? jsonRes(isIpv6 ? IP6 : IP4)
        : jsonRes({ ips: [IP4, IP6], total_count: 2 });
    if (p === `${ZONE}/ips/ip4-1`) return jsonRes(c.method === 'DELETE' ? {} : IP4);
    if (p === `${ZONE}/ips/ip6-1`) return jsonRes(c.method === 'DELETE' ? {} : IP6);
    if (p === `${ZONE}/lb-types`)
      return jsonRes({ lb_types: [{ name: 'LB-S', stock_status: 'available' }], total_count: 1 });
    return jsonRes({ message: 'not found', type: 'not_found' }, 404);
  };

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const stub = mockFetch(route);
    useStub();
    await scalewayProvider.testCredentials(cfg);

    let ledger: Ledger = { steps: [], resources: [] };
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual([
      'allocate_ip',
      'allocate_ipv6',
      'create_lb',
      'create_backend',
      'create_frontend',
    ]);
    for (const step of steps) {
      const out = await scalewayProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
    }
    for (const step of steps) await scalewayProvider.discover(cfg, step, spec, ledger, 1);

    await scalewayProvider.describe(cfg, ledger);
    await scalewayProvider.inspect(cfg, ledger);
    await scalewayProvider.inventory(cfg);
    expect(await destroyAll(scalewayProvider as never, cfg as never, ledger)).toEqual([
      'frontend',
      'backend',
      'lb',
      'ip',
      'ipv6',
    ]);

    expectContractCovered('scaleway', fromCaptured(stub.calls));
    expect(stub.calls.every((c) => c.headers['x-auth-token'] === cfg.secretKey)).toBe(true);
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const steps = scalewayProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    for (const status of [429, 500] as const) {
      const stub = mockFetch(() => jsonRes({ message: 'busy', type: 'busy' }, status));
      useStub();
      expect(
        await caught(() => scalewayProvider.runStep(cfg, steps[0], spec, tpl, empty)),
      ).toBeTruthy();
      expect(stub.calls).toHaveLength(1);
      vi.unstubAllGlobals();
    }
    const aborted = mockFetch(() => {
      throw abortError();
    });
    useStub();
    expect(
      await caught(() => scalewayProvider.runStep(cfg, steps[0], spec, tpl, empty)),
    ).toBeTruthy();
    expect(aborted.calls).toHaveLength(1);
    vi.unstubAllGlobals();

    const recovery = mockFetch(route);
    useStub();
    expect((await scalewayProvider.discover(cfg, steps[0], spec, empty, 1)).status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expectDeclared('scaleway', fromCaptured(recovery.calls));
  });

  test('errors carry no secret key, no origin address and no response body', async () => {
    mockFetch(() =>
      jsonRes({ message: `denied ${cfg.secretKey} ${ORIGIN_IP}`, type: 'denied' }, 403),
    );
    useStub();
    const [step] = scalewayProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() =>
      scalewayProvider.runStep(cfg, step, spec, tpl, { steps: [], resources: [] }),
    );
    expect(errorBlob(err)).not.toContain(cfg.secretKey);
    expect(errorBlob(err)).not.toContain(ORIGIN_IP);
  });
});

// --- ovh ------------------------------------------------------------------------------

describe('wire contract: ovh', () => {
  afterEach(() => {
    __resetOvhSkewCache();
    vi.unstubAllGlobals();
  });

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
  };
  const spec: EdgeSpec = {
    name: 'fcp-relay-o4-feedface',
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN_IP, port: 443 }] }],
  };
  const tpl = ovhProvider.templateSchema.parse({ flavorId: 'small' }) as never;
  const PROJECT = '/1.0/cloud/project/svc-1';
  const REGION = `${PROJECT}/region/GRA9`;
  const LBS = `${REGION}/loadbalancing/loadbalancer`;

  // Shapes from https://api.ovh.com/console/ (/cloud/project), read 2026-09-16.
  const LB = {
    id: 'lb-1',
    name: spec.name,
    provisioningStatus: 'ACTIVE',
    operatingStatus: 'ONLINE',
    vipAddress: '10.0.0.5',
    floatingIp: { id: 'fip-1', ip: '203.0.113.90', description: spec.name, status: 'ACTIVE' },
    flavorId: 'small',
    createdAt: '2026-09-16T10:00:00Z',
  };
  const GATEWAY = { id: 'gw-1', name: `${spec.name}-gw`, status: 'active' };

  function route(over: { empty?: boolean } = {}) {
    return (c: Captured): Response => {
      const p = c.path;
      if (p === '/1.0/auth/time') return jsonRes(1_700_000_000);
      if (p === '/1.0/cloud/project') return jsonRes(['svc-1']);
      if (p === PROJECT) return jsonRes({ description: 'freesocks' });
      if (p === `${PROJECT}/region`) return jsonRes(['GRA9']);
      if (p === `${PROJECT}/network/private`)
        return jsonRes([{ id: 'net-1', name: 'private', regions: [{ region: 'GRA9' }] }]);
      if (p === `${PROJECT}/network/private/net-1/subnet`)
        return jsonRes([{ id: 'sub-1', cidr: '10.0.0.0/24', ipPools: [{ region: 'GRA9' }] }]);
      if (p === `${PROJECT}/operation`) return jsonRes([]);
      if (p.startsWith(`${PROJECT}/operation/`))
        return jsonRes({
          id: 'op-1',
          status: 'completed',
          resourceId: 'lb-1',
          action: 'loadbalancer_create',
          createdAt: '2026-09-16T10:00:00Z',
        });
      if (p === `${REGION}/loadbalancing/flavor`) return jsonRes([{ id: 'small', name: 'small' }]);
      if (p === `${LBS}/lb-1/stats`) return jsonRes({ connections: 0 });
      if (p === `${LBS}/lb-1`)
        return jsonRes(c.method === 'DELETE' ? { id: 'op-2', status: 'created' } : LB);
      if (p === LBS)
        return c.method === 'POST'
          ? jsonRes({ id: 'op-1', status: 'created' })
          : jsonRes(over.empty ? [] : [LB]);
      if (p === `${REGION}/floatingip`)
        return jsonRes(
          over.empty ? [] : [{ id: 'fip-1', ip: '203.0.113.90', description: spec.name }],
        );
      if (p === `${REGION}/floatingip/fip-1`)
        return jsonRes(
          c.method === 'DELETE'
            ? { id: 'op-3', status: 'created' }
            : { id: 'fip-1', status: 'ACTIVE' },
        );
      if (p === `${REGION}/gateway`) return jsonRes(over.empty ? [] : [GATEWAY]);
      if (p === `${REGION}/gateway/gw-1`)
        return jsonRes(c.method === 'DELETE' ? { id: 'op-4', status: 'created' } : GATEWAY);
      return jsonRes({ class: 'Client::NotFound' }, 404);
    };
  }

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const stub = mockFetch(route());
    await ovhProvider.testCredentials(cfg);
    await ovhProvider.listRegions!(cfg);
    await ovhProvider.discoverOptions!(partial(cfg));

    const [step] = ovhProvider.planProvision(cfg, spec, tpl);
    let ledger: Ledger = { steps: [], resources: [] };
    const started = await ovhProvider.runStep(cfg, step, spec, tpl, ledger);
    ledger = apply(ledger, step, started);
    const polled = await ovhProvider.pollStep!(cfg, step, 'op-1', ledger);
    ledger = apply(ledger, step, polled);
    expect(polled.status).toBe('done');
    // The compound create mints the floating IP; the ledger records it the way
    // the orchestrator does, so destroy has every child.
    ledger = {
      ...ledger,
      resources: [...ledger.resources, resource('lb', 'floating_ip', 'fip-1')],
    };

    expect((await ovhProvider.discover(cfg, step, spec, ledger, 1)).status).toBe('found');
    const listingOnly: Ledger = { steps: [], resources: ledger.resources };
    expect((await ovhProvider.discover(cfg, step, spec, listingOnly, 1)).status).toBe('found');

    await ovhProvider.describe(cfg, ledger);
    await ovhProvider.inspect(cfg, ledger);
    await ovhProvider.inventory(cfg);
    expect(await destroyAll(ovhProvider as never, cfg as never, ledger)).toEqual([
      'lb',
      'floating_ip',
      'gateway',
    ]);

    // Nothing left anywhere: the in-flight operation listing is what keeps an
    // absence from being confirmed too early.
    stub.route(route({ empty: true }));
    const quiet: Ledger = {
      // A step requested long ago (past the settle floor) and never settled.
      steps: [
        {
          stepId: step.id,
          kind: step.kind,
          resourceName: step.resourceName,
          state: 'unresolved',
          attempt: 3,
          startedAt: 1,
        },
      ],
      resources: [],
    };
    expect((await ovhProvider.discover(cfg, step, spec, quiet, 3)).status).toBe('confirmed_absent');

    expectContractCovered('ovh', fromCaptured(stub.calls));
    expect(stub.calls.every((c) => c.redirect === 'manual')).toBe(true);
    for (const call of stub.calls) {
      if (call.path === '/1.0/auth/time') continue;
      expect(call.headers['x-ovh-application']).toBe(cfg.applicationKey);
      expect(call.headers['x-ovh-signature']).toMatch(/^\$1\$[0-9a-f]{40}$/);
    }
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const [step] = ovhProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    const withTime =
      (rest: (c: Captured) => Response) =>
      (c: Captured): Response =>
        c.path === '/1.0/auth/time' ? jsonRes(1_700_000_000) : rest(c);
    for (const status of [429, 500] as const) {
      __resetOvhSkewCache();
      const stub = mockFetch(withTime(() => jsonRes({ class: 'Client::Busy' }, status)));
      expect(await caught(() => ovhProvider.runStep(cfg, step, spec, tpl, empty))).toBeTruthy();
      expect(stub.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
      vi.unstubAllGlobals();
    }
    __resetOvhSkewCache();
    const aborted = mockFetch(
      withTime(() => {
        throw abortError();
      }),
    );
    expect(await caught(() => ovhProvider.runStep(cfg, step, spec, tpl, empty))).toBeTruthy();
    expect(aborted.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
    vi.unstubAllGlobals();

    __resetOvhSkewCache();
    const recovery = mockFetch(route());
    expect((await ovhProvider.discover(cfg, step, spec, empty, 1)).status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expectDeclared('ovh', fromCaptured(recovery.calls));
  });

  test('errors carry no signing secret, no origin address and no response body', async () => {
    mockFetch((c: Captured) =>
      c.path === '/1.0/auth/time'
        ? jsonRes(1_700_000_000)
        : jsonRes(
            { class: 'Client::Forbidden', message: `${cfg.applicationSecret} ${ORIGIN_IP}` },
            403,
          ),
    );
    const [step] = ovhProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() =>
      ovhProvider.runStep(cfg, step, spec, tpl, { steps: [], resources: [] }),
    );
    expect(errorBlob(err)).not.toContain('SECRET_');
    expect(errorBlob(err)).not.toContain(ORIGIN_IP);
  });
});

// --- cloudflare ------------------------------------------------------------------------------

describe('wire contract: cloudflare', () => {
  afterEach(() => {
    __setCloudflareApiFactory(null);
    vi.unstubAllGlobals();
  });

  const ZONE = '023e105f4ecef8ad9ca31a8372d0c353';
  const HOSTNAME = 'k7m2x9qp4n3f.example.net';
  const NAME = 'fcp-relay-o1-0badf00d';
  const RULESET = '3c0b456bc2aa443089c5f40defb5fdc9';
  const RULE_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const RECORD_ID = '372e67954025e0ba6aaa6d586b9e0b59';

  const cfg: CloudflareConfig = {
    type: 'cloudflare',
    apiToken: 'SECRET_CF_TOKEN',
    zoneId: ZONE,
    zoneName: 'example.net',
    accountId: 'acct_1',
  };
  const base = cloudflareProvider.templateSchema.parse({}) as Record<string, unknown>;
  /** The zone mode reaches the adapter as a frozen, rendered template param. */
  const tpl = { ...base, zoneSslMode: 'full' } as never;
  /** Port 8443 is not the mode's default, so the plan includes the origin rule. */
  const spec: EdgeSpec = {
    name: NAME,
    hostname: HOSTNAME,
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN_IP, port: 8443 }] }],
  };

  const fx = (name: string): Record<string, unknown> => {
    const raw = JSON.parse(
      readFileSync(new URL(`./fixtures/cloudflare/${name}`, import.meta.url), 'utf8'),
    ) as Record<string, unknown>;
    const { _source: _ignored, ...rest } = raw;
    return rest;
  };

  function route(over: { phaseMissing?: boolean } = {}) {
    return (c: Captured): Response => {
      const p = c.path;
      if (p.endsWith('/user/tokens/verify')) return jsonRes(fx('token_verify.json'));
      if (p.endsWith('/settings/ssl')) return jsonRes(fx('setting_ssl.json'));
      if (p.endsWith('/settings/websockets')) return jsonRes(fx('setting_websockets.json'));
      if (p.endsWith('/ssl/certificate_packs')) return jsonRes(fx('certificate_packs_list.json'));
      if (p.endsWith('/rulesets/phases/http_request_origin/entrypoint')) {
        if (c.method === 'PUT') return jsonRes(fx('ruleset_rule_created.json'));
        return over.phaseMissing
          ? jsonRes(fx('error_record_not_found.json'), 404)
          : jsonRes(fx('ruleset_origin_phase.json'));
      }
      if (p.includes('/rulesets/') && p.endsWith('/rules'))
        return jsonRes(fx('ruleset_rule_created.json'));
      if (p.includes('/rulesets/') && p.includes('/rules/'))
        return jsonRes({ result: null, success: true });
      if (p.includes('/dns_records/')) return jsonRes(fx('dns_record_created.json'));
      if (p.endsWith('/dns_records'))
        return jsonRes(
          c.method === 'POST' ? fx('dns_record_created.json') : fx('dns_records_list.json'),
        );
      if (p.endsWith(`/zones/${ZONE}`)) return jsonRes(fx('zone_get.json'));
      if (p.endsWith('/zones')) return jsonRes(fx('zones_list.json'));
      return jsonRes(fx('error_record_not_found.json'), 404);
    };
  }

  /** The SDK's own fetch option: every request is observed at the HTTP layer. */
  function useStub() {
    __setCloudflareApiFactory((c, f) => cloudflareApi(c, f ?? (globalThis.fetch as typeof fetch)));
  }

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const stub = mockFetch(route());
    useStub();
    await cloudflareProvider.testCredentials(cfg);
    await cloudflareProvider.listRegions!(cfg);
    await cloudflareProvider.discoverOptions!({ apiToken: cfg.apiToken });

    const steps = cloudflareProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual(['create_dns_record', 'create_origin_rule']);
    let ledger: Ledger = { steps: [], resources: [] };
    for (const step of steps) {
      const out = await cloudflareProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      expect(out.status).toBe('done');
    }
    for (const step of steps) {
      const found = await cloudflareProvider.discover(cfg, step, spec, ledger, 1);
      expect(found.status).toBe('found');
    }

    await cloudflareProvider.describe(cfg, ledger);
    await cloudflareProvider.inspect(cfg, ledger);
    await cloudflareProvider.inventory(cfg);
    // The import path: an existing record read back as adoptable children.
    const adopted = await cloudflareProvider.inspectForAdoption!(cfg, RECORD_ID, HOSTNAME);
    expect(adopted).toMatchObject({ hostname: HOSTNAME, shared: false, content: ORIGIN_IP });
    // Both deletes are synchronous and idempotent (no confirmDestroyed).
    expect(await destroyAll(cloudflareProvider as never, cfg as never, ledger)).toEqual([
      'origin_rule',
      'dns_record',
    ]);

    // A zone with no origin-rules entry point yet: the bootstrap PUT.
    stub.route(route({ phaseMissing: true }));
    const ruleStep = steps[1];
    const bootstrapped = await cloudflareProvider.runStep(cfg, ruleStep, spec, tpl, ledger);
    expect(bootstrapped.status).toBe('done');
    expect(
      stub.calls.some(
        (c) => c.method === 'PUT' && c.path.endsWith('/phases/http_request_origin/entrypoint'),
      ),
    ).toBe(true);

    expectContractCovered('cloudflare', fromCaptured(stub.calls));
    expect(stub.calls.every((c) => c.headers.authorization === `Bearer ${cfg.apiToken}`)).toBe(
      true,
    );
    // The rule is located by our ref, in both the bootstrap and the append path.
    const rulePost = stub.calls.find((c) => c.method === 'POST' && c.path.endsWith('/rules'));
    expect((rulePost!.body as { ref?: string }).ref).toBe(NAME);
    expect(rulePost!.path).toContain(`/rulesets/${RULESET}/rules`);
    const del = stub.calls.find((c) => c.method === 'DELETE' && c.path.includes('/rules/'));
    expect(del!.path.endsWith(`/rules/${RULE_ID}`)).toBe(true);
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const [dnsStep] = cloudflareProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    for (const status of [429, 500] as const) {
      const stub = mockFetch(() => jsonRes(fx('error_rate_limited.json'), status));
      useStub();
      expect(
        await caught(() => cloudflareProvider.runStep(cfg, dnsStep, spec, tpl, empty)),
      ).toBeTruthy();
      expect(stub.calls).toHaveLength(1);
      vi.unstubAllGlobals();
    }
    const aborted = mockFetch(() => {
      throw abortError();
    });
    useStub();
    expect(
      await caught(() => cloudflareProvider.runStep(cfg, dnsStep, spec, tpl, empty)),
    ).toBeTruthy();
    expect(aborted.calls).toHaveLength(1);
    vi.unstubAllGlobals();

    const recovery = mockFetch(route());
    useStub();
    const found = await cloudflareProvider.discover(cfg, dnsStep, spec, empty, 1);
    expect(found.status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expect(new URLSearchParams(recovery.calls[0].query).get('name.exact')).toBe(HOSTNAME);
    expectDeclared('cloudflare', fromCaptured(recovery.calls));
  });

  test('a destroy after a partial provisioning touches only the recorded children', async () => {
    const stub = mockFetch(route());
    useStub();
    // The record landed, the rule never did.
    const partial: Ledger = {
      steps: [],
      resources: [
        resource('dns', 'dns_record', RECORD_ID, { name: HOSTNAME, zoneId: ZONE, type: 'A' }),
      ],
    };
    expect(await destroyAll(cloudflareProvider as never, cfg as never, partial)).toEqual([
      'dns_record',
    ]);
    const deletes = stub.calls.filter((c) => c.method === 'DELETE');
    expect(deletes.map((c) => c.path.split('/client/v4')[1])).toEqual([
      `/zones/${ZONE}/dns_records/${RECORD_ID}`,
    ]);
    expectDeclared('cloudflare', fromCaptured(stub.calls));
  });

  test('errors carry no token, no origin address and no hostname', async () => {
    mockFetch(() =>
      jsonRes(
        {
          success: false,
          errors: [{ code: 1004, message: `bad ${cfg.apiToken} ${ORIGIN_IP} ${HOSTNAME}` }],
          result: null,
        },
        403,
      ),
    );
    useStub();
    const [step] = cloudflareProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() =>
      cloudflareProvider.runStep(cfg, step, spec, tpl, { steps: [], resources: [] }),
    );
    const blob = errorBlob(err);
    expect(blob).not.toContain('SECRET_');
    expect(blob).not.toContain(ORIGIN_IP);
    expect(blob).not.toContain(HOSTNAME);
  });
});

// --- fastly ------------------------------------------------------------------------------

describe('wire contract: fastly', () => {
  const HOST = 'k3m7q9zb.example.org';
  const ORIGIN = 'node-7.origin.example.net';
  const SVC = 'SU1Z0isxPaozGVKXdv0eY';
  const SUB = 'C0cuTFmLzMCiyMcOZuLEZ1';

  const cfg: FastlyConfig = {
    type: 'fastly',
    apiToken: 'SECRET_FASTLY_TOKEN',
    certificateAuthority: 'certainly',
    dns: {
      apiToken: 'SECRET_CF_TOKEN',
      zoneId: '0123456789abcdef0123456789abcdef',
      zoneName: 'example.org',
      accountId: 'dnsacct1',
    },
  };
  const spec: EdgeSpec = {
    name: 'fcp-relay-o1-deadbeef',
    hostname: HOST,
    listeners: [{ edgePort: 443, members: [{ address: ORIGIN, port: 443 }] }],
    originTransport: {
      scheme: 'https',
      certPublic: true,
      certNames: ['*.origin.example.net'],
      acceptsHostHeader: 'any',
    },
  };
  const tpl = fastlyProvider.templateSchema.parse({}) as never;

  /** Fixture bodies as the API sends them (the `_source` header is for reviewers). */
  function fixture(name: string): unknown {
    const raw = JSON.parse(
      readFileSync(new URL(`./fixtures/fastly/${name}`, import.meta.url), 'utf8'),
    ) as Record<string, unknown>;
    if ('_body' in raw) return raw._body;
    const { _source: _ignored, ...rest } = raw;
    return rest;
  }
  const ok = (name: string) => ({ status: 200, body: fixture(name) });
  const api = (name: string) => ({
    status: 200,
    body: fixture(name),
    contentType: 'application/vnd.api+json',
  });
  const NOT_FOUND = { status: 404, body: { msg: 'Record not found' } };

  /** The DNS records live in another account's zone: an in-memory writer here. */
  function fakeDns(): DnsClient & { deleted: string[] } {
    const rows: DnsRecord[] = [];
    const deleted: string[] = [];
    let next = 1;
    const client: DnsClient & { deleted: string[] } = {
      deleted,
      zoneId: cfg.dns!.zoneId,
      zoneName: cfg.dns!.zoneName,
      accountId: cfg.dns!.accountId,
      async createRecord(args: DnsCreateArgs) {
        const rec: DnsRecord = { id: `rec${next++}`, ...args };
        rows.push(rec);
        return rec;
      },
      async findRecordsByName(name: string, type?: DnsRecordType) {
        return rows.filter((r) => r.name === name && (!type || r.type === type));
      },
      async getRecord(id: string) {
        return rows.find((r) => r.id === id) ?? null;
      },
      async deleteRecord(id: string) {
        deleted.push(id);
        const i = rows.findIndex((r) => r.id === id);
        if (i >= 0) rows.splice(i, 1);
      },
      async listCaa() {
        return [];
      },
    };
    __setFastlyDnsClientFactory(() => client);
    return client;
  }

  function defaultReply(c: RecordedCall) {
    const p = c.path;
    const m = c.method;
    if (m === 'POST' && p === '/service') return ok('service-create.json');
    if (m === 'GET' && p === '/service/search') return ok('service-search.json');
    if (m === 'GET' && p === `/service/${SVC}/details`) return ok('service-detail-active.json');
    if (m === 'GET' && p === '/service') return ok('service-list.json');
    if (m === 'GET' && p === `/service/${SVC}/domain`) return ok('service-domains.json');
    if (m === 'DELETE' && p === `/service/${SVC}`) return { status: 200, body: { status: 'ok' } };
    if (m === 'GET' && p === `/service/${SVC}/version`) return ok('version-list.json');
    if (m === 'PUT' && /\/version\/\d+\/clone$/.test(p)) return ok('version-clone.json');
    if (m === 'GET' && /\/version\/\d+\/validate$/.test(p)) return ok('version-validate-ok.json');
    if (m === 'PUT' && /\/version\/\d+\/(activate|deactivate)$/.test(p))
      return ok('version-activate.json');
    if (m === 'PUT' && /\/version\/\d+$/.test(p)) return ok('version-clone.json');
    if (m === 'POST' && /\/backend$/.test(p)) return ok('backend-create.json');
    if (m === 'GET' && /\/backend\/origin$/.test(p)) return ok('backend-create.json');
    if (m === 'GET' && /\/backend$/.test(p))
      return { status: 200, body: [fixture('backend-create.json')] };
    if (m === 'POST' && /\/snippet$/.test(p)) return ok('snippet-create.json');
    if (m === 'GET' && /\/snippet\/ws-upgrade$/.test(p)) return ok('snippet-create.json');
    if (m === 'POST' && /\/domain$/.test(p)) return ok('domain-create.json');
    if (m === 'GET' && p.endsWith(`/domain/${HOST}/check`)) return ok('domain-check-ok.json');
    if (m === 'GET' && p.endsWith(`/domain/${HOST}`)) return ok('domain-create.json');
    if (m === 'DELETE' && p.endsWith(`/domain/${HOST}`))
      return { status: 200, body: { status: 'ok' } };
    if (m === 'GET' && /\/domain$/.test(p))
      return { status: 200, body: [fixture('domain-create.json')] };
    if (p === `/enabled-products/v1/websockets/services/${SVC}`)
      return m === 'DELETE' ? { status: 204 } : ok('websockets-enabled.json');
    if (m === 'POST' && p === '/tls/subscriptions') return api('tls-subscription-create.json');
    if (m === 'GET' && p === '/tls/subscriptions') return api('tls-subscriptions-list.json');
    if (m === 'GET' && p === `/tls/subscriptions/${SUB}`)
      return api(
        c.query.include ? 'tls-subscription-authorizations.json' : 'tls-subscription-issued.json',
      );
    if (m === 'DELETE' && p === `/tls/subscriptions/${SUB}`) return { status: 204 };
    if (m === 'GET' && p === '/tls/configurations') return api('tls-configurations.json');
    if (p === '/tokens/self') return ok('token-self.json');
    if (p === '/current_customer') return ok('current-customer.json');
    return NOT_FOUND;
  }

  let rec: HttpRecorder | undefined;
  afterEach(async () => {
    __setFastlyBasePath(null);
    __setFastlyDnsClientFactory(null);
    await rec?.close();
    rec = undefined;
  });

  async function serve(route = defaultReply): Promise<HttpRecorder> {
    rec = await startHttpRecorder(route);
    __setFastlyBasePath(rec.base);
    return rec;
  }

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const server = await serve();
    fakeDns();
    await fastlyProvider.testCredentials(cfg);
    await fastlyProvider.discoverOptions!({ apiToken: cfg.apiToken });

    let ledger: Ledger = { steps: [], resources: [] };
    const steps = fastlyProvider.planProvision(cfg, spec, tpl);
    for (const step of steps) {
      const out = await fastlyProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      if (out.status === 'requested') {
        const polled = await fastlyProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = apply(ledger, step, polled);
      }
    }
    expect(ledger.resources.map((r) => r.kind)).toEqual([
      'service',
      'backend',
      'snippet',
      'domain',
      'ws_product',
      'active_version',
      'tls_subscription',
      'dns_record',
      'dns_record',
    ]);
    for (const step of steps) await fastlyProvider.discover(cfg, step, spec, ledger, 1);

    await fastlyProvider.describe(cfg, ledger);
    await fastlyProvider.inspect(cfg, ledger);
    await fastlyProvider.inventory(cfg);
    // The import path: an existing service read back as adoptable children.
    const adopted = await fastlyProvider.inspectForAdoption!(cfg, SVC, HOST);
    expect(adopted).toMatchObject({ hostname: HOST, hostnames: [HOST], shared: false });
    expect(await destroyAll(fastlyProvider as never, cfg as never, ledger)).toEqual([
      'dns_record',
      'tls_subscription',
      'dns_record',
      'active_version',
      'service',
      'backend',
      'snippet',
      'domain',
      'ws_product',
    ]);

    // A shared service: only our own domain is removed, on a cloned version.
    const sharedLedger: Ledger = {
      steps: [],
      resources: [
        resource('service', 'service', SVC, {
          version: 2,
          activeVersion: 1,
          name: spec.name,
          shared: true,
        }),
        resource('domain', 'domain', HOST),
      ],
    };
    const teardown = fastlyProvider.sharedTeardown!;
    let state = teardown.plan(sharedLedger, 'op-1', Date.parse('2027-01-01T00:00:00Z'))!;
    expect(state.phase).toBe('clone');
    for (const expected of ['remove_domain', 'validate', 'activate', 'confirm'] as const) {
      state = await teardown.step(cfg, state);
      expect(state.phase).toBe(expected);
    }
    const work = state.workVersion!;
    server.route((c) => {
      if (c.method === 'GET' && c.path === `/service/${SVC}/details`)
        return { status: 200, body: { id: SVC, active_version: { number: work, active: true } } };
      if (c.method === 'GET' && c.path === `/service/${SVC}/version/${work}/domain`)
        return { status: 200, body: [] };
      return defaultReply(c);
    });
    state = await teardown.step(cfg, state);
    expect(state.phase).toBe('done');

    expectContractCovered('fastly', fromRecorded(server.calls));
    expect(server.calls.every((c) => c.headers['fastly-key'] === cfg.apiToken)).toBe(true);
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const [serviceStep] = fastlyProvider.planProvision(cfg, spec, tpl);
    const empty: Ledger = { steps: [], resources: [] };
    for (const status of [429, 500] as const) {
      const server = await serve(() => ({ status, body: { msg: 'Rate limit exceeded' } }));
      expect(
        await caught(() => fastlyProvider.runStep(cfg, serviceStep, spec, tpl, empty)),
      ).toBeTruthy();
      expect(server.calls).toHaveLength(1);
      await server.close();
      rec = undefined;
    }
    // A lost response: the connection dies with the request already accepted.
    const aborting = await serve(() => ({ status: 0, abort: true }));
    expect(
      await caught(() => fastlyProvider.runStep(cfg, serviceStep, spec, tpl, empty)),
    ).toBeTruthy();
    expect(aborting.calls).toHaveLength(1);
    await aborting.close();
    rec = undefined;

    const recovery = await serve();
    const found = await fastlyProvider.discover(cfg, serviceStep, spec, empty, 1);
    expect(found.status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expect(recovery.calls[0].query.name).toBe(spec.name);
    expectDeclared('fastly', fromRecorded(recovery.calls));
  });

  test('a destroy after a partial provisioning touches only the recorded children', async () => {
    const server = await serve();
    fakeDns();
    // The service and its backend landed; nothing else did.
    const partial: Ledger = {
      steps: [],
      resources: [
        resource('service', 'service', SVC, { version: 1, name: spec.name }),
        resource('backend', 'backend', 'origin'),
      ],
    };
    expect(await destroyAll(fastlyProvider as never, cfg as never, partial)).toEqual([
      'service',
      'backend',
    ]);
    expect(server.calls.filter((c) => c.method === 'DELETE').map((c) => c.path)).toEqual([
      `/service/${SVC}`,
    ]);
    expectDeclared('fastly', fromRecorded(server.calls));
  });

  test('errors carry no token, no origin address and no hostname', async () => {
    await serve(() => ({
      status: 422,
      body: { msg: `Domain ${HOST} is already taken`, detail: `${ORIGIN} ${cfg.apiToken}` },
    }));
    const empty: Ledger = { steps: [], resources: [] };
    const [step] = fastlyProvider.planProvision(cfg, spec, tpl);
    const err = await caught(() => fastlyProvider.runStep(cfg, step, spec, tpl, empty));
    const blob = errorBlob(err);
    expect(blob).not.toContain('SECRET_');
    expect(blob).not.toContain(ORIGIN);
    expect(blob).not.toContain(HOST);
  });

  test('the ACME record is written under the challenge name the subscription reports', async () => {
    await serve();
    const dns = fakeDns();
    let ledger: Ledger = { steps: [], resources: [] };
    const steps = fastlyProvider.planProvision(cfg, spec, tpl);
    for (const step of steps) {
      const out = await fastlyProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      if (out.status === 'requested') {
        const polled = await fastlyProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = apply(ledger, step, polled);
      }
    }
    const names = await dns.findRecordsByName(acmeChallengeName(HOST), 'CNAME');
    expect(names).toHaveLength(1);
    expect(names[0].proxied).toBe(false);
  });
});

// --- the documented table ----------------------------------------------------------------

describe('wire contract docs', () => {
  const DOC = new URL('../../../../docs/edges.md', import.meta.url);

  function section(): string {
    const text = readFileSync(DOC, 'utf8');
    const start = text.indexOf(WIRE_CONTRACT_HEADING);
    expect(start).toBeGreaterThan(-1);
    const rest = text.slice(start + WIRE_CONTRACT_HEADING.length);
    const next = rest.search(/^## /m);
    return next === -1 ? rest : rest.slice(0, next);
  }

  /** The section's table, cell by cell (the repo formatter pads the columns). */
  function docCells(): string[][] {
    return section()
      .split('\n')
      .map(tableRowCells)
      .filter((row): row is string[] => row !== null);
  }

  test('every contract entry is a row in docs/edges.md, and every row is a contract entry', () => {
    // One comparison both ways: a missing row, an extra row, a reordered row and
    // an edited purpose all fail here.
    expect(docCells()).toEqual(wireContractCells());
  });

  test('the table names every provider and cites a dated source for each', () => {
    const rows = docCells().slice(1);
    for (const [id, contract] of Object.entries(WIRE_CONTRACTS)) {
      expect(contract.calls.length).toBeGreaterThan(0);
      expect(contract.source).toMatch(/20\d\d-\d\d-\d\d/);
      const mine = rows.filter((r) => r[0] === id);
      expect(mine).toHaveLength(contract.calls.length);
      expect(mine.every((r) => r[4] === contract.source)).toBe(true);
    }
  });

  test('the doc says nothing about which provider carries production traffic', () => {
    // Confidentiality rule for this subsystem: never name a provider as the one
    // in use. The table is a capability list, not a deployment description.
    expect(section().toLowerCase()).not.toMatch(/\bproduction\b|\bin use\b|\bwe use\b/);
  });

  test('a call the contract does not declare is reported rather than silently accepted', () => {
    expect(matchWireCall('gcore', { method: 'GET', path: '/cloud/v1/secrets' })).toBeUndefined();
    expect(
      matchWireCall('gcore', { method: 'GET', path: '/cloud/v1/loadbalancers/1/2' }),
    ).toBeDefined();
    // A declared path with a missing required query key does not match either.
    expect(
      matchWireCall('fastly', { method: 'GET', path: '/service/search', queryKeys: [] }),
    ).toBeUndefined();
  });
});
