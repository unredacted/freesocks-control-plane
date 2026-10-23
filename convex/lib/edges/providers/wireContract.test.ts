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
import {
  startHttpRecorder,
  type HttpRecorder,
  type RecordedCall,
  type RecorderRoute,
} from '../testing/httpRecorder';
import { acmeChallengeName } from '../hostname';
import {
  WIRE_CONTRACTS,
  ambiguousCalls,
  matchWireCall,
  tableRowCells,
  uncoveredEntries,
  unmatchedCalls,
  wireCallLabel,
  wireContractCells,
  WIRE_CONTRACT_HEADING,
  type ObservedCall,
} from './wireContract';
import type {
  ChildResource,
  CloudFrontConfig,
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
import {
  scalewayKeys,
  scalewayProvider,
  __setScalewayApiFactory,
  __setScalewayKeysFactory,
} from './scaleway';
import { ovhProvider, __resetOvhCatalogCache, __resetOvhSkewCache } from './ovh';
import {
  cloudflareProvider,
  __setCloudflareApiFactory,
  __setCloudflareCaaLookup,
} from './cloudflare';
import { cloudflareApi } from './dns/cloudflareDns';
import { fastlyProvider, __setFastlyCaaLookup, __setFastlyDnsClientFactory } from './fastly';
import { __setFastlyBasePath } from './fastly/sdk';
import {
  cloudFrontProvider,
  __setCloudFrontCaaLookup,
  __setCloudFrontDnsClientFactory,
} from './cloudfront';
import { __setCloudFrontEndpoint } from './cloudfront/sdk';
import { fakeDnsZone } from '../testing/fakeCloudFront';
import { readFileSync } from 'node:fs';
import ovhCatalog from './fixtures/pricing/ovh_public_cloud_catalog_lb.json';
import scalewayCatalog from './fixtures/pricing/scaleway_catalog_lb_zone.json';

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

/**
 * Every recorded call is declared by exactly one entry (an undeclared endpoint,
 * or a call two entries both claim, fails here).
 */
function expectDeclared(id: EdgeProviderId, calls: readonly ObservedCall[]): void {
  expect(calls.length).toBeGreaterThan(0);
  expect(unmatchedCalls(id, calls).map(show)).toEqual([]);
  expect(ambiguousCalls(id, calls).map(show)).toEqual([]);
}

/** ...and every declared call was exercised (a dead contract entry fails here). */
function expectContractCovered(id: EdgeProviderId, calls: readonly ObservedCall[]): void {
  expectDeclared(id, calls);
  expect(uncoveredEntries(id, calls).map((e) => `${e.method} ${e.path}`)).toEqual([]);
}

/** Fold a step outcome into the ledger the way the orchestrator's mutation does. */
function apply(ledger: Ledger, step: ResourceStep, out: StepOutcome): Ledger {
  // A resource reported again (a poll's `done` naming the step's own) is kept
  // once, as the rotation's `settleOp` does.
  const known = new Set(ledger.resources.map((r) => `${r.kind}:${r.resourceId}`));
  const resources: ChildResource[] = ('resources' in out ? out.resources : []).filter(
    (r) => !known.has(`${r.kind}:${r.resourceId}`),
  );
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
  // Price shapes from https://docs.gcore.com/api-reference/cloud/load-balancers/
  // (LbFlavorPricingSerializer, LoadBalancerPricingPreviewResponseSerializer), read 2026-10-22.
  const PRICED_FLAVORS = {
    count: 2,
    results: [
      {
        flavor_id: 'lb1-1-2',
        flavor_name: 'lb1-1-2',
        ram: 2048,
        vcpus: 1,
        currency_code: 'EUR',
        price_per_hour: 0.0208,
        price_per_month: 15,
        price_status: 'show',
      },
      {
        flavor_id: 'lb1-2-4',
        flavor_name: 'lb1-2-4',
        ram: 4096,
        vcpus: 2,
        currency_code: null,
        price_per_hour: null,
        price_per_month: null,
        price_status: 'hide',
      },
    ],
  };
  const PRICE_PREVIEW = {
    currency_code: 'EUR',
    discount_percent: 0,
    per_hour: { external_ip: 0, flavor: 0.0416, floating_ip: 0.004 },
    per_month: { external_ip: 0, flavor: 30, floating_ip: 2.88 },
    price_status: 'show',
    price_without_discount_per_month: 32.88,
    tax_percent: 0,
    total_price_per_hour: 0.0456,
    total_price_per_month: 32.88,
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
        return new URLSearchParams(c.query).get('include_prices') === 'true'
          ? jsonRes(PRICED_FLAVORS)
          : jsonRes({ results: [{ flavor_name: 'lb1-1-2' }] });
      if (p === '/cloud/v2/pricing/11/22/loadbalancers' && c.method === 'POST')
        return jsonRes(PRICE_PREVIEW);
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
    // The hidden flavor's price comes from the preview, which names it alone.
    expect(await gcoreProvider.plans!(cfg)).toMatchObject([
      { size: 'lb1-1-2', perMonth: 15, currency: 'EUR', source: 'api' },
      { size: 'lb1-2-4', perMonth: 30, currency: 'EUR', source: 'api' },
    ]);
    expect(
      stub.calls.filter((c) => c.path.startsWith('/cloud/v2/pricing/')).map((c) => c.body),
    ).toEqual([{ flavor: 'lb1-2-4' }]);
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

  test('the priced flavor read never stands in for the plain one, nor the other way round', async () => {
    const stub = mockFetch(route());
    const unexercisedFlavorReads = () =>
      uncoveredEntries('gcore', fromCaptured(stub.calls))
        .filter((e) => e.path.includes('/lbflavors/'))
        .map(wireCallLabel);
    // The price read alone: the inventory and location-form entry is still unexercised.
    await gcoreProvider.plans!(cfg);
    expect(unexercisedFlavorReads()).toEqual([
      '^/cloud/v1/lbflavors/[^/]+/[^/]+$ without ?include_prices',
    ]);
    // The inventory alone: the price read's entry is.
    stub.calls.length = 0;
    await gcoreProvider.inventory(cfg);
    expect(unexercisedFlavorReads()).toEqual(['^/cloud/v1/lbflavors/[^/]+/[^/]+$ ?include_prices']);
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
    if (p === '/1.3/account/details/automation')
      return jsonRes({ account: { username: 'automation', currency: 'EUR' } });
    if (p === '/1.3/price')
      return jsonRes({
        prices: {
          zone: [
            { name: 'fi-hel1', managed_load_balancer_development: { amount: 1, price: 1.4881 } },
          ],
        },
      });
    if (p === '/1.3/zone')
      return jsonRes({ zones: { zone: [{ id: 'fi-hel1', description: 'Helsinki' }] } });
    if (p === '/1.3/load-balancer/plans')
      return jsonRes([{ name: 'development', per_server_max_sessions: 1000, server_number: 1 }]);
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
    expect(await upcloudProvider.plans!(cfg)).toMatchObject([
      { size: 'development', perMonth: 10, currency: 'EUR', source: 'api' },
    ]);
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
    __setScalewayKeysFactory(null);
    vi.unstubAllGlobals();
  });

  const DEFAULT_PROJECT = '66666666-7777-4888-8999-000000000000';
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
  const CATALOG = '/product-catalog/v2alpha1/public-catalog/products';

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
    __setScalewayKeysFactory((c) => scalewayKeys(c, globalThis.fetch as typeof fetch));
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
    if (p === `/iam/v1alpha1/api-keys/${cfg.accessKey}`)
      return jsonRes({ access_key: cfg.accessKey, default_project_id: DEFAULT_PROJECT });
    // The public product catalog, recorded 2026-10-22 (trimmed to one zone's load balancer products).
    if (p === CATALOG) return jsonRes(scalewayCatalog);
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
      let out = await scalewayProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      // Every change is waited on until the LB is `ready` again.
      while (out.status === 'requested') {
        out = await scalewayProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = apply(ledger, step, out);
      }
      expect(out.status).toBe('done');
    }
    for (const step of steps) await scalewayProvider.discover(cfg, step, spec, ledger, 1);
    expect(await scalewayProvider.reapply!(cfg, ledger)).toEqual({ status: 'sent', settled: true });

    await scalewayProvider.describe(cfg, ledger);
    await scalewayProvider.inspect(cfg, ledger);
    await scalewayProvider.inventory(cfg);
    // Each node priced an hour with the IPv4 its edge allocates added.
    expect((await scalewayProvider.plans!(cfg)).find((p) => p.size === 'LB-S')).toMatchObject({
      perHour: 0.028,
      currency: 'EUR',
      acceptsOutsideNode: false,
      source: 'api',
    });
    expect(await destroyAll(scalewayProvider as never, cfg as never, ledger)).toEqual([
      'frontend',
      'backend',
      'lb',
      'ip',
      'ipv6',
    ]);

    expectContractCovered('scaleway', fromCaptured(stub.calls));
    // The public catalog is asked without the key; every other call carries it.
    const [open, keyed] = [
      stub.calls.filter((c) => c.path === CATALOG),
      stub.calls.filter((c) => c.path !== CATALOG),
    ];
    expect(open.map((c) => c.headers['x-auth-token'])).toEqual([undefined]);
    expect(keyed.every((c) => c.headers['x-auth-token'] === cfg.secretKey)).toBe(true);
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

  test("a location with no Project id creates in the key's default project: the createIp body carries it", async () => {
    const stub = mockFetch(route);
    useStub();
    // The credential test (account-level: no project) reads the key's default project.
    const account = { ...cfg, projectId: undefined };
    const tested = await scalewayProvider.testCredentials(account);
    expect(tested).toEqual({ ok: true, observed: { defaultProjectId: DEFAULT_PROJECT } });
    // The adapter config takes the observed project for a location that names none.
    const located = { ...account, projectId: tested.observed!.defaultProjectId };
    const steps = scalewayProvider.planProvision(located, spec, tpl);
    await scalewayProvider.runStep(located, steps[0], spec, tpl, { steps: [], resources: [] });
    const create = stub.calls.find((c) => c.method === 'POST' && c.path === `${ZONE}/ips`)!;
    expect(create.body).toMatchObject({ project_id: DEFAULT_PROJECT, tags: [spec.name] });
    expectDeclared('scaleway', fromCaptured(stub.calls));
    // With no project at all, nothing is sent.
    stub.calls.length = 0;
    expect(
      await scalewayProvider.runStep(account, steps[0]!, spec, tpl, { steps: [], resources: [] }),
    ).toMatchObject({ status: 'partial', code: 'project_unresolved', refused: true });
    expect(stub.calls).toHaveLength(0);
  });

  test("Scaleway's 400 on an address allocation is a known refusal, not a step to retry", async () => {
    const stub = mockFetch(() =>
      jsonRes(
        {
          type: 'invalid_arguments',
          message: 'invalid argument(s)',
          details: [{ argument_name: 'project_id', reason: 'required', help_message: 'required' }],
        },
        400,
      ),
    );
    useStub();
    const [step] = scalewayProvider.planProvision(cfg, spec, tpl);
    expect(
      await scalewayProvider.runStep(cfg, step!, spec, tpl, { steps: [], resources: [] }),
    ).toEqual({
      status: 'partial',
      resources: [],
      code: 'ip_allocation_refused',
      refused: true,
      httpStatus: 400,
      detail: 'invalid argument(s): project_id is required, required',
    });
    expect(stub.calls).toHaveLength(1);
  });
});

// --- ovh ------------------------------------------------------------------------------

describe('wire contract: ovh', () => {
  afterEach(() => {
    __resetOvhSkewCache();
    __resetOvhCatalogCache();
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
  const CATALOG = '/1.0/order/catalog/public/cloud';

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
      // `/me` (nichandle.Nichandle, trimmed) and the public cloud catalog (recorded
      // 2026-10-22, trimmed to its balancer and floating IP addons).
      if (p === '/1.0/me') return jsonRes({ nichandle: 'zz0000-ovh', ovhSubsidiary: 'FR' });
      if (p === CATALOG) return jsonRes(ovhCatalog);
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
    // `small` at the catalog's price with the floating IP every balancer gets added.
    expect(await ovhProvider.plans!(cfg)).toMatchObject([
      { size: 'small', perHour: 0.011, perMonth: 7.8, currency: 'EUR', source: 'api' },
    ]);
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
      if (call.path === CATALOG) {
        // The public catalog is read unsigned: no account header reaches it.
        expect(Object.keys(call.headers).filter((h) => h.startsWith('x-ovh'))).toEqual([]);
        continue;
      }
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
    __setCloudflareCaaLookup(null);
    vi.unstubAllGlobals();
  });

  const ZONE = '023e105f4ecef8ad9ca31a8372d0c353';
  const HEADER_RULESET = '5d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a';
  const HEADER_RULE_ID = 'b2c3d4e5f60718293a4b5c6d7e8f90a1';
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

  function route(
    over: { phaseMissing?: boolean; accountToken?: boolean; sslStrict?: boolean } = {},
  ) {
    return (c: Captured): Response => {
      const p = c.path;
      if (p.endsWith('/settings/ssl') && over.sslStrict) {
        const ssl = fx('setting_ssl.json') as { result: Record<string, unknown> };
        return jsonRes({ ...ssl, result: { ...ssl.result, value: 'strict' } });
      }
      for (const id of ['min_tls_version', 'pseudo_ipv4', 'ip_geolocation'])
        if (p.endsWith(`/settings/${id}`)) return jsonRes(fx(`setting_${id}.json`));
      if (p.endsWith('/rulesets/phases/http_request_late_transform/entrypoint')) {
        if (c.method === 'PUT') return jsonRes(fx('ruleset_header_phase.json'));
        return over.phaseMissing
          ? jsonRes(fx('error_record_not_found.json'), 404)
          : jsonRes(fx('ruleset_header_phase.json'));
      }
      if (p.includes(`/rulesets/${HEADER_RULESET}/rules`))
        return c.method === 'POST'
          ? jsonRes(fx('ruleset_header_phase.json'))
          : jsonRes({ result: null, success: true });
      if (p.endsWith('/user/tokens/verify'))
        return over.accountToken
          ? jsonRes(fx('error_invalid_token.json'), 401)
          : jsonRes(fx('token_verify.json'));
      if (/\/accounts\/[^/]+\/tokens\/verify$/.test(p))
        return jsonRes(fx('token_verify_account.json'));
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
    const stub = mockFetch(route({ accountToken: true }));
    useStub();
    // An account-owned token: the user endpoint does not know it, the account one does.
    expect(await cloudflareProvider.testCredentials(cfg)).toMatchObject({ ok: true });
    stub.route(route());
    expect(await cloudflareProvider.testCredentials(cfg)).toMatchObject({ ok: true });
    await cloudflareProvider.listRegions!(cfg);
    await cloudflareProvider.discoverOptions!({ apiToken: cfg.apiToken });
    // A zone location is checked on its own: the zone, its mode and WebSockets.
    expect(await cloudflareProvider.checkLocation!(cfg)).toMatchObject({ ok: true });
    // A fronting account's zone also: what a front needs (Full (strict), the
    // zone's wildcard certificate, CAA) and the settings that put more of the
    // member on the request.
    stub.route(route({ sslStrict: true }));
    __setCloudflareCaaLookup(async () => []);
    expect(await cloudflareProvider.checkLocation!({ ...cfg, frontsTraffic: true })).toMatchObject({
      ok: true,
      observed: {
        zoneSslMode: 'strict',
        edgeCertificate: 'active',
        caa: 'no_records',
        minTlsVersion: '1.2',
        pseudoIpv4: 'off',
        ipGeolocation: 'on',
      },
    });
    stub.route(route());

    const steps = cloudflareProvider.planProvision(cfg, spec, tpl);
    expect(steps.map((s) => s.kind)).toEqual([
      'create_dns_record',
      'create_origin_rule',
      'create_header_rule',
    ]);
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
    expect(adopted.resources.map((r) => r.kind)).toEqual([
      'dns_record',
      'origin_rule',
      'header_rule',
    ]);
    // Every delete is synchronous and idempotent (no confirmDestroyed).
    expect(await destroyAll(cloudflareProvider as never, cfg as never, ledger)).toEqual([
      'header_rule',
      'origin_rule',
      'dns_record',
    ]);

    // A zone with no entry point for either phase yet: the bootstrap PUTs.
    stub.route(route({ phaseMissing: true }));
    for (const ruleStep of steps.slice(1)) {
      const bootstrapped = await cloudflareProvider.runStep(cfg, ruleStep, spec, tpl, ledger);
      expect(bootstrapped.status).toBe('done');
    }
    for (const phase of ['http_request_origin', 'http_request_late_transform'])
      expect(
        stub.calls.some(
          (c) => c.method === 'PUT' && c.path.endsWith(`/phases/${phase}/entrypoint`),
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
    const dels = stub.calls.filter((c) => c.method === 'DELETE' && c.path.includes('/rules/'));
    expect(dels.map((c) => c.path.slice(c.path.lastIndexOf('/') + 1))).toEqual([
      HEADER_RULE_ID,
      RULE_ID,
    ]);
    // The header rule removes the member's address for this hostname only.
    const headerPost = stub.calls.find(
      (c) => c.method === 'POST' && c.path.includes(`/rulesets/${HEADER_RULESET}/rules`),
    );
    expect(headerPost!.body).toMatchObject({
      action: 'rewrite',
      expression: `(http.host eq "${HOSTNAME}")`,
      ref: NAME,
      action_parameters: { headers: { 'cf-connecting-ip': { operation: 'remove' } } },
    });
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
    // An edge on a version-scoped (classic) domain; `newEdgeLifecycle` drives a versionless one.
    domainModel: 'classic',
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
      async readZone() {
        return { id: cfg.dns!.zoneId, name: cfg.dns!.zoneName, status: 'active', paused: false };
      },
    };
    __setFastlyDnsClientFactory(() => client);
    return client;
  }

  const DM = 'DMDOM01kq7v3xzwYb9pRn';
  const WILD = 'WILDsub0example0org01';

  function defaultReply(c: RecordedCall) {
    const p = c.path;
    const m = c.method;
    if (p === '/domain-management/v1/domains')
      return m === 'POST'
        ? ok('dm-domain-create.json')
        : ok(c.query.service_id ? 'dm-domains-list.json' : 'dm-domains-empty.json');
    if (p === `/domain-management/v1/domains/${DM}`)
      return m === 'DELETE' ? { status: 204 } : ok('dm-domain-create.json');
    // The zone's one wildcard: already ordered and issued.
    if (
      m === 'GET' &&
      p === '/tls/subscriptions' &&
      c.query['filter[tls_domains.id]'] === '*.example.org'
    )
      return api('tls-subscriptions-wildcard-list.json');
    if (m === 'GET' && p === `/tls/subscriptions/${WILD}`)
      return api('tls-subscription-wildcard-issued.json');
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
        c.query.include?.includes('tls_authorizations')
          ? 'tls-subscription-authorizations.json'
          : 'tls-subscription-issued.json',
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
    __setFastlyCaaLookup(null);
    await rec?.close();
    rec = undefined;
  });

  async function serve(route = defaultReply): Promise<HttpRecorder> {
    rec = await startHttpRecorder(route);
    __setFastlyBasePath(rec.base);
    // CAA is DNS, not HTTP: no record anywhere (the suite refuses real lookups).
    __setFastlyCaaLookup(async () => []);
    return rec;
  }

  /** A NEW edge: a versionless domain and the account's shared wildcard certificate. */
  async function newEdgeLifecycle(): Promise<void> {
    const cfgNew: FastlyConfig = {
      ...cfg,
      domainModel: 'versionless',
      certificateScope: 'wildcard',
    };
    let ledger: Ledger = { steps: [], resources: [] };
    const steps = fastlyProvider.planProvision(cfgNew, spec, tpl);
    for (const step of steps) {
      const out = await fastlyProvider.runStep(cfgNew, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
    }
    expect(ledger.resources.map((r) => r.kind)).toContain('versionless_domain');
    for (const step of steps) await fastlyProvider.discover(cfgNew, step, spec, ledger, 1);
    await fastlyProvider.describe(cfgNew, ledger);
    await fastlyProvider.sharedCertificate!(cfgNew);
    expect(await destroyAll(fastlyProvider as never, cfgNew as never, ledger)).toContain(
      'versionless_domain',
    );
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

    server.route(defaultReply);
    await newEdgeLifecycle();

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

// --- cloudfront ---------------------------------------------------------------------------

describe('wire contract: cloudfront', () => {
  const ZONE = 'example.org';
  const HOST = 'k3m7q9zbx2wd.example.org';
  const ORIGIN = 'node-7.origin.example.net';
  const ACCOUNT = '123456789012';
  const XMLNS = 'http://cloudfront.amazonaws.com/doc/2020-05-31/';

  const cfg: CloudFrontConfig = {
    type: 'cloudfront',
    accessKeyId: 'AKIAEXAMPLEEXAMPLE00',
    secretAccessKey: 'SECRET_AWS_ACCESS_KEY_0123456789',
    certificateScope: 'wildcard',
    dns: {
      apiToken: 'SECRET_CF_TOKEN',
      zoneId: '0123456789abcdef0123456789abcdef',
      zoneName: ZONE,
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
  const tpl = cloudFrontProvider.templateSchema.parse({}) as never;

  /** The top-level element names of an XML request body (the root's children). */
  function xmlTopKeys(raw: string): string[] {
    const body = raw.replace(/<\?xml[^>]*\?>/, '');
    const keys: string[] = [];
    let depth = 0;
    for (const m of body.matchAll(/<(\/?)([A-Za-z][\w.-]*)[^>]*?(\/?)>/g)) {
      const [, closing, name, selfClosing] = m;
      if (closing) depth--;
      else {
        if (depth === 1) keys.push(name!);
        if (!selfClosing) depth++;
      }
    }
    return keys;
  }

  function observed(calls: readonly RecordedCall[]): ObservedCall[] {
    return calls.map((c) => {
      const target = c.headers['x-amz-target'];
      return {
        method: c.method,
        path: c.path,
        queryKeys: Object.keys(c.query),
        bodyKeys: typeof c.body === 'string' ? xmlTopKeys(c.body) : keysOf(c.body),
        ...(target ? { target } : {}),
      };
    });
  }

  /** The inner XML of the request's root element (what CloudFront echoes inside its answer). */
  const inner = (raw: string, root: string) =>
    raw
      .replace(/<\?xml[^>]*\?>/, '')
      .replace(new RegExp(`^\\s*<${root}[^>]*>|</${root}>\\s*$`, 'g'), '');
  const xml = (status: number, body: string, headers: Record<string, string> = {}) => ({
    status,
    raw: `<?xml version="1.0" encoding="UTF-8"?>${body}`,
    contentType: 'text/xml',
    headers,
  });
  const cfError = (status: number, code: string, message: string) =>
    xml(
      status,
      `<ErrorResponse xmlns="${XMLNS}"><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`,
    );
  const acm = (status: number, body: unknown) => ({
    status,
    body,
    contentType: 'application/x-amz-json-1.1',
  });

  /** A tiny CloudFront + ACM account answering the way their APIs do. */
  function account() {
    const state = {
      certificate: null as null | { arn: string; status: string },
      policies: [] as Array<{ id: string; config: string }>,
      distributions: [] as Array<{
        id: string;
        config: string;
        status: string;
        etag: number;
        reads: number;
      }>,
      seq: 0,
      dns: fakeDnsZone(cfg.dns!),
    };
    const record = {
      name: `_0a1b2c3d.${ZONE}.`,
      value: '_4e5f6a7b.abcdefghij.acm-validations.aws.',
    };
    const distributionXml = (d: (typeof state.distributions)[number], root: string) =>
      `<${root}${root === 'Distribution' ? ` xmlns="${XMLNS}"` : ''}><Id>${d.id}</Id><ARN>arn:aws:cloudfront::${ACCOUNT}:distribution/${d.id}</ARN><Status>${d.status}</Status><LastModifiedTime>2026-10-22T00:00:00.000Z</LastModifiedTime>${root === 'Distribution' ? '<InProgressInvalidationBatches>0</InProgressInvalidationBatches>' : ''}<DomainName>d${d.id.toLowerCase()}.cloudfront.net</DomainName>${root === 'Distribution' ? `<DistributionConfig>${d.config}</DistributionConfig>` : `${d.config}<Staging>false</Staging>`}</${root}>`;
    const etag = (d: (typeof state.distributions)[number]) => ({ ETag: `${d.id}-v${d.etag}` });
    const enabled = (d: (typeof state.distributions)[number]) =>
      /<Enabled>true<\/Enabled>/.test(d.config);

    function route(c: RecordedCall) {
      const target = c.headers['x-amz-target'];
      if (target) {
        const b = (c.body ?? {}) as Record<string, string>;
        switch (target) {
          case 'CertificateManager.ListCertificates':
            return acm(200, {
              CertificateSummaryList: state.certificate
                ? [
                    {
                      CertificateArn: state.certificate.arn,
                      DomainName: `*.${ZONE}`,
                      Status: state.certificate.status,
                      Type: 'AMAZON_ISSUED',
                      InUse: state.distributions.length > 0,
                    },
                  ]
                : [],
            });
          case 'CertificateManager.RequestCertificate':
            state.certificate = {
              arn: `arn:aws:acm:us-east-1:${ACCOUNT}:certificate/11111111-2222-3333-4444-555555555555`,
              status: 'PENDING_VALIDATION',
            };
            return acm(200, { CertificateArn: state.certificate.arn });
          case 'CertificateManager.DescribeCertificate': {
            const cert = state.certificate;
            if (!cert || b.CertificateArn !== cert.arn)
              return acm(400, { __type: 'ResourceNotFoundException', message: 'not found' });
            // ACM issues once its validation record is in the zone.
            if (state.dns.rows.some((r) => `${r.name}.` === record.name)) cert.status = 'ISSUED';
            return acm(200, {
              Certificate: {
                CertificateArn: cert.arn,
                DomainName: `*.${ZONE}`,
                Status: cert.status,
                Type: 'AMAZON_ISSUED',
                ...(cert.status === 'ISSUED' ? { NotAfter: Date.now() / 1000 + 395 * 86_400 } : {}),
                InUseBy: state.distributions.map(
                  (d) => `arn:aws:cloudfront::${ACCOUNT}:distribution/${d.id}`,
                ),
                DomainValidationOptions: [
                  {
                    DomainName: `*.${ZONE}`,
                    ValidationMethod: 'DNS',
                    ValidationStatus: cert.status === 'ISSUED' ? 'SUCCESS' : 'PENDING_VALIDATION',
                    ResourceRecord: { Name: record.name, Type: 'CNAME', Value: record.value },
                  },
                ],
              },
            });
          }
          case 'CertificateManager.DeleteCertificate':
            state.certificate = null;
            return acm(200, {});
          default:
            return acm(400, { __type: 'UnknownOperationException', message: target });
        }
      }
      const m = c.method;
      const p = c.path;
      const raw = typeof c.body === 'string' ? c.body : '';
      if (p === '/2020-05-31/origin-request-policy' && m === 'GET') {
        const items = state.policies
          .map(
            (x) =>
              `<OriginRequestPolicySummary><Type>custom</Type><OriginRequestPolicy><Id>${x.id}</Id><LastModifiedTime>2026-10-22T00:00:00.000Z</LastModifiedTime><OriginRequestPolicyConfig>${x.config}</OriginRequestPolicyConfig></OriginRequestPolicy></OriginRequestPolicySummary>`,
          )
          .join('');
        return xml(
          200,
          `<OriginRequestPolicyList xmlns="${XMLNS}"><MaxItems>100</MaxItems><Quantity>${state.policies.length}</Quantity>${items ? `<Items>${items}</Items>` : ''}</OriginRequestPolicyList>`,
        );
      }
      if (p === '/2020-05-31/origin-request-policy' && m === 'POST') {
        const x = { id: `orp-${++state.seq}`, config: inner(raw, 'OriginRequestPolicyConfig') };
        state.policies.push(x);
        return xml(
          201,
          `<OriginRequestPolicy xmlns="${XMLNS}"><Id>${x.id}</Id><LastModifiedTime>2026-10-22T00:00:00.000Z</LastModifiedTime><OriginRequestPolicyConfig>${x.config}</OriginRequestPolicyConfig></OriginRequestPolicy>`,
          { ETag: 'P1' },
        );
      }
      const byPolicy = /^\/2020-05-31\/distributionsByOriginRequestPolicyId\/([^/]+)$/.exec(p);
      if (byPolicy && m === 'GET') {
        const ids = state.distributions
          .filter((d) =>
            d.config.includes(`<OriginRequestPolicyId>${byPolicy[1]}</OriginRequestPolicyId>`),
          )
          .map((d) => `<DistributionId>${d.id}</DistributionId>`);
        return xml(
          200,
          `<DistributionIdList xmlns="${XMLNS}"><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>${ids.length}</Quantity>${ids.length ? `<Items>${ids.join('')}</Items>` : ''}</DistributionIdList>`,
        );
      }
      if (p === '/2020-05-31/distribution' && m === 'POST') {
        const config = inner(raw, 'DistributionConfig');
        const ref = /<CallerReference>([^<]*)</.exec(config)?.[1];
        if (state.distributions.some((d) => d.config.includes(`<CallerReference>${ref}<`)))
          return cfError(
            409,
            'DistributionAlreadyExists',
            'The caller reference that you are using is already associated with another distribution.',
          );
        const d = {
          id: `E${String(++state.seq).padStart(13, '0')}`,
          config,
          status: 'InProgress',
          etag: 1,
          reads: 0,
        };
        state.distributions.push(d);
        return xml(201, distributionXml(d, 'Distribution'), etag(d));
      }
      if (p === '/2020-05-31/distribution' && m === 'GET') {
        const items = state.distributions
          .map((d) => distributionXml(d, 'DistributionSummary'))
          .join('');
        return xml(
          200,
          `<DistributionList xmlns="${XMLNS}"><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>${state.distributions.length}</Quantity>${items ? `<Items>${items}</Items>` : ''}</DistributionList>`,
        );
      }
      const one = /^\/2020-05-31\/distribution\/([^/]+)(\/config)?$/.exec(p);
      if (one) {
        const d = state.distributions.find((x) => x.id === one[1]);
        if (!d)
          return cfError(404, 'NoSuchDistribution', 'The specified distribution does not exist.');
        const ifMatch = c.headers['if-match'];
        if (m === 'GET' && one[2])
          return xml(
            200,
            `<DistributionConfig xmlns="${XMLNS}">${d.config}</DistributionConfig>`,
            etag(d),
          );
        if (m === 'GET') {
          // A change deploys after one more read.
          if (d.status === 'InProgress' && d.reads++ >= 1) d.status = 'Deployed';
          return xml(200, distributionXml(d, 'Distribution'), etag(d));
        }
        if (m === 'PUT' && one[2]) {
          if (ifMatch !== etag(d).ETag) return cfError(412, 'PreconditionFailed', 'stale');
          d.config = inner(raw, 'DistributionConfig');
          d.status = 'InProgress';
          d.reads = 0;
          d.etag++;
          return xml(200, distributionXml(d, 'Distribution'), etag(d));
        }
        if (m === 'DELETE') {
          if (ifMatch !== etag(d).ETag) return cfError(412, 'PreconditionFailed', 'stale');
          if (enabled(d) || d.status !== 'Deployed')
            return cfError(409, 'DistributionNotDisabled', 'not disabled');
          state.distributions = state.distributions.filter((x) => x !== d);
          return { status: 204 };
        }
      }
      return cfError(400, 'InvalidRequest', `unrouted ${m} ${p}`);
    }
    return { state, route };
  }

  let rec: HttpRecorder | undefined;
  afterEach(async () => {
    __setCloudFrontEndpoint(null);
    __setCloudFrontDnsClientFactory(null);
    __setCloudFrontCaaLookup(null);
    await rec?.close();
    rec = undefined;
  });

  async function serve(route: RecorderRoute) {
    rec = await startHttpRecorder(route);
    __setCloudFrontEndpoint(rec.base);
    __setCloudFrontCaaLookup(async () => []);
    return rec;
  }

  test('the lifecycle stays inside the contract and exercises all of it', async () => {
    const aws = account();
    const server = await serve(aws.route);
    __setCloudFrontDnsClientFactory(() => aws.state.dns);
    expect((await cloudFrontProvider.testCredentials(cfg)).ok).toBe(true);

    let ledger: Ledger = { steps: [], resources: [] };
    const steps = cloudFrontProvider.planProvision(cfg, spec, tpl);
    for (const step of steps) {
      let out = await cloudFrontProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      for (let i = 0; out.status === 'requested' && i < 5; i++) {
        out = await cloudFrontProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = apply(ledger, step, out);
      }
      expect(out.status, step.id).toBe('done');
    }
    expect(ledger.resources.map((r) => r.kind)).toEqual([
      'tls_subscription',
      'dns_record',
      'origin_request_policy',
      'distribution',
      'dns_record',
    ]);
    // What the SDK put on the wire for the distribution: FCP's policy and the
    // uncached policy, the certificate by ARN for SNI, the origin by name.
    const create = server.calls.find(
      (c) => c.method === 'POST' && c.path === '/2020-05-31/distribution',
    )!;
    expect(create.body).toContain(`<CallerReference>${spec.name}</CallerReference>`);
    expect(create.body).toContain(`<CNAME>${HOST}</CNAME>`);
    expect(create.body).toContain(`<DomainName>${ORIGIN}</DomainName>`);
    expect(create.body).toContain('<SSLSupportMethod>sni-only</SSLSupportMethod>');
    expect(create.body).toContain(
      '<CachePolicyId>4135ea2d-6df8-44a3-9df3-4b5a84be39ad</CachePolicyId>',
    );
    const policy = server.calls.find(
      (c) => c.method === 'POST' && c.path === '/2020-05-31/origin-request-policy',
    )!;
    expect(policy.body).toContain('<HeaderBehavior>whitelist</HeaderBehavior>');
    expect(policy.body).not.toMatch(/Forwarded|Viewer-Address|Real-IP|Client-IP/i);
    const request = server.calls.find(
      (c) => c.headers['x-amz-target'] === 'CertificateManager.RequestCertificate',
    )!;
    expect(request.body).toMatchObject({ DomainName: `*.${ZONE}`, ValidationMethod: 'DNS' });

    // A second front of the zone: the policy is counted, then reused.
    const second: EdgeSpec = {
      ...spec,
      name: 'fcp-relay-o2-feedface',
      hostname: `zz9q8w7e6r5t.${ZONE}`,
    };
    const createStep = steps.find((s) => s.kind === 'create_service')!;
    const secondLedger: Ledger = {
      steps: [],
      resources: ledger.resources.filter((r) => r.kind === 'tls_subscription'),
    };
    expect(
      (await cloudFrontProvider.runStep(cfg, createStep, second, tpl, secondLedger)).status,
    ).toBe('done');

    for (const step of steps) await cloudFrontProvider.discover(cfg, step, spec, ledger, 1);
    await cloudFrontProvider.describe(cfg, ledger);
    await cloudFrontProvider.inspect(cfg, ledger);
    await cloudFrontProvider.inventory(cfg);
    expect(await cloudFrontProvider.sharedCertificate!(cfg, {})).toMatchObject({ state: 'issued' });
    const id = ledger.resources.find((r) => r.kind === 'distribution')!.resourceId;
    expect(await cloudFrontProvider.inspectForAdoption!(cfg, id, HOST)).toMatchObject({
      hostname: HOST,
      shared: false,
      content: ORIGIN,
    });

    // Teardown of both fronts: disable, wait for the deployment, delete.
    for (const d of [...aws.state.distributions]) {
      const row = resource('distribution', 'distribution', d.id);
      for (let pass = 0; pass < 6 && aws.state.distributions.some((x) => x.id === d.id); pass++) {
        const out = await cloudFrontProvider.runDestroy(cfg, row, ledger);
        expect(out.status).toBe('delete_requested');
        await cloudFrontProvider.confirmDestroyed!(
          cfg,
          { ...row, deleteState: 'delete_requested' },
          ledger,
        );
      }
      expect(await cloudFrontProvider.confirmDestroyed!(cfg, row, ledger)).toEqual({
        status: 'confirmed_gone',
      });
    }
    expect(await destroyAll(cloudFrontProvider as never, cfg as never, ledger)).toEqual([
      'dns_record',
      'distribution',
      'tls_subscription',
      'dns_record',
      'origin_request_policy',
    ]);
    const arn = aws.state.certificate!.arn;
    expect(
      await cloudFrontProvider.removeSharedCertificate!(cfg, {
        ordered: [`tls_subscription:${arn}`],
      }),
    ).toEqual({
      removed: true,
    });

    const calls = observed(server.calls);
    expectContractCovered('cloudfront', calls);
    // Every call is signed for us-east-1 with the key id, never the secret, and
    // the SDK was told it may make ONE attempt.
    for (const c of server.calls) {
      const auth = c.headers.authorization ?? '';
      expect(auth).toMatch(
        /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE00\/\d{8}\/us-east-1\/(acm|cloudfront)\/aws4_request/,
      );
      expect(JSON.stringify(c.headers)).not.toContain(cfg.secretAccessKey);
      expect(c.headers['amz-sdk-request']).toMatch(/max=1/);
    }
  });

  test('an allocating call is never retried and never replayed after a lost response', async () => {
    const aws = account();
    __setCloudFrontDnsClientFactory(() => aws.state.dns);
    const steps = cloudFrontProvider.planProvision(cfg, spec, tpl);
    const certStep = steps[0]!;
    const empty: Ledger = { steps: [], resources: [] };
    for (const status of [429, 500] as const) {
      const server = await serve((c) =>
        c.headers['x-amz-target'] === 'CertificateManager.RequestCertificate'
          ? acm(status, {
              __type: status === 429 ? 'ThrottlingException' : 'InternalFailure',
              message: 'x',
            })
          : aws.route(c),
      );
      expect(
        await caught(() => cloudFrontProvider.runStep(cfg, certStep, spec, tpl, empty)),
      ).toBeTruthy();
      expect(
        server.calls.filter(
          (c) => c.headers['x-amz-target'] === 'CertificateManager.RequestCertificate',
        ),
      ).toHaveLength(1);
      await server.close();
      rec = undefined;
    }
    // A lost answer to the distribution create: ONE request, then discovery reads it back.
    let ledger: Ledger = { steps: [], resources: [] };
    const setup = await serve(aws.route);
    for (const step of steps.slice(0, 3)) {
      let out = await cloudFrontProvider.runStep(cfg, step, spec, tpl, ledger);
      ledger = apply(ledger, step, out);
      if (out.status === 'requested') {
        out = await cloudFrontProvider.pollStep!(cfg, step, out.opRef, ledger);
        ledger = apply(ledger, step, out);
      }
    }
    await setup.close();
    rec = undefined;
    const createStep = steps[3]!;
    const aborting = await serve((c) => {
      const out = aws.route(c);
      return c.method === 'POST' && c.path === '/2020-05-31/distribution'
        ? { ...out, abort: true }
        : out;
    });
    expect(
      await caught(() => cloudFrontProvider.runStep(cfg, createStep, spec, tpl, ledger)),
    ).toBeTruthy();
    expect(
      aborting.calls.filter((c) => c.method === 'POST' && c.path === '/2020-05-31/distribution'),
    ).toHaveLength(1);
    await aborting.close();
    rec = undefined;
    const recovery = await serve(aws.route);
    const found = await cloudFrontProvider.discover(cfg, createStep, spec, ledger, 1);
    expect(found.status).toBe('found');
    expect(recovery.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expectDeclared('cloudfront', observed(recovery.calls));
  });

  test('a destroy after a partial provisioning touches only the recorded children', async () => {
    const aws = account();
    const server = await serve(aws.route);
    __setCloudFrontDnsClientFactory(() => aws.state.dns);
    // The shared certificate landed; nothing else did.
    const partial: Ledger = {
      steps: [],
      resources: [
        resource('tls', 'tls_subscription', `arn:aws:acm:us-east-1:${ACCOUNT}:certificate/x`, {
          shared: true,
          hostname: `*.${ZONE}`,
        }),
      ],
    };
    expect(await destroyAll(cloudFrontProvider as never, cfg as never, partial)).toEqual([
      'tls_subscription',
    ]);
    expect(server.calls).toEqual([]);
  });

  test('errors carry no secret, no origin address and no hostname', async () => {
    const aws = account();
    __setCloudFrontDnsClientFactory(() => aws.state.dns);
    await serve((c) =>
      c.headers['x-amz-target']
        ? acm(400, {
            __type: 'InvalidParameterException',
            message: `bad ${HOST} ${ORIGIN} ${cfg.secretAccessKey}`,
          })
        : cfError(400, 'InvalidArgument', `The parameter ${HOST} ${ORIGIN} is invalid.`),
    );
    const empty: Ledger = { steps: [], resources: [] };
    const [step] = cloudFrontProvider.planProvision(cfg, spec, tpl);
    for (const err of [
      await caught(() => cloudFrontProvider.runStep(cfg, step!, spec, tpl, empty)),
      await caught(() => cloudFrontProvider.inventory(cfg)),
    ]) {
      expect(err).toBeTruthy();
      const blob = errorBlob(err);
      expect(blob).not.toContain('SECRET_');
      expect(blob).not.toContain(ORIGIN);
      expect(blob).not.toContain(HOST);
    }
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

  test('a call two entries both claim is reported, since it would count both as exercised', () => {
    const dnsRecords = { method: 'GET', path: '/client/v4/zones/z/dns_records' };
    expect(
      ambiguousCalls('cloudflare', [
        { ...dnsRecords, queryKeys: ['name.exact', 'per_page'] },
        { ...dnsRecords, queryKeys: ['page', 'per_page', 'proxied'] },
      ]),
    ).toEqual([]);
    expect(
      ambiguousCalls('cloudflare', [
        { ...dnsRecords, queryKeys: ['name.exact', 'page', 'per_page', 'proxied'] },
      ]),
    ).toHaveLength(1);
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
