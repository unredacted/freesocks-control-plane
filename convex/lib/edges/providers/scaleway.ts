/**
 * Scaleway Load Balancer adapter, driven by the official `@scaleway/sdk-lb` +
 * `@scaleway/sdk-client` (zero runtime deps, native fetch — the fetch used is
 * injectable so tests stub it).
 *
 * Model (synchronous zoned API, five small steps): allocate a flexible IPv4
 * (+ an IPv6 when the template asks), create the LB with those IP ids, add a
 * TCP backend pointing at the origin, add a frontend on the edge port. Deletes
 * are asynchronous on the LB (`to_delete` → gone); IPs release synchronously.
 *
 * Discovery: every resource carries our deterministic name or tag and the
 * listings are authoritative, so each step answers found / confirmed_absent.
 *
 * Destroy order is by kind: frontend → backend → LB → flexible IPs (an IP
 * cannot be released while an LB holds it). Every kind is read back after its
 * delete: an LB still `ready` means the delete never landed (`still_present`).
 *
 * Project: every created resource names one. A location may leave its Project
 * id empty; the API key's default project is then used, read from IAM by the
 * credential test (`GET /iam/v1alpha1/api-keys/{access_key}`) and kept on the
 * account as the observed `defaultProjectId` (never a secret), which the
 * adapter config takes as `projectId` (`EDGE_OBSERVED_PLACEMENT`). A create with
 * no project at all is never sent: the run stops on `project_unresolved`.
 */
import {
  API,
  createAdvancedClient,
  isJSONObject,
  validatePathParam,
  withHTTPClient,
  withProfile,
  withUserAgent,
} from '@scaleway/sdk-client';
import { Lbv1 } from '@scaleway/sdk-lb';
import type {
  DiscoverResult,
  Addresses,
  ChildResource,
  EdgeDescription,
  EdgeSpec,
  Ledger,
  EdgeProvider,
  ResourceStep,
  ScalewayConfig,
  StepOutcome,
} from './types';
import { firstResource, orderByKind, resourcesOfKind } from './types';
import { z } from 'zod';
import {
  EdgeProviderError,
  toProviderError,
  credentialTestFailure,
  providerFetch,
  refusalOf,
} from './http';
import type { ProviderPlan } from '../pricing';
import { addressFamily } from '../ip';
import {
  ScalewayTemplate,
  SCALEWAY_TEMPLATE_FIELDS,
  durationMs,
  type ScalewayTemplateParams,
} from './templates';

export { ScalewayTemplate, SCALEWAY_TEMPLATE_FIELDS } from './templates';
export type { ScalewayTemplateParams } from './templates';

export const SCALEWAY_ZONES = [
  'fr-par-1',
  'fr-par-2',
  'nl-ams-1',
  'nl-ams-2',
  'nl-ams-3',
  'pl-waw-1',
  'pl-waw-2',
  'pl-waw-3',
];

type ZonedApi = InstanceType<typeof Lbv1.ZonedAPI>;
type FetchLike = typeof fetch;

/**
 * Build the SDK client. `fetchImpl` is injectable for tests. Built with the
 * advanced factory: `createClient` runs its argument through `withProfile`,
 * which copies only the profile fields and silently DROPS `httpClient`, so the
 * simple form kept the fetch captured at module import and no stub could ever
 * replace it (the wire-contract test caught a call reaching the real API).
 * `withHTTPClient` is the documented way to substitute the transport, and the
 * production path resolves `fetch` lazily per call so a runtime polyfill applies.
 */
function scalewayClient(cfg: ScalewayConfig, fetchImpl?: FetchLike) {
  return createAdvancedClient(
    withProfile({
      accessKey: cfg.accessKey,
      secretKey: cfg.secretKey,
      defaultProjectId: cfg.projectId,
      defaultZone: cfg.zone as never,
    }),
    withHTTPClient(fetchImpl ?? ((input, init) => fetch(input, init))),
    withUserAgent('fcp-relay/1'),
  );
}

export function scalewayApi(cfg: ScalewayConfig, fetchImpl?: FetchLike): ZonedApi {
  return new Lbv1.ZonedAPI(scalewayClient(cfg, fetchImpl));
}

/**
 * The one IAM read FCP makes, on the same client (auth, transport) as the
 * load-balancer API: the project an API key's resources go to when a call
 * names none (`default_project_id`; null when the key has none).
 */
export interface ScalewayKeysApi {
  defaultProjectOf(accessKey: string): Promise<string | null>;
}

class IamApiKeys extends API implements ScalewayKeysApi {
  defaultProjectOf = (accessKey: string): Promise<string | null> =>
    this.client.fetch(
      {
        method: 'GET',
        path: `/iam/v1alpha1/api-keys/${validatePathParam('accessKey', accessKey)}`,
      },
      (raw: unknown) => {
        const id = isJSONObject(raw) ? raw.default_project_id : null;
        return typeof id === 'string' && id ? id : null;
      },
    );
}

export function scalewayKeys(cfg: ScalewayConfig, fetchImpl?: FetchLike): ScalewayKeysApi {
  return new IamApiKeys(scalewayClient(cfg, fetchImpl));
}

let apiFactory: (cfg: ScalewayConfig) => ZonedApi = (cfg) => scalewayApi(cfg);
/** Test seam: replace the SDK client factory. */
export function __setScalewayApiFactory(f: ((cfg: ScalewayConfig) => ZonedApi) | null): void {
  apiFactory = f ?? ((cfg) => scalewayApi(cfg));
}

/**
 * The public product catalog (`GET /product-catalog/v2alpha1/public-catalog/products`,
 * no authentication; an alpha API): every load balancer offer of a zone with
 * its retail price per node an hour, its bandwidth and whether it takes a
 * server outside Scaleway. A small HTTP client (no SDK covers it).
 */
export interface ScalewayLbOffer {
  type: string;
  perHour: number;
  currency: string;
  bandwidthMbps: number | null;
  multicloud: boolean | null;
}
export interface ScalewayCatalogApi {
  /** The zone's offers, and its "Load Balancer IP" price an hour (null when it lists none). */
  loadBalancerOffers(
    zone: string,
  ): Promise<{ offers: ScalewayLbOffer[]; ipv4PerHour: number | null }>;
}

const CATALOG_URL = 'https://api.scaleway.com/product-catalog/v2alpha1/public-catalog/products';
const CatalogProducts = z
  .object({
    products: z
      .array(
        z
          .object({
            product: z.string().nullish(),
            locality: z.object({ zone: z.string().nullish() }).passthrough().nullish(),
            price: z
              .object({
                retail_price: z
                  .object({
                    currency_code: z.string().nullish(),
                    units: z.union([z.number(), z.string()]).nullish(),
                    nanos: z.number().nullish(),
                  })
                  .passthrough()
                  .nullish(),
              })
              .passthrough()
              .nullish(),
            properties: z
              .object({
                load_balancer: z
                  .object({
                    node: z
                      .object({
                        offer_id: z.string().nullish(),
                        multi_cloud_provider: z.boolean().nullish(),
                        bandwidth: z.number().nullish(),
                      })
                      .passthrough()
                      .nullish(),
                    // The "Load Balancer IP" product (priced per IP an hour).
                    ipv4: z.object({}).passthrough().nullish(),
                  })
                  .passthrough()
                  .nullish(),
              })
              .passthrough()
              .nullish(),
          })
          .passthrough(),
      )
      .default([]),
  })
  .passthrough();

/** A catalog retail price (`google.type.Money`: units + nanos), or null. */
function retailOf(
  price: { units?: number | string | null; nanos?: number | null } | null | undefined,
) {
  if (!price) return null;
  const units = Number(price.units ?? 0);
  return Number.isFinite(units) ? units + (price.nanos ?? 0) / 1e9 : null;
}

/** The zone's "Load Balancer IP" price an hour (each IPv4 a load balancer holds), or null (exported for tests). */
export function scalewayIpv4PriceOf(
  raw: z.infer<typeof CatalogProducts>,
  zone: string,
): number | null {
  const ip = raw.products.find(
    (p) =>
      !!p.properties?.load_balancer?.ipv4 &&
      (!p.locality?.zone || p.locality.zone === zone) &&
      !!p.price?.retail_price?.currency_code,
  );
  return ip ? retailOf(ip.price?.retail_price) : null;
}

/** The catalog's load balancer nodes of one zone (exported for tests). */
export function scalewayOffersOf(
  raw: z.infer<typeof CatalogProducts>,
  zone: string,
): ScalewayLbOffer[] {
  return raw.products.flatMap((p) => {
    const node = p.properties?.load_balancer?.node;
    const price = p.price?.retail_price;
    if (!node?.offer_id || !p.product || !price?.currency_code) return [];
    if (p.locality?.zone && p.locality.zone !== zone) return [];
    const units = Number(price.units ?? 0);
    if (!Number.isFinite(units)) return [];
    return [
      {
        type: p.product,
        perHour: units + (price.nanos ?? 0) / 1e9,
        currency: price.currency_code.toUpperCase(),
        bandwidthMbps: typeof node.bandwidth === 'number' ? node.bandwidth / 1e6 : null,
        multicloud:
          typeof node.multi_cloud_provider === 'boolean' ? node.multi_cloud_provider : null,
      },
    ];
  });
}

function scalewayCatalog(): ScalewayCatalogApi {
  return {
    loadBalancerOffers: async (zone) => {
      const raw = await providerFetch({
        provider: 'scaleway',
        step: 'plans',
        url: `${CATALOG_URL}?product_types=load_balancer&zone=${encodeURIComponent(zone)}&page_size=100`,
        method: 'GET',
        headers: {},
        schema: CatalogProducts,
      });
      return { offers: scalewayOffersOf(raw, zone), ipv4PerHour: scalewayIpv4PriceOf(raw, zone) };
    },
  };
}

let catalogFactory: () => ScalewayCatalogApi = () => scalewayCatalog();
/** Test seam: replace the product catalog client. */
export function __setScalewayCatalogFactory(f: (() => ScalewayCatalogApi) | null): void {
  catalogFactory = f ?? (() => scalewayCatalog());
}

/**
 * The load balancer offers of the pricing page, for a zone the catalog does not
 * answer for: €/hour before tax, bandwidth, unlimited traffic, which ones are
 * multi-cloud, and the IPv4 each edge allocates (billed as its own asset).
 * https://www.scaleway.com/en/pricing/network/ (read 2026-10-22).
 */
export const SCALEWAY_LB_PRICES = {
  asOf: '2026-10-22',
  currency: 'EUR',
  /** "IPv4 IP per asset", the Load Balancer row of Additional IP: each IPv4 FCP allocates. */
  ipv4PerHour: 0.005,
  types: [
    { type: 'LB-S', perHour: 0.023, bandwidthMbps: 200, multicloud: false },
    { type: 'LB-GP-M', perHour: 0.054, bandwidthMbps: 500, multicloud: false },
    { type: 'LB-GP-L', perHour: 0.094, bandwidthMbps: 1000, multicloud: true },
    { type: 'LB-GP-XL', perHour: 0.941, bandwidthMbps: 4000, multicloud: true },
  ],
} as const;

/** A node's price an hour with the IPv4 its edge allocates added (kept to the catalog's nanos). */
const withIpv4 = (perHour: number, ipv4: number) => Math.round((perHour + ipv4) * 1e9) / 1e9;

/**
 * The plans of the dated table, for the sizes the zone lists (`listLbTypes`:
 * its own multi-cloud flag and bandwidth win), or every size of the table when
 * the list could not be read (exported for tests).
 */
export function scalewayTablePlans(
  types: ReadonlyArray<{ name: string; bandwidth?: number; multicloud?: boolean }> | null,
): ProviderPlan[] {
  type Listed = { name: string; bandwidth?: number; multicloud?: boolean };
  const listed: readonly Listed[] =
    types && types.length > 0 ? types : SCALEWAY_LB_PRICES.types.map((t) => ({ name: t.type }));
  return listed.map((t) => {
    const row = SCALEWAY_LB_PRICES.types.find(
      (x) => x.type.toLowerCase() === t.name.trim().toLowerCase(),
    );
    const bandwidth =
      typeof t.bandwidth === 'number' && t.bandwidth > 0
        ? t.bandwidth / 1e6
        : (row?.bandwidthMbps ?? null);
    return {
      size: t.name,
      label: t.name,
      perHour: row ? withIpv4(row.perHour, SCALEWAY_LB_PRICES.ipv4PerHour) : null,
      perMonth: null,
      currency: row ? SCALEWAY_LB_PRICES.currency : null,
      traffic: { kind: 'unlimited' },
      bandwidthMbps: bandwidth,
      acceptsOutsideNode:
        typeof t.multicloud === 'boolean' ? t.multicloud : (row?.multicloud ?? null),
      source: 'catalog',
      ...(row ? { catalogAsOf: SCALEWAY_LB_PRICES.asOf } : {}),
    };
  });
}

let keysFactory: (cfg: ScalewayConfig) => ScalewayKeysApi = (cfg) => scalewayKeys(cfg);
/** Test seam: replace the IAM client factory. */
export function __setScalewayKeysFactory(
  f: ((cfg: ScalewayConfig) => ScalewayKeysApi) | null,
): void {
  keysFactory = f ?? ((cfg) => scalewayKeys(cfg));
}

/**
 * The API key's default project, or null when the key may not read it (a
 * refused or unknown key answer: a location must then name its Project id).
 * Any other failure (the network, the provider) is thrown as usual.
 */
async function defaultProjectOf(cfg: ScalewayConfig): Promise<string | null> {
  try {
    return await sdk(cfg, 'test', () => keysFactory(cfg).defaultProjectOf(cfg.accessKey));
  } catch (e) {
    const status = e instanceof EdgeProviderError ? e.meta.status : undefined;
    if (status === 401 || status === 403 || status === 404) return null;
    throw e;
  }
}

/** The project a create names: the location's, else the key's default (filled in by the config). */
function projectFor(cfg: ScalewayConfig, step: string): string {
  if (cfg.projectId) return cfg.projectId;
  throw new EdgeProviderError('scaleway: no project for a create', {
    provider: 'scaleway',
    step,
    code: 'project_unresolved',
    retryable: false,
    timedOut: false,
  });
}

async function sdk<T>(cfg: ScalewayConfig, step: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw toProviderError('scaleway', step, e, [cfg.secretKey]);
  }
}

function isNotFound(e: unknown): boolean {
  return e instanceof EdgeProviderError && e.meta.status === 404;
}

function addressesOf(ips: Array<{ ipAddress: string }>): Addresses {
  const out: Addresses = {};
  for (const ip of ips) {
    const fam = addressFamily(ip.ipAddress);
    if (fam === 'v4' && !out.v4) out.v4 = ip.ipAddress;
    if (fam === 'v6' && !out.v6) out.v6 = ip.ipAddress;
  }
  return out;
}

/** A template duration as whole milliseconds; a value that is none refuses the run. */
function msOf(value: string, key: string, step: string): number {
  const ms = durationMs(value);
  if (ms !== null) return ms;
  throw new EdgeProviderError(`scaleway: ${key} is not a whole number of milliseconds`, {
    provider: 'scaleway',
    step,
    code: 'template_invalid',
    retryable: false,
    timedOut: false,
  });
}

/**
 * The eight timing fields as the API reads them; a backend or frontend create
 * and its update take the same. The template keeps `600s`-style values.
 *
 * - `check_delay`, `check_timeout`, `timeout_server`, `timeout_connect`,
 *   `timeout_tunnel` and `timeout_client` are int64 MILLISECONDS (Scaleway's Go
 *   SDK sends them as `marshaler.Duration`, a JSON integer). The JS SDK types
 *   them as strings and marshals them unchanged, so a `5s` reached the API as is
 *   and was refused (`invalid value for int64 field milliseconds`): the number
 *   goes in the string's place and the body carries a JSON integer.
 * - `transient_check_delay` and `timeout_queue` are protobuf durations (the Go
 *   SDK's `scw.Duration`, `"0.500000000s"`): they stay strings, in seconds.
 */
export function scalewayTimings(tpl: ScalewayTemplateParams, step: string) {
  const ms = (value: string, key: string) => msOf(value, key, step) as unknown as string;
  const seconds = (value: string, key: string) => `${msOf(value, key, step) / 1000}s`;
  const hc = tpl.healthCheck;
  return {
    backend: {
      timeoutServer: ms(tpl.timeoutServer, 'timeoutServer'),
      timeoutConnect: ms(tpl.timeoutConnect, 'timeoutConnect'),
      timeoutTunnel: ms(tpl.timeoutTunnel, 'timeoutTunnel'),
      ...(tpl.timeoutQueue ? { timeoutQueue: seconds(tpl.timeoutQueue, 'timeoutQueue') } : {}),
    },
    healthCheck: {
      checkDelay: ms(hc.checkDelay, 'healthCheck.checkDelay'),
      checkTimeout: ms(hc.checkTimeout, 'healthCheck.checkTimeout'),
      ...(hc.transientCheckDelay
        ? {
            transientCheckDelay: seconds(hc.transientCheckDelay, 'healthCheck.transientCheckDelay'),
          }
        : {}),
    },
    frontend: { timeoutClient: ms(tpl.timeoutClient, 'timeoutClient') },
  };
}

function lbState(status: string): EdgeDescription['state'] {
  switch (status) {
    case 'ready':
      return 'active';
    case 'error':
    case 'locked':
    case 'stopped':
      return 'error';
    default:
      return 'pending';
  }
}

export const scalewayProvider: EdgeProvider<ScalewayConfig, ScalewayTemplateParams> = {
  id: 'scaleway',
  templateSchema: ScalewayTemplate,
  templateFields: SCALEWAY_TEMPLATE_FIELDS,
  defaultTemplate: ScalewayTemplate.parse({}),

  async testCredentials(cfg) {
    try {
      // An account is credentials only: without a location the key is tested
      // in the first offered zone (a key is valid in every zone), and in no
      // project (one an earlier test observed may be another key's).
      const at: ScalewayConfig = {
        ...cfg,
        zone: cfg.zone || SCALEWAY_ZONES[0]!,
        projectId: undefined,
      };
      await sdk(at, 'test', () => apiFactory(at).listLbs({ pageSize: 1 }));
      // Where a location with no Project id creates its resources: the key's
      // default project, kept as an observed fact. A key that may not read it
      // still passes; such a location is then not offered (`project_unresolved`)
      // until it names a Project id, so nothing fails later at provisioning.
      const defaultProjectId = await defaultProjectOf(at);
      return defaultProjectId ? { ok: true, observed: { defaultProjectId } } : { ok: true };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  async listRegions() {
    return SCALEWAY_ZONES.map((z) => ({ id: z, label: z }));
  },

  /** Zones are a fixed list; the project defaults to the key's project when left empty. */
  async discoverOptions(): Promise<DiscoverResult> {
    return { regions: SCALEWAY_ZONES.map((z) => ({ id: z, label: z })) };
  },

  planProvision(_cfg, spec, tpl) {
    // A timing the API cannot take refuses the run before anything is billed.
    scalewayTimings(tpl, 'plan');
    const steps: ResourceStep[] = [
      { id: 'ip4', kind: 'allocate_ip', resourceName: spec.name, discoverability: 'by_tag' },
    ];
    if (tpl.ipv6)
      steps.push({
        id: 'ip6',
        kind: 'allocate_ipv6',
        resourceName: spec.name,
        discoverability: 'by_tag',
      });
    steps.push({
      id: 'lb',
      kind: 'create_lb',
      resourceName: spec.name,
      discoverability: 'by_name',
    });
    steps.push({
      id: 'backend',
      kind: 'create_backend',
      resourceName: `${spec.name}-backend`,
      discoverability: 'by_name',
    });
    steps.push({
      id: 'frontend',
      kind: 'create_frontend',
      resourceName: `${spec.name}-frontend`,
      discoverability: 'by_name',
    });
    return steps;
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    const api = apiFactory(cfg);
    const listener = spec.listeners[0];
    if (!listener)
      throw new EdgeProviderError('scaleway: spec has no listener', {
        provider: 'scaleway',
        step: step.id,
        code: 'spec_invalid',
        retryable: false,
        timedOut: false,
      });
    switch (step.kind) {
      case 'allocate_ip':
      case 'allocate_ipv6': {
        const isIpv6 = step.kind === 'allocate_ipv6';
        // No project from the location nor from the key: the run stops on it
        // at once (planning never offers such a location; this is the guard).
        if (!cfg.projectId)
          return { status: 'partial', resources: [], code: 'project_unresolved', refused: true };
        const projectId = cfg.projectId;
        let ip;
        try {
          ip = await sdk(cfg, step.id, () =>
            api.createIp({
              projectId,
              isIpv6,
              tags: [spec.name],
              ...(tpl.reverse ? { reverse: tpl.reverse } : {}),
            }),
          );
        } catch (e) {
          // Scaleway refused the arguments (400): the same call would be
          // refused again, so the run stops on a known code at once instead
          // of retrying the step until it gives up.
          if (e instanceof EdgeProviderError && e.meta.status === 400)
            return {
              status: 'partial',
              resources: [],
              code: 'ip_allocation_refused',
              refused: true,
              ...(refusalOf(e) ? { detail: refusalOf(e) } : {}),
            };
          throw e;
        }
        return {
          status: 'done',
          resources: [
            {
              kind: isIpv6 ? 'ipv6' : 'ip',
              resourceId: ip.id,
              ownership: 'created',
              meta: { address: ip.ipAddress },
            },
          ],
          addresses: isIpv6 ? { v6: ip.ipAddress } : { v4: ip.ipAddress },
        };
      }
      case 'create_lb': {
        const ipIds = [...resourcesOfKind(ledger, 'ip'), ...resourcesOfKind(ledger, 'ipv6')].map(
          (r) => r.resourceId,
        );
        const lb = await sdk(cfg, step.id, () =>
          api.createLb({
            name: spec.name,
            description: tpl.description ?? 'origin edge',
            type: tpl.type,
            projectId: projectFor(cfg, step.id),
            ipIds,
            assignFlexibleIp: false,
            tags: [spec.name, ...tpl.tags],
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'lb', resourceId: lb.id, ownership: 'created' }],
          addresses: addressesOf(lb.ip),
        };
      }
      case 'create_backend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) throw ledgerIncomplete(step);
        const timings = scalewayTimings(tpl, step.id);
        const backend = await sdk(cfg, step.id, () =>
          api.createBackend({
            lbId: lb.resourceId,
            name: step.resourceName,
            forwardProtocol: 'tcp',
            forwardPort: listener.members[0]?.port ?? 443,
            forwardPortAlgorithm: tpl.forwardPortAlgorithm,
            stickySessions: 'none',
            stickySessionsCookieName: '',
            healthCheck: {
              port: listener.members[0]?.port ?? 443,
              ...timings.healthCheck,
              checkMaxRetries: tpl.healthCheck.checkMaxRetries,
              tcpConfig: {},
              checkSendProxy: false,
            },
            serverIp: listener.members.map((m) => m.address),
            ...timings.backend,
            proxyProtocol: 'proxy_protocol_none',
            onMarkedDownAction: tpl.closeOnFailure
              ? 'shutdown_sessions'
              : 'on_marked_down_action_none',
            ...(tpl.maxConnections !== undefined ? { maxConnections: tpl.maxConnections } : {}),
            ...(tpl.maxRetries !== undefined ? { maxRetries: tpl.maxRetries } : {}),
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'backend', resourceId: backend.id, ownership: 'created' }],
        };
      }
      case 'create_frontend': {
        const lb = firstResource(ledger, 'lb');
        const backend = firstResource(ledger, 'backend');
        if (!lb || !backend) throw ledgerIncomplete(step);
        const { frontend: timings } = scalewayTimings(tpl, step.id);
        const frontend = await sdk(cfg, step.id, () =>
          api.createFrontend({
            lbId: lb.resourceId,
            name: step.resourceName,
            inboundPort: listener.edgePort,
            backendId: backend.resourceId,
            ...timings,
            enableHttp3: false,
            enableAccessLogs: false,
            ...(tpl.connectionRateLimit ? { connectionRateLimit: tpl.connectionRateLimit } : {}),
          }),
        );
        return {
          status: 'done',
          resources: [{ kind: 'frontend', resourceId: frontend.id, ownership: 'created' }],
        };
      }
      default:
        throw new EdgeProviderError(`scaleway: unknown step kind ${step.kind}`, {
          provider: 'scaleway',
          step: step.id,
          code: 'unknown_step',
          retryable: false,
          timedOut: false,
        });
    }
  },

  async discover(cfg, step, spec, ledger) {
    const api = apiFactory(cfg);
    switch (step.kind) {
      case 'allocate_ip':
      case 'allocate_ipv6': {
        const wantV6 = step.kind === 'allocate_ipv6';
        const ips = await sdk(cfg, step.id, () => api.listIPs({ projectId: cfg.projectId }).all());
        const hit = ips.find(
          (ip) => ip.tags.includes(spec.name) && (addressFamily(ip.ipAddress) === 'v6') === wantV6,
        );
        return hit
          ? {
              status: 'found',
              resources: [
                {
                  kind: wantV6 ? 'ipv6' : 'ip',
                  resourceId: hit.id,
                  ownership: 'adopted',
                  meta: { address: hit.ipAddress },
                },
              ],
              addresses: wantV6 ? { v6: hit.ipAddress } : { v4: hit.ipAddress },
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_lb': {
        const lbs = await sdk(cfg, step.id, () =>
          api.listLbs({ name: spec.name, projectId: cfg.projectId }).all(),
        );
        const hit = lbs.find((l) => l.name === spec.name);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'lb', resourceId: hit.id, ownership: 'adopted' }],
              addresses: addressesOf(hit.ip),
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_backend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) return { status: 'confirmed_absent' };
        const list = await sdk(cfg, step.id, () =>
          api.listBackends({ lbId: lb.resourceId, name: step.resourceName }).all(),
        );
        const hit = list.find((b) => b.name === step.resourceName);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'backend', resourceId: hit.id, ownership: 'adopted' }],
            }
          : { status: 'confirmed_absent' };
      }
      case 'create_frontend': {
        const lb = firstResource(ledger, 'lb');
        if (!lb) return { status: 'confirmed_absent' };
        const list = await sdk(cfg, step.id, () =>
          api.listFrontends({ lbId: lb.resourceId, name: step.resourceName }).all(),
        );
        const hit = list.find((f) => f.name === step.resourceName);
        return hit
          ? {
              status: 'found',
              resources: [{ kind: 'frontend', resourceId: hit.id, ownership: 'adopted' }],
            }
          : { status: 'confirmed_absent' };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_lb_yet' };
    const api = apiFactory(cfg);
    let obj;
    try {
      obj = await sdk(cfg, 'describe', () => api.getLb({ lbId: lb.resourceId }));
    } catch (e) {
      if (isNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    const state = lbState(obj.status);
    let health: EdgeDescription['health'] = 'unknown';
    if (state === 'active') {
      try {
        const stats = await sdk(cfg, 'describe-stats', () =>
          api.getLbStats({ lbId: lb.resourceId }),
        );
        const checks = stats.backendServersStats.map((s) => String(s.lastHealthCheckStatus));
        if (checks.length > 0)
          health = checks.some((c) => c === 'passed')
            ? 'online'
            : checks.every((c) => c === 'failed')
              ? 'offline'
              : 'degraded';
      } catch {
        health = 'unknown';
      }
    }
    // Adopt IPs the LB reports that the ledger does not know (e.g. assigned by the provider).
    const known = new Set(ledger.resources.map((r) => r.resourceId));
    const resources: ChildResource[] = obj.ip
      .filter((ip) => !known.has(ip.id))
      .map((ip) => ({
        kind: addressFamily(ip.ipAddress) === 'v6' ? 'ipv6' : 'ip',
        resourceId: ip.id,
        ownership: 'created' as const,
        meta: { address: ip.ipAddress },
      }));
    return {
      state,
      addresses: addressesOf(obj.ip),
      health,
      ...(resources.length > 0 ? { resources } : {}),
    };
  },

  async inspect(cfg, ledger) {
    const lb = firstResource(ledger, 'lb');
    if (!lb)
      throw new EdgeProviderError('scaleway inspect: no lb in ledger', {
        provider: 'scaleway',
        step: 'inspect',
        code: 'no_lb',
        retryable: false,
        timedOut: false,
      });
    const api = apiFactory(cfg);
    const obj = await sdk(cfg, 'inspect', () => api.getLb({ lbId: lb.resourceId }));
    const [backends, frontends, stats] = await Promise.all([
      sdk(cfg, 'inspect', () => api.listBackends({ lbId: lb.resourceId }).all()).catch(() => []),
      sdk(cfg, 'inspect', () => api.listFrontends({ lbId: lb.resourceId }).all()).catch(() => []),
      sdk(cfg, 'inspect', () => api.getLbStats({ lbId: lb.resourceId })).catch(() => null),
    ]);
    const healthByIp = new Map(
      (stats?.backendServersStats ?? []).map((s) => [s.ip, String(s.lastHealthCheckStatus)]),
    );
    return {
      summary: {
        status: obj.status,
        flavor: obj.type,
        region: obj.zone,
        createdAt: obj.createdAt?.toISOString(),
        addresses: addressesOf(obj.ip),
        members: backends.flatMap((b) =>
          b.pool.map((ip) => ({ address: ip, port: b.forwardPort, health: healthByIp.get(ip) })),
        ),
        listeners: frontends.map((f) => ({ port: f.inboundPort, protocol: 'tcp' })),
      },
      raw: { lb: obj, backends, frontends, stats },
    };
  },

  async inventory(cfg) {
    const api = apiFactory(cfg);
    const [lbs, ips, types] = await Promise.all([
      sdk(cfg, 'inventory', () => api.listLbs({ projectId: cfg.projectId }).all()),
      sdk(cfg, 'inventory', () => api.listIPs({ projectId: cfg.projectId }).all()).catch(() => []),
      sdk(cfg, 'inventory', () => api.listLbTypes({}).all()).catch(() => []),
    ]);
    return {
      loadBalancers: lbs.map((l) => ({
        id: l.id,
        name: l.name,
        status: l.status,
        addresses: addressesOf(l.ip),
        createdAt: l.createdAt?.toISOString(),
      })),
      ips: ips.map((ip) => ({ id: ip.id, address: ip.ipAddress, attachedTo: ip.lbId ?? null })),
      // Only a multi-cloud offer accepts a node outside Scaleway: the label says
      // which, and the flag is kept for planning (lib/edges/sizeCheck.ts).
      flavors: types.map((t) => ({
        id: t.name,
        label: t.multicloud ? `${t.name} (multi-cloud)` : t.name,
        multicloud: t.multicloud === true,
      })),
    };
  },

  /**
   * Every load balancer offer of the zone with its price: the public product
   * catalog (per node an hour, with the IPv4 each edge allocates added: its
   * "Load Balancer IP"), else the zone's size list priced from the dated
   * table of the pricing page (`SCALEWAY_LB_PRICES`). Traffic is not charged;
   * only the multi-cloud offers take a node outside Scaleway.
   */
  async plans(cfg) {
    try {
      const { offers, ipv4PerHour } = await catalogFactory().loadBalancerOffers(cfg.zone);
      // Every edge allocates its own IPv4 (`allocate_ip`), billed as its own asset.
      const ipv4 = ipv4PerHour ?? SCALEWAY_LB_PRICES.ipv4PerHour;
      if (offers.length > 0)
        return offers.map((o) => ({
          size: o.type,
          label: o.type,
          perHour: withIpv4(o.perHour, ipv4),
          perMonth: null,
          currency: o.currency,
          traffic: { kind: 'unlimited' },
          bandwidthMbps: o.bandwidthMbps,
          acceptsOutsideNode: o.multicloud,
          source: 'api',
        }));
    } catch {
      // The catalog is an alpha API: the dated table answers instead.
    }
    const types = await sdk(cfg, 'plans', () => apiFactory(cfg).listLbTypes({}).all()).catch(
      () => null,
    );
    return scalewayTablePlans(types);
  },

  planDestroy: (_cfg, ledger) => orderByKind(ledger, SCALEWAY_DESTROY_ORDER),

  /**
   * Every delete is reported `delete_requested` and confirmed by a read-back
   * (`confirmDestroyed`), never assumed from a 2xx. A kind this adapter never
   * creates is `unresolved`, never assumed gone.
   */
  async runDestroy(cfg, r) {
    const api = apiFactory(cfg);
    try {
      switch (r.kind) {
        case 'frontend':
          await sdk(cfg, 'destroy', () => api.deleteFrontend({ frontendId: r.resourceId }));
          return { status: 'delete_requested' };
        case 'backend':
          await sdk(cfg, 'destroy', () => api.deleteBackend({ backendId: r.resourceId }));
          return { status: 'delete_requested' };
        case 'lb':
          await sdk(cfg, 'destroy', () => api.deleteLb({ lbId: r.resourceId, releaseIp: false }));
          return { status: 'delete_requested' };
        case 'ip':
        case 'ipv6':
          await sdk(cfg, 'destroy', () => api.releaseIp({ ipId: r.resourceId }));
          return { status: 'delete_requested' };
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  /** Read back: 404 → gone; an LB deleting → unresolved; anything readable otherwise → still present. */
  async confirmDestroyed(cfg, r) {
    const api = apiFactory(cfg);
    try {
      switch (r.kind) {
        case 'lb': {
          const lb = await sdk(cfg, 'confirm-destroy', () => api.getLb({ lbId: r.resourceId }));
          return lb.status === 'deleting' || lb.status === 'to_delete'
            ? { status: 'unresolved' }
            : { status: 'still_present' };
        }
        case 'ip':
        case 'ipv6':
          await sdk(cfg, 'confirm-destroy', () => api.getIp({ ipId: r.resourceId }));
          return { status: 'still_present' };
        case 'frontend':
          await sdk(cfg, 'confirm-destroy', () => api.getFrontend({ frontendId: r.resourceId }));
          return { status: 'still_present' };
        case 'backend':
          await sdk(cfg, 'confirm-destroy', () => api.getBackend({ backendId: r.resourceId }));
          return { status: 'still_present' };
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

/** Attach semantics: a frontend needs its backend, both need the LB, the LB holds the IPs. */
const SCALEWAY_DESTROY_ORDER = ['frontend', 'backend', 'lb', 'ip', 'ipv6'] as const;

function ledgerIncomplete(step: ResourceStep): EdgeProviderError {
  return new EdgeProviderError(`scaleway ${step.id}: ledger missing a prerequisite resource`, {
    provider: 'scaleway',
    step: step.id,
    code: 'ledger_incomplete',
    retryable: false,
    timedOut: false,
  });
}

export type { Ledger as ScalewayLedger, EdgeSpec as ScalewayEdgeSpec };
