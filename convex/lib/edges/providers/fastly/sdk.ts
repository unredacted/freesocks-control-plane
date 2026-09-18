'use node';
/**
 * Typed, body-free wrapper over the official `fastly` JS SDK (16.1.0).
 *
 * Why a wrapper rather than the SDK directly:
 *  - The SDK ships Babel output with no typings; ./fastlySdk.d.ts declares only
 *    the classes and methods used here, so an unlisted call cannot be made by
 *    accident.
 *  - The generated `*Api` methods return MODEL objects that drop unknown fields
 *    and coerce timestamps to `Date`. Every method below calls the
 *    `*WithHttpInfo` variant instead and validates the RAW JSON body with a
 *    lenient zod schema, so the adapter sees exactly what the API sent.
 *  - SDK rejections are plain objects carrying `status`, `body` and the whole
 *    superagent `response`. Those bodies echo request fields (a hostname, an
 *    origin address) and superagent's own error message embeds the URL, so
 *    nothing from them ever reaches an `EdgeProviderError` except the HTTP
 *    status and a code from a small ALLOWLIST of known Fastly error strings.
 *    `detail` is never read.
 *  - The SDK has NO retry of its own, which is what the edge orchestrator
 *    needs: an unknown outcome is resolved by discovery, never by a blind
 *    replay of an allocating POST.
 *
 * Residual risk, accepted and documented: superagent follows redirects by
 * default and the SDK exposes no way to set `redirects(0)`, so a 3xx from the
 * API host would replay the `Fastly-Key` header to wherever it points. The
 * base path is therefore pinned to the HTTPS API origin (`https://api.fastly.com`,
 * which never redirects) and overridden only by tests. If Fastly ever starts
 * redirecting an endpoint used here, that call moves to `providerFetch`.
 */
import { z } from 'zod';
import {
  ApiClient,
  BackendApi,
  CustomerApi,
  DomainApi,
  ProductWebsocketsApi,
  ServiceApi,
  SnippetApi,
  TlsConfigurationsApi,
  TlsSubscriptionsApi,
  TokensApi,
  VersionApi,
  type FastlyHttpInfo,
  type FastlyPlugin,
} from 'fastly';
import { EdgeProviderError, capturesErrorDetail, redactErrorDetail } from '../http';
import type { FastlyConfig } from '../types';

/** The one origin the SDK's generated methods target. Also the redirect-safety pin. */
export const FASTLY_API_ORIGIN = 'https://api.fastly.com';
/** Every provider call is a small object or a bounded page; 15 s is generous. */
export const FASTLY_TIMEOUT_MS = 15_000;
const USER_AGENT = 'fcp-relay/1';

// --- response schemas (lenient: unknown fields survive, nothing is required that is not read) ---

const Version = z.looseObject({
  number: z.number(),
  active: z.boolean().optional(),
  locked: z.boolean().optional(),
  deployed: z.boolean().optional(),
  staging: z.boolean().optional(),
  testing: z.boolean().optional(),
  comment: z.string().nullish(),
  created_at: z.string().nullish(),
  deleted_at: z.string().nullish(),
});
export type FastlyVersion = z.infer<typeof Version>;

const Service = z.looseObject({
  id: z.string(),
  name: z.string().optional(),
  type: z.string().optional(),
  comment: z.string().nullish(),
  deleted_at: z.string().nullish(),
  version: z.number().optional(),
  versions: z.array(Version).optional(),
});
export type FastlyService = z.infer<typeof Service>;

const ServiceDetail = z.looseObject({
  id: z.string(),
  name: z.string().optional(),
  active_version: z.union([Version, z.number(), z.null()]).optional(),
  version: z.union([Version, z.number()]).optional(),
  versions: z.array(Version).optional(),
  deleted_at: z.string().nullish(),
});
export type FastlyServiceDetail = z.infer<typeof ServiceDetail>;

const Backend = z.looseObject({
  name: z.string(),
  address: z.string().nullish(),
  hostname: z.string().nullish(),
  port: z.number().nullish(),
  use_ssl: z.boolean().nullish(),
  override_host: z.string().nullish(),
  comment: z.string().nullish(),
});
export type FastlyBackend = z.infer<typeof Backend>;

const Domain = z.looseObject({
  name: z.string(),
  comment: z.string().nullish(),
  service_id: z.string().optional(),
  version: z.number().optional(),
});
export type FastlyDomain = z.infer<typeof Domain>;

const Snippet = z.looseObject({
  name: z.string(),
  id: z.string().optional(),
  type: z.string().optional(),
  priority: z.union([z.string(), z.number()]).nullish(),
  dynamic: z.union([z.string(), z.number()]).nullish(),
});

/** `GET .../domain/{name}/check` answers a positional triple; the shape beyond it is not read. */
const DomainCheck = z.array(z.unknown());

/** `GET .../version/{n}/validate` answers `{status:'ok'}` or `{status:'error', msg, errors}`. */
const VersionValidation = z.looseObject({
  status: z.string().optional(),
  errors: z.array(z.unknown()).nullish(),
});

const WebsocketsProduct = z.looseObject({
  product: z.looseObject({ id: z.string().optional() }).optional(),
  service: z.looseObject({ id: z.string().optional() }).optional(),
});

/** JSON:API resource object (TLS subscriptions, configurations, authorizations, DNS records). */
const JsonApiResource = z.looseObject({
  id: z.string(),
  type: z.string(),
  attributes: z.looseObject({}).optional(),
  relationships: z.looseObject({}).optional(),
});
const JsonApiDoc = z.looseObject({
  data: JsonApiResource,
  included: z.array(JsonApiResource).optional(),
});
const JsonApiCollection = z.looseObject({
  data: z.array(JsonApiResource),
  included: z.array(JsonApiResource).optional(),
  meta: z.looseObject({}).optional(),
});
export type FastlyJsonApiResource = z.infer<typeof JsonApiResource>;
export type FastlyJsonApiDoc = z.infer<typeof JsonApiDoc>;
export type FastlyJsonApiCollection = z.infer<typeof JsonApiCollection>;

const TokenSelf = z.looseObject({
  id: z.string().optional(),
  /** Space-separated scope list, e.g. `global` or `purge_all purge_select`. */
  scope: z.string().nullish(),
  expires_at: z.string().nullish(),
  user_id: z.string().optional(),
});
export type FastlyTokenSelf = z.infer<typeof TokenSelf>;

const Customer = z.looseObject({
  id: z.string().optional(),
  name: z.string().nullish(),
  pricing_plan: z.string().nullish(),
});
export type FastlyCustomer = z.infer<typeof Customer>;

const ServiceList = z.array(Service);
const BackendList = z.array(Backend);
const DomainList = z.array(Domain);
const VersionList = z.array(Version);
const Empty = z.unknown();

// --- errors --------------------------------------------------------------------------

/**
 * The ONLY error strings that may become an `EdgeProviderError.code`. Fastly's
 * legacy envelope puts free text in `msg`/`title` ("Domain <name> is already
 * taken"), which would leak the hostname or the origin address, so a candidate
 * is normalised to snake_case and kept only when it is one of these known,
 * value-free codes. Anything else becomes no code at all (the HTTP status still
 * travels). `detail` is never read at all.
 */
const FASTLY_ERROR_CODES: ReadonlySet<string> = new Set([
  'access_denied',
  'bad_request',
  'conflict',
  'duplicate_record',
  'forbidden',
  'internal_server_error',
  'invalid_credentials',
  'invalid_parameters',
  'not_authorized',
  'not_found',
  'payment_required',
  'provided_credentials_are_missing_or_invalid',
  'rate_limit_exceeded',
  'record_not_found',
  'service_unavailable',
  'unauthorized',
  'unprocessable_entity',
  'you_are_not_authorized_to_perform_this_action',
]);

/** Lowercase, punctuation to underscores, collapsed: `Record not found` → `record_not_found`. */
export function normalizeFastlyCode(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const slug = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (slug.length === 0 || slug.length > 64) return undefined;
  return FASTLY_ERROR_CODES.has(slug) ? slug : undefined;
}

/**
 * The allowlisted code for an error body, looking at the two envelopes Fastly
 * uses: legacy `{msg, detail, title}` and JSON:API `{errors:[{code,title,detail,status}]}`.
 */
export function fastlyErrorCode(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const o = body as Record<string, unknown>;
  const errors = o.errors;
  if (Array.isArray(errors)) {
    for (const e of errors.slice(0, 3)) {
      if (e && typeof e === 'object') {
        const rec = e as Record<string, unknown>;
        const code = normalizeFastlyCode(rec.code) ?? normalizeFastlyCode(rec.title);
        if (code) return code;
      }
    }
  }
  return normalizeFastlyCode(o.msg) ?? normalizeFastlyCode(o.title);
}

interface SdkRejection {
  status?: unknown;
  body?: unknown;
  response?: { status?: unknown; body?: unknown };
  error?: { code?: unknown; timeout?: unknown; name?: unknown };
}

/** SDK rejection → body-free `EdgeProviderError` (status + allowlisted code only). */
export function toFastlyError(
  step: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const e = (err ?? {}) as SdkRejection;
  const status =
    typeof e.status === 'number'
      ? e.status
      : typeof e.response?.status === 'number'
        ? e.response.status
        : undefined;
  const body = e.body ?? e.response?.body;
  const code = fastlyErrorCode(body);
  // superagent marks its own timeouts with `ECONNABORTED` / `ETIMEDOUT`.
  const inner = e.error ?? {};
  const timedOut =
    inner.timeout !== undefined ||
    inner.code === 'ECONNABORTED' ||
    inner.code === 'ETIMEDOUT' ||
    inner.name === 'AbortError';
  return new EdgeProviderError(
    `fastly ${status ?? (timedOut ? 'timeout' : 'error')} on ${step}${code ? ` (${code})` : ''}`,
    {
      provider: 'fastly',
      step,
      status,
      code,
      detail:
        !capturesErrorDetail(step) || body === undefined || body === null
          ? undefined
          : redactErrorDetail(typeof body === 'string' ? body : JSON.stringify(body), secrets),
      retryable: timedOut || status === 429 || (status !== undefined && status >= 500),
      timedOut,
    },
  );
}

export function isFastlyNotFound(err: unknown): boolean {
  return err instanceof EdgeProviderError && err.meta.status === 404;
}

// --- client construction -------------------------------------------------------------

/** Test seam: point the real SDK at an in-process recorder instead of the API host. */
let basePathOverride: string | null = null;
export function __setFastlyBasePath(url: string | null): void {
  basePathOverride = url;
}

function rewritePlugin(base: string): FastlyPlugin {
  return (request) => {
    if (request.url.startsWith(FASTLY_API_ORIGIN)) {
      request.url = base.replace(/\/+$/, '') + request.url.slice(FASTLY_API_ORIGIN.length);
    }
  };
}

function newClient(cfg: FastlyConfig, basePath: string | undefined, extra: FastlyPlugin[]) {
  const client = new ApiClient();
  const base = basePath ?? basePathOverride ?? FASTLY_API_ORIGIN;
  // Set both: `basePath` documents the intent, but the generated methods pass
  // their own base path to `callApi`, so only the plugin actually redirects.
  client.basePath = base;
  client.timeout = FASTLY_TIMEOUT_MS;
  client.cache = true; // `false` would append a `_=<now>` param to every GET.
  client.enableCookies = false;
  client.defaultHeaders = { 'User-Agent': USER_AGENT };
  client.authenticate(cfg.apiToken);
  const plugins = [...(base === FASTLY_API_ORIGIN ? [] : [rewritePlugin(base)]), ...extra];
  client.plugins = plugins.length > 0 ? plugins : null;
  return client;
}

/** Reads the RAW body (never the SDK model) and validates it. */
async function call<T>(
  step: string,
  schema: z.ZodType<T>,
  fn: () => Promise<FastlyHttpInfo>,
  secrets: string[] = [],
): Promise<T> {
  let raw: unknown;
  try {
    const res = await fn();
    raw = res.response?.body;
    // 204 and other empty answers: superagent yields `{}`; treat as undefined.
    // An empty ARRAY is a real answer (an empty listing) and must survive.
    if (
      raw &&
      typeof raw === 'object' &&
      !Array.isArray(raw) &&
      Object.keys(raw as object).length === 0
    )
      raw = undefined;
  } catch (e) {
    throw toFastlyError(step, e, secrets);
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 6)
      .map((i) => i.path.join('.') || '(root)')
      .join(', ');
    throw new EdgeProviderError(`fastly schema mismatch on ${step} [${issues}]`, {
      provider: 'fastly',
      step,
      code: 'schema_mismatch',
      retryable: false,
      timedOut: false,
    });
  }
  return parsed.data;
}

export interface FastlyApi {
  // service
  createService(o: { name: string; type: string; comment?: string }): Promise<FastlyService>;
  searchService(name: string): Promise<FastlyService>;
  getServiceDetail(serviceId: string, version?: number): Promise<FastlyServiceDetail>;
  listServices(page: number, perPage: number): Promise<FastlyService[]>;
  listServiceDomains(serviceId: string): Promise<FastlyDomain[]>;
  deleteService(serviceId: string): Promise<void>;
  // version
  listServiceVersions(serviceId: string): Promise<FastlyVersion[]>;
  cloneServiceVersion(serviceId: string, version: number): Promise<FastlyVersion>;
  updateServiceVersion(
    serviceId: string,
    version: number,
    patch: { comment: string },
  ): Promise<FastlyVersion>;
  validateServiceVersion(serviceId: string, version: number): Promise<{ status?: string }>;
  activateServiceVersion(serviceId: string, version: number): Promise<FastlyVersion>;
  deactivateServiceVersion(serviceId: string, version: number): Promise<FastlyVersion>;
  // backend / snippet / domain
  createBackend(
    serviceId: string,
    version: number,
    body: FastlyBackendBody,
  ): Promise<FastlyBackend>;
  getBackend(serviceId: string, version: number, name: string): Promise<FastlyBackend>;
  listBackends(serviceId: string, version: number): Promise<FastlyBackend[]>;
  createSnippet(
    serviceId: string,
    version: number,
    body: FastlySnippetBody,
  ): Promise<{ name: string; id?: string }>;
  getSnippet(serviceId: string, version: number, name: string): Promise<{ name: string }>;
  createDomain(
    serviceId: string,
    version: number,
    body: { name: string; comment?: string },
  ): Promise<FastlyDomain>;
  getDomain(serviceId: string, version: number, name: string): Promise<FastlyDomain>;
  deleteDomain(serviceId: string, version: number, name: string): Promise<void>;
  listDomains(serviceId: string, version: number): Promise<FastlyDomain[]>;
  checkDomain(serviceId: string, version: number, name: string): Promise<unknown[]>;
  // products
  enableWebsockets(serviceId: string): Promise<unknown>;
  getWebsockets(serviceId: string): Promise<unknown>;
  disableWebsockets(serviceId: string): Promise<void>;
  // tls
  createTlsSubscription(body: unknown): Promise<FastlyJsonApiDoc>;
  getTlsSubscription(id: string, include?: string): Promise<FastlyJsonApiDoc>;
  listTlsSubscriptionsForDomain(hostname: string): Promise<FastlyJsonApiCollection>;
  deleteTlsSubscription(id: string): Promise<void>;
  listTlsConfigurations(include?: string): Promise<FastlyJsonApiCollection>;
  // account
  getTokenCurrent(): Promise<FastlyTokenSelf>;
  getLoggedInCustomer(): Promise<FastlyCustomer>;
}

export interface FastlyBackendBody {
  name: string;
  address: string;
  use_ssl: boolean;
  override_host: string;
  comment: string;
}
export interface FastlySnippetBody {
  name: string;
  type: string;
  content: string;
  priority: string;
  dynamic: string;
}

/**
 * Build the typed API surface for one account. `basePath` (tests) overrides the
 * API origin for every call this object makes.
 */
export function fastlyApi(cfg: FastlyConfig, basePath?: string): FastlyApi {
  const client = newClient(cfg, basePath, []);
  const service = new ServiceApi(client);
  const version = new VersionApi(client);
  const backend = new BackendApi(client);
  const domain = new DomainApi(client);
  const snippet = new SnippetApi(client);
  const websockets = new ProductWebsocketsApi(client);
  const tlsSubs = new TlsSubscriptionsApi(client);
  const tlsConfigs = new TlsConfigurationsApi(client);
  const tokens = new TokensApi(client);
  const customer = new CustomerApi(client);
  /**
   * `deleteTlsSub` has no `force` option in the SDK, and a subscription with an
   * enabled domain cannot be destroyed without it. A dedicated client whose
   * plugin appends the query param keeps that concern out of every other call.
   */
  const forceDeleteSubs = new TlsSubscriptionsApi(
    newClient(cfg, basePath, [(request) => void request.query({ force: 'true' })]),
  );

  return {
    createService: (o) =>
      call('create-service', Service, () =>
        service.createServiceWithHttpInfo({ name: o.name, type: o.type, comment: o.comment }),
      ),
    searchService: (name) =>
      call('discover-service', Service, () => service.searchServiceWithHttpInfo({ name })),
    getServiceDetail: (serviceId, v) =>
      call('service-detail', ServiceDetail, () =>
        service.getServiceDetailWithHttpInfo({ service_id: serviceId, version: v }),
      ),
    listServices: (page, perPage) =>
      call('inventory-services', ServiceList, () =>
        service.listServicesWithHttpInfo({ page, per_page: perPage }),
      ),
    listServiceDomains: (serviceId) =>
      call('inventory-domains', DomainList, () =>
        service.listServiceDomainsWithHttpInfo({ service_id: serviceId }),
      ),
    deleteService: async (serviceId) => {
      await call('destroy-service', Empty, () =>
        service.deleteServiceWithHttpInfo({ service_id: serviceId }),
      );
    },

    listServiceVersions: (serviceId) =>
      call('list-versions', VersionList, () =>
        version.listServiceVersionsWithHttpInfo({ service_id: serviceId }),
      ),
    cloneServiceVersion: (serviceId, v) =>
      call('clone-version', Version, () =>
        version.cloneServiceVersionWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),
    updateServiceVersion: (serviceId, v, patch) =>
      call('mark-version', Version, () =>
        version.updateServiceVersionWithHttpInfo({
          service_id: serviceId,
          version_id: v,
          comment: patch.comment,
        }),
      ),
    validateServiceVersion: (serviceId, v) =>
      call('validate-version', VersionValidation, () =>
        version.validateServiceVersionWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),
    activateServiceVersion: (serviceId, v) =>
      call('activate-version', Version, () =>
        version.activateServiceVersionWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),
    deactivateServiceVersion: (serviceId, v) =>
      call('deactivate-version', Version, () =>
        version.deactivateServiceVersionWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),

    createBackend: (serviceId, v, body) =>
      call('create-backend', Backend, () =>
        backend.createBackendWithHttpInfo({ service_id: serviceId, version_id: v, ...body }),
      ),
    getBackend: (serviceId, v, name) =>
      call('discover-backend', Backend, () =>
        backend.getBackendWithHttpInfo({
          service_id: serviceId,
          version_id: v,
          backend_name: name,
        }),
      ),
    listBackends: (serviceId, v) =>
      call('list-backends', BackendList, () =>
        backend.listBackendsWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),

    createSnippet: (serviceId, v, body) =>
      call('create-snippet', Snippet, () =>
        snippet.createSnippetWithHttpInfo({ service_id: serviceId, version_id: v, ...body }),
      ),
    getSnippet: (serviceId, v, name) =>
      call('discover-snippet', Snippet, () =>
        snippet.getSnippetWithHttpInfo({ service_id: serviceId, version_id: v, name }),
      ),

    createDomain: (serviceId, v, body) =>
      call('create-domain', Domain, () =>
        domain.createDomainWithHttpInfo({ service_id: serviceId, version_id: v, ...body }),
      ),
    getDomain: (serviceId, v, name) =>
      call('discover-domain', Domain, () =>
        domain.getDomainWithHttpInfo({ service_id: serviceId, version_id: v, domain_name: name }),
      ),
    deleteDomain: async (serviceId, v, name) => {
      await call('remove-domain', Empty, () =>
        domain.deleteDomainWithHttpInfo({
          service_id: serviceId,
          version_id: v,
          domain_name: name,
        }),
      );
    },
    listDomains: (serviceId, v) =>
      call('list-domains', DomainList, () =>
        domain.listDomainsWithHttpInfo({ service_id: serviceId, version_id: v }),
      ),
    checkDomain: (serviceId, v, name) =>
      call('domain-check', DomainCheck, () =>
        domain.checkDomainWithHttpInfo({
          service_id: serviceId,
          version_id: v,
          domain_name: name,
        }),
      ),

    enableWebsockets: (serviceId) =>
      call('enable-websockets', WebsocketsProduct, () =>
        websockets.enableProductWebsocketsWithHttpInfo({ service_id: serviceId }),
      ),
    getWebsockets: (serviceId) =>
      call('discover-websockets', WebsocketsProduct, () =>
        websockets.getProductWebsocketsWithHttpInfo({ service_id: serviceId }),
      ),
    disableWebsockets: async (serviceId) => {
      await call('disable-websockets', Empty, () =>
        websockets.disableProductWebsocketsWithHttpInfo({ service_id: serviceId }),
      );
    },

    createTlsSubscription: (body) =>
      call('create-tls-subscription', JsonApiDoc, () =>
        tlsSubs.createTlsSubWithHttpInfo({ tls_subscription: body }),
      ),
    getTlsSubscription: (id, include) =>
      call('tls-subscription', JsonApiDoc, () =>
        tlsSubs.getTlsSubWithHttpInfo({ tls_subscription_id: id, include }),
      ),
    listTlsSubscriptionsForDomain: (hostname) =>
      call('discover-tls-subscription', JsonApiCollection, () =>
        tlsSubs.listTlsSubsWithHttpInfo({ filter_tls_domains_id: hostname, page_size: 20 }),
      ),
    deleteTlsSubscription: async (id) => {
      await call('destroy-tls-subscription', Empty, () =>
        forceDeleteSubs.deleteTlsSubWithHttpInfo({ tls_subscription_id: id }),
      );
    },
    listTlsConfigurations: (include) =>
      call(
        'tls-configurations',
        JsonApiCollection,
        () => tlsConfigs.listTlsConfigsWithHttpInfo({ include, page_size: 100 }),
        [cfg.apiToken],
      ),

    getTokenCurrent: () =>
      call('token-self', TokenSelf, () => tokens.getTokenCurrentWithHttpInfo({}), [cfg.apiToken]),
    getLoggedInCustomer: () =>
      call('customer', Customer, () => customer.getLoggedInCustomerWithHttpInfo({}), [
        cfg.apiToken,
      ]),
  };
}

let apiFactory: ((cfg: FastlyConfig) => FastlyApi) | null = null;
/** Test seam: replace the whole API surface (unit tests that never touch HTTP). */
export function __setFastlyApiFactory(f: ((cfg: FastlyConfig) => FastlyApi) | null): void {
  apiFactory = f;
}
export function fastlyApiFor(cfg: FastlyConfig): FastlyApi {
  return apiFactory ? apiFactory(cfg) : fastlyApi(cfg);
}
