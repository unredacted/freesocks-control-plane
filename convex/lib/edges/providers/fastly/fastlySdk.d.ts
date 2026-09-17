/**
 * Ambient typings for the official `fastly` JS SDK (16.1.0), which ships Babel
 * output with NO bundled `.d.ts`. Only the classes and the `*WithHttpInfo`
 * methods ./sdk.ts actually calls are declared: anything not listed here is a
 * call FCP does not make, and adding one is a deliberate wire-contract change.
 *
 * `*WithHttpInfo` (not the plain variants) on purpose: the plain methods return
 * the SDK's generated MODEL objects, which silently drop unknown fields and
 * coerce timestamps to `Date`. The HttpInfo variants hand back the superagent
 * response too, so ./sdk.ts validates the RAW JSON body with its own zod
 * schemas and never inherits the models' lossy shape.
 *
 * This file lives under convex/ so `tsc -p convex/tsconfig.json` (include
 * `./**\/*`) picks it up. The Convex bundler skips it: its entry-point walk
 * drops any basename containing more than one dot, so `fastlySdk.d.ts` is
 * never treated as a function module.
 */
declare module 'fastly' {
  /** The subset of a superagent response ./sdk.ts reads. */
  export interface FastlyResponse {
    status: number;
    body: unknown;
    text?: string;
  }
  /** What every `*WithHttpInfo` call resolves to. */
  export interface FastlyHttpInfo {
    /** The SDK's model object (lossy; ./sdk.ts ignores it). */
    data: unknown;
    response: FastlyResponse;
  }
  /**
   * A superagent plugin. `ApiClient.callApi` runs every plugin on the freshly
   * built request before it sets query params, so a plugin may rewrite the URL
   * (base-path override) or add query params the SDK has no option for.
   */
  export interface FastlyRequest {
    url: string;
    query(params: Record<string, string>): FastlyRequest;
  }
  export type FastlyPlugin = (request: FastlyRequest) => void;

  export class ApiClient {
    /** Default `https://api.fastly.com`. NOTE: every generated method passes its own base path, so this field alone does not redirect calls; ./sdk.ts uses a plugin. */
    basePath: string;
    /** Response timeout in ms (SDK default 60_000). */
    timeout: number;
    /** `false` appends a cache-busting `_` query param to every GET; keep it `true`. */
    cache: boolean;
    enableCookies: boolean;
    defaultHeaders: Record<string, string>;
    requestAgent: unknown;
    plugins: FastlyPlugin[] | null;
    /** Sets `authentications.token.apiKey`, sent as the `Fastly-Key` header. */
    authenticate(token: string, type?: string): void;
  }

  type Options = Record<string, unknown>;

  export class ServiceApi {
    constructor(apiClient: ApiClient);
    createServiceWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
    deleteServiceWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getServiceDetailWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    listServicesWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
    listServiceDomainsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    searchServiceWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class VersionApi {
    constructor(apiClient: ApiClient);
    activateServiceVersionWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    cloneServiceVersionWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    deactivateServiceVersionWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    listServiceVersionsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    updateServiceVersionWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    validateServiceVersionWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class BackendApi {
    constructor(apiClient: ApiClient);
    createBackendWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getBackendWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    listBackendsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class DomainApi {
    constructor(apiClient: ApiClient);
    checkDomainWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    createDomainWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    deleteDomainWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getDomainWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    listDomainsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class SnippetApi {
    constructor(apiClient: ApiClient);
    createSnippetWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getSnippetWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class ProductWebsocketsApi {
    constructor(apiClient: ApiClient);
    disableProductWebsocketsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    enableProductWebsocketsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getProductWebsocketsWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
  }

  export class TlsSubscriptionsApi {
    constructor(apiClient: ApiClient);
    createTlsSubWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
    deleteTlsSubWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    getTlsSubWithHttpInfo(options: Options): Promise<FastlyHttpInfo>;
    listTlsSubsWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
  }

  export class TlsConfigurationsApi {
    constructor(apiClient: ApiClient);
    listTlsConfigsWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
  }

  export class TokensApi {
    constructor(apiClient: ApiClient);
    getTokenCurrentWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
  }

  export class CustomerApi {
    constructor(apiClient: ApiClient);
    getLoggedInCustomerWithHttpInfo(options?: Options): Promise<FastlyHttpInfo>;
  }
}
