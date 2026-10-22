'use node';
/**
 * Typed, body-free wrapper over the official AWS SDK v3 clients the CloudFront
 * adapter drives: `@aws-sdk/client-cloudfront` (distributions, origin request
 * policies) and `@aws-sdk/client-acm` (the viewer certificate), both 3.1063.0.
 *
 * Why a wrapper rather than the SDK directly:
 *  - The adapter (and its tests' fake) see ONE small interface (`CloudFrontApi`)
 *    with plain records, never the SDK's command objects, so an unlisted call
 *    cannot be made by accident and the wire contract stays reviewable here.
 *  - Errors: an SDK `ServiceException` carries the provider's message (which can
 *    echo request values, an alias or an origin name) and the raw response.
 *    Nothing from them reaches an `EdgeProviderError` except the HTTP status and
 *    the exception NAME as a snake_case code (`NoSuchDistribution` ->
 *    `no_such_distribution`): AWS error names are fixed identifiers, never
 *    values. The message is only held aside as a refusal (`http.ts`), redacted.
 *  - No retries: `maxAttempts: 1`, so an unknown outcome is resolved by
 *    discovery, never by the SDK replaying an allocating call.
 *
 * Pinned on purpose: the credentials are ALWAYS the account's static key pair
 * (never the SDK's default provider chain, which would read the backend's own
 * environment or instance role), the region is `us-east-1` (CloudFront takes
 * viewer certificates from ACM there only, and its own API is global), and the
 * endpoints are the two public API hosts, so an `AWS_ENDPOINT_URL*` variable in
 * the backend's environment can never send a signed request elsewhere. The
 * SDK's Node handler follows no redirects. Tests point both clients at an
 * in-process recorder (`__setCloudFrontEndpoint`) or replace the whole API
 * with a fake (`__setCloudFrontApiFactory`).
 */
import {
  ACMClient,
  DeleteCertificateCommand,
  DescribeCertificateCommand,
  ListCertificatesCommand,
  RequestCertificateCommand,
  type CertificateDetail,
  type CertificateSummary,
  type KeyAlgorithm,
} from '@aws-sdk/client-acm';
import {
  CloudFrontClient,
  CreateDistributionCommand,
  CreateOriginRequestPolicyCommand,
  DeleteDistributionCommand,
  GetDistributionCommand,
  GetDistributionConfigCommand,
  ListDistributionsByOriginRequestPolicyIdCommand,
  ListDistributionsCommand,
  ListOriginRequestPoliciesCommand,
  UpdateDistributionCommand,
  type Distribution,
  type DistributionConfig,
  type DistributionSummary,
  type OriginRequestPolicy,
  type OriginRequestPolicyConfig,
} from '@aws-sdk/client-cloudfront';
import { EdgeProviderError, refusalOf, toProviderError, withRefusal } from '../http';
import type { CloudFrontConfig } from '../types';

export type { DistributionConfig, OriginRequestPolicyConfig } from '@aws-sdk/client-cloudfront';

/** CloudFront takes viewer certificates from ACM in this region only; its own API is global. */
export const CLOUDFRONT_REGION = 'us-east-1';
/** The two API hosts every call goes to (the redirect and environment pin, see above). */
export const CLOUDFRONT_API_ORIGIN = 'https://cloudfront.amazonaws.com';
export const ACM_API_ORIGIN = `https://acm.${CLOUDFRONT_REGION}.amazonaws.com`;
/** Every call is a small object or one bounded page. */
export const CLOUDFRONT_TIMEOUT_MS = 15_000;
const CONNECT_TIMEOUT_MS = 5_000;
/** Listings are read in bounded pages (inventory, discovery by comment, certificate lookup). */
const PAGE_SIZE = 100;
const MAX_PAGES = 10;
/** Every key type ACM issues: its listing otherwise returns RSA 2048 certificates only. */
const ALL_KEY_TYPES: KeyAlgorithm[] = [
  'RSA_1024',
  'RSA_2048',
  'RSA_3072',
  'RSA_4096',
  'EC_prime256v1',
  'EC_secp384r1',
  'EC_secp521r1',
];

// --- the records the adapter sees ------------------------------------------------------

export interface AcmCertificateSummary {
  arn: string;
  domainName: string;
  status?: string;
  /** `AMAZON_ISSUED`, `IMPORTED`, `PRIVATE`. */
  type?: string;
  /** Set when another service (CloudFront's own multi-tenant certificates) manages it. */
  managedBy?: string;
  inUse?: boolean;
  notAfter?: string;
}

/** The DNS record ACM validates one name with (a CNAME, the same for `zone` and `*.zone`). */
export interface AcmValidationRecord {
  name: string;
  type: string;
  value: string;
}

export interface AcmCertificate extends AcmCertificateSummary {
  /** Every name the certificate covers (ACM lists the domain name among them). */
  subjectAlternativeNames: string[];
  /** Why issuance failed (`CAA_ERROR`, `NO_AVAILABLE_CONTACTS`, ...): an identifier, never text. */
  failureReason?: string;
  /** `PENDING_AUTO_RENEWAL`, `PENDING_VALIDATION`, `SUCCESS`, `FAILED` while a renewal runs. */
  renewalStatus?: string;
  /** The ARNs of what uses it (distributions). */
  inUseBy: string[];
  validationRecords: AcmValidationRecord[];
}

export interface CloudFrontOrigin {
  id: string;
  domainName: string;
  httpPort?: number;
  httpsPort?: number;
  protocolPolicy?: string;
}

export interface CloudFrontDistribution {
  id: string;
  arn?: string;
  /** `InProgress` while a change propagates, `Deployed` once every edge has it. */
  status?: string;
  /** `dXXXX.cloudfront.net`: what the front's traffic name points at. */
  domainName: string;
  enabled: boolean;
  comment?: string;
  aliases: string[];
  origins: CloudFrontOrigin[];
  originRequestPolicyId?: string;
  cachePolicyId?: string;
  certificateArn?: string;
  /** The version a conditional update or delete must name (`IfMatch`); single reads only. */
  etag?: string;
  lastModified?: string;
}

export interface CloudFrontOriginRequestPolicy {
  id: string;
  name: string;
  comment?: string;
  headerBehavior?: string;
  headers: string[];
  /** `none`, `whitelist`, `all`: the cookies the policy forwards. */
  cookieBehavior?: string;
  /** `none`, `whitelist`, `allExcept`, `all`: the query strings it forwards. */
  queryStringBehavior?: string;
}

export interface CloudFrontApi {
  // ACM (us-east-1)
  requestCertificate(o: { domainName: string; idempotencyToken: string }): Promise<string>;
  describeCertificate(arn: string): Promise<AcmCertificate>;
  /** Every certificate the key can list (bounded pages; `truncated` when more exist). */
  listCertificates(): Promise<{ items: AcmCertificateSummary[]; truncated: boolean }>;
  deleteCertificate(arn: string): Promise<void>;
  // CloudFront
  createDistribution(config: DistributionConfig): Promise<CloudFrontDistribution>;
  getDistribution(id: string): Promise<CloudFrontDistribution>;
  getDistributionConfig(id: string): Promise<{ config: DistributionConfig; etag: string }>;
  updateDistribution(
    id: string,
    config: DistributionConfig,
    ifMatch: string,
  ): Promise<CloudFrontDistribution>;
  deleteDistribution(id: string, ifMatch: string): Promise<void>;
  /** Every distribution of the account (bounded pages; `truncated` when more exist). */
  listDistributions(): Promise<{ items: CloudFrontDistribution[]; truncated: boolean }>;
  /** The account's own (custom) origin request policies. */
  listOriginRequestPolicies(): Promise<CloudFrontOriginRequestPolicy[]>;
  createOriginRequestPolicy(
    config: OriginRequestPolicyConfig,
  ): Promise<CloudFrontOriginRequestPolicy>;
  /** How many distributions use one policy (CloudFront allows 100 per policy). */
  countDistributionsOfPolicy(id: string): Promise<number>;
}

// --- errors ----------------------------------------------------------------------------------

/** `CNAMEAlreadyExists` -> `cname_already_exists`; anything that is not a bare identifier -> undefined. */
export function awsErrorCode(name: unknown): string | undefined {
  if (typeof name !== 'string' || !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name)) return undefined;
  if (name === 'Error') return undefined;
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase();
}

interface SdkError {
  name?: unknown;
  message?: unknown;
  code?: unknown;
  $metadata?: { httpStatusCode?: unknown };
}

/** SDK rejection -> body-free `EdgeProviderError` (status + the exception name only). */
export function toCloudFrontError(
  step: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const e = (err ?? {}) as SdkError;
  const status =
    typeof e.$metadata?.httpStatusCode === 'number' ? e.$metadata.httpStatusCode : undefined;
  const timedOut =
    e.name === 'TimeoutError' ||
    e.name === 'AbortError' ||
    e.code === 'ETIMEDOUT' ||
    e.code === 'ECONNABORTED';
  // The generic reducer keeps the status, a timeout and the refusal's words
  // (redacted, held aside); the code is the exception name, made snake_case.
  const base = toProviderError(
    'cloudfront',
    step,
    {
      status,
      name: timedOut ? 'TimeoutError' : 'Error',
      message: typeof e.message === 'string' ? e.message : '',
    },
    secrets,
  );
  const code = awsErrorCode(e.name);
  if (!code || timedOut) return base;
  const out = new EdgeProviderError(`cloudfront ${status ?? 'error'} on ${step} (${code})`, {
    ...base.meta,
    code,
  });
  // The refusal's words the reducer held aside travel with the re-coded error.
  return out.meta.detail ? out : withRefusal(out, refusalOf(base));
}

/** Not there: CloudFront answers 404, ACM a 400 named `ResourceNotFoundException`. */
export function isCloudFrontNotFound(err: unknown): boolean {
  if (!(err instanceof EdgeProviderError)) return false;
  if (err.meta.status === 404) return true;
  return (
    err.meta.code === 'resource_not_found_exception' ||
    err.meta.code === 'no_such_distribution' ||
    err.meta.code === 'no_such_origin_request_policy'
  );
}

/** The provider's answer carried this exception name (snake_case). */
export function isCloudFrontCode(err: unknown, code: string): boolean {
  return err instanceof EdgeProviderError && err.meta.code === code;
}

// --- record readers (pure) -------------------------------------------------------------------

const iso = (d: Date | undefined): string | undefined =>
  d instanceof Date && Number.isFinite(d.getTime()) ? d.toISOString() : undefined;

function summaryOf(c: CertificateSummary | CertificateDetail): AcmCertificateSummary {
  return {
    arn: c.CertificateArn ?? '',
    domainName: c.DomainName ?? '',
    ...(c.Status ? { status: c.Status } : {}),
    ...(c.Type ? { type: c.Type } : {}),
    ...(c.ManagedBy ? { managedBy: c.ManagedBy } : {}),
    ...('InUse' in c && typeof c.InUse === 'boolean' ? { inUse: c.InUse } : {}),
    ...(iso(c.NotAfter) ? { notAfter: iso(c.NotAfter) } : {}),
  };
}

export function certificateOf(c: CertificateDetail): AcmCertificate {
  const records: AcmValidationRecord[] = [];
  for (const o of [
    ...(c.DomainValidationOptions ?? []),
    ...(c.RenewalSummary?.DomainValidationOptions ?? []),
  ]) {
    const r = o.ResourceRecord;
    if (!r?.Name || !r.Value) continue;
    if (records.some((x) => x.name === r.Name && x.value === r.Value)) continue;
    records.push({ name: r.Name, type: r.Type ?? 'CNAME', value: r.Value });
  }
  return {
    ...summaryOf(c),
    subjectAlternativeNames: [...(c.SubjectAlternativeNames ?? [])],
    inUse: (c.InUseBy ?? []).length > 0,
    ...(c.FailureReason ? { failureReason: c.FailureReason } : {}),
    ...(c.RenewalSummary?.RenewalStatus ? { renewalStatus: c.RenewalSummary.RenewalStatus } : {}),
    inUseBy: [...(c.InUseBy ?? [])],
    validationRecords: records,
  };
}

/** One distribution (a full read, a create's answer or a listing's summary) as the adapter reads it. */
export function distributionOf(
  d: Distribution | DistributionSummary,
  etag?: string,
): CloudFrontDistribution {
  const cfg: Partial<DistributionConfig> & Partial<DistributionSummary> =
    'DistributionConfig' in d && d.DistributionConfig
      ? d.DistributionConfig
      : (d as DistributionSummary);
  const origins = (cfg.Origins?.Items ?? []).map((o) => ({
    id: o.Id ?? '',
    domainName: o.DomainName ?? '',
    ...(o.CustomOriginConfig?.HTTPPort !== undefined
      ? { httpPort: o.CustomOriginConfig.HTTPPort }
      : {}),
    ...(o.CustomOriginConfig?.HTTPSPort !== undefined
      ? { httpsPort: o.CustomOriginConfig.HTTPSPort }
      : {}),
    ...(o.CustomOriginConfig?.OriginProtocolPolicy
      ? { protocolPolicy: o.CustomOriginConfig.OriginProtocolPolicy }
      : {}),
  }));
  return {
    id: d.Id ?? '',
    ...(d.ARN ? { arn: d.ARN } : {}),
    ...(d.Status ? { status: d.Status } : {}),
    domainName: d.DomainName ?? '',
    enabled: cfg.Enabled === true,
    ...(cfg.Comment ? { comment: cfg.Comment } : {}),
    aliases: [...(cfg.Aliases?.Items ?? [])],
    origins,
    ...(cfg.DefaultCacheBehavior?.OriginRequestPolicyId
      ? { originRequestPolicyId: cfg.DefaultCacheBehavior.OriginRequestPolicyId }
      : {}),
    ...(cfg.DefaultCacheBehavior?.CachePolicyId
      ? { cachePolicyId: cfg.DefaultCacheBehavior.CachePolicyId }
      : {}),
    ...(cfg.ViewerCertificate?.ACMCertificateArn
      ? { certificateArn: cfg.ViewerCertificate.ACMCertificateArn }
      : {}),
    ...(etag ? { etag } : {}),
    ...(iso(d.LastModifiedTime) ? { lastModified: iso(d.LastModifiedTime) } : {}),
  };
}

function policyOf(p: OriginRequestPolicy): CloudFrontOriginRequestPolicy {
  const c = p.OriginRequestPolicyConfig;
  return {
    id: p.Id ?? '',
    name: c?.Name ?? '',
    ...(c?.Comment ? { comment: c.Comment } : {}),
    ...(c?.HeadersConfig?.HeaderBehavior ? { headerBehavior: c.HeadersConfig.HeaderBehavior } : {}),
    headers: [...(c?.HeadersConfig?.Headers?.Items ?? [])],
    ...(c?.CookiesConfig?.CookieBehavior ? { cookieBehavior: c.CookiesConfig.CookieBehavior } : {}),
    ...(c?.QueryStringsConfig?.QueryStringBehavior
      ? { queryStringBehavior: c.QueryStringsConfig.QueryStringBehavior }
      : {}),
  };
}

// --- client construction ---------------------------------------------------------------------

/** Test seam: point both real SDK clients at an in-process recorder instead of the API hosts. */
let endpointOverride: string | null = null;
export function __setCloudFrontEndpoint(url: string | null): void {
  endpointOverride = url;
}

type ApiFactory = (cfg: CloudFrontConfig, diagnostic?: string) => CloudFrontApi;
/** Test seam: replace the whole API (the adapter tests' fake AWS account). */
let apiFactory: ApiFactory | null = null;
export function __setCloudFrontApiFactory(f: ApiFactory | null): void {
  apiFactory = f;
}

function clientConfig(cfg: CloudFrontConfig, origin: string) {
  return {
    region: CLOUDFRONT_REGION,
    endpoint: endpointOverride ?? origin,
    credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
    maxAttempts: 1,
    requestHandler: {
      requestTimeout: CLOUDFRONT_TIMEOUT_MS,
      connectionTimeout: CONNECT_TIMEOUT_MS,
    },
  };
}

/**
 * The API for one account. `diagnostic`: the step name every call reports
 * (`test`, `location`), so a refusal behind "Test credentials" keeps the
 * provider's redacted words for the admin (http.ts `DIAGNOSTIC_STEPS`).
 */
export function cloudFrontApiFor(cfg: CloudFrontConfig, diagnostic?: string): CloudFrontApi {
  if (apiFactory) return apiFactory(cfg, diagnostic);
  return cloudFrontSdkApi(cfg, diagnostic);
}

export function cloudFrontSdkApi(cfg: CloudFrontConfig, diagnostic?: string): CloudFrontApi {
  const acm = new ACMClient(clientConfig(cfg, ACM_API_ORIGIN));
  const cf = new CloudFrontClient(clientConfig(cfg, CLOUDFRONT_API_ORIGIN));
  const secrets = [cfg.secretAccessKey];
  async function call<T>(step: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      throw toCloudFrontError(diagnostic ?? step, e, secrets);
    }
  }
  const missing = (step: string, what: string): EdgeProviderError =>
    new EdgeProviderError(`cloudfront schema mismatch on ${step} [${what}]`, {
      provider: 'cloudfront',
      step: diagnostic ?? step,
      code: 'schema_mismatch',
      retryable: false,
      timedOut: false,
    });

  return {
    async requestCertificate(o) {
      const out = await call('acm-request', () =>
        acm.send(
          new RequestCertificateCommand({
            DomainName: o.domainName,
            ValidationMethod: 'DNS',
            IdempotencyToken: o.idempotencyToken,
          }),
        ),
      );
      if (!out.CertificateArn) throw missing('acm-request', 'CertificateArn');
      return out.CertificateArn;
    },
    async describeCertificate(arn) {
      const out = await call('acm-describe', () =>
        acm.send(new DescribeCertificateCommand({ CertificateArn: arn })),
      );
      if (!out.Certificate) throw missing('acm-describe', 'Certificate');
      return certificateOf(out.Certificate);
    },
    async listCertificates() {
      const items: AcmCertificateSummary[] = [];
      let token: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await call('acm-list', () =>
          acm.send(
            new ListCertificatesCommand({
              Includes: { keyTypes: ALL_KEY_TYPES },
              MaxItems: PAGE_SIZE,
              ...(token ? { NextToken: token } : {}),
            }),
          ),
        );
        items.push(...(out.CertificateSummaryList ?? []).map(summaryOf));
        token = out.NextToken;
        if (!token) return { items, truncated: false };
      }
      return { items, truncated: true };
    },
    async deleteCertificate(arn) {
      await call('acm-delete', () =>
        acm.send(new DeleteCertificateCommand({ CertificateArn: arn })),
      );
    },
    async createDistribution(config) {
      const out = await call('distribution-create', () =>
        cf.send(new CreateDistributionCommand({ DistributionConfig: config })),
      );
      if (!out.Distribution?.Id) throw missing('distribution-create', 'Distribution.Id');
      return distributionOf(out.Distribution, out.ETag);
    },
    async getDistribution(id) {
      const out = await call('distribution-get', () =>
        cf.send(new GetDistributionCommand({ Id: id })),
      );
      if (!out.Distribution?.Id) throw missing('distribution-get', 'Distribution.Id');
      return distributionOf(out.Distribution, out.ETag);
    },
    async getDistributionConfig(id) {
      const out = await call('distribution-config', () =>
        cf.send(new GetDistributionConfigCommand({ Id: id })),
      );
      if (!out.DistributionConfig || !out.ETag)
        throw missing('distribution-config', 'DistributionConfig');
      return { config: out.DistributionConfig, etag: out.ETag };
    },
    async updateDistribution(id, config, ifMatch) {
      const out = await call('distribution-update', () =>
        cf.send(
          new UpdateDistributionCommand({ Id: id, DistributionConfig: config, IfMatch: ifMatch }),
        ),
      );
      if (!out.Distribution?.Id) throw missing('distribution-update', 'Distribution.Id');
      return distributionOf(out.Distribution, out.ETag);
    },
    async deleteDistribution(id, ifMatch) {
      await call('distribution-delete', () =>
        cf.send(new DeleteDistributionCommand({ Id: id, IfMatch: ifMatch })),
      );
    },
    async listDistributions() {
      const items: CloudFrontDistribution[] = [];
      let marker: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await call('distribution-list', () =>
          cf.send(
            new ListDistributionsCommand({
              MaxItems: PAGE_SIZE,
              ...(marker ? { Marker: marker } : {}),
            }),
          ),
        );
        const list = out.DistributionList;
        items.push(...(list?.Items ?? []).map((d) => distributionOf(d)));
        marker = list?.IsTruncated ? list.NextMarker : undefined;
        if (!marker) return { items, truncated: false };
      }
      return { items, truncated: true };
    },
    async listOriginRequestPolicies() {
      const items: CloudFrontOriginRequestPolicy[] = [];
      let marker: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await call('policy-list', () =>
          cf.send(
            new ListOriginRequestPoliciesCommand({
              Type: 'custom',
              MaxItems: PAGE_SIZE,
              ...(marker ? { Marker: marker } : {}),
            }),
          ),
        );
        const list = out.OriginRequestPolicyList;
        for (const s of list?.Items ?? [])
          if (s.OriginRequestPolicy) items.push(policyOf(s.OriginRequestPolicy));
        marker = list?.NextMarker;
        if (!marker) break;
      }
      return items;
    },
    async createOriginRequestPolicy(config) {
      const out = await call('policy-create', () =>
        cf.send(new CreateOriginRequestPolicyCommand({ OriginRequestPolicyConfig: config })),
      );
      if (!out.OriginRequestPolicy?.Id) throw missing('policy-create', 'OriginRequestPolicy.Id');
      return policyOf(out.OriginRequestPolicy);
    },
    async countDistributionsOfPolicy(id) {
      let count = 0;
      let marker: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await call('policy-distributions', () =>
          cf.send(
            new ListDistributionsByOriginRequestPolicyIdCommand({
              OriginRequestPolicyId: id,
              MaxItems: PAGE_SIZE,
              ...(marker ? { Marker: marker } : {}),
            }),
          ),
        );
        const list = out.DistributionIdList;
        count += list?.Items?.length ?? 0;
        marker = list?.IsTruncated ? list.NextMarker : undefined;
        if (!marker) break;
      }
      return count;
    },
  };
}
