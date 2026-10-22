'use node';
/**
 * Amazon CloudFront L7 (CDN) edge adapter: one hostname fronted by one
 * distribution in front of one WebSocket origin.
 *
 * Model. A provisioned edge is six steps:
 *  1. `create_tls_subscription`: the zone's ACM certificate for `*.<zone>`,
 *     requested in us-east-1 (the only region CloudFront takes viewer
 *     certificates from), ONE per account and zone: the first front requests
 *     it, every later one finds it by name and reuses it. Recorded as `shared`,
 *     so no edge's destroy deletes it (Fastly's wildcard model, docs/edges.md
 *     § "L7 edges"). A front's own name never reaches the CT logs.
 *  2. `create_dns_acme`: ACM's validation CNAME (one record covers `zone` and
 *     `*.zone`, and stays for renewals), written into the referenced DNS
 *     account's zone through the `DnsClient`, commented
 *     `fcp-cert:<aws account>:<certificate id>`.
 *  3. `await_tls`: wait for `ISSUED` (CloudFront refuses a pending certificate).
 *  4. `create_service`: the distribution. The same step finds or creates the
 *     account's shared origin request policy (below), under the account's
 *     policy lock (`cloudfront-policy:<account>`), so counting a policy's
 *     distributions and attaching one more never race.
 *  5. `activate_version`: wait for the distribution to be `Deployed`.
 *  6. `create_dns_record`: the traffic CNAME `<front> -> dXXXX.cloudfront.net`.
 *
 * The member's address. CloudFront ALWAYS adds `X-Forwarded-For` with the
 * member's address to an origin request (appending to one the client sent),
 * and no policy can remove it; it removes `X-Real-IP` itself. Everything else
 * an origin request carries is what the origin request policy forwards: FCP's
 * policy is a WHITELIST of the WebSocket handshake headers only
 * (`CLOUDFRONT_WEBSOCKET_HEADERS`), so `CloudFront-Viewer-Address`, the
 * geolocation and TLS fingerprint headers, and any address header a client
 * forged (`True-Client-IP`, `Forwarded`, ...) never reach the node. With
 * `forwardClientAddress` on, a second policy also forwards
 * `CloudFront-Viewer-Address`. CloudFront also always sends `X-Amz-Cf-Id` (a
 * request id), `Via`, `User-Agent: Amazon CloudFront` and `Host` (the origin's
 * own name: Host is never forwarded, since the front would then check the
 * origin's certificate against the front name). The node role's Caddy removes
 * `X-Forwarded-For` before Xray; both layers stay.
 *
 * Policies. CloudFront allows 20 custom origin request policies per account
 * and 100 distributions per policy, so the policy is shared: `fcp-ws-<n>` (or
 * `fcp-ws-address-<n>`), the first one with room and the expected headers, a
 * new one when all are full. Recorded as `shared`; only an operator removes one.
 *
 * Idempotency. A distribution is created with `CallerReference` = the edge's
 * name: a repeated create answers `DistributionAlreadyExists`, the proof of an
 * earlier one, which is then found by its `Comment` (also the edge's name). A
 * certificate request carries an `IdempotencyToken` derived from the edge's
 * name and the certificate name: repeated within an hour, ACM answers the same
 * certificate. A lost response is therefore resolved by a read, and even a
 * re-run never creates a second object.
 *
 * Teardown. The traffic record first, then the distribution: disabled
 * (`UpdateDistribution` with `Enabled: false` and the `ETag`), read back until
 * `Deployed` (minutes), then deleted with the new `ETag`. The shared
 * certificate, its validation record and the policy stay.
 *
 * WebSocket limits. HTTP/1.1 only between members and the front (a client that
 * agrees on HTTP/2 cannot upgrade, hence `viewerHttpVersion: http1.1` by
 * default), and an open WebSocket closes after 10 minutes without bytes from
 * the origin: the node keeps a quiet tunnel open with a server-side heartbeat.
 *
 * Errors. ./cloudfront/sdk.ts reduces every SDK error to a status and the
 * exception's name; nothing here adds a body, a URL or a credential.
 */
import type {
  AdoptionInspection,
  ChildResource,
  CloudFrontConfig,
  CloudflareDnsConfig,
  CredentialTestResult,
  Discovery,
  EdgeDescription,
  EdgeProvider,
  EdgeReadiness,
  EdgeSpec,
  InspectResult,
  Inventory,
  Ledger,
  LedgerResource,
  LocationCheckResult,
  ReadinessState,
  ResourceStep,
  SharedCertificateStatus,
  StepOutcome,
} from './types';
import { firstResource, metaOf, resourcesOfKind } from './types';
import { EdgeProviderError, credentialTestFailure, refusalOf } from './http';
import { normalizeZoneName } from '../hostname';
import { addressFamily } from '../ip';
import { certCovers } from '../layers';
import { checkCaa, wildcardNameFor, type CaaLookup } from '../caa';
import { dnsCaaLookup } from './dns/caaLookup';
import type { L7CertificateCode } from '../../../../src/shared/contracts/edgeCodes';
import type { DnsClient, DnsCreateArgs, DnsRecord } from './dns/types';
import { originPortDialable } from './capabilities';
import {
  cloudFrontApiFor,
  isCloudFrontCode,
  isCloudFrontNotFound,
  type AcmCertificate,
  type AcmCertificateSummary,
  type CloudFrontApi,
  type CloudFrontDistribution,
  type CloudFrontOriginRequestPolicy,
  type DistributionConfig,
  type OriginRequestPolicyConfig,
} from './cloudfront/sdk';
import {
  CloudFrontTemplate,
  CLOUDFRONT_TEMPLATE_FIELDS,
  type CloudFrontTemplateParams,
} from './templates';
import { deepMerge, defaultsOf } from './options';

export { CloudFrontTemplate, CLOUDFRONT_TEMPLATE_FIELDS } from './templates';
export type { CloudFrontTemplateParams } from './templates';

/** The managed `CachingDisabled` cache policy (a tunnel is never cached). */
export const CLOUDFRONT_CACHING_DISABLED_POLICY_ID = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad';
/** The certificate authority CAA is checked for (lib/edges/caa.ts: ACM's four domains). */
export const CLOUDFRONT_CERTIFICATE_AUTHORITY = 'amazon';
const ORIGIN_ID = 'origin';
/** CloudFront allows 100 distributions per origin request policy and 20 custom policies per account. */
export const CLOUDFRONT_DISTRIBUTIONS_PER_POLICY = 100;
const MAX_POLICIES = 20;

/**
 * The request headers FCP's origin request policy forwards: the WebSocket
 * handshake (CloudFront's WebSocket guide needs `Sec-WebSocket-Key` and
 * `Sec-WebSocket-Version` and recommends the other three). None carries an
 * address.
 * Source: docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.websockets.html, 2026-10-22.
 */
export const CLOUDFRONT_WEBSOCKET_HEADERS = [
  'Sec-WebSocket-Key',
  'Sec-WebSocket-Version',
  'Sec-WebSocket-Protocol',
  'Sec-WebSocket-Accept',
  'Sec-WebSocket-Extensions',
] as const;

/** The viewer-address header a policy forwards only with `forwardClientAddress` on. */
export const CLOUDFRONT_VIEWER_ADDRESS_HEADER = 'CloudFront-Viewer-Address';

/**
 * What CloudFront adds to EVERY origin request whatever the policy says:
 * `X-Forwarded-For` carries the member's address and cannot be removed by any
 * policy; the rest carry none.
 * Source: docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html, 2026-10-22.
 */
export const CLOUDFRONT_ALWAYS_SENT = [
  'X-Forwarded-For',
  'X-Amz-Cf-Id',
  'Via',
  'User-Agent',
  'Host',
] as const;

// --- DNS client and CAA injection -----------------------------------------------------------

type DnsClientFactory = (cfg: CloudflareDnsConfig) => DnsClient | Promise<DnsClient>;
let dnsFactory: DnsClientFactory | null = null;
/** Test seam: an in-memory DnsClient, so these tests never load the Cloudflare SDK. */
export function __setCloudFrontDnsClientFactory(f: DnsClientFactory | null): void {
  dnsFactory = f;
}

/** The DNS writer for this edge's records (the Cloudflare client, imported lazily). */
async function dnsClientFor(cfg: CloudFrontConfig): Promise<DnsClient> {
  const dns = cfg.dns;
  if (!dns)
    throw refusal('dns', 'dns_account_missing', 'the referenced DNS account is not resolved');
  if (dnsFactory) return await dnsFactory(dns);
  const mod = await import('./dns/cloudflareDns');
  return mod.cloudflareDnsClient(dns);
}

let caaLookupOverride: CaaLookup | null = null;
/** Test seam: answer CAA lookups from a table (the offline suite refuses real DNS). */
export function __setCloudFrontCaaLookup(f: CaaLookup | null): void {
  caaLookupOverride = f;
}

// --- small helpers ---------------------------------------------------------------------------

function refusal(step: string, code: string, why: string, retryable = false): EdgeProviderError {
  return new EdgeProviderError(`cloudfront ${step}: ${why}`, {
    provider: 'cloudfront',
    step,
    code,
    retryable,
    timedOut: false,
  });
}

function ledgerIncomplete(step: string): EdgeProviderError {
  return refusal(step, 'ledger_incomplete', 'the ledger is missing a prerequisite resource');
}

const sameDnsName = (a: string, b: string) =>
  a.trim().toLowerCase().replace(/\.$/, '') === b.trim().toLowerCase().replace(/\.$/, '');

/** The DNS zone this account's fronts live in, as the resolved config carries it. */
export function cloudFrontZoneOf(cfg: CloudFrontConfig): string | undefined {
  return cfg.dns?.zoneName ? normalizeZoneName(cfg.dns.zoneName) : undefined;
}

function requireHostname(spec: EdgeSpec, step: string): string {
  if (!spec.hostname) throw refusal(step, 'hostname_missing', 'the spec carries no hostname');
  return spec.hostname;
}

function originMember(spec: EdgeSpec, step: string): { address: string; port: number } {
  const m = spec.listeners[0]?.members[0];
  if (!m) throw refusal(step, 'spec_invalid', 'the spec has no origin member');
  return m;
}

/** The options a distribution is always built with: each one's declared default when unset. */
type EffectiveCloudFrontParams = CloudFrontTemplateParams &
  Required<
    Pick<
      CloudFrontTemplateParams,
      | 'priceClass'
      | 'ipv6'
      | 'viewerHttpVersion'
      | 'viewerMinTlsVersion'
      | 'originMinTlsVersion'
      | 'originConnectTimeoutS'
      | 'originConnectAttempts'
      | 'originReadTimeoutS'
      | 'originKeepaliveTimeoutS'
    >
  >;

/** The template with every option the operator left unset at its declared default. */
export function effectiveCloudFrontParams(
  tpl: Partial<CloudFrontTemplateParams>,
): EffectiveCloudFrontParams {
  return deepMerge(defaultsOf(CLOUDFRONT_TEMPLATE_FIELDS), tpl) as EffectiveCloudFrontParams;
}

/**
 * The origin refusals CloudFront forces, before any call: the origin is a DNS
 * name (never an IP address), on 80, 443 or 1024-65535, and over TLS presents
 * a publicly trusted certificate for that name (CloudFront drops a self-signed
 * or mismatched one).
 */
export function assertCloudFrontOriginTransport(spec: EdgeSpec, step = 'plan'): void {
  const t = spec.originTransport;
  if (!t) throw refusal(step, 'origin_transport_missing', 'the slot declares no origin transport');
  const { address, port } = originMember(spec, step);
  if (addressFamily(address) !== null)
    throw refusal(
      step,
      'origin_not_a_name',
      'this front dials its origin by name, never by address',
    );
  if (!originPortDialable('cloudfront', port))
    throw refusal(
      step,
      'origin_port_unsupported',
      'the origin must listen on 80, 443 or 1024-65535',
    );
  if (t.scheme === 'https') {
    if (!t.certPublic)
      throw refusal(
        step,
        'origin_cert_not_public',
        'an https origin behind this front needs a publicly trusted certificate',
      );
    if (!certCovers(address, t.certNames))
      throw refusal(
        step,
        'origin_cert_name_uncovered',
        'an https origin behind this front must be addressed by a name its certificate covers',
      );
  }
}

/** The fronted hostname as the LEDGER knows it (describe/destroy get no spec). */
export function cloudFrontHostnameOf(ledger: Ledger): string | undefined {
  const h = metaOf(firstResource(ledger, 'distribution')).hostname;
  if (typeof h === 'string') return h;
  for (const r of resourcesOfKind(ledger, 'dns_record')) {
    const meta = metaOf(r);
    if (meta.role === 'traffic' && typeof meta.name === 'string') return meta.name;
  }
  return undefined;
}

/** The distribution the edge owns (never a candidate discovery could not prove is its own). */
function ownDistributionOf(ledger: Ledger): LedgerResource | undefined {
  return resourcesOfKind(ledger, 'distribution').find((r) => metaOf(r).candidate !== true);
}

/** A resource discovery saw but cannot prove is this edge's: recorded, never destroyed. */
function candidateOf(r: ChildResource): ChildResource {
  return { ...r, ownership: 'adopted', meta: { ...(r.meta ?? {}), candidate: true } };
}

/** FNV-1a 64-bit as 16 hex chars: a short deterministic token. */
function fnv1a64Hex(input: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

/**
 * ACM's idempotency token for one edge's certificate request (`\w{1,32}`):
 * the same request within an hour answers the same certificate.
 */
export function certificateIdempotencyToken(edgeName: string, certificateName: string): string {
  return `fcp${fnv1a64Hex(`${edgeName}|${certificateName}`)}`;
}

/** `arn:aws:acm:us-east-1:<account>:certificate/<id>` -> its account and id. */
export function acmArnParts(arn: string): { account: string; id: string } | null {
  const m = /^arn:aws[a-z-]*:acm:[a-z0-9-]+:(\d{12}):certificate\/([A-Za-z0-9-]+)$/.exec(arn);
  return m ? { account: m[1]!, id: m[2]! } : null;
}

/**
 * The ownership marker of the shared certificate's validation record: the AWS
 * account and the certificate it was written for. ACM gives one account the
 * SAME record for every certificate of one name, so a record whose marker
 * names this account is this account's whichever certificate it names.
 */
export function cloudFrontAcmMarker(arn: string): string {
  const p = acmArnParts(arn);
  return p ? `fcp-cert:${p.account}:${p.id}` : `fcp-cert:${fnv1a64Hex(arn)}`;
}

/** The account and certificate a validation record's comment names (null: not a marker). */
export function parseCloudFrontAcmMarker(
  comment: string | undefined,
): { account: string; id: string } | null {
  const m = /^fcp-cert:(\d{12}):([A-Za-z0-9-]+)$/.exec(comment ?? '');
  return m ? { account: m[1]!, id: m[2]! } : null;
}

/** The record options the template chose for the front's records (the traffic name may be flattened). */
export function cloudFrontRecordOptions(
  tpl: Pick<CloudFrontTemplateParams, 'dnsTtl' | 'dnsTags' | 'dnsFlatten'>,
  traffic: boolean,
): Pick<DnsCreateArgs, 'ttl' | 'tags' | 'settings'> {
  const tags = Object.entries(tpl.dnsTags ?? {}).map(([k, v]) => `${k}:${v}`);
  return {
    ...(tpl.dnsTtl !== undefined ? { ttl: tpl.dnsTtl } : {}),
    ...(tags.length > 0 ? { tags } : {}),
    ...(traffic && tpl.dnsFlatten ? { settings: { flatten_cname: true } } : {}),
  };
}

// --- wire bodies (pure, pinned by the tests) -------------------------------------------------

export type CloudFrontPolicyVariant = 'ws' | 'ws-address';

/** Which shared policy a front uses: with the viewer address only when its options pass it on. */
export function cloudFrontPolicyVariant(
  tpl: Pick<CloudFrontTemplateParams, 'forwardClientAddress'>,
): CloudFrontPolicyVariant {
  return tpl.forwardClientAddress === true ? 'ws-address' : 'ws';
}

/** The headers a policy variant forwards (its whitelist, in order). */
export function cloudFrontPolicyHeaders(variant: CloudFrontPolicyVariant): string[] {
  return variant === 'ws-address'
    ? [...CLOUDFRONT_WEBSOCKET_HEADERS, CLOUDFRONT_VIEWER_ADDRESS_HEADER]
    : [...CLOUDFRONT_WEBSOCKET_HEADERS];
}

/** `fcp-ws-1`, `fcp-ws-address-2`: the shared policies FCP names. */
export function cloudFrontPolicyName(variant: CloudFrontPolicyVariant, batch: number): string {
  return `fcp-${variant}-${batch}`;
}

/**
 * The origin request policy of a variant: a WHITELIST of headers (never
 * `allViewer*`, which would pass on whatever a client sent, nor
 * `allViewerAndWhitelistCloudFront`), no cookies, every query string (a
 * WebSocket path may carry one; none carries an address).
 */
export function cloudFrontOriginRequestPolicyConfig(
  variant: CloudFrontPolicyVariant,
  batch: number,
): OriginRequestPolicyConfig {
  const headers = cloudFrontPolicyHeaders(variant);
  return {
    Name: cloudFrontPolicyName(variant, batch),
    Comment:
      variant === 'ws-address'
        ? 'FCP fronts: the WebSocket handshake headers and the viewer address'
        : 'FCP fronts: the WebSocket handshake headers only',
    HeadersConfig: {
      HeaderBehavior: 'whitelist',
      Headers: { Quantity: headers.length, Items: headers },
    },
    CookiesConfig: { CookieBehavior: 'none' },
    QueryStringsConfig: { QueryStringBehavior: 'all' },
  };
}

/** Whether an existing policy is exactly what FCP would create for the variant (and so reusable). */
export function policyMatchesVariant(
  p: CloudFrontOriginRequestPolicy,
  variant: CloudFrontPolicyVariant,
): boolean {
  if (p.headerBehavior !== 'whitelist') return false;
  const want = cloudFrontPolicyHeaders(variant).map((h) => h.toLowerCase());
  const have = p.headers.map((h) => h.toLowerCase());
  return have.length === want.length && want.every((h) => have.includes(h));
}

/** The ports the origin config names: the listener's on its scheme, the scheme default on the other. */
function originPorts(spec: EdgeSpec): { http: number; https: number } {
  const { port } = originMember(spec, 'distribution');
  return spec.originTransport?.scheme === 'http'
    ? { http: port, https: 443 }
    : { http: 80, https: port };
}

const ORIGIN_TLS_LADDER = ['TLSv1', 'TLSv1.1', 'TLSv1.2'] as const;

/**
 * The distribution one front is built as: one origin (the node, by name, on
 * its port), every request passed through uncached to it with FCP's origin
 * request policy, the zone's shared certificate for the front's own name (SNI
 * only), logging off. `CallerReference` and `Comment` are the edge's name.
 */
export function cloudFrontDistributionConfig(
  spec: EdgeSpec,
  rawTpl: Partial<CloudFrontTemplateParams>,
  certificateArn: string,
  originRequestPolicyId: string,
): DistributionConfig {
  const hostname = requireHostname(spec, 'distribution');
  assertCloudFrontOriginTransport(spec, 'distribution');
  const tpl = effectiveCloudFrontParams(rawTpl);
  const { address } = originMember(spec, 'distribution');
  const ports = originPorts(spec);
  const https = spec.originTransport?.scheme === 'https';
  const tls = ORIGIN_TLS_LADDER.slice(ORIGIN_TLS_LADDER.indexOf(tpl.originMinTlsVersion));
  return {
    CallerReference: spec.name,
    Comment: spec.name,
    Enabled: true,
    Aliases: { Quantity: 1, Items: [hostname] },
    DefaultRootObject: '',
    Origins: {
      Quantity: 1,
      Items: [
        {
          Id: ORIGIN_ID,
          DomainName: address.toLowerCase().replace(/\.$/, ''),
          OriginPath: '',
          CustomHeaders: { Quantity: 0 },
          CustomOriginConfig: {
            HTTPPort: ports.http,
            HTTPSPort: ports.https,
            OriginProtocolPolicy: https ? 'https-only' : 'http-only',
            OriginSslProtocols: { Quantity: tls.length, Items: [...tls] },
            OriginReadTimeout: tpl.originReadTimeoutS,
            OriginKeepaliveTimeout: tpl.originKeepaliveTimeoutS,
          },
          ConnectionAttempts: tpl.originConnectAttempts,
          ConnectionTimeout: tpl.originConnectTimeoutS,
          OriginShield: { Enabled: false },
        },
      ],
    },
    DefaultCacheBehavior: {
      TargetOriginId: ORIGIN_ID,
      ViewerProtocolPolicy: 'https-only',
      AllowedMethods: {
        Quantity: 2,
        Items: ['GET', 'HEAD'],
        CachedMethods: { Quantity: 2, Items: ['GET', 'HEAD'] },
      },
      Compress: false,
      SmoothStreaming: false,
      CachePolicyId: CLOUDFRONT_CACHING_DISABLED_POLICY_ID,
      OriginRequestPolicyId: originRequestPolicyId,
      FieldLevelEncryptionId: '',
      LambdaFunctionAssociations: { Quantity: 0 },
      FunctionAssociations: { Quantity: 0 },
    },
    CacheBehaviors: { Quantity: 0 },
    CustomErrorResponses: { Quantity: 0 },
    Logging: { Enabled: false, IncludeCookies: false, Bucket: '', Prefix: '' },
    PriceClass: tpl.priceClass,
    ViewerCertificate: {
      CloudFrontDefaultCertificate: false,
      ACMCertificateArn: certificateArn,
      SSLSupportMethod: 'sni-only',
      MinimumProtocolVersion: tpl.viewerMinTlsVersion,
    },
    Restrictions: { GeoRestriction: { RestrictionType: 'none', Quantity: 0 } },
    WebACLId: '',
    HttpVersion: tpl.viewerHttpVersion,
    IsIPV6Enabled: tpl.ipv6,
  };
}

// --- certificates ----------------------------------------------------------------------------

/** States in which a certificate is the zone's shared one (a failed one is reported, not replaced). */
const SHARED_STATES = new Set(['PENDING_VALIDATION', 'ISSUED', 'FAILED', 'VALIDATION_TIMED_OUT']);
const FAILED_STATES = new Set(['FAILED', 'VALIDATION_TIMED_OUT', 'REVOKED', 'EXPIRED', 'INACTIVE']);

/** A certificate this account would request itself: ACM-issued, not managed by another service. */
function requestable(c: AcmCertificateSummary): boolean {
  return c.type === 'AMAZON_ISSUED' && !c.managedBy;
}

/**
 * The account's one shared certificate for `name` (`*.<zone>`): `found` when
 * exactly one ACM-issued certificate for it is pending, issued or failed (an
 * expired, revoked or inactive one is history: a new one is requested),
 * `absent` when none is, `ambiguous` when several are. An imported
 * certificate, or one another service manages, is never ours to reuse.
 */
async function sharedCertificateOf(
  api: CloudFrontApi,
  name: string,
): Promise<
  | { status: 'found'; certificate: AcmCertificateSummary }
  | { status: 'absent' }
  | { status: 'ambiguous'; candidates: AcmCertificateSummary[] }
> {
  const list = await api.listCertificates();
  const covering = list.items.filter(
    (c) => sameDnsName(c.domainName, name) && requestable(c) && SHARED_STATES.has(c.status ?? ''),
  );
  if (covering.length === 1) return { status: 'found', certificate: covering[0]! };
  if (covering.length > 1) return { status: 'ambiguous', candidates: covering };
  // A listing cut short cannot prove absence: never request a second one on it.
  if (list.truncated)
    throw refusal('certificate', 'certificate_listing_truncated', 'too many certificates to list');
  return { status: 'absent' };
}

function sharedCertificateResource(
  arn: string,
  name: string,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'tls_subscription',
    resourceId: arn,
    ownership,
    // `shared`: no edge's destroy ever deletes it (the account's other fronts use it).
    meta: { hostname: name, shared: true, wildcard: true },
  };
}

/** The sole candidate an edge of this account ordered, else null. */
function orderedCandidate(
  candidates: AcmCertificateSummary[],
  ordered: readonly string[] | undefined,
): AcmCertificateSummary | null {
  if (!ordered) return null;
  const own = candidates.filter((c) => ordered.includes(`tls_subscription:${c.arn}`));
  return own.length === 1 ? own[0]! : null;
}

/** A shared certificate this close to expiry (or past it) means its renewal is late. */
export const CERTIFICATE_EXPIRY_WARN_MS = 7 * 24 * 60 * 60_000;

/** Whether a certificate serves now: issued and not past its `NotAfter`. */
export function certificateServes(c: AcmCertificate, now: number = Date.now()): boolean {
  if (c.status !== 'ISSUED') return false;
  return c.notAfter === undefined || Date.parse(c.notAfter) > now;
}

/** The provider's state in the words the account page and the watch read. */
export function sharedCertificateState(c: AcmCertificate): string {
  if (c.status === 'ISSUED')
    return c.renewalStatus === 'PENDING_VALIDATION' || c.renewalStatus === 'PENDING_AUTO_RENEWAL'
      ? 'renewing'
      : 'issued';
  if (c.status === 'PENDING_VALIDATION') return 'pending';
  return 'failed';
}

function certificateReadiness(c: AcmCertificate | undefined, now: number): ReadinessState {
  if (!c) return 'unknown';
  if (certificateServes(c, now)) return 'ready';
  if (c.status === 'PENDING_VALIDATION' || c.status === 'ISSUED') return 'pending';
  return FAILED_STATES.has(c.status ?? '') ? 'failed' : 'unknown';
}

/** What a failed issuance or a failed validation says (an identifier, never text). */
function failureCode(c: AcmCertificate): L7CertificateCode {
  return c.failureReason === 'CAA_ERROR' ? 'tls_caa_conflict' : 'tls_failed';
}

/**
 * FCP's own look at the validation record while a certificate waits: the zone
 * either holds the CNAME ACM named, with its value, or it does not
 * (`tls_challenge_missing`). A DNS API that does not answer says nothing.
 */
async function challengeRecordProblem(
  cfg: CloudFrontConfig,
  c: AcmCertificate,
): Promise<L7CertificateCode | undefined> {
  const record = c.validationRecords[0];
  if (!cfg.dns || !record) return undefined;
  try {
    const dns = await dnsClientFor(cfg);
    const found = await dns.findRecordsByName(normalizeZoneName(record.name), 'CNAME');
    return found.some((r) => sameDnsName(r.content, record.value))
      ? undefined
      : 'tls_challenge_missing';
  } catch {
    return undefined;
  }
}

/**
 * One look at the certificate the edge waits on: issued (and not expired)
 * finishes the step; failed is partial; else the step stays requested with
 * what it waits on, when that is known.
 */
async function awaitCertificate(
  cfg: CloudFrontConfig,
  opRef: string,
  ledger: Ledger,
  now: number = Date.now(),
): Promise<StepOutcome> {
  const c = await cloudFrontApiFor(cfg).describeCertificate(opRef);
  if (certificateServes(c, now)) {
    const hostname = cloudFrontHostnameOf(ledger);
    return { status: 'done', resources: [], ...(hostname ? { addresses: { hostname } } : {}) };
  }
  if (FAILED_STATES.has(c.status ?? ''))
    return { status: 'partial', resources: [], code: failureCode(c) };
  const code: L7CertificateCode | undefined =
    c.status === 'ISSUED' ? 'certificate_expiring' : await challengeRecordProblem(cfg, c);
  return { status: 'requested', opRef, resources: [], ...(code ? { code } : {}) };
}

/**
 * One look at the distribution the edge waits on: `Deployed` (every edge
 * location has it) finishes the step; one somebody disabled stops the run.
 */
async function awaitDeployed(
  cfg: CloudFrontConfig,
  opRef: string,
  ledger: Ledger,
): Promise<StepOutcome> {
  const d = await cloudFrontApiFor(cfg).getDistribution(opRef);
  if (!d.enabled)
    return { status: 'partial', resources: [], code: 'distribution_disabled', refused: true };
  if (d.status === 'Deployed') {
    const hostname = cloudFrontHostnameOf(ledger);
    return { status: 'done', resources: [], ...(hostname ? { addresses: { hostname } } : {}) };
  }
  return { status: 'requested', opRef, resources: [] };
}

/**
 * The CAA preflight of a front location: whether the zone's CAA records let
 * ACM issue the zone's wildcard (`issuewild` when the deciding set has one).
 * Recorded as observed facts; a refusal only when records exist and none
 * allows any of Amazon's domains.
 */
async function caaPreflight(cfg: CloudFrontConfig): Promise<
  | {
      observed: Record<string, string>;
      refusal?: { ok: false; code: L7CertificateCode; detail: string };
    }
  | undefined
> {
  const zone = cloudFrontZoneOf(cfg);
  if (!zone) return undefined;
  const v = await checkCaa({
    name: `*.${zone}`,
    certificateAuthority: CLOUDFRONT_CERTIFICATE_AUTHORITY,
    lookup: caaLookupOverride ?? dnsCaaLookup,
  });
  const observed: Record<string, string> = {
    caa: v.verdict,
    caaIssuer: v.issuer,
    caaCertificate: 'wildcard',
    ...(v.decidedAt ? { caaAt: v.decidedAt } : {}),
  };
  if (v.verdict !== 'forbids') return { observed };
  return {
    observed,
    refusal: {
      ok: false,
      code: 'caa_forbids_ca',
      detail: `the CAA records at ${v.decidedAt} do not allow ${v.issuer} (or another Amazon domain) for a wildcard (issuewild)`,
    },
  };
}

/**
 * The validation record of the zone's shared certificate, for its step and its
 * discovery. A record at ACM's name holding ACM's value already validates the
 * certificate: it is used as it is (ours when its marker names this AWS
 * account, else a candidate that is never deleted). Our own account's record
 * with another value is stale (edited by hand) and replaced. A record with any
 * other marker, or none, and another value is somebody else's: ambiguous.
 */
async function sharedValidationRecord(
  cfg: CloudFrontConfig,
  certificate: AcmCertificate,
): Promise<
  | { status: 'found'; resource: ChildResource }
  | { status: 'absent'; stale: DnsRecord[]; dns: DnsClient }
  | { status: 'ambiguous'; candidates: ChildResource[] }
  | { status: 'pending' }
> {
  const want = certificate.validationRecords[0];
  if (!want) return { status: 'pending' };
  const account = acmArnParts(certificate.arn)?.account;
  const dns = await dnsClientFor(cfg);
  const records = await dns.findRecordsByName(normalizeZoneName(want.name), 'CNAME');
  const oursByMarker = (r: DnsRecord) => {
    const m = parseCloudFrontAcmMarker(r.comment);
    return !!m && !!account && m.account === account;
  };
  const exact = records.find((r) => sameDnsName(r.content, want.value));
  if (exact) {
    const resource: ChildResource = {
      ...dnsResource('acme', exact, dns, true),
      ownership: 'adopted',
    };
    return { status: 'found', resource: oursByMarker(exact) ? resource : candidateOf(resource) };
  }
  const foreign = records.filter((r) => !oursByMarker(r));
  if (foreign.length > 0)
    return {
      status: 'ambiguous',
      candidates: foreign.map((r) => candidateOf(dnsResource('acme', r, dns, true))),
    };
  return { status: 'absent', stale: records, dns };
}

// --- steps -----------------------------------------------------------------------------------

const STEP_IDS = {
  tls: 'tls',
  acme: 'acme',
  await: 'await-tls',
  distribution: 'distribution',
  deploy: 'deploy',
  dns: 'dns',
} as const;

function planSteps(spec: EdgeSpec): ResourceStep[] {
  const hostname = requireHostname(spec, 'plan');
  const certName = wildcardNameFor(hostname);
  return [
    {
      id: STEP_IDS.tls,
      kind: 'create_tls_subscription',
      resourceName: certName,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.acme,
      kind: 'create_dns_acme',
      resourceName: certName,
      discoverability: 'by_name',
    },
    { id: STEP_IDS.await, kind: 'await_tls', resourceName: certName, discoverability: 'by_name' },
    {
      id: STEP_IDS.distribution,
      kind: 'create_service',
      resourceName: spec.name,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.deploy,
      kind: 'activate_version',
      resourceName: spec.name,
      discoverability: 'by_name',
    },
    {
      id: STEP_IDS.dns,
      kind: 'create_dns_record',
      resourceName: hostname,
      discoverability: 'by_name',
    },
  ];
}

function dnsResource(
  role: 'acme' | 'traffic',
  record: DnsRecord,
  dns: DnsClient,
  shared = false,
): ChildResource {
  return {
    kind: 'dns_record',
    resourceId: record.id,
    ownership: 'created',
    meta: {
      dnsAccountId: dns.accountId,
      zoneId: dns.zoneId,
      recordId: record.id,
      name: record.name,
      role,
      ...(shared ? { shared: true } : {}),
    },
  };
}

function distributionResource(
  d: CloudFrontDistribution,
  hostname: string | undefined,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'distribution',
    resourceId: d.id,
    ownership,
    meta: {
      domainName: d.domainName,
      ...(d.comment ? { comment: d.comment } : {}),
      ...(hostname ? { hostname } : {}),
    },
  };
}

function policyResource(
  p: CloudFrontOriginRequestPolicy,
  ownership: 'created' | 'adopted',
): ChildResource {
  return {
    kind: 'origin_request_policy',
    resourceId: p.id,
    ownership,
    // Shared by up to 100 fronts of the account: no edge's destroy deletes it.
    meta: { name: p.name, shared: true },
  };
}

/**
 * The account's shared origin request policy for a variant with room for one
 * more distribution: the lowest-numbered `fcp-<variant>-<n>` that forwards
 * exactly the variant's headers and has fewer than 100 distributions, else a
 * new one under the first free number. A policy under our name with other
 * headers (edited by hand) is never used. Runs under the account's policy lock.
 */
async function ensurePolicy(
  api: CloudFrontApi,
  variant: CloudFrontPolicyVariant,
): Promise<{ policy: CloudFrontOriginRequestPolicy; created: boolean }> {
  const existing = await api.listOriginRequestPolicies();
  for (let batch = 1; batch <= MAX_POLICIES; batch++) {
    const name = cloudFrontPolicyName(variant, batch);
    const p = existing.find((x) => x.name === name);
    if (!p) {
      try {
        return {
          policy: await api.createOriginRequestPolicy(
            cloudFrontOriginRequestPolicyConfig(variant, batch),
          ),
          created: true,
        };
      } catch (e) {
        // Made by a lost earlier answer: read it back and judge it like the rest.
        if (!isCloudFrontCode(e, 'origin_request_policy_already_exists')) throw e;
        const again = (await api.listOriginRequestPolicies()).find((x) => x.name === name);
        if (!again) throw e;
        if (!policyMatchesVariant(again, variant)) continue;
        if ((await api.countDistributionsOfPolicy(again.id)) < CLOUDFRONT_DISTRIBUTIONS_PER_POLICY)
          return { policy: again, created: false };
        continue;
      }
    }
    if (!policyMatchesVariant(p, variant)) continue;
    if ((await api.countDistributionsOfPolicy(p.id)) < CLOUDFRONT_DISTRIBUTIONS_PER_POLICY)
      return { policy: p, created: false };
  }
  throw refusal(
    'distribution',
    'origin_request_policies_full',
    'every origin request policy FCP may use is full',
  );
}

/** The distributions whose `Comment` is the edge's name (the discovery key). */
async function distributionsNamed(
  api: CloudFrontApi,
  name: string,
): Promise<{ items: CloudFrontDistribution[]; truncated: boolean }> {
  const list = await api.listDistributions();
  return { items: list.items.filter((d) => d.comment === name), truncated: list.truncated };
}

/**
 * The one distribution discovery or a repeated create may adopt: named by its
 * comment AND serving the front's hostname. Several, or one serving another
 * name, are never taken over.
 */
async function findDistribution(
  api: CloudFrontApi,
  spec: EdgeSpec,
  hostname: string | undefined,
): Promise<Discovery> {
  const { items, truncated } = await distributionsNamed(api, spec.name);
  if (items.length === 0)
    return truncated ? { status: 'unresolved' } : { status: 'confirmed_absent' };
  const serving = items.filter((d) => !hostname || d.aliases.some((a) => sameDnsName(a, hostname)));
  if (items.length === 1 && serving.length === 1) {
    const d = serving[0]!;
    const resources: ChildResource[] = [distributionResource(d, hostname, 'adopted')];
    if (d.originRequestPolicyId)
      resources.unshift({
        kind: 'origin_request_policy',
        resourceId: d.originRequestPolicyId,
        ownership: 'adopted',
        meta: { shared: true },
      });
    return { status: 'found', resources };
  }
  return {
    status: 'ambiguous',
    candidates: items.map((d) => candidateOf(distributionResource(d, hostname, 'adopted'))),
  };
}

/** What a client fault on create means: a refusal that would be repeated as it is. */
function refusedCreate(e: unknown, resources: ChildResource[]): StepOutcome | null {
  if (!(e instanceof EdgeProviderError)) return null;
  const status = e.meta.status;
  if (status === undefined || status < 400 || status >= 500 || status === 429) return null;
  if (e.meta.code === 'distribution_already_exists') return null;
  if (/throttl|limit_exceeded/.test(e.meta.code ?? '')) return null;
  const detail = refusalOf(e);
  return {
    status: 'partial',
    resources,
    code: e.meta.code === 'cname_already_exists' ? 'alias_in_use' : (e.meta.code ?? 'refused'),
    refused: true,
    ...(detail ? { detail } : {}),
  };
}

// --- the adapter -----------------------------------------------------------------------------

export const cloudFrontProvider: EdgeProvider<CloudFrontConfig, CloudFrontTemplateParams> = {
  id: 'cloudfront',
  templateSchema: CloudFrontTemplate,
  templateFields: CLOUDFRONT_TEMPLATE_FIELDS,
  defaultTemplate: CloudFrontTemplate.parse({}),

  async certificatePreflight(cfg) {
    const caa = await caaPreflight(cfg);
    return caa?.refusal
      ? { ok: false as const, code: caa.refusal.code, detail: caa.refusal.detail }
      : { ok: true as const };
  },

  /**
   * The key reads what every step needs to read: ACM's certificate list in
   * us-east-1, the distributions and the custom origin request policies. A
   * key that may read but not write passes here and is refused at its first
   * write (the refusal names the action).
   */
  async testCredentials(cfg): Promise<CredentialTestResult> {
    const api = cloudFrontApiFor(cfg, 'test');
    try {
      const certificates = await api.listCertificates();
      const distributions = await api.listDistributions();
      const policies = await api.listOriginRequestPolicies();
      const ours = policies.filter((p) => /^fcp-ws(-address)?-\d+$/.test(p.name)).length;
      return {
        ok: true,
        detail: `certificates=${certificates.items.length}${certificates.truncated ? '+' : ''}; distributions=${distributions.items.length}${distributions.truncated ? '+' : ''}; fcp_policies=${ours}`,
      };
    } catch (e) {
      return credentialTestFailure(e);
    }
  },

  /** The zone's shared certificate as ACM sees it now (a read; never requests one). */
  async sharedCertificate(cfg, opts): Promise<SharedCertificateStatus | null> {
    const zone = cloudFrontZoneOf(cfg);
    if (!zone) return null;
    const name = `*.${zone}`;
    const api = cloudFrontApiFor(cfg);
    const found = await sharedCertificateOf(api, name);
    if (found.status === 'absent') return { name, state: 'absent' };
    if (found.status === 'ambiguous') {
      const own = orderedCandidate(found.candidates, opts?.ordered);
      return own
        ? { name, subscriptionId: own.arn, state: 'ambiguous' }
        : { name, state: 'ambiguous' };
    }
    const c = await api.describeCertificate(found.certificate.arn);
    const state = sharedCertificateState(c);
    const late =
      c.notAfter !== undefined && Date.parse(c.notAfter) - Date.now() < CERTIFICATE_EXPIRY_WARN_MS;
    const code: L7CertificateCode | undefined =
      state === 'failed'
        ? failureCode(c)
        : state === 'issued'
          ? late
            ? 'certificate_expiring'
            : undefined
          : ((await challengeRecordProblem(cfg, c)) ?? (late ? 'certificate_expiring' : undefined));
    return {
      name,
      subscriptionId: c.arn,
      state,
      ...(code ? { code } : {}),
      ...(c.notAfter ? { notAfter: c.notAfter } : {}),
    };
  },

  /**
   * Remove the zone's shared certificate and OUR validation record, for an
   * operator who no longer wants it (the caller refuses while a live edge
   * fronts through it). Only a certificate an edge of this account requested
   * is deleted; ACM itself refuses one a distribution still uses.
   */
  async removeSharedCertificate(cfg, opts): Promise<{ removed: boolean; code?: string }> {
    const zone = cloudFrontZoneOf(cfg);
    if (!zone) return { removed: false, code: 'dns_zone_missing' };
    const api = cloudFrontApiFor(cfg);
    const shared = await sharedCertificateOf(api, `*.${zone}`);
    // The one certificate an edge of this account requested is its to remove;
    // among several, only when exactly one of them is.
    let target: AcmCertificateSummary | null = null;
    if (shared.status === 'found') target = shared.certificate;
    else if (shared.status === 'ambiguous') {
      target = orderedCandidate(shared.candidates, opts.ordered);
      if (!target) return { removed: false, code: 'shared_certificate_ambiguous' };
    }
    if (target && !opts.ordered.includes(`tls_subscription:${target.arn}`))
      return { removed: false, code: 'shared_certificate_not_ours' };
    let record: { name: string } | undefined;
    if (target) {
      try {
        record = (await api.describeCertificate(target.arn)).validationRecords[0];
        await api.deleteCertificate(target.arn);
      } catch (e) {
        if (isCloudFrontCode(e, 'resource_in_use_exception'))
          return { removed: false, code: 'shared_certificate_in_use' };
        if (!isCloudFrontNotFound(e)) throw e;
      }
    }
    // Our account's validation record goes only when no certificate of ours
    // for the name is left to renew through it.
    const left = (await sharedCertificateOf(api, `*.${zone}`)).status !== 'absent';
    const account = target ? acmArnParts(target.arn)?.account : undefined;
    if (record && account && !left) {
      const dns = await dnsClientFor(cfg);
      for (const r of await dns.findRecordsByName(normalizeZoneName(record.name), 'CNAME')) {
        if (parseCloudFrontAcmMarker(r.comment)?.account === account) await dns.deleteRecord(r.id);
      }
    }
    return { removed: !!target };
  },

  /**
   * One front location is usable: its DNS account's credentials read its zone
   * (active, the name the location recorded; paused is only noted) and the
   * zone's CAA records let ACM issue its wildcard. The label is the zone's name.
   */
  async checkLocation(cfg): Promise<LocationCheckResult> {
    const detail: string[] = [];
    try {
      const dns = await dnsClientFor(cfg);
      const zone = await dns.readZone();
      const observed: Record<string, string> = {
        zoneStatus: zone.paused ? 'paused' : zone.status,
        ...(zone.plan ? { zonePlan: zone.plan } : {}),
      };
      const out = (code?: string): LocationCheckResult => ({
        ok: !code,
        ...(code ? { code } : {}),
        detail: detail.join(' '),
        observed,
        label: zone.name,
        zoneName: zone.name,
      });
      if (cfg.dns?.zoneName && zone.name !== cfg.dns.zoneName.toLowerCase())
        return out('zone_name_mismatch');
      if (zone.paused) detail.push('zone_paused');
      if (zone.status !== 'active') {
        detail.push('zone_not_active');
        return out('zone_not_active');
      }
      const caa = await caaPreflight(cfg);
      if (caa) Object.assign(observed, caa.observed);
      if (caa?.refusal) {
        detail.push(caa.refusal.detail);
        return out('caa_forbids_ca');
      }
      return out();
    } catch (e) {
      const failed = credentialTestFailure(e);
      if (failed.code === 'error' || !(e instanceof EdgeProviderError) || e.meta.retryable) throw e;
      return { ok: false, code: failed.code, detail: failed.detail };
    }
  },

  planProvision(_cfg, spec) {
    // Feasibility is decided before any provider call.
    assertCloudFrontOriginTransport(spec, 'plan');
    return planSteps(spec);
  },

  async runStep(cfg, step, spec, tpl, ledger): Promise<StepOutcome> {
    const api = cloudFrontApiFor(cfg);
    const hostname = requireHostname(spec, step.id);
    switch (step.kind) {
      case 'create_tls_subscription': {
        // ONE certificate per account and zone: found by its name and reused,
        // requested only when none exists (the step holds the account's
        // certificate lock, so two edges never both request it).
        const name = wildcardNameFor(hostname);
        const found = await sharedCertificateOf(api, name);
        if (found.status === 'found')
          return {
            status: 'done',
            resources: [sharedCertificateResource(found.certificate.arn, name, 'adopted')],
          };
        if (found.status === 'ambiguous')
          throw refusal(
            step.id,
            'shared_certificate_ambiguous',
            'the wildcard is covered by several certificates',
          );
        const arn = await api.requestCertificate({
          domainName: name,
          idempotencyToken: certificateIdempotencyToken(spec.name, name),
        });
        return { status: 'done', resources: [sharedCertificateResource(arn, name, 'created')] };
      }
      case 'create_dns_acme': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        const certificate = await api.describeCertificate(sub.resourceId);
        const shared = await sharedValidationRecord(cfg, certificate);
        if (shared.status === 'found') return { status: 'done', resources: [shared.resource] };
        if (shared.status === 'ambiguous')
          throw refusal(
            step.id,
            'acme_name_in_use',
            'the validation name already holds a record FCP did not write',
          );
        if (shared.status === 'pending')
          // ACM names the record within seconds of the request.
          throw refusal(step.id, 'acme_challenge_pending', 'no validation record yet', true);
        const want = certificate.validationRecords[0]!;
        // Our own account's record with another value (edited by hand): the
        // name takes one CNAME, so it is replaced.
        for (const old of shared.stale) await shared.dns.deleteRecord(old.id);
        const record = await shared.dns.createRecord({
          type: 'CNAME',
          name: normalizeZoneName(want.name),
          content: normalizeZoneName(want.value),
          proxied: false,
          comment: cloudFrontAcmMarker(certificate.arn),
          ...cloudFrontRecordOptions(tpl, false),
        });
        return { status: 'done', resources: [dnsResource('acme', record, shared.dns, true)] };
      }
      case 'await_tls': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        // One look before waiting: an already issued certificate (the zone's
        // shared one, typically) finishes the step without a poll.
        return awaitCertificate(cfg, sub.resourceId, ledger);
      }
      case 'create_service': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) throw ledgerIncomplete(step.id);
        const { policy, created } = await ensurePolicy(api, cloudFrontPolicyVariant(tpl));
        const policyChild = policyResource(policy, created ? 'created' : 'adopted');
        let distribution: CloudFrontDistribution;
        try {
          distribution = await api.createDistribution(
            cloudFrontDistributionConfig(spec, tpl, sub.resourceId, policy.id),
          );
        } catch (e) {
          // The same CallerReference again: an earlier create landed (its answer
          // was lost). Adopt it by its comment once the listing shows it.
          if (isCloudFrontCode(e, 'distribution_already_exists')) {
            const found = await findDistribution(api, spec, hostname);
            if (found.status === 'found') return { status: 'done', resources: found.resources };
            throw refusal(
              step.id,
              'distribution_not_listed_yet',
              'an earlier create landed but is not listed yet',
              true,
            );
          }
          const refused = refusedCreate(e, [policyChild]);
          if (refused) return refused;
          throw e;
        }
        return {
          status: 'done',
          resources: [policyChild, distributionResource(distribution, hostname, 'created')],
        };
      }
      case 'activate_version': {
        const d = ownDistributionOf(ledger);
        if (!d) throw ledgerIncomplete(step.id);
        return awaitDeployed(cfg, d.resourceId, ledger);
      }
      case 'create_dns_record': {
        const d = ownDistributionOf(ledger);
        if (!d) throw ledgerIncomplete(step.id);
        const meta = metaOf(d);
        const target =
          typeof meta.domainName === 'string' && meta.domainName
            ? meta.domainName
            : (await api.getDistribution(d.resourceId)).domainName;
        if (!target)
          throw refusal(step.id, 'distribution_name_missing', 'no CNAME target to point at');
        const dns = await dnsClientFor(cfg);
        const record = await dns.createRecord({
          type: 'CNAME',
          name: hostname,
          content: target,
          proxied: false,
          comment: spec.name,
          ...cloudFrontRecordOptions(tpl, true),
        });
        return {
          status: 'done',
          resources: [dnsResource('traffic', record, dns)],
          addresses: { hostname },
        };
      }
      default:
        throw refusal(step.id, 'unknown_step', `unknown step kind ${step.kind}`);
    }
  },

  /**
   * Two waits are asynchronous: the certificate's issuance (`await_tls`,
   * minutes for a first one, at once when the zone's is issued) and the
   * distribution's deployment (`activate_version`, `InProgress` to
   * `Deployed`).
   */
  async pollStep(cfg, step, opRef, ledger): Promise<StepOutcome> {
    if (step.kind === 'await_tls') return awaitCertificate(cfg, opRef, ledger);
    if (step.kind === 'activate_version') return awaitDeployed(cfg, opRef, ledger);
    throw refusal(step.id, 'unknown_step', 'not a polled step');
  },

  async discover(cfg, step, spec, ledger): Promise<Discovery> {
    const api = cloudFrontApiFor(cfg);
    const hostname = spec.hostname ?? cloudFrontHostnameOf(ledger);
    switch (step.kind) {
      case 'create_tls_subscription': {
        if (!hostname) return { status: 'confirmed_absent' };
        // The step's own rule, so a lost request is recognised; a re-run with
        // the same idempotency token answers the same certificate anyway.
        const name = wildcardNameFor(hostname);
        const found = await sharedCertificateOf(api, name);
        if (found.status === 'absent') return { status: 'confirmed_absent' };
        if (found.status === 'ambiguous')
          return {
            status: 'ambiguous',
            candidates: found.candidates.map((c) =>
              candidateOf(sharedCertificateResource(c.arn, name, 'adopted')),
            ),
          };
        return {
          status: 'found',
          resources: [sharedCertificateResource(found.certificate.arn, name, 'adopted')],
        };
      }
      case 'create_dns_acme': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) return { status: 'confirmed_absent' };
        const shared = await sharedValidationRecord(
          cfg,
          await api.describeCertificate(sub.resourceId),
        );
        if (shared.status === 'found') return { status: 'found', resources: [shared.resource] };
        if (shared.status === 'ambiguous')
          return { status: 'ambiguous', candidates: shared.candidates };
        return shared.status === 'pending'
          ? { status: 'unresolved' }
          : { status: 'confirmed_absent' };
      }
      case 'await_tls': {
        const sub = firstResource(ledger, 'tls_subscription');
        if (!sub) return { status: 'confirmed_absent' };
        return certificateServes(await api.describeCertificate(sub.resourceId))
          ? { status: 'found', resources: [], ...(hostname ? { addresses: { hostname } } : {}) }
          : { status: 'unresolved' };
      }
      case 'create_service':
        // Absent is safe to act on: a re-run carries the same CallerReference,
        // which CloudFront refuses rather than creating a second distribution.
        return findDistribution(api, spec, hostname);
      case 'activate_version': {
        const d = ownDistributionOf(ledger);
        if (!d) return { status: 'confirmed_absent' };
        const live = await api.getDistribution(d.resourceId);
        return live.status === 'Deployed' && live.enabled
          ? { status: 'found', resources: [], ...(hostname ? { addresses: { hostname } } : {}) }
          : { status: 'confirmed_absent' };
      }
      case 'create_dns_record': {
        if (!hostname) return { status: 'confirmed_absent' };
        const dns = await dnsClientFor(cfg);
        const records = await dns.findRecordsByName(hostname, 'CNAME');
        if (records.length === 0) return { status: 'confirmed_absent' };
        // Ownership is the comment marker; a same-name record we did not write
        // is never adopted or deleted.
        const ours = records.filter((r) => r.comment === spec.name);
        if (ours.length === 0)
          return {
            status: 'ambiguous',
            candidates: records.map((r) => candidateOf(dnsResource('traffic', r, dns))),
          };
        return {
          status: 'found',
          resources: [{ ...dnsResource('traffic', ours[0]!, dns), ownership: 'adopted' }],
          addresses: { hostname },
        };
      }
      default:
        return { status: 'confirmed_absent' };
    }
  },

  async describe(cfg, ledger): Promise<EdgeDescription> {
    const own = ownDistributionOf(ledger);
    if (!own) return { state: 'pending', addresses: {}, health: 'unknown', code: 'no_service_yet' };
    const hostname = cloudFrontHostnameOf(ledger);
    const api = cloudFrontApiFor(cfg);
    let d: CloudFrontDistribution;
    try {
      d = await api.getDistribution(own.resourceId);
    } catch (e) {
      if (isCloudFrontNotFound(e)) return { state: 'gone', addresses: {}, health: 'unknown' };
      throw e;
    }
    const now = Date.now();
    const readiness: EdgeReadiness = { dns: 'pending', certificate: 'unknown' };
    // The traffic record as the zone holds it NOW: there, and still pointing
    // at the distribution.
    const traffic = resourcesOfKind(ledger, 'dns_record').find(
      (r) => metaOf(r).role === 'traffic' && metaOf(r).candidate !== true,
    );
    if (traffic) {
      try {
        const meta = metaOf(traffic);
        const record = await (
          await dnsClientFor(cfg)
        ).getRecord(typeof meta.recordId === 'string' ? meta.recordId : traffic.resourceId);
        readiness.dns = record && sameDnsName(record.content, d.domainName) ? 'ready' : 'pending';
      } catch {
        readiness.dns = 'unknown';
      }
    }
    const sub = firstResource(ledger, 'tls_subscription');
    let certificate: AcmCertificate | undefined;
    if (sub) {
      try {
        certificate = await api.describeCertificate(sub.resourceId);
      } catch (e) {
        if (!isCloudFrontNotFound(e)) throw e;
      }
    }
    readiness.certificate = certificateReadiness(certificate, now);
    const deployed = d.status === 'Deployed' && d.enabled;
    const ready = readiness.dns === 'ready' && readiness.certificate === 'ready' && deployed;
    const code =
      readiness.certificate === 'failed' && certificate
        ? failureCode(certificate)
        : certificate?.status === 'ISSUED' && !certificateServes(certificate, now)
          ? 'certificate_expiring'
          : !d.enabled
            ? 'distribution_disabled'
            : undefined;
    return {
      state: readiness.certificate === 'failed' ? 'error' : ready ? 'active' : 'pending',
      // Reported as soon as the ledger knows it; publishability is decided by
      // state + readiness + the front qualification.
      addresses: hostname ? { hostname } : {},
      // DNS and certificate say nothing about the origin (memberHealth false).
      health: 'unknown',
      ...(code ? { code } : {}),
      readiness,
    };
  },

  async inspect(cfg, ledger): Promise<InspectResult> {
    const own = ownDistributionOf(ledger);
    if (!own) throw ledgerIncomplete('inspect');
    const api = cloudFrontApiFor(cfg);
    const d = await api.getDistribution(own.resourceId);
    const sub = firstResource(ledger, 'tls_subscription');
    let certificate: { arn: string; status?: string; notAfter?: string } | undefined;
    if (sub) {
      const c = await api.describeCertificate(sub.resourceId).catch(() => undefined);
      certificate = {
        arn: sub.resourceId,
        ...(c?.status ? { status: c.status } : {}),
        ...(c?.notAfter ? { notAfter: c.notAfter } : {}),
      };
    }
    const hostname = cloudFrontHostnameOf(ledger);
    const { etag: _etag, ...distribution } = d;
    return {
      summary: {
        status: d.enabled ? d.status : 'disabled',
        addresses: hostname ? { hostname } : {},
        members: d.origins.map((o) => ({
          address: o.domainName,
          port: o.protocolPolicy === 'http-only' ? (o.httpPort ?? 80) : (o.httpsPort ?? 443),
        })),
        listeners: [{ port: 443, protocol: 'https' }],
      },
      // The distribution as read (it carries no credentials) and the
      // certificate reduced to its id, state and expiry.
      raw: { distribution, certificate },
    };
  },

  async inventory(cfg): Promise<Inventory> {
    const { items } = await cloudFrontApiFor(cfg).listDistributions();
    return {
      loadBalancers: items.map((d) => ({
        id: d.id,
        name: d.comment || d.id,
        status: d.enabled ? (d.status ?? 'unknown') : 'disabled',
        addresses: d.aliases[0] ? { hostname: d.aliases[0] } : {},
        hostnames: [...d.aliases],
        ...(d.origins[0]?.domainName ? { content: d.origins[0].domainName } : {}),
      })),
      ips: [],
      flavors: [],
    };
  },

  /**
   * Import: an EXISTING distribution serving exactly this one hostname, as the
   * children FCP would have created. One serving other names too is refused
   * (`distribution_shared`): FCP deletes what it imports, and removing one
   * alias from somebody else's distribution is not a workflow it has. Its
   * certificate is recorded as shared (never deleted by the edge) unless it
   * covers this hostname alone.
   */
  async inspectForAdoption(cfg, resourceId, hostname): Promise<AdoptionInspection> {
    const step = 'adopt';
    const api = cloudFrontApiFor(cfg);
    const d = await api.getDistribution(resourceId);
    const mine = d.aliases.find((a) => sameDnsName(a, hostname));
    if (!mine)
      throw refusal(step, 'hostname_mismatch', 'the distribution does not serve that hostname');
    if (d.aliases.length > 1)
      throw refusal(step, 'distribution_shared', 'the distribution also serves other names');
    if (!d.enabled) throw refusal(step, 'distribution_disabled', 'the distribution is disabled');
    const name = mine.toLowerCase();
    const resources: ChildResource[] = [];
    if (d.originRequestPolicyId)
      resources.push({
        kind: 'origin_request_policy',
        resourceId: d.originRequestPolicyId,
        ownership: 'adopted',
        meta: { shared: true },
      });
    resources.push(distributionResource(d, name, 'adopted'));
    if (d.certificateArn) {
      const c = await api.describeCertificate(d.certificateArn).catch((e: unknown) => {
        if (isCloudFrontNotFound(e)) return undefined;
        throw e;
      });
      if (c)
        resources.push({
          kind: 'tls_subscription',
          resourceId: c.arn,
          ownership: 'adopted',
          // A certificate for this name alone is the edge's; anything wider
          // (the zone's wildcard) serves other fronts and is never deleted.
          meta: { hostname: c.domainName, shared: !sameDnsName(c.domainName, name) },
        });
    }
    const dns = await dnsClientFor(cfg);
    const record = (await dns.findRecordsByName(name, 'CNAME'))[0];
    if (record) resources.push({ ...dnsResource('traffic', record, dns), ownership: 'adopted' });
    return {
      resources,
      hostname: name,
      hostnames: [...d.aliases],
      shared: false,
      ...(d.origins[0]?.domainName ? { content: d.origins[0].domainName } : {}),
    };
  },

  /**
   * Destroy order by kind: the traffic record first, so no member is sent to
   * a front being dismantled, then the distribution (disable, wait, delete),
   * then the certificate an edge owns alone (an import's), then the shared
   * ones, which keep their places but are left in place (`runDestroy`). A
   * candidate discovery could not prove is this edge's is never destroyed.
   */
  planDestroy(_cfg, ledger) {
    const live = ledger.resources.filter(
      (r) => r.deleteState !== 'confirmed_gone' && metaOf(r).candidate !== true,
    );
    return [...live]
      .reverse()
      .map((r, i) => ({ r, i }))
      .sort((a, b) => destroyRank(a.r) - destroyRank(b.r) || a.i - b.i)
      .map((x) => x.r);
  },

  async runDestroy(cfg, r) {
    const api = cloudFrontApiFor(cfg);
    // Never somebody else's, and never what other fronts share.
    if (metaOf(r).candidate === true || metaOf(r).shared === true)
      return { status: 'confirmed_gone' };
    try {
      switch (r.kind) {
        case 'dns_record': {
          const meta = metaOf(r);
          const dns = await dnsClientFor(cfg);
          await dns.deleteRecord(typeof meta.recordId === 'string' ? meta.recordId : r.resourceId);
          return { status: 'delete_requested' };
        }
        case 'distribution': {
          const d = await api.getDistribution(r.resourceId);
          if (d.enabled) {
            // Disabled first: CloudFront deletes only a disabled distribution
            // whose change has deployed. `IfMatch` names the version read.
            const { config, etag } = await api.getDistributionConfig(r.resourceId);
            if (config.Enabled !== false)
              await api.updateDistribution(r.resourceId, { ...config, Enabled: false }, etag);
            return { status: 'delete_requested' };
          }
          // The disable is still propagating: wait for it.
          if (d.status !== 'Deployed') return { status: 'delete_requested' };
          if (!d.etag) return { status: 'unresolved' };
          await api.deleteDistribution(r.resourceId, d.etag);
          return { status: 'delete_requested' };
        }
        case 'tls_subscription': {
          // An imported front's own certificate, once no distribution uses it.
          await api.deleteCertificate(r.resourceId);
          return { status: 'delete_requested' };
        }
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isCloudFrontNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },

  /**
   * Read back after a delete was requested. A distribution still enabled, or
   * disabled and deployed, is `still_present` (the next pass issues the next
   * call: the disable again, or the delete); one whose disable is still
   * propagating is `unresolved`.
   */
  async confirmDestroyed(cfg, r) {
    const api = cloudFrontApiFor(cfg);
    if (metaOf(r).candidate === true || metaOf(r).shared === true)
      return { status: 'confirmed_gone' };
    try {
      switch (r.kind) {
        case 'dns_record': {
          const meta = metaOf(r);
          const dns = await dnsClientFor(cfg);
          const id = typeof meta.recordId === 'string' ? meta.recordId : r.resourceId;
          return (await dns.getRecord(id)) === null
            ? { status: 'confirmed_gone' }
            : { status: 'still_present' };
        }
        case 'distribution': {
          const d = await api.getDistribution(r.resourceId);
          if (d.enabled || d.status === 'Deployed') return { status: 'still_present' };
          return { status: 'unresolved' };
        }
        case 'tls_subscription': {
          await api.describeCertificate(r.resourceId);
          return { status: 'still_present' };
        }
        default:
          return { status: 'unresolved' };
      }
    } catch (e) {
      if (isCloudFrontNotFound(e)) return { status: 'confirmed_gone' };
      throw e;
    }
  },
};

// --- destroy ordering --------------------------------------------------------------------------

/**
 * Destroy order by kind (DNS role included): the traffic record, the
 * distribution, a certificate the edge owns alone, then the shared children
 * (the certificate, its validation record, the policy), confirmed without a
 * call.
 */
export const CLOUDFRONT_DESTROY_ORDER = [
  'dns_record:traffic',
  'distribution',
  'tls_subscription',
  'dns_record:acme',
  'origin_request_policy',
] as const;

export function cloudFrontDestroyKey(r: LedgerResource): string {
  const role = metaOf(r).role;
  return typeof role === 'string' ? `${r.kind}:${role}` : r.kind;
}

function destroyRank(r: LedgerResource): number {
  const i = (CLOUDFRONT_DESTROY_ORDER as readonly string[]).indexOf(cloudFrontDestroyKey(r));
  return i === -1 ? CLOUDFRONT_DESTROY_ORDER.length : i;
}
