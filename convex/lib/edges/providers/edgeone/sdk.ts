'use node';
/**
 * Typed, body-free wrapper over Tencent's official EdgeOne SDK
 * (`tencentcloud-sdk-nodejs-teo` 4.1.333 on `tencentcloud-sdk-nodejs-common`
 * 4.1.220, API version 2022-09-01), the only calls the EdgeOne adapter makes.
 *
 * Why a wrapper rather than the SDK directly (the CloudFront wrapper's reasons):
 *  - The adapter and its tests' fake see ONE small interface (`EdgeOneApi`)
 *    with plain records, so an unlisted call cannot be made by accident and
 *    the wire contract stays reviewable here.
 *  - Errors: a Tencent error carries a fixed code (`LimitExceeded.PackNotAllow`)
 *    and a message that can echo request values (the front's name, the
 *    origin). Only a status FCP derives from the code class and a short code
 *    from a fixed vocabulary (`EDGEONE_ERROR_CODES`) reach an
 *    `EdgeProviderError`; Tencent's code, the action and the redacted message
 *    are held aside as the refusal's words (`http.ts`), so a refusal names the
 *    CAM action it needed.
 *  - No retries: the SDK makes one request per call and so does the wrapper,
 *    so an unknown outcome is resolved by discovery, never by a replayed create.
 *
 * Pinned on purpose: the credentials are ALWAYS the account's own SecretId and
 * SecretKey (and the optional STS session token), never a credential chain;
 * the endpoint is the account's site's API host; and every client gets its own
 * `agent`, so the SDK never builds a proxy agent from the backend's
 * `http_proxy` variable. The SDK's node-fetch follows redirects; a TC3
 * signature is bound to the API host, so a redirected request is refused
 * wherever it lands. Tests point the real SDK at an in-process recorder
 * (`__setEdgeOneEndpoint`) or replace the whole API with a fake
 * (`__setEdgeOneApiFactory`).
 */
import http from 'node:http';
import https from 'node:https';
import { teo } from 'tencentcloud-sdk-nodejs-teo';
import type {
  AccelerationDomain,
  DnsRecord as TeoDnsRecord,
  Zone,
} from 'tencentcloud-sdk-nodejs-teo/tencentcloud/services/teo/v20220901/teo_models';
import { EdgeProviderError, refusalOf, toProviderError, withRefusal } from '../http';
import type { EdgeOneConfig } from '../types';

/** The API host of each Tencent Cloud site: an account lives on one of them. */
export const EDGEONE_API_HOSTS = {
  intl: 'teo.intl.tencentcloudapi.com',
  china: 'teo.tencentcloudapi.com',
} as const;
export type EdgeOneSite = keyof typeof EDGEONE_API_HOSTS;

/** Every call is a small object or one bounded page (the SDK takes seconds). */
export const EDGEONE_TIMEOUT_S = 15;
const PAGE_SIZE = 100;
const MAX_PAGES = 10;

// --- the records the adapter sees ------------------------------------------------------

export interface EdgeOneZone {
  id: string;
  name: string;
  /** `full` (EdgeOne hosts the zone's DNS: NS access), `partial` (CNAME access), others. */
  type?: string;
  /**
   * `active`, `pending`, `moved`, `deactivated`, `initializing`. For NS access
   * `active` means the name servers point at EdgeOne; a CNAME-access zone never
   * switches them and stays `pending` (its verification is `cnameStatus`).
   */
  status?: string;
  /** CNAME access only: `finished` (the site is verified) or `pending`. */
  cnameStatus?: string;
  /** `active`, `inactive`, `paused`. */
  activeStatus?: string;
  paused: boolean;
  /** `global`, `mainland`, `overseas`. */
  area?: string;
}

export interface EdgeOneCertificate {
  id?: string;
  /** `default`, `upload`, `managed`. */
  type?: string;
  /** `deployed`, `processing`, `applying`, `failed`, `issued`. */
  status?: string;
  expireTime?: string;
}

export interface EdgeOneDomain {
  zoneId: string;
  name: string;
  /** `online`, `process` (deploying), `offline`, `init` (zone not active yet). */
  status?: string;
  /** What the front's name points at (CNAME access, and the record EdgeOne writes). */
  cname?: string;
  /** `pending` while a CNAME-access zone's ownership is not proven, then `finished`. */
  identification?: string;
  originType?: string;
  origin?: string;
  hostHeader?: string;
  originProtocol?: string;
  httpPort?: number;
  httpsPort?: number;
  ipv6Status?: string;
  /** `eofreecert`, `sslcert`, `disable`, ... */
  certificateMode?: string;
  certificates: EdgeOneCertificate[];
  /** Why the domain is restricted somewhere (`ICP_RECORD_REQUIRED`, `GOVERNMENT_ORDER`). */
  restrictions: string[];
}

export interface EdgeOneDnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  /** `enable` or `disable`. */
  status?: string;
  ttl?: number;
}

export interface EdgeOneDomainSpec {
  zoneId: string;
  name: string;
  origin: string;
  /** The Host the node receives (the front name, or the node's own). */
  hostHeader: string;
  originProtocol: 'HTTP' | 'HTTPS';
  httpPort: number;
  httpsPort: number;
  ipv6Status: 'follow' | 'on' | 'off';
}

/** The zone's site-acceleration settings the location check reads. */
export interface EdgeOneZoneSettings {
  /** `on` or `off`: off still carries WebSocket with a 15 s idle timeout (the SDK's words). */
  webSocket?: string;
  webSocketTimeout?: number;
  /** `on` sends the member's address in a header of the zone's choosing. */
  clientIpHeader?: string;
  grpc?: string;
}

export interface EdgeOneApi {
  /** Zones the key can list (bounded pages); `zoneId` filters to one. */
  listZones(zoneId?: string): Promise<{ items: EdgeOneZone[]; truncated: boolean }>;
  zoneSettings(zoneId: string): Promise<EdgeOneZoneSettings>;
  createDomain(spec: EdgeOneDomainSpec): Promise<void>;
  /** The one domain with exactly this name in the zone, or null. */
  getDomain(zoneId: string, name: string): Promise<EdgeOneDomain | null>;
  listDomains(zoneId: string): Promise<{ items: EdgeOneDomain[]; truncated: boolean }>;
  /** EdgeOne deletes only a domain switched off: `offline` first, then `deleteDomain`. */
  setDomainStatus(zoneId: string, name: string, status: 'online' | 'offline'): Promise<void>;
  deleteDomain(zoneId: string, name: string): Promise<void>;
  /** Ask for EdgeOne's free certificate on the host (`eofreecert`). */
  requestFreeCertificate(zoneId: string, host: string): Promise<void>;
  /** NS access: the zone's own records with exactly this name. */
  findDnsRecords(zoneId: string, name: string): Promise<EdgeOneDnsRecord[]>;
  createDnsRecord(
    zoneId: string,
    r: { name: string; type: 'CNAME'; content: string; ttl?: number },
  ): Promise<string>;
  enableDnsRecords(zoneId: string, ids: string[]): Promise<void>;
  deleteDnsRecords(zoneId: string, ids: string[]): Promise<void>;
}

// --- errors ----------------------------------------------------------------------------------

/**
 * The short codes an EdgeOne error is reduced to: what the adapter and the
 * admin words act on. Tencent's own code goes with the refusal's words.
 */
export const EDGEONE_ERROR_CODES = [
  /** The SecretId is unknown, the signature or the session token does not verify. */
  'token_rejected',
  /** The CAM sub-user may not call the action (the refusal names it). */
  'permission_missing',
  /** The zone's plan does not allow it (a count, a feature, an expired or unbound plan). */
  'plan_limit',
  /** The domain needs an ICP filing for the zone's service area. */
  'icp_filing_required',
  /** Another Tencent account has the name on EdgeOne. */
  'domain_taken_elsewhere',
  /** The zone holds a DNS record at the name already. */
  'dns_record_exists',
  /** A free certificate is asked for before the name points at EdgeOne. */
  'tls_waiting_for_dns',
  /** Too many calls: retried later. */
  'rate_limited',
  /** The zone or the name is locked by another change: retried later. */
  'provider_busy',
  /** The zone, the domain or the record is not there. */
  'not_found',
  /** Tencent's own failure: retried later. */
  'provider_error',
  /** A parameter or an operation Tencent refused for good. */
  'refused',
] as const;
export type EdgeOneErrorCode = (typeof EDGEONE_ERROR_CODES)[number];

interface Reduced {
  status: number;
  code: EdgeOneErrorCode;
}

const PLAN_CODES = new Set([
  'OperationDenied.UnsupportedPlan',
  'OperationDenied.PlanHasBeenExpired',
  'OperationDenied.PlanHasBeenIsolated',
  'OperationDenied.PlanNotSupportModifyZoneArea',
  'InvalidParameter.ZoneHasNotBeenBoundToPlan',
  'InvalidParameter.InvalidResourceIdBilling',
  'InvalidParameter.InvalidQuicBilling',
]);
const BUSY_CODES = new Set([
  'OperationDenied.ResourceLockedTemporary',
  'OperationDenied.ConfigLocked',
  'InternalError.ConfigLocked',
  'OperationDenied.VersionControlIsGraying',
  'OperationDenied.VersionControlLocked',
  'InvalidParameter.ZoneIsGrayPublishing',
  'InvalidParameter.ActionInProgress',
]);
const NOT_FOUND_CODES = new Set([
  'ResourceNotFound',
  'InvalidParameter.ZoneNotFound',
  'InvalidParameter.DomainNotFound',
]);

/**
 * A Tencent error code -> what FCP does with it. Plan and quota refusals are a
 * definite 4xx (the run stops with `plan_limit` instead of retrying), auth is
 * 401 and a missing CAM grant 403 (both count against the account), a lock or
 * a rate limit passes (409 / 429, retried), Tencent's own failure is a 5xx.
 * Sources: https://www.tencentcloud.com/document/api/1145/50466 (common error
 * codes) and the error tables of each action, 2026-11-15.
 */
export function reduceEdgeOneCode(code: string): Reduced {
  if (code === 'AuthFailure.UnauthorizedOperation' || code.startsWith('UnauthorizedOperation'))
    return { status: 403, code: 'permission_missing' };
  if (code.startsWith('AuthFailure')) return { status: 401, code: 'token_rejected' };
  if (code.startsWith('RequestLimitExceeded') || code === 'LimitExceeded.RateLimitExceeded')
    return { status: 429, code: 'rate_limited' };
  if (
    code.startsWith('LimitExceeded') ||
    code.startsWith('ResourcesSoldOut') ||
    code === 'ResourceInsufficient' ||
    PLAN_CODES.has(code)
  )
    return { status: 400, code: 'plan_limit' };
  if (BUSY_CODES.has(code)) return { status: 409, code: 'provider_busy' };
  if (code === 'InvalidParameter.HostStatusNotAllowApplyCertificate')
    return { status: 409, code: 'tls_waiting_for_dns' };
  if (code === 'OperationDenied.DomainNoICP') return { status: 400, code: 'icp_filing_required' };
  if (code === 'ResourceUnavailable.DomainAlreadyExists')
    return { status: 400, code: 'domain_taken_elsewhere' };
  if (code === 'ResourceInUse.DnsRecord') return { status: 400, code: 'dns_record_exists' };
  if (NOT_FOUND_CODES.has(code) || /^ResourceUnavailable\.\w*NotFound$/.test(code))
    return { status: 404, code: 'not_found' };
  if (
    code.startsWith('InternalError') ||
    code === 'FailedOperation' ||
    code === 'ResourceUnavailable'
  )
    return { status: 500, code: 'provider_error' };
  return { status: 400, code: 'refused' };
}

interface SdkError {
  name?: unknown;
  message?: unknown;
  code?: unknown;
  httpCode?: unknown;
  requestId?: unknown;
}

/**
 * SDK rejection -> body-free `EdgeProviderError`. `action` is the API action
 * (`CreateAccelerationDomain`): it goes into the held-aside words as the CAM
 * action (`teo:CreateAccelerationDomain`) with Tencent's code, so a refusal
 * says what to grant without the code itself carrying a value.
 */
export function toEdgeOneError(
  step: string,
  action: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const e = (err ?? {}) as SdkError;
  const tencentCode =
    typeof e.code === 'string' && /^[A-Za-z][A-Za-z0-9.]{0,95}$/.test(e.code) ? e.code : undefined;
  const message = typeof e.message === 'string' ? e.message : '';
  if (!tencentCode) {
    // No API answer: an HTTP status from a gateway, or a transport failure.
    const status = typeof e.httpCode === 'number' ? e.httpCode : undefined;
    const timedOut = /timeout|timed out|aborted/i.test(message) || e.name === 'AbortError';
    return toProviderError(
      'edgeone',
      step,
      { status, name: timedOut ? 'TimeoutError' : 'Error', message: '' },
      secrets,
    );
  }
  const r = reduceEdgeOneCode(tencentCode);
  // The generic reducer keeps the status and the refusal's words (redacted,
  // held aside, or as the diagnostic detail of a credential test).
  const base = toProviderError(
    'edgeone',
    step,
    { status: r.status, name: 'Error', message: `${tencentCode} on teo:${action}: ${message}` },
    secrets,
  );
  const out = new EdgeProviderError(`edgeone ${r.status} on ${step} (${r.code})`, {
    ...base.meta,
    code: r.code,
  });
  return out.meta.detail ? out : withRefusal(out, refusalOf(base));
}

/** Not there (a zone, a domain, a record). */
export function isEdgeOneNotFound(err: unknown): boolean {
  return err instanceof EdgeProviderError && err.meta.code === 'not_found';
}

export function isEdgeOneCode(err: unknown, code: EdgeOneErrorCode): boolean {
  return err instanceof EdgeProviderError && err.meta.code === code;
}

// --- record readers (pure) -------------------------------------------------------------------

const lower = (s: string | undefined) => (s ?? '').trim().toLowerCase().replace(/\.$/, '');

export function zoneOf(z: Zone): EdgeOneZone {
  return {
    id: z.ZoneId ?? '',
    name: lower(z.ZoneName),
    ...(z.Type ? { type: z.Type } : {}),
    ...(z.Status ? { status: z.Status } : {}),
    ...(z.CnameStatus ? { cnameStatus: z.CnameStatus } : {}),
    ...(z.ActiveStatus ? { activeStatus: z.ActiveStatus } : {}),
    paused: z.Paused === true || z.ActiveStatus === 'paused',
    ...(z.Area ? { area: z.Area } : {}),
  };
}

/**
 * Whether a zone can carry fronts, in one word: `active`, `paused`, or the
 * state that keeps it from it. A CNAME-access zone is judged by its
 * verification (`cnameStatus`) only while its `status` is one of the two
 * name-server states (`pending`, which it keeps for good, or `active`); any
 * other status (`moved`, `deactivated`, `initializing`, `deleted`, or one
 * Tencent adds later) is returned as is, so it refuses under either mode.
 */
export function zoneState(z: EdgeOneZone): string {
  if (z.paused) return 'paused';
  if (z.type === 'partial' && (z.status === 'pending' || z.status === 'active'))
    return z.cnameStatus === 'finished' ? 'active' : 'pending';
  return z.status ?? 'unknown';
}

export function domainOf(d: AccelerationDomain): EdgeOneDomain {
  const o = d.OriginDetail;
  return {
    zoneId: d.ZoneId ?? '',
    name: lower(d.DomainName),
    ...(d.DomainStatus ? { status: d.DomainStatus } : {}),
    ...(d.Cname ? { cname: lower(d.Cname) } : {}),
    ...(d.IdentificationStatus ? { identification: d.IdentificationStatus } : {}),
    ...(o?.OriginType ? { originType: o.OriginType } : {}),
    ...(o?.Origin ? { origin: lower(o.Origin) } : {}),
    ...(o?.HostHeader ? { hostHeader: lower(o.HostHeader) } : {}),
    ...(d.OriginProtocol ? { originProtocol: d.OriginProtocol } : {}),
    ...(typeof d.HttpOriginPort === 'number' ? { httpPort: Number(d.HttpOriginPort) } : {}),
    ...(typeof d.HttpsOriginPort === 'number' ? { httpsPort: Number(d.HttpsOriginPort) } : {}),
    ...(d.IPv6Status ? { ipv6Status: d.IPv6Status } : {}),
    ...(d.Certificate?.Mode ? { certificateMode: d.Certificate.Mode } : {}),
    certificates: (d.Certificate?.List ?? []).map((c) => ({
      ...(c.CertId ? { id: c.CertId } : {}),
      ...(c.Type ? { type: c.Type } : {}),
      ...(c.Status ? { status: c.Status } : {}),
      ...(c.ExpireTime ? { expireTime: c.ExpireTime } : {}),
    })),
    restrictions: (d.ComplianceRestrictions ?? []).map((r) => r.Reason ?? '').filter(Boolean),
  };
}

export function dnsRecordOf(r: TeoDnsRecord): EdgeOneDnsRecord {
  return {
    id: r.RecordId ?? '',
    name: lower(r.Name),
    type: r.Type ?? '',
    content: lower(r.Content),
    ...(r.Status ? { status: r.Status } : {}),
    ...(typeof r.TTL === 'number' ? { ttl: Number(r.TTL) } : {}),
  };
}

// --- client construction ---------------------------------------------------------------------

/** Test seam: point the real SDK at an in-process recorder (`http://127.0.0.1:<port>`). */
let endpointOverride: string | null = null;
export function __setEdgeOneEndpoint(url: string | null): void {
  endpointOverride = url;
}

type ApiFactory = (cfg: EdgeOneConfig, diagnostic?: string) => EdgeOneApi;
/** Test seam: replace the whole API (the adapter tests' fake Tencent account). */
let apiFactory: ApiFactory | null = null;
export function __setEdgeOneApiFactory(f: ApiFactory | null): void {
  apiFactory = f;
}

/**
 * The API for one account. `diagnostic`: the step name every call reports
 * (`test`, `location`, `zones`), so a refusal behind "Test credentials" keeps
 * the provider's redacted words for the admin (http.ts `DIAGNOSTIC_STEPS`).
 */
export function edgeOneApiFor(cfg: EdgeOneConfig, diagnostic?: string): EdgeOneApi {
  if (apiFactory) return apiFactory(cfg, diagnostic);
  return edgeOneSdkApi(cfg, diagnostic);
}

function sdkClient(cfg: EdgeOneConfig) {
  const override = endpointOverride ? new URL(endpointOverride) : null;
  const host = override ? override.host : EDGEONE_API_HOSTS[cfg.site ?? 'intl'];
  const protocol = override ? `${override.protocol}//` : 'https://';
  // Its own agent: the SDK builds a proxy agent from `http_proxy` only when none is given.
  const agent = override?.protocol === 'http:' ? new http.Agent() : new https.Agent();
  return new teo.v20220901.Client({
    credential: {
      secretId: cfg.secretId,
      secretKey: cfg.secretKey,
      ...(cfg.sessionToken ? { token: cfg.sessionToken } : {}),
    },
    profile: {
      language: 'en-US',
      httpProfile: { endpoint: host, protocol, reqTimeout: EDGEONE_TIMEOUT_S, agent },
    },
  });
}

/** The SDK client's calls the wrapper makes (the real one, or a test's fake account). */
export type EdgeOneSdkClient = Pick<
  InstanceType<typeof teo.v20220901.Client>,
  | 'DescribeZones'
  | 'DescribeL7AccSetting'
  | 'DescribeAccelerationDomains'
  | 'CreateAccelerationDomain'
  | 'ModifyAccelerationDomainStatuses'
  | 'DeleteAccelerationDomains'
  | 'ModifyHostsCertificate'
  | 'DescribeDnsRecords'
  | 'CreateDnsRecord'
  | 'ModifyDnsRecordsStatus'
  | 'DeleteDnsRecords'
>;

export function edgeOneSdkApi(
  cfg: EdgeOneConfig,
  diagnostic?: string,
  client: EdgeOneSdkClient = sdkClient(cfg),
): EdgeOneApi {
  const secrets = [cfg.secretKey, ...(cfg.sessionToken ? [cfg.sessionToken] : [])];
  async function call<T>(step: string, action: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      throw toEdgeOneError(diagnostic ?? step, action, e, secrets);
    }
  }
  const exact = (name: string, value: string) => [{ Name: name, Values: [value], Fuzzy: false }];

  async function domainsWhere(
    zoneId: string,
    filters?: Array<{ Name: string; Values: string[]; Fuzzy: boolean }>,
  ): Promise<{ items: EdgeOneDomain[]; truncated: boolean }> {
    const items: EdgeOneDomain[] = [];
    for (let page = 0; page < MAX_PAGES; page++) {
      const out = await call('domain-list', 'DescribeAccelerationDomains', () =>
        client.DescribeAccelerationDomains({
          ZoneId: zoneId,
          Offset: page * PAGE_SIZE,
          Limit: PAGE_SIZE,
          ...(filters ? { Filters: filters } : {}),
        }),
      );
      const got = (out.AccelerationDomains ?? []).map(domainOf);
      items.push(...got);
      const total = Number(out.TotalCount ?? items.length);
      if (got.length < PAGE_SIZE || items.length >= total) return { items, truncated: false };
    }
    return { items, truncated: true };
  }

  return {
    async listZones(zoneId) {
      const items: EdgeOneZone[] = [];
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await call('zone-list', 'DescribeZones', () =>
          client.DescribeZones({
            Offset: page * PAGE_SIZE,
            Limit: PAGE_SIZE,
            ...(zoneId ? { Filters: exact('zone-id', zoneId) } : {}),
          }),
        );
        const got = (out.Zones ?? []).map(zoneOf);
        items.push(...got);
        const total = Number(out.TotalCount ?? items.length);
        if (got.length < PAGE_SIZE || items.length >= total) return { items, truncated: false };
      }
      return { items, truncated: true };
    },
    async zoneSettings(zoneId) {
      const out = await call('zone-settings', 'DescribeL7AccSetting', () =>
        client.DescribeL7AccSetting({ ZoneId: zoneId }),
      );
      const z = out.ZoneSetting?.ZoneConfig;
      return {
        ...(z?.WebSocket?.Switch ? { webSocket: z.WebSocket.Switch } : {}),
        ...(typeof z?.WebSocket?.Timeout === 'number'
          ? { webSocketTimeout: Number(z.WebSocket.Timeout) }
          : {}),
        ...(z?.ClientIPHeader?.Switch ? { clientIpHeader: z.ClientIPHeader.Switch } : {}),
        ...(z?.Grpc?.Switch ? { grpc: z.Grpc.Switch } : {}),
      };
    },
    async createDomain(s) {
      await call('domain-create', 'CreateAccelerationDomain', () =>
        client.CreateAccelerationDomain({
          ZoneId: s.zoneId,
          DomainName: s.name,
          OriginInfo: { OriginType: 'IP_DOMAIN', Origin: s.origin, HostHeader: s.hostHeader },
          OriginProtocol: s.originProtocol,
          HttpOriginPort: s.httpPort,
          HttpsOriginPort: s.httpsPort,
          IPv6Status: s.ipv6Status,
        }),
      );
    },
    async getDomain(zoneId, name) {
      const { items } = await domainsWhere(zoneId, exact('domain-name', name));
      return items.find((d) => d.name === lower(name)) ?? null;
    },
    listDomains: (zoneId) => domainsWhere(zoneId),
    async setDomainStatus(zoneId, name, status) {
      await call('domain-status', 'ModifyAccelerationDomainStatuses', () =>
        // Not forced, as the delete: only the domain itself is switched.
        client.ModifyAccelerationDomainStatuses({
          ZoneId: zoneId,
          DomainNames: [name],
          Status: status,
          Force: false,
        }),
      );
    },
    async deleteDomain(zoneId, name) {
      await call('domain-delete', 'DeleteAccelerationDomains', () =>
        // Not forced: Force would also delete what other features link to the name.
        client.DeleteAccelerationDomains({ ZoneId: zoneId, DomainNames: [name], Force: false }),
      );
    },
    async requestFreeCertificate(zoneId, host) {
      await call('certificate', 'ModifyHostsCertificate', () =>
        client.ModifyHostsCertificate({ ZoneId: zoneId, Hosts: [host], Mode: 'eofreecert' }),
      );
    },
    async findDnsRecords(zoneId, name) {
      // Tencent does not say whether a record's name is the full name or the
      // label under the zone: search by the label (a fuzzy match finds either
      // form), read a bare label as a name in the zone, keep the exact name.
      const fqdn = lower(name);
      const zone = lower(cfg.zoneName);
      const label = zone && fqdn.endsWith(`.${zone}`) ? fqdn.slice(0, -(zone.length + 1)) : fqdn;
      const out = await call('dns-list', 'DescribeDnsRecords', () =>
        client.DescribeDnsRecords({
          ZoneId: zoneId,
          Limit: PAGE_SIZE,
          Filters: [{ Name: 'name', Values: [label], Fuzzy: true }],
        }),
      );
      return (out.DnsRecords ?? [])
        .map(dnsRecordOf)
        .map((r) => (zone && r.name === label ? { ...r, name: fqdn } : r))
        .filter((r) => r.name === fqdn);
    },
    async createDnsRecord(zoneId, r) {
      const out = await call('dns-create', 'CreateDnsRecord', () =>
        client.CreateDnsRecord({
          ZoneId: zoneId,
          Name: r.name,
          Type: r.type,
          Content: r.content,
          ...(r.ttl ? { TTL: r.ttl } : {}),
        }),
      );
      if (!out.RecordId)
        throw new EdgeProviderError(`edgeone schema mismatch on dns-create [RecordId]`, {
          provider: 'edgeone',
          step: diagnostic ?? 'dns-create',
          code: 'schema_mismatch',
          retryable: false,
          timedOut: false,
        });
      return out.RecordId;
    },
    async enableDnsRecords(zoneId, ids) {
      await call('dns-enable', 'ModifyDnsRecordsStatus', () =>
        client.ModifyDnsRecordsStatus({ ZoneId: zoneId, RecordsToEnable: ids }),
      );
    },
    async deleteDnsRecords(zoneId, ids) {
      await call('dns-delete', 'DeleteDnsRecords', () =>
        client.DeleteDnsRecords({ ZoneId: zoneId, RecordIds: ids }),
      );
    },
  };
}
