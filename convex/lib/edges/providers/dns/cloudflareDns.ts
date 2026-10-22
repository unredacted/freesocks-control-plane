'use node';
/**
 * Cloudflare DNS on the official TypeScript SDK (`cloudflare@7.1.0`).
 *
 * This module owns the ONE Cloudflare client factory the whole subsystem uses:
 * the L7 Cloudflare adapter (its own zone) and the Fastly adapter (the
 * referenced DNS account's zone) both go through it, so there is a single
 * place where retries, logging, the API version and error hygiene are pinned.
 *
 * Client options, and why each one is not the SDK default:
 *  - `maxRetries: 0`: the SDK otherwise replays 408/409/429/5xx and timeouts.
 *    An allocating POST that is replayed blindly mints a second resource; this
 *    subsystem retries ONLY through `discover()` (docs/edges.md, four-outcome
 *    discovery), so the transport must never retry on its own.
 *  - `logLevel: 'off'`: the SDK's debug logger prints request URLs, headers
 *    (including the bearer token) and raw error bodies.
 *  - `apiVersion`: the SDK defaults it to TODAY'S date (`new Date()` at
 *    construction) and sends it as the `api-version` request header, so an
 *    unpinned client changes its wire behaviour overnight.
 *  - `timeout: 15_000`: matches providerFetch's budget for the hand-rolled
 *    adapters.
 *
 * Error hygiene: `Cloudflare.APIError.message` embeds the response body, which
 * echoes request fields (an origin address, a zone name) and sometimes the
 * token's own description. Only the HTTP status and the NUMERIC Cloudflare
 * error code (`errors[0].code`) ever leave this module.
 */
import Cloudflare, { APIConnectionError, APIConnectionTimeoutError, APIError } from 'cloudflare';
import type { CloudflareDnsConfig } from '../types';
import {
  EdgeProviderError,
  capturesErrorDetail,
  isRefusal,
  redactErrorDetail,
  withRefusal,
} from '../http';
import type { DnsClient, DnsCreateArgs, DnsRecord, DnsRecordType } from './types';

export type FetchLike = typeof fetch;

/**
 * The API version pinned into every request (`api-version` header). Bump it
 * deliberately, with the wire-contract fixtures re-taken from the docs.
 * Source: https://developers.cloudflare.com/api/ (API versioning), 2026-09-16.
 */
export const CLOUDFLARE_API_VERSION = '2026-09-16';
export const CLOUDFLARE_TIMEOUT_MS = 15_000;

/** Just the credential part of a config: both CloudflareConfig and CloudflareDnsConfig satisfy it. */
export interface CloudflareTokenConfig {
  apiToken: string;
}

/**
 * Build the SDK client. `fetchImpl` is injectable for tests; when it is absent
 * the call resolves `globalThis.fetch` LATE, so a test that stubs the global
 * after construction is still observed.
 */
export function cloudflareApi(cfg: CloudflareTokenConfig, fetchImpl?: FetchLike): Cloudflare {
  return new Cloudflare({
    apiToken: cfg.apiToken,
    fetch: fetchImpl ?? ((input, init) => globalThis.fetch(input as never, init as never)),
    maxRetries: 0,
    timeout: CLOUDFLARE_TIMEOUT_MS,
    logLevel: 'off',
    apiVersion: CLOUDFLARE_API_VERSION,
  });
}

type ApiFactory = (cfg: CloudflareTokenConfig, fetchImpl?: FetchLike) => Cloudflare;

let apiFactory: ApiFactory = cloudflareApi;

/** Test seam: replace the SDK client factory (the Scaleway pattern). */
export function __setCloudflareApiFactory(f: ApiFactory | null): void {
  apiFactory = f ?? cloudflareApi;
}

/** The client every Cloudflare call in this subsystem goes through. */
export function cloudflareClient(cfg: CloudflareTokenConfig, fetchImpl?: FetchLike): Cloudflare {
  return apiFactory(cfg, fetchImpl);
}

/**
 * Reduce any SDK throwable to the provider error class. The message holds the
 * `status` and the numeric `errors[0].code` only; `meta.detail` holds the
 * envelope's redacted `errors[].message` texts for the admin on a diagnostic
 * step (on any other refused call they are held aside: `refusalOf`). Never headers or
 * the URL. See https://developers.cloudflare.com/api/ (error envelope).
 */
export function cloudflareError(
  step: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const status = err instanceof APIError && typeof err.status === 'number' ? err.status : undefined;
  let code: string | undefined;
  let detail: string | undefined;
  const diagnostic = capturesErrorDetail(step);
  if (err instanceof APIError && Array.isArray(err.errors)) {
    const first = err.errors[0]?.code;
    if (typeof first === 'number' && Number.isFinite(first)) code = String(first);
    if (diagnostic || isRefusal(status))
      detail = redactErrorDetail(
        err.errors
          .map((x) => (typeof x?.message === 'string' ? `${x.code ?? ''} ${x.message}`.trim() : ''))
          .filter(Boolean)
          .join('; '),
        secrets,
      );
  }
  const timedOut = err instanceof APIConnectionTimeoutError;
  const connection = err instanceof APIConnectionError;
  const out = new EdgeProviderError(
    `cloudflare ${status ?? (timedOut ? 'timeout' : 'error')} on ${step}${code ? ` (${code})` : ''}`,
    {
      provider: 'cloudflare',
      step,
      status,
      code,
      detail: diagnostic ? detail : undefined,
      retryable:
        timedOut || connection || status === 429 || (status !== undefined && status >= 500),
      timedOut,
    },
  );
  // A refusal of any other call: its words held aside for the ops layer (http.ts).
  return diagnostic ? out : withRefusal(out, detail);
}

/** Every SDK call goes through here so no raw SDK error can escape. */
export async function cfCall<T>(
  step: string,
  fn: () => Promise<T>,
  secrets: string[] = [],
): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw cloudflareError(step, e, secrets);
  }
}

export function isCloudflareNotFound(err: unknown): boolean {
  return err instanceof EdgeProviderError && err.meta.status === 404;
}

/**
 * Cloudflare's answer to a token it does not recognise at the endpoint asked:
 * `1000 Invalid API Token`, under 401 (or 403 on some edges of the API).
 */
const INVALID_TOKEN_CODE = '1000';

function tokenNotRecognised(err: unknown): boolean {
  if (!(err instanceof EdgeProviderError) || err.meta.retryable) return false;
  return err.meta.code === INVALID_TOKEN_CODE || err.meta.status === 401 || err.meta.status === 403;
}

/** Which kind of token passed, and its status (`active`, `disabled`, `expired`). */
export interface CloudflareTokenCheck {
  kind: 'user' | 'account';
  status: string;
}

/**
 * Verify an API token of EITHER kind Cloudflare issues:
 *  - a user token (created under My Profile) verifies at `/user/tokens/verify`;
 *  - an account-owned token (created under the account, the kind Cloudflare
 *    recommends for automation) verifies only at
 *    `/accounts/{account_id}/tokens/verify`. The user endpoint answers it with
 *    `1000 Invalid API Token`, exactly as it answers a token that is wrong.
 *
 * So the user endpoint is asked first and a token it does not recognise is
 * asked again at the account endpoint. `accountIdOf` is only called then: the
 * account id comes from the zone the token reads (authoritative: an account
 * token can only read its own account's zones) or the account settings.
 * A retryable answer (429, 5xx, a timeout) is never taken for a rejection.
 *
 * Rejected at both, or with no account id to ask with, the token is refused
 * as `token_rejected`: a short code the admin console words, with the
 * provider's own (redacted) answer kept as `detail`.
 * Source: https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/
 * via cloudflare@7.1.0 (`client.accounts.tokens.verify`), 2026-10-20.
 */
export async function verifyCloudflareToken(
  cfg: CloudflareTokenConfig,
  accountIdOf: () => Promise<string | undefined>,
  step = 'test',
): Promise<CloudflareTokenCheck> {
  const client = cloudflareClient(cfg);
  let userAnswer: EdgeProviderError;
  try {
    const token = await cfCall(step, () => client.user.tokens.verify(), [cfg.apiToken]);
    return { kind: 'user', status: token.status };
  } catch (e) {
    if (!tokenNotRecognised(e)) throw e;
    userAnswer = e as EdgeProviderError;
  }
  const accountId = await accountIdOf();
  if (!accountId) throw rejected(step, userAnswer);
  try {
    const token = await cfCall(
      step,
      () => client.accounts.tokens.verify({ account_id: accountId }),
      [cfg.apiToken],
    );
    return { kind: 'account', status: token.status };
  } catch (e) {
    if (!tokenNotRecognised(e)) throw e;
    throw rejected(step, e as EdgeProviderError);
  }
}

function rejected(step: string, answer: EdgeProviderError): EdgeProviderError {
  return new EdgeProviderError(`cloudflare token rejected on ${step}`, {
    provider: 'cloudflare',
    step,
    status: answer.meta.status,
    code: 'token_rejected',
    ...(answer.meta.detail ? { detail: answer.meta.detail } : {}),
    retryable: false,
    timedOut: false,
  });
}

/** The record fields this subsystem reads; the SDK's response is a 20-way union. */
interface RawRecord {
  id: string;
  name: string;
  type: string;
  content?: string;
  proxied?: boolean;
  comment?: string;
  ttl?: number;
  data?: { flags?: number; tag?: string; value?: string };
}

/** Cloudflare returns names lowercased and in Punycode; comparisons are case-insensitive. */
export function normalizeDnsName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

function toDnsRecord(raw: RawRecord): DnsRecord {
  return {
    id: raw.id,
    type: raw.type as DnsRecordType,
    name: normalizeDnsName(raw.name),
    content: raw.content ?? '',
    proxied: raw.proxied === true,
    ...(raw.comment !== undefined ? { comment: raw.comment } : {}),
  };
}

/**
 * A `DnsClient` bound to one zone of one Cloudflare account.
 *
 * `findRecordsByName` is deliberately ONE request: the SDK's `for await`
 * iteration over a page promise costs N+1 requests against a rate limit shared
 * with the dashboard (1,200 requests / 5 min per user), and the exact-name
 * filter already bounds the answer to a handful of rows.
 */
export function cloudflareDnsClient(cfg: CloudflareDnsConfig, fetchImpl?: FetchLike): DnsClient {
  const client = cloudflareClient(cfg, fetchImpl);
  const zone_id = cfg.zoneId;

  return {
    zoneId: cfg.zoneId,
    zoneName: cfg.zoneName,
    accountId: cfg.accountId,

    async createRecord(args: DnsCreateArgs): Promise<DnsRecord> {
      // ttl 1 = "automatic": the only value a proxied record accepts.
      const body = {
        zone_id,
        type: args.type,
        name: normalizeDnsName(args.name),
        content: args.content,
        proxied: args.proxied,
        ttl: args.proxied ? 1 : (args.ttl ?? 1),
        comment: args.comment,
        ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
        ...(args.settings && Object.keys(args.settings).length > 0
          ? { settings: args.settings }
          : {}),
      };
      const rec = await cfCall(
        'dns-create',
        () =>
          // The SDK's params type is a discriminated union over `type`; the body
          // is built from a runtime value, so the union is resolved here.
          client.dns.records.create(body as never),
        [cfg.apiToken],
      );
      return toDnsRecord(rec as unknown as RawRecord);
    },

    async findRecordsByName(name: string, type?: DnsRecordType): Promise<DnsRecord[]> {
      const wanted = normalizeDnsName(name);
      const page = await cfCall(
        'dns-list',
        () =>
          client.dns.records.list({
            zone_id,
            name: { exact: wanted },
            ...(type ? { type } : {}),
            per_page: 5,
          }),
        [cfg.apiToken],
      );
      return (page.result as unknown as RawRecord[])
        .map(toDnsRecord)
        .filter((r) => r.name === wanted);
    },

    async getRecord(id: string): Promise<DnsRecord | null> {
      try {
        const rec = await cfCall('dns-get', () => client.dns.records.get(id, { zone_id }), [
          cfg.apiToken,
        ]);
        return toDnsRecord(rec as unknown as RawRecord);
      } catch (e) {
        if (isCloudflareNotFound(e)) return null;
        throw e;
      }
    },

    async deleteRecord(id: string): Promise<void> {
      try {
        await cfCall('dns-delete', () => client.dns.records.delete(id, { zone_id }), [
          cfg.apiToken,
        ]);
      } catch (e) {
        // Already gone is the outcome the caller wanted (idempotent destroy).
        if (isCloudflareNotFound(e)) return;
        throw e;
      }
    },

    async readZone() {
      const zone = await cfCall('location', () => client.zones.get({ zone_id }), [cfg.apiToken]);
      const plan = (zone.plan as { legacy_id?: string } | undefined)?.legacy_id;
      return {
        id: zone.id,
        name: normalizeDnsName(zone.name),
        status: typeof zone.status === 'string' ? zone.status : 'unknown',
        paused: zone.paused === true,
        ...(plan ? { plan } : {}),
      };
    },

    async flattensAllCnames(): Promise<boolean | null> {
      try {
        const setting = await cfCall(
          'location',
          () => client.zones.settings.get('cname_flattening', { zone_id }),
          [cfg.apiToken],
        );
        const value = (setting as unknown as { value?: unknown }).value;
        return value === 'flatten_all' ? true : value === 'flatten_at_root' ? false : null;
      } catch (e) {
        // A token without Zone Settings Read: unknown, never a refusal.
        if (e instanceof EdgeProviderError && (e.meta.status ?? 500) < 500) return null;
        throw e;
      }
    },

    async listCaa(): Promise<Array<{ flags: number; tag: string; value: string }>> {
      const apex = normalizeDnsName(cfg.zoneName);
      const page = await cfCall(
        'dns-caa',
        () =>
          client.dns.records.list({ zone_id, name: { exact: apex }, type: 'CAA', per_page: 100 }),
        [cfg.apiToken],
      );
      return (page.result as unknown as RawRecord[]).map((r) => ({
        flags: r.data?.flags ?? 0,
        tag: r.data?.tag ?? '',
        value: r.data?.value ?? '',
      }));
    },
  };
}
