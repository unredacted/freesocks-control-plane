/**
 * Shared HTTP plumbing for the hand-rolled provider adapters.
 *
 * `EdgeProviderError` carries NO URL and NO headers: URLs may embed project ids
 * or tokens. Its MESSAGE (what gets thrown, logged and audited) holds only the
 * HTTP status and a short provider error CODE, when the JSON body carried one
 * under a conventional key.
 *
 * `meta.detail` is the one exception, for the operator who has to debug a
 * refusal: a bounded excerpt of the provider's error body, with address
 * literals and the credential replaced. It is captured ONLY on the calls an
 * admin makes by hand before anything exists (`DIAGNOSTIC_STEPS`: the
 * credential test and the account form's listings). Those requests carry no
 * origin and no fronted hostname, so the answer cannot echo one; every
 * provisioning, describe and destroy error stays body-free. The detail is
 * shown to admins and never goes into a message, a log line or an audit row.
 */
import type { z } from 'zod';
import type { EdgeProviderId } from '../../edgeProviderIds';

export interface RelayProviderErrorMeta {
  provider: EdgeProviderId;
  step: string;
  status?: number;
  code?: string;
  /** Redacted excerpt of the provider's error body; admin display only. */
  detail?: string;
  retryable: boolean;
  timedOut: boolean;
}

/**
 * The step names of the read-only calls behind "Test credentials" and the
 * account form's choice lists, across every adapter. Only these capture
 * `meta.detail`.
 */
const DIAGNOSTIC_STEPS = new Set([
  'test',
  'token-self',
  'customer',
  'projects',
  'project',
  'regions',
  'region-probe',
  'zones',
  'networks',
  'subnets',
  'tls-configurations',
]);
export const capturesErrorDetail = (step: string): boolean => DIAGNOSTIC_STEPS.has(step);

/** Longest error-body excerpt kept on an error. */
export const MAX_ERROR_DETAIL_CHARS = 600;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9:])/g;

/**
 * An error body made safe to show an admin: address literals and every secret
 * in `secrets` (request header values, 8+ chars, and their scheme-less tails)
 * are replaced, whitespace is collapsed, and the result is capped.
 */
export function redactErrorDetail(text: string, secrets: string[] = []): string | undefined {
  let out = text;
  for (const raw of secrets) {
    for (const s of [raw, raw.split(' ').pop() ?? '']) {
      if (s.length >= 8) out = out.split(s).join('[redacted]');
    }
  }
  out = out
    .replace(IPV4_RE, '[address]')
    .replace(IPV6_RE, (m) => (m.replace(/:/g, '').length >= 4 ? '[address]' : m))
    .replace(/\s+/g, ' ')
    .trim();
  if (out.length === 0) return undefined;
  return out.length > MAX_ERROR_DETAIL_CHARS ? `${out.slice(0, MAX_ERROR_DETAIL_CHARS)}…` : out;
}

/** The failing half of a credential test, from whatever the adapter caught. */
export function credentialTestFailure(e: unknown): { ok: false; code: string; detail?: string } {
  if (e instanceof EdgeProviderError) {
    return {
      ok: false,
      code: e.meta.code ?? String(e.meta.status ?? 'error'),
      ...(e.meta.detail ? { detail: e.meta.detail } : {}),
    };
  }
  return { ok: false, code: 'error' };
}

/**
 * Record one failed listing of the account form: its code under `errors`, and
 * the provider's redacted answer (when there was one) under `errorDetails`.
 */
export function noteDiscoverError(
  out: { errors?: Record<string, string>; errorDetails?: Record<string, string> },
  list: string,
  e: unknown,
): void {
  const f = credentialTestFailure(e);
  (out.errors ??= {})[list] = f.code;
  if (f.detail) (out.errorDetails ??= {})[list] = f.detail;
}

export class EdgeProviderError extends Error {
  readonly meta: RelayProviderErrorMeta;
  constructor(message: string, meta: RelayProviderErrorMeta) {
    super(message);
    this.name = 'EdgeProviderError';
    this.meta = meta;
  }
}

export function isProviderNotFound(err: unknown): boolean {
  return err instanceof EdgeProviderError && err.meta.status === 404;
}

export function isProviderTimeout(err: unknown): boolean {
  return err instanceof EdgeProviderError && err.meta.timedOut;
}

/** A short error code from a JSON error body, under the keys providers use; else undefined. */
export function extractErrorCode(json: unknown): string | undefined {
  if (!json || typeof json !== 'object') return undefined;
  const o = json as Record<string, unknown>;
  const direct = o.code ?? o.error_code ?? o.errorCode ?? o.type ?? o.class ?? o.error;
  if (typeof direct === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(direct)) return direct;
  if (direct && typeof direct === 'object') {
    const inner =
      (direct as Record<string, unknown>).error_code ?? (direct as Record<string, unknown>).code;
    if (typeof inner === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(inner)) return inner;
  }
  const errors = o.errors;
  if (Array.isArray(errors) && errors.length > 0) return extractErrorCode(errors[0]);
  return undefined;
}

export interface ProviderFetchArgs<T> {
  provider: EdgeProviderId;
  step: string;
  url: string;
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  body?: unknown;
  schema: z.ZodType<T>;
  timeoutMs?: number;
  /** Statuses treated as success with an `undefined` body (e.g. 404 on DELETE). */
  okStatuses?: number[];
  /** Secrets that are NOT a request header value (a signing secret): redacted from `meta.detail`. */
  secrets?: string[];
}

const DEFAULT_TIMEOUT_MS = 15_000;
/** Largest response body read (provider objects are small; a listing is paged). */
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

/**
 * Read at most `limit` bytes of a body; `null` when the body is larger. Reads
 * the stream incrementally so an oversized answer never fully buffers.
 */
async function readBounded(res: Response, limit: number): Promise<string | null> {
  const declared = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > limit) return null;
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  }
  const joined = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    joined.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(joined);
}

/**
 * One provider call: JSON in/out, AbortController timeout, schema-validated
 * response, body-free errors. A 2xx with an empty body parses as `undefined`
 * (callers of such routes use `z.unknown()`).
 *
 * Redirects are never followed (`redirect: 'manual'` + a refusal): the request
 * carries credentials in its headers and a redirect would replay them against
 * another host. The body read is capped at `MAX_RESPONSE_BYTES`. There is NO
 * retry here on purpose — POST/DELETE are not idempotent at every provider;
 * the orchestrator retries through discovery instead.
 */
export async function providerFetch<T>(a: ProviderFetchArgs<T>): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), a.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let res: Response;
  let text = '';
  try {
    try {
      res = await fetch(a.url, {
        method: a.method,
        headers: {
          accept: 'application/json',
          ...(a.body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...a.headers,
        },
        body: a.body !== undefined ? JSON.stringify(a.body) : undefined,
        signal: controller.signal,
        redirect: 'manual',
      });
    } catch (err) {
      const timedOut = err instanceof Error && err.name === 'AbortError';
      throw new EdgeProviderError(
        `${a.provider} ${timedOut ? 'timeout' : 'network error'} on ${a.step}`,
        { provider: a.provider, step: a.step, retryable: true, timedOut },
      );
    }
    if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
      throw new EdgeProviderError(`${a.provider} redirect refused on ${a.step}`, {
        provider: a.provider,
        step: a.step,
        status: res.status || undefined,
        code: 'redirect_refused',
        retryable: false,
        timedOut: false,
      });
    }
    let bounded: string | null;
    try {
      bounded = await readBounded(res, MAX_RESPONSE_BYTES);
    } catch (err) {
      const timedOut = err instanceof Error && err.name === 'AbortError';
      if (timedOut)
        throw new EdgeProviderError(`${a.provider} timeout on ${a.step}`, {
          provider: a.provider,
          step: a.step,
          retryable: true,
          timedOut: true,
        });
      bounded = '';
    }
    if (bounded === null) {
      throw new EdgeProviderError(`${a.provider} response too large on ${a.step}`, {
        provider: a.provider,
        step: a.step,
        status: res.status,
        code: 'response_too_large',
        retryable: false,
        timedOut: false,
      });
    }
    text = bounded;
  } finally {
    clearTimeout(timer);
  }
  let json: unknown = undefined;
  if (text.trim().length > 0) {
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
  }
  if (!res.ok && !(a.okStatuses ?? []).includes(res.status)) {
    const code = extractErrorCode(json);
    throw new EdgeProviderError(
      `${a.provider} ${res.status} on ${a.step}${code ? ` (${code})` : ''}`,
      {
        provider: a.provider,
        step: a.step,
        status: res.status,
        code,
        detail: capturesErrorDetail(a.step)
          ? redactErrorDetail(text, [...Object.values(a.headers), ...(a.secrets ?? [])])
          : undefined,
        retryable: res.status === 429 || res.status >= 500,
        timedOut: false,
      },
    );
  }
  if ((a.okStatuses ?? []).includes(res.status) && !res.ok) {
    return undefined as T;
  }
  const parsed = a.schema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .slice(0, 6)
      .map((i) => i.path.join('.') || '(root)')
      .join(', ');
    throw new EdgeProviderError(`${a.provider} schema mismatch on ${a.step} [${issues}]`, {
      provider: a.provider,
      step: a.step,
      status: res.status,
      code: 'schema_mismatch',
      retryable: false,
      timedOut: false,
    });
  }
  return parsed.data;
}

/** Wrap an SDK/other error into the body-free error class (idempotent). */
export function toProviderError(
  provider: EdgeProviderId,
  step: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const anyErr = err as { status?: unknown; name?: unknown; message?: unknown } | null;
  const status = typeof anyErr?.status === 'number' ? anyErr.status : undefined;
  const timedOut = anyErr?.name === 'AbortError' || anyErr?.name === 'TimeoutError';
  const code =
    typeof anyErr?.name === 'string' && anyErr.name !== 'Error' && anyErr.name.length <= 64
      ? anyErr.name
      : undefined;
  return new EdgeProviderError(
    `${provider} ${status ?? (timedOut ? 'timeout' : 'error')} on ${step}${code ? ` (${code})` : ''}`,
    {
      provider,
      step,
      status,
      code,
      // An SDK error's message is the provider's own explanation of the refusal.
      detail:
        capturesErrorDetail(step) && typeof anyErr?.message === 'string'
          ? redactErrorDetail(anyErr.message, secrets)
          : undefined,
      retryable: timedOut || status === 429 || (status !== undefined && status >= 500),
      timedOut,
    },
  );
}
