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
 * credential test, the account form's listings and a location check). Those
 * requests carry no origin and no fronted hostname, so the answer cannot echo
 * one; every provisioning, describe and destroy error stays body-free.
 *
 * A REFUSAL (a 4xx) of any other call keeps the provider's words too, made safe
 * the same way, but never on the error itself: such an answer may echo what
 * the request carried (the edge's resource name, its fronted hostname), and an
 * error object can end up logged. It is held aside (`refusalOf`), and the ops
 * layer (edgeProviderOps `toOpsFailure`) forwards it only from a create step,
 * after `scrubNames` replaced every name the edge is known by. Neither ever
 * goes into a message, a log line or an audit row.
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
  'flavors',
  'tls-configurations',
  'location',
]);
export const capturesErrorDetail = (step: string): boolean => DIAGNOSTIC_STEPS.has(step);

/** Whether an answer is the provider REFUSING the call (its own reason, not an outage). */
export const isRefusal = (status: number | undefined): boolean =>
  status !== undefined && status >= 400 && status < 500;

/**
 * The provider's redacted words on a refused call that is not a diagnostic one,
 * kept OFF the error object (a WeakMap entry: no property, so no log line,
 * `JSON.stringify` or inspection of the error shows it).
 */
const refusals = new WeakMap<EdgeProviderError, string>();

/** Hold a refusal's redacted words aside for the ops layer; returns the error. */
export function withRefusal(err: EdgeProviderError, said: string | undefined): EdgeProviderError {
  if (said) refusals.set(err, said);
  return err;
}

/**
 * What the provider said on a failed call: the diagnostic `meta.detail`, else
 * the refusal held aside. Only the ops layer reads it (scrubbed before it
 * leaves the action) and an adapter that turns a refusal into a known outcome.
 */
export function refusalOf(err: unknown): string | undefined {
  if (!(err instanceof EdgeProviderError)) return undefined;
  return err.meta.detail ?? refusals.get(err);
}

/** Longest error-body excerpt kept on an error. */
export const MAX_ERROR_DETAIL_CHARS = 600;

/** Shortest secret that is replaced in place; a shorter one suppresses the detail. */
const MIN_REDACTABLE_SECRET_CHARS = 8;

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9:])/g;

/**
 * An error body made safe to show an admin: address literals and every secret
 * in `secrets` (request header values and their scheme-less tails) are
 * replaced, whitespace is collapsed, and the result is capped.
 *
 * A secret too short to replace safely (under 8 characters: replacing it would
 * shred the text, and leaving it would show it) means NO detail at all. An
 * echoed short credential must never reach the UI or `lastTestErrorDetail`.
 */
export function redactErrorDetail(text: string, secrets: string[] = []): string | undefined {
  let out = text;
  for (const raw of secrets) {
    for (const s of new Set([raw, raw.split(' ').pop() ?? ''])) {
      if (s.length === 0) continue;
      if (s.length < MIN_REDACTABLE_SECRET_CHARS) return undefined;
      out = out.split(s).join('[redacted]');
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

/** Shortest name `scrubNames` looks for (a shorter one would shred ordinary words). */
const MIN_SCRUBBED_NAME_CHARS = 3;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * A detail with every name an edge is known by replaced (`[name]`): its
 * resource name, fronted hostname, certificate names, zone, origin. Matched
 * without regard to case (a provider may echo a hostname lowered), longest
 * first so a hostname goes before the zone inside it. A detail
 * `redactErrorDetail` capped may end inside a name: a trailing fragment that
 * starts a name is cut too, so no part of one survives the cap.
 */
export function scrubNames(detail: string | undefined, names: string[]): string | undefined {
  if (!detail) return undefined;
  const wanted = [
    ...new Set(names.map((n) => n.trim()).filter((n) => n.length >= MIN_SCRUBBED_NAME_CHARS)),
  ].sort((a, b) => b.length - a.length);
  let out = detail;
  for (const n of wanted) out = out.replace(new RegExp(escapeRe(n), 'gi'), '[name]');
  if (out.endsWith('…')) {
    const body = out.slice(0, -1);
    const lower = body.toLowerCase();
    let cut = 0;
    for (const n of wanted) {
      const ln = n.toLowerCase();
      for (let k = Math.min(ln.length - 1, lower.length); k > cut; k--)
        if (lower.endsWith(ln.slice(0, k))) {
          cut = k;
          break;
        }
    }
    out = `${body.slice(0, body.length - cut)}…`;
  }
  return out.trim().length > 0 ? out : undefined;
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
    const secrets = [...Object.values(a.headers), ...(a.secrets ?? [])];
    const diagnostic = capturesErrorDetail(a.step);
    const err = new EdgeProviderError(
      `${a.provider} ${res.status} on ${a.step}${code ? ` (${code})` : ''}`,
      {
        provider: a.provider,
        step: a.step,
        status: res.status,
        code,
        detail: diagnostic ? redactErrorDetail(text, secrets) : undefined,
        retryable: res.status === 429 || res.status >= 500,
        timedOut: false,
      },
    );
    throw !diagnostic && isRefusal(res.status)
      ? withRefusal(err, redactErrorDetail(text, secrets))
      : err;
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

/**
 * The generic error class of an SDK, whose message keeps only part of the
 * answer: Scaleway's `ScalewayError` builds it from `message`, `resource` and
 * `fields`, while its specific classes (`InvalidArgumentsError`, ...) word the
 * whole answer themselves.
 */
const GENERIC_SDK_ERRORS = new Set(['ScalewayError']);

/**
 * What an SDK error says about the refusal: its message (the SDKs build it from
 * the answer's own words), plus, for a generic error class, whatever else the
 * JSON error body it kept carries.
 */
function sdkErrorText(err: { name?: unknown; message?: unknown; body?: unknown }): string {
  const message = typeof err.message === 'string' ? err.message : '';
  const body = err.body;
  if (
    typeof err.name !== 'string' ||
    !GENERIC_SDK_ERRORS.has(err.name) ||
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body)
  )
    return message;
  const { message: _m, resource: _r, fields: _f, ...rest } = body as Record<string, unknown>;
  return Object.keys(rest).length > 0 ? `${message} ${JSON.stringify(rest)}` : message;
}

/** Wrap an SDK/other error into the body-free error class (idempotent). */
export function toProviderError(
  provider: EdgeProviderId,
  step: string,
  err: unknown,
  secrets: string[] = [],
): EdgeProviderError {
  if (err instanceof EdgeProviderError) return err;
  const anyErr = err as {
    status?: unknown;
    name?: unknown;
    message?: unknown;
    body?: unknown;
  } | null;
  const status = typeof anyErr?.status === 'number' ? anyErr.status : undefined;
  const timedOut = anyErr?.name === 'AbortError' || anyErr?.name === 'TimeoutError';
  const code =
    typeof anyErr?.name === 'string' && anyErr.name !== 'Error' && anyErr.name.length <= 64
      ? anyErr.name
      : undefined;
  // An SDK error's message is the provider's own explanation of the refusal.
  const diagnostic = capturesErrorDetail(step);
  const said =
    anyErr && (diagnostic || isRefusal(status))
      ? redactErrorDetail(sdkErrorText(anyErr), secrets)
      : undefined;
  const out = new EdgeProviderError(
    `${provider} ${status ?? (timedOut ? 'timeout' : 'error')} on ${step}${code ? ` (${code})` : ''}`,
    {
      provider,
      step,
      status,
      code,
      detail: diagnostic ? said : undefined,
      retryable: timedOut || status === 429 || (status !== undefined && status >= 500),
      timedOut,
    },
  );
  return diagnostic ? out : withRefusal(out, said);
}
