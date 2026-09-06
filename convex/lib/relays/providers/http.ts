/**
 * Shared HTTP plumbing for the hand-rolled provider adapters.
 *
 * `RelayProviderError` deliberately carries NO response body text, NO URL and
 * NO headers: provider error bodies echo request fields (which may include an
 * origin address) and URLs may embed project ids or tokens. The most detail an
 * error holds is the HTTP status and a short provider error CODE, when the JSON
 * body carried one under a conventional key.
 */
import type { z } from 'zod';
import type { RelayProviderId } from '../../relayProviderIds';

export interface RelayProviderErrorMeta {
  provider: RelayProviderId;
  step: string;
  status?: number;
  code?: string;
  retryable: boolean;
  timedOut: boolean;
}

export class RelayProviderError extends Error {
  readonly meta: RelayProviderErrorMeta;
  constructor(message: string, meta: RelayProviderErrorMeta) {
    super(message);
    this.name = 'RelayProviderError';
    this.meta = meta;
  }
}

export function isProviderNotFound(err: unknown): boolean {
  return err instanceof RelayProviderError && err.meta.status === 404;
}

export function isProviderTimeout(err: unknown): boolean {
  return err instanceof RelayProviderError && err.meta.timedOut;
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
  provider: RelayProviderId;
  step: string;
  url: string;
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  body?: unknown;
  schema: z.ZodType<T>;
  timeoutMs?: number;
  /** Statuses treated as success with an `undefined` body (e.g. 404 on DELETE). */
  okStatuses?: number[];
}

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * One provider call: JSON in/out, AbortController timeout, schema-validated
 * response, body-free errors. A 2xx with an empty body parses as `undefined`
 * (callers of such routes use `z.unknown()`).
 */
export async function providerFetch<T>(a: ProviderFetchArgs<T>): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), a.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let res: Response;
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
    });
  } catch (err) {
    const timedOut = err instanceof Error && err.name === 'AbortError';
    throw new RelayProviderError(
      `${a.provider} ${timedOut ? 'timeout' : 'network error'} on ${a.step}`,
      { provider: a.provider, step: a.step, retryable: true, timedOut },
    );
  } finally {
    clearTimeout(timer);
  }
  let text = '';
  try {
    text = await res.text();
  } catch {
    text = '';
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
    throw new RelayProviderError(
      `${a.provider} ${res.status} on ${a.step}${code ? ` (${code})` : ''}`,
      {
        provider: a.provider,
        step: a.step,
        status: res.status,
        code,
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
    throw new RelayProviderError(`${a.provider} schema mismatch on ${a.step} [${issues}]`, {
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
  provider: RelayProviderId,
  step: string,
  err: unknown,
): RelayProviderError {
  if (err instanceof RelayProviderError) return err;
  const anyErr = err as { status?: unknown; name?: unknown; message?: unknown } | null;
  const status = typeof anyErr?.status === 'number' ? anyErr.status : undefined;
  const timedOut = anyErr?.name === 'AbortError' || anyErr?.name === 'TimeoutError';
  const code =
    typeof anyErr?.name === 'string' && anyErr.name !== 'Error' && anyErr.name.length <= 64
      ? anyErr.name
      : undefined;
  return new RelayProviderError(
    `${provider} ${status ?? (timedOut ? 'timeout' : 'error')} on ${step}${code ? ` (${code})` : ''}`,
    {
      provider,
      step,
      status,
      code,
      retryable: timedOut || status === 429 || (status !== undefined && status >= 500),
      timedOut,
    },
  );
}
