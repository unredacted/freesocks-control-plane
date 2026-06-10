import type { z } from 'zod';
import type { ApiError } from '../../shared/contracts/common';
import { openInbound, prepareOutbound } from './e2ee';
import { augmentLoginBody, signedHeaders } from './pop';

/**
 * Coerce ANY error body into our `{ error: { code, message } }` envelope so
 * `err.payload.error.message` is always safe for consumers (P1-8). A non-JSON
 * body (a reverse-proxy 502 HTML page) or a bare upstream error otherwise leaves
 * `payload.error` undefined and throws inside the consumer's onError handler.
 */
function toEnvelope(status: number, body: unknown): { error: { code: string; message: string } } {
  const e = (body as { error?: { code?: unknown; message?: unknown } } | null)?.error;
  if (e && typeof e.message === 'string') {
    return {
      error: { code: typeof e.code === 'string' ? e.code : `http.${status}`, message: e.message },
    };
  }
  return { error: { code: `http.${status}`, message: `Request failed (${status})` } };
}

class ApiCallError extends Error {
  readonly payload: { error: { code: string; message: string } };
  constructor(
    public readonly status: number,
    payload: z.infer<typeof ApiError> | { error: { code: string; message: string } } | unknown,
  ) {
    const envelope = toEnvelope(status, payload);
    super(envelope.error.message);
    this.payload = envelope;
  }
}

async function request<S extends z.ZodTypeAny>(
  path: string,
  init: RequestInit | undefined,
  schema: S,
): Promise<z.infer<S>> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const bodyStr = typeof init?.body === 'string' ? init.body : undefined;

  // PoP (Phase 2): at login, mint/ensure the session signing key and fold its
  // public point into the body (it then gets sealed with the account number on
  // the login route). No-op for every other route.
  const outBodyStr = await augmentLoginBody(path, method, bodyStr);

  // CDN-blinding: seal the request body and/or set up to open a sealed response,
  // per the route policy. No-op (undefined) for non-sealed routes or when the
  // pinned key is not baked in (then everything stays plaintext, dual-mode).
  const seal = await prepareOutbound(path, method, outBodyStr);

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };
  let body: BodyInit | undefined = outBodyStr;
  let respEph: string | undefined;
  if (seal) {
    if (seal.body !== undefined) body = seal.body;
    if (seal.header) {
      headers[seal.header.name] = seal.header.value;
      // The reveal-leg ephemeral (GET routes) is bound into the PoP v2 signature.
      if (seal.header.name === 'x-fs-resp-eph') respEph = seal.header.value;
    }
  }

  // PoP (Phase 2): sign the EXACT wire body (post-seal) for authenticated routes.
  // Returns null pre-login (no session key) or for ineligible routes, so the
  // request then goes out unsigned. respEph binds the reveal-leg ephemeral (P3d).
  const popHeaders = await signedHeaders(
    path,
    method,
    typeof body === 'string' ? body : undefined,
    respEph,
  );
  if (popHeaders) Object.assign(headers, popHeaders);

  // P1-9: a network failure (offline / dropped connection) rejects fetch with a
  // TypeError. Surface it as a structured status-0 ApiCallError so consumers can
  // show an "offline" message instead of a raw "TypeError: Failed to fetch".
  let res: Response;
  try {
    res = await fetch(path, { credentials: 'include', method, headers, body });
  } catch {
    throw new ApiCallError(0, {
      error: { code: 'network.offline', message: 'Network request failed' },
    });
  }
  let json: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiCallError(res.status, json);
  }
  if (seal) json = await openInbound(seal, path, method, json);
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    throw new ApiCallError(500, {
      error: { code: 'client.parse_error', message: 'Invalid server response' },
    });
  }
  return parsed.data;
}

export const apiClient = {
  get: <S extends z.ZodTypeAny>(path: string, schema: S) =>
    request(path, { method: 'GET' }, schema),
  post: <S extends z.ZodTypeAny>(path: string, body: unknown, schema: S) =>
    request(path, { method: 'POST', body: JSON.stringify(body) }, schema),
  patch: <S extends z.ZodTypeAny>(path: string, body: unknown, schema: S) =>
    request(path, { method: 'PATCH', body: JSON.stringify(body) }, schema),
  delete: <S extends z.ZodTypeAny>(path: string, schema: S) =>
    request(path, { method: 'DELETE' }, schema),
};

export { ApiCallError };
