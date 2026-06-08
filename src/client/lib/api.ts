import type { z } from 'zod';
import type { ApiError } from '../../shared/contracts/common';
import { openInbound, prepareOutbound } from './e2ee';
import { augmentLoginBody, signedHeaders } from './pop';

class ApiCallError extends Error {
  constructor(
    public readonly status: number,
    public readonly payload:
      | z.infer<typeof ApiError>
      | { error: { code: string; message: string } },
  ) {
    super(payload.error.message);
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
  const outBodyStr = await augmentLoginBody(path, bodyStr);

  // CDN-blinding: seal the request body and/or set up to open a sealed response,
  // per the route policy. No-op (undefined) for non-sealed routes or when the
  // pinned key is not baked in (then everything stays plaintext, dual-mode).
  const seal = await prepareOutbound(path, method, outBodyStr);

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };
  let body: BodyInit | undefined = outBodyStr;
  if (seal) {
    if (seal.body !== undefined) body = seal.body;
    if (seal.header) headers[seal.header.name] = seal.header.value;
  }

  // PoP (Phase 2): sign the EXACT wire body (post-seal) for authenticated routes.
  // Returns null pre-login (no session key) or for ineligible routes, so the
  // request then goes out unsigned.
  const popHeaders = await signedHeaders(path, method, typeof body === 'string' ? body : undefined);
  if (popHeaders) Object.assign(headers, popHeaders);

  const res = await fetch(path, { credentials: 'include', method, headers, body });
  let json: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiCallError(res.status, json as never);
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
