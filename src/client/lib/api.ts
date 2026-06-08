import type { z } from 'zod';
import type { ApiError } from '../../shared/contracts/common';
import { openInbound, prepareOutbound } from './e2ee';

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

  // CDN-blinding: seal the request body and/or set up to open a sealed response,
  // per the route policy. No-op (undefined) for non-sealed routes or when the
  // pinned key is not baked in (then everything stays plaintext, dual-mode).
  const seal = await prepareOutbound(path, method, bodyStr);

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };
  let body = init?.body;
  if (seal) {
    if (seal.body !== undefined) body = seal.body;
    if (seal.header) headers[seal.header.name] = seal.header.value;
  }

  const res = await fetch(path, { credentials: 'include', ...init, headers, body });
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
