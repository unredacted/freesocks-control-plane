import type { z } from 'zod';
import type { ApiError } from '../../shared/contracts/common';

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
  const res = await fetch(path, {
    credentials: 'include',
    ...init,
    headers: {
      'content-type': 'application/json',
      ...init?.headers,
    },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiCallError(res.status, json as never);
  }
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
