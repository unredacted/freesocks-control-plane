/**
 * Test helper: a routing `fetch` stub that records every call (path, method,
 * headers, parsed JSON body) so adapter tests can assert request shapes and
 * that nothing secret leaks into errors. Not a test file itself.
 */
import { vi } from 'vitest';

export interface Captured {
  url: string;
  path: string;
  query: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  rawBody: string | undefined;
}

export interface FetchStub {
  calls: Captured[];
  /** Replace the handler (e.g. for a second phase of one test). */
  route: (handler: Handler) => void;
}

export type Handler = (call: Captured, index: number) => Response | Promise<Response>;

export function jsonRes(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export function emptyRes(status = 204): Response {
  return new Response(null, { status });
}

/** Install the stub as the global fetch; returns the call log + a rerouter. */
export function mockFetch(handler: Handler): FetchStub {
  const calls: Captured[] = [];
  let current = handler;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      const u = new URL(url);
      const method = (
        init.method ?? (input instanceof Request ? input.method : 'GET')
      ).toUpperCase();
      const hdrs: Record<string, string> = {};
      const h = init.headers ?? (input instanceof Request ? input.headers : undefined);
      if (h instanceof Headers) h.forEach((v, k) => (hdrs[k.toLowerCase()] = v));
      else if (Array.isArray(h)) for (const [k, v] of h) hdrs[k.toLowerCase()] = v;
      else if (h) for (const [k, v] of Object.entries(h)) hdrs[k.toLowerCase()] = String(v);
      let rawBody: string | undefined;
      if (typeof init.body === 'string') rawBody = init.body;
      else if (input instanceof Request && init.body === undefined) {
        try {
          rawBody = await input.clone().text();
        } catch {
          rawBody = undefined;
        }
      }
      let body: unknown = undefined;
      if (rawBody) {
        try {
          body = JSON.parse(rawBody);
        } catch {
          body = rawBody;
        }
      }
      const captured: Captured = {
        url,
        path: u.pathname,
        query: u.search,
        method,
        headers: hdrs,
        body,
        rawBody,
      };
      calls.push(captured);
      return current(captured, calls.length - 1);
    }),
  );
  return {
    calls,
    route: (h) => {
      current = h;
    },
  };
}

/** Assert no secret or host string appears in an error's message or meta. */
export function errorBlob(err: unknown): string {
  const e = err as { message?: string; meta?: unknown };
  return `${e?.message ?? ''} ${JSON.stringify(e?.meta ?? {})}`;
}
