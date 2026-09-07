import { afterEach, describe, expect, test, vi } from 'vitest';
import { z } from 'zod';
import { extractErrorCode, providerFetch, EdgeProviderError, toProviderError } from './http';
import { errorBlob, jsonRes, mockFetch } from '../testing/mockFetch';

afterEach(() => vi.unstubAllGlobals());

const args = (over: Partial<Parameters<typeof providerFetch>[0]> = {}) => ({
  provider: 'gcore' as const,
  step: 'lb',
  url: 'https://api.example/cloud/v1/x?token=SECRET_QUERY',
  method: 'GET' as const,
  headers: { authorization: 'APIKey SECRET_HEADER' },
  schema: z.object({ ok: z.boolean() }),
  ...over,
});

describe('providerFetch', () => {
  test('parses a JSON 2xx through the schema', async () => {
    mockFetch(() => jsonRes({ ok: true, extra: 1 }));
    await expect(providerFetch(args())).resolves.toEqual({ ok: true });
  });

  test('a non-2xx carries status + short code but never the body, URL or headers', async () => {
    mockFetch(() => jsonRes({ code: 'quota_exceeded', message: 'origin 192.0.2.9 rejected' }, 400));
    let err: unknown;
    try {
      await providerFetch(args());
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(EdgeProviderError);
    const m = (err as EdgeProviderError).meta;
    expect(m.status).toBe(400);
    expect(m.code).toBe('quota_exceeded');
    expect(m.retryable).toBe(false);
    const blob = errorBlob(err);
    expect(blob).not.toContain('192.0.2.9');
    expect(blob).not.toContain('SECRET');
    expect(blob).not.toContain('api.example');
  });

  test('5xx and 429 are retryable', async () => {
    mockFetch(() => new Response('boom', { status: 503 }));
    await expect(providerFetch(args())).rejects.toMatchObject({
      meta: { retryable: true, status: 503 },
    });
    mockFetch(() => new Response('slow', { status: 429 }));
    await expect(providerFetch(args())).rejects.toMatchObject({
      meta: { retryable: true, status: 429 },
    });
  });

  test('an abort is a timed-out, retryable error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_u: unknown, init: RequestInit) => {
        return new Promise<Response>((_res, rej) => {
          init.signal?.addEventListener('abort', () => {
            const e = new Error('aborted');
            e.name = 'AbortError';
            rej(e);
          });
        });
      }),
    );
    await expect(providerFetch(args({ timeoutMs: 5 }))).rejects.toMatchObject({
      meta: { timedOut: true, retryable: true },
    });
  });

  test('okStatuses turn a 404 DELETE into an undefined success', async () => {
    mockFetch(() => new Response('', { status: 404 }));
    await expect(
      providerFetch(args({ method: 'DELETE', schema: z.unknown(), okStatuses: [404] })),
    ).resolves.toBeUndefined();
  });

  test('schema mismatch names paths only', async () => {
    mockFetch(() => jsonRes({ ok: 'yes-secret-value' }));
    let err: unknown;
    try {
      await providerFetch(args());
    } catch (e) {
      err = e;
    }
    expect((err as Error).message).toContain('schema mismatch');
    expect((err as Error).message).toContain('[ok]');
    expect((err as Error).message).not.toContain('yes-secret-value');
  });
});

describe('extractErrorCode', () => {
  test('reads conventional keys and rejects free text', () => {
    expect(extractErrorCode({ code: 'E1' })).toBe('E1');
    expect(extractErrorCode({ error: { code: 'nested' } })).toBe('nested');
    expect(extractErrorCode({ errors: [{ error_code: 'first' }] })).toBe('first');
    expect(extractErrorCode({ message: 'a sentence with spaces' })).toBeUndefined();
    expect(extractErrorCode({ code: 'has spaces and 192.0.2.1' })).toBeUndefined();
  });
});

describe('toProviderError', () => {
  test('wraps SDK-style errors keeping only status + name', () => {
    const e = Object.assign(new Error('ResourceNotFound: lb 12 at https://api.x'), {
      status: 404,
      name: 'ResourceNotFoundError',
    });
    const out = toProviderError('scaleway', 'describe', e);
    expect(out.meta).toMatchObject({
      status: 404,
      code: 'ResourceNotFoundError',
      retryable: false,
    });
    expect(out.message).not.toContain('https://api.x');
  });
});
