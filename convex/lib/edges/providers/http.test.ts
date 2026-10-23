import { afterEach, describe, expect, test, vi } from 'vitest';
import { z } from 'zod';
import {
  extractErrorCode,
  providerFetch,
  redactErrorDetail,
  refusalOf,
  scrubNames,
  EdgeProviderError,
  MAX_RESPONSE_BYTES,
  isDefiniteRefusal,
  refusedCreate,
  toProviderError,
} from './http';
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

  test('redirects are never followed: manual mode + a non-retryable refusal (auth headers stay home)', async () => {
    const stub = mockFetch(
      () =>
        new Response(null, {
          status: 302,
          headers: { location: 'https://evil.example/collect?token=SECRET_HEADER' },
        }),
    );
    let err: unknown;
    try {
      await providerFetch(args());
    } catch (e) {
      err = e;
    }
    expect(stub.calls[0].redirect).toBe('manual');
    expect(err).toBeInstanceOf(EdgeProviderError);
    expect((err as EdgeProviderError).meta).toMatchObject({
      code: 'redirect_refused',
      status: 302,
      retryable: false,
    });
    expect(errorBlob(err)).not.toContain('evil.example');
    // A 2xx still parses; only 3xx is refused.
    mockFetch(() => jsonRes({ ok: true }));
    await expect(providerFetch(args())).resolves.toEqual({ ok: true });
  });

  test('an oversized body is refused without buffering it into the error', async () => {
    const big = `{"ok":true,"pad":"${'x'.repeat(MAX_RESPONSE_BYTES + 16)}"}`;
    mockFetch(() => new Response(big, { status: 200 }));
    await expect(providerFetch(args())).rejects.toMatchObject({
      meta: { code: 'response_too_large', retryable: false },
    });
    // A declared content-length over the cap is refused before reading.
    mockFetch(
      () =>
        new Response('{}', {
          status: 200,
          headers: { 'content-length': String(MAX_RESPONSE_BYTES + 1) },
        }),
    );
    await expect(providerFetch(args())).rejects.toMatchObject({
      meta: { code: 'response_too_large' },
    });
    // Just under the cap is fine.
    const fits = `{"ok":true,"pad":"${'x'.repeat(1024)}"}`;
    mockFetch(() => new Response(fits, { status: 200 }));
    await expect(providerFetch(args())).resolves.toEqual({ ok: true });
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

describe('refusedCreate: a create the provider refused for good', () => {
  const failure = (status: number | undefined, timedOut = false) =>
    new EdgeProviderError('x', {
      provider: 'gcore',
      step: 'lb',
      status,
      retryable: false,
      timedOut,
    });

  test('a validation error, a forbidden call or a quota; never a conflict, a wait, a fault or a timeout', () => {
    for (const status of [400, 401, 402, 403, 413, 422])
      expect(isDefiniteRefusal(failure(status))).toBe(true);
    for (const status of [404, 408, 409, 412, 423, 425, 429, 500, 502, 503])
      expect(isDefiniteRefusal(failure(status))).toBe(false);
    expect(isDefiniteRefusal(failure(undefined, true))).toBe(false);
    expect(isDefiniteRefusal(new Error('boom'))).toBe(false);
  });

  test("the outcome stops the run on the code with the provider's words held aside", async () => {
    mockFetch(() =>
      jsonRes({ message: '1 input is not valid', error_code: 'validation-error' }, 400),
    );
    const err = await providerFetch(args()).catch((e: unknown) => e);
    expect(refusedCreate(err, 'create_refused')).toEqual({
      status: 'partial',
      resources: [],
      code: 'create_refused',
      refused: true,
      detail: expect.stringContaining('1 input is not valid'),
    });
    mockFetch(() => jsonRes({ message: 'busy' }, 409));
    expect(refusedCreate(await providerFetch(args()).catch((e: unknown) => e), 'x')).toBeNull();
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

describe('error detail (the provider answer, for the admin)', () => {
  const failing = async (step: string) => {
    mockFetch(() =>
      jsonRes({ message: 'region 112 refused SECRET_HEADER from 192.0.2.9 / 2001:db8::7' }, 400),
    );
    try {
      await providerFetch(args({ step }));
    } catch (e) {
      return (e as EdgeProviderError).meta;
    }
    throw new Error('expected a failure');
  };

  test('a credential test keeps the redacted answer; the message stays body-free', async () => {
    const m = await failing('test');
    expect(m.detail).toContain('region 112 refused');
    expect(m.detail).not.toContain('SECRET_HEADER');
    expect(m.detail).not.toContain('192.0.2.9');
    expect(m.detail).not.toContain('2001:db8::7');
  });

  test('a provisioning step keeps a refusal (4xx) aside, redacted, never on the error; an outage keeps nothing', async () => {
    mockFetch(() =>
      jsonRes({ message: 'region 112 refused SECRET_HEADER from 192.0.2.9 / 2001:db8::7' }, 400),
    );
    let err: unknown;
    try {
      await providerFetch(args({ step: 'lb' }));
    } catch (e) {
      err = e;
    }
    // The error itself stays body-free: nothing a log line or JSON could show.
    expect((err as EdgeProviderError).meta.detail).toBeUndefined();
    expect(errorBlob(err)).not.toContain('region 112');
    expect(JSON.stringify(err)).not.toContain('region 112');
    const said = refusalOf(err)!;
    expect(said).toContain('region 112 refused');
    expect(said).not.toContain('SECRET_HEADER');
    expect(said).not.toContain('192.0.2.9');
    expect(said).not.toContain('2001:db8::7');
    mockFetch(() => jsonRes({ message: 'upstream SECRET_HEADER down' }, 503));
    try {
      await providerFetch(args());
    } catch (e) {
      err = e;
    }
    expect(refusalOf(err)).toBeUndefined();
    expect(refusalOf(toProviderError('scaleway', 'ip4', { status: 500, message: 'x' }))).toBe(
      undefined,
    );
    expect(
      refusalOf(toProviderError('scaleway', 'ip4', { name: 'TimeoutError', message: 'slow' })),
    ).toBeUndefined();
  });

  test('an SDK refusal keeps its message and the rest of its JSON body, redacted, aside', () => {
    const err = Object.assign(new Error('http error 400: server_ip refused for 198.51.100.7'), {
      status: 400,
      name: 'ScalewayError',
      body: {
        message: 'server_ip refused for 198.51.100.7',
        type: 'invalid_request_error',
        help_message: 'key SECRET_SCW_KEY_1 may not',
      },
    });
    const wrapped = toProviderError('scaleway', 'backend', err, ['SECRET_SCW_KEY_1']);
    expect(wrapped.meta.detail).toBeUndefined();
    const d = refusalOf(wrapped)!;
    expect(d).toContain('server_ip refused for [address]');
    expect(d).toContain('invalid_request_error');
    expect(d).toContain('may not');
    expect(d).not.toContain('SECRET_SCW_KEY_1');
    expect(d).not.toContain('198.51.100.7');
  });

  test('redaction replaces extra secrets and caps the length', () => {
    expect(redactErrorDetail('bad SIGNING_SECRET_1 here', ['SIGNING_SECRET_1'])).toBe(
      'bad [redacted] here',
    );
    expect(redactErrorDetail('x'.repeat(5_000))!.length).toBeLessThan(700);
    expect(redactErrorDetail('  ')).toBeUndefined();
    // A credential too short to replace safely suppresses the whole answer.
    expect(redactErrorDetail('invalid token secret1', ['secret1'])).toBeUndefined();
    expect(redactErrorDetail('invalid token', ['Bearer abc'])).toBeUndefined();
  });
});

describe('scrubNames: a create step refusal, before it leaves the action', () => {
  test('replaces every name without regard to case, the longest first', () => {
    expect(
      scrubNames('no record Front-1.Example.org in example.org for fcp-relay-o1-ab-backend', [
        'example.org',
        'front-1.example.org',
        'fcp-relay-o1-ab',
      ]),
    ).toBe('no record [name] in [name] for [name]-backend');
  });

  test('a capped detail ending inside a name loses that fragment too', () => {
    const capped = redactErrorDetail(`${'x '.repeat(298)}front-1.example.org refused`)!;
    expect(capped.endsWith('…')).toBe(true);
    const out = scrubNames(capped, ['front-1.example.org'])!;
    expect(out).not.toMatch(/fr…$/);
    expect(out.endsWith('…')).toBe(true);
    expect(out).not.toContain('fr');
  });

  test('short names are left alone; nothing left is no detail', () => {
    expect(scrubNames('a b refused', ['a', 'b'])).toBe('a b refused');
    expect(scrubNames(undefined, ['x'])).toBeUndefined();
  });
});
