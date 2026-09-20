// @vitest-environment node
/**
 * Wrapper-level contract for the official `fastly` SDK: what goes on the wire,
 * what comes back, and what an error is allowed to say.
 *
 * These drive the REAL SDK (superagent, hence the node environment) against an
 * in-process HTTP recorder through `__setFastlyBasePath`, so nothing here can
 * agree with a hand-written mock on a shape the SDK does not actually produce.
 */
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, test } from 'vitest';
import { errorBlob } from '../../testing/mockFetch';
import type { FastlyConfig } from '../types';
import {
  FASTLY_TIMEOUT_MS,
  __setFastlyBasePath,
  fastlyApi,
  fastlyErrorCode,
  normalizeFastlyCode,
} from './sdk';

// --- in-process recorder (the real SDK talks to this over real HTTP) ---------------

interface Call {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string | undefined>;
  body: unknown;
}
type Reply = { status: number; body?: unknown; contentType?: string };
type Route = (call: Call, index: number) => Reply;

interface Recorder {
  calls: Call[];
  base: string;
  close: () => Promise<void>;
}

/** A fixture body with its provenance marker stripped (arrays are stored under `_body`). */
function fixture(name: string): unknown {
  const raw = JSON.parse(
    readFileSync(new URL(`../fixtures/fastly/${name}`, import.meta.url), 'utf8'),
  ) as Record<string, unknown>;
  if ('_body' in raw) return raw._body;
  const { _source: _ignored, ...rest } = raw;
  return rest;
}

async function startRecorder(route: Route): Promise<Recorder> {
  const calls: Call[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const url = new URL(req.url ?? '/', 'http://recorder.invalid');
      const query: Record<string, string> = {};
      url.searchParams.forEach((v, k) => (query[k] = v));
      const contentType = String(req.headers['content-type'] ?? '');
      let body: unknown;
      if (raw.length > 0) {
        if (contentType.includes('json')) {
          try {
            body = JSON.parse(raw);
          } catch {
            body = raw;
          }
        } else if (contentType.includes('x-www-form-urlencoded')) {
          body = Object.fromEntries(new URLSearchParams(raw).entries());
        } else body = raw;
      }
      const call: Call = {
        method: req.method ?? 'GET',
        path: url.pathname,
        query,
        headers: req.headers as Record<string, string | undefined>,
        body,
      };
      calls.push(call);
      const reply = route(call, calls.length - 1);
      const payload = reply.body === undefined ? '' : JSON.stringify(reply.body);
      res.writeHead(reply.status, {
        'content-type': reply.contentType ?? 'application/json',
        'content-length': Buffer.byteLength(payload),
      });
      res.end(payload);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    calls,
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const HOST = 'k3m7q9zb.example.org';
const ORIGIN = 'node-7.origin.example.net';
const cfg: FastlyConfig = {
  type: 'fastly',
  apiToken: 'SECRET_FASTLY_TOKEN',
  certificateAuthority: 'certainly',
};

let rec: Recorder;
afterEach(async () => {
  __setFastlyBasePath(null);
  await rec?.close();
});

async function recorder(route: Route) {
  rec = await startRecorder(route);
  __setFastlyBasePath(rec.base);
  return rec;
}

describe('fastly sdk wrapper: requests', () => {
  test('a create is form-encoded on POST /service, authenticated with Fastly-Key and our user agent', async () => {
    await recorder(() => ({ status: 200, body: fixture('service-create.json') }));
    const api = fastlyApi(cfg);
    const svc = await api.createService({
      name: 'fcp-relay-o1-deadbeef',
      type: 'vcl',
      comment: 'origin edge',
    });
    expect(svc.id).toBe('SU1Z0isxPaozGVKXdv0eY');
    expect(rec.calls).toHaveLength(1);
    const call = rec.calls[0];
    expect(call.method).toBe('POST');
    expect(call.path).toBe('/service');
    expect(call.headers['fastly-key']).toBe('SECRET_FASTLY_TOKEN');
    expect(call.headers['user-agent']).toBe('fcp-relay/1');
    expect(call.headers['content-type']).toContain('application/x-www-form-urlencoded');
    expect(call.body).toEqual({
      name: 'fcp-relay-o1-deadbeef',
      type: 'vcl',
      comment: 'origin edge',
    });
  });

  test('a GET carries no cache-busting parameter (the wire contract stays deterministic)', async () => {
    await recorder(() => ({ status: 200, body: fixture('service-search.json') }));
    await fastlyApi(cfg).searchService('fcp-relay-o1-deadbeef');
    expect(rec.calls[0].path).toBe('/service/search');
    expect(rec.calls[0].query).toEqual({ name: 'fcp-relay-o1-deadbeef' });
  });

  test('the TLS subscription filter and page size are serialised as JSON:API expects', async () => {
    await recorder(() => ({
      status: 200,
      body: fixture('tls-subscriptions-list.json'),
      contentType: 'application/vnd.api+json',
    }));
    const doc = await fastlyApi(cfg).listTlsSubscriptionsForDomain(HOST);
    expect(doc.data[0].id).toBe('C0cuTFmLzMCiyMcOZuLEZ1');
    expect(rec.calls[0].path).toBe('/tls/subscriptions');
    expect(rec.calls[0].query).toEqual({ 'filter[tls_domains.id]': HOST, 'page[size]': '20' });
  });

  test('destroying a subscription forces it (the SDK has no such option; a plugin adds it)', async () => {
    await recorder(() => ({ status: 204 }));
    await fastlyApi(cfg).deleteTlsSubscription('C0cuTFmLzMCiyMcOZuLEZ1');
    expect(rec.calls[0].method).toBe('DELETE');
    expect(rec.calls[0].path).toBe('/tls/subscriptions/C0cuTFmLzMCiyMcOZuLEZ1');
    expect(rec.calls[0].query).toEqual({ force: 'true' });
  });

  test('the base path override only rewrites the API origin, and the timeout is ours', async () => {
    await recorder(() => ({ status: 200, body: fixture('current-customer.json') }));
    await fastlyApi(cfg).getLoggedInCustomer();
    expect(rec.calls[0].path).toBe('/current_customer');
    expect(FASTLY_TIMEOUT_MS).toBe(15_000);
  });
});

describe('fastly sdk wrapper: responses', () => {
  test('the RAW body is validated, so unknown fields survive and timestamps stay strings', async () => {
    await recorder(() => ({
      status: 200,
      body: { ...(fixture('service-create.json') as object), unknown_future_field: 'kept' },
    }));
    const svc = await fastlyApi(cfg).createService({ name: 'n', type: 'vcl' });
    // The SDK's own model would drop an unlisted field and turn `created_at`
    // into a Date; reading the raw body keeps both intact.
    expect((svc as Record<string, unknown>).unknown_future_field).toBe('kept');
    expect(typeof (svc as Record<string, unknown>).created_at).toBe('string');
    expect(svc.versions?.[0]).toMatchObject({ number: 1, active: false, locked: false });
  });

  test('an empty listing survives as an empty array (not as a missing body)', async () => {
    await recorder(() => ({ status: 200, body: [] }));
    await expect(fastlyApi(cfg).listServices(1, 100)).resolves.toEqual([]);
  });

  test('a positional domain check parses as the array it is', async () => {
    await recorder(() => ({ status: 200, body: fixture('domain-check-ok.json') }));
    const res = await fastlyApi(cfg).checkDomain('svc', 1, HOST);
    expect(Array.isArray(res)).toBe(true);
    expect(res[2]).toBe(true);
  });

  test('a body of the wrong shape is a schema mismatch, and the error quotes no content', async () => {
    await recorder(() => ({ status: 200, body: { unexpected: true } }));
    const err = await fastlyApi(cfg)
      .createService({ name: 'n', type: 'vcl' })
      .catch((e) => e);
    expect(err.meta).toMatchObject({ provider: 'fastly', code: 'schema_mismatch' });
    expect(errorBlob(err)).not.toContain('unexpected');
  });
});

describe('fastly sdk wrapper: errors never carry bodies', () => {
  test('the legacy envelope yields status + an allowlisted code, never the detail text', async () => {
    await recorder(() => ({ status: 409, body: fixture('error-legacy.json') }));
    const err = await fastlyApi(cfg)
      .createDomain('svc', 1, { name: HOST })
      .catch((e) => e);
    expect(err.meta).toMatchObject({ status: 409, code: 'duplicate_record', retryable: false });
    const blob = errorBlob(err);
    for (const secret of [
      'SECRET_FASTLY_TOKEN',
      HOST,
      ORIGIN,
      'is already taken',
      'Duplicate record',
    ])
      expect(blob).not.toContain(secret);
  });

  test('the JSON:API envelope yields the normalised code from errors[].code', async () => {
    await recorder(() => ({
      status: 422,
      body: fixture('error-jsonapi.json'),
      contentType: 'application/vnd.api+json',
    }));
    const err = await fastlyApi(cfg)
      .createTlsSubscription({})
      .catch((e) => e);
    expect(err.meta).toMatchObject({ status: 422, code: 'unprocessable_entity' });
    expect(errorBlob(err)).not.toContain(HOST);
  });

  test('free text that is not an allowlisted code yields NO code at all', async () => {
    await recorder(() => ({
      status: 400,
      body: { msg: `Backend ${ORIGIN} is unreachable`, detail: `dial tcp ${ORIGIN}:443` },
    }));
    const err = await fastlyApi(cfg)
      .createBackend('svc', 1, {
        name: 'origin',
        address: ORIGIN,
        use_ssl: true,
        override_host: HOST,
        comment: 'c',
      })
      .catch((e) => e);
    expect(err.meta.status).toBe(400);
    expect(err.meta.code).toBeUndefined();
    expect(errorBlob(err)).not.toContain(ORIGIN);
  });

  test('a 5xx is retryable and is issued EXACTLY once: the SDK has no retry of its own', async () => {
    await recorder(() => ({ status: 500, body: { msg: 'Internal Server Error' } }));
    const err = await fastlyApi(cfg)
      .createService({ name: 'n', type: 'vcl' })
      .catch((e) => e);
    expect(err.meta).toMatchObject({ status: 500, retryable: true, code: 'internal_server_error' });
    expect(rec.calls).toHaveLength(1);
  });

  test('a 429 is retryable and also issued exactly once', async () => {
    await recorder(() => ({ status: 429, body: { msg: 'Rate limit exceeded' } }));
    const err = await fastlyApi(cfg)
      .listServices(1, 100)
      .catch((e) => e);
    expect(err.meta).toMatchObject({ status: 429, retryable: true, code: 'rate_limit_exceeded' });
    expect(rec.calls).toHaveLength(1);
  });

  test('a 404 keeps its status so callers can read it as absence', async () => {
    await recorder(() => ({ status: 404, body: { msg: 'Record not found' } }));
    const err = await fastlyApi(cfg)
      .searchService('missing')
      .catch((e) => e);
    expect(err.meta).toMatchObject({ status: 404, code: 'record_not_found', retryable: false });
  });
});

describe('fastly error-code allowlist', () => {
  test('known strings normalise, anything carrying a value does not', () => {
    expect(normalizeFastlyCode('Record not found')).toBe('record_not_found');
    expect(normalizeFastlyCode('Unprocessable Entity')).toBe('unprocessable_entity');
    // A hostname or an address would normalise to a perfectly shaped token, so
    // shape alone is not enough: only the allowlist may produce a code.
    expect(normalizeFastlyCode(HOST)).toBeUndefined();
    expect(normalizeFastlyCode(ORIGIN)).toBeUndefined();
    expect(normalizeFastlyCode('198.51.100.7')).toBeUndefined();
    expect(normalizeFastlyCode(`Domain ${HOST} is already taken`)).toBeUndefined();
    expect(normalizeFastlyCode(undefined)).toBeUndefined();
  });

  test('the envelope reader never looks at `detail`', () => {
    expect(fastlyErrorCode({ msg: 'Not authorized', detail: `token SECRET on ${HOST}` })).toBe(
      'not_authorized',
    );
    expect(fastlyErrorCode({ detail: 'Record not found' })).toBeUndefined();
    expect(fastlyErrorCode({ errors: [{ code: 'Forbidden', detail: HOST }] })).toBe('forbidden');
    expect(fastlyErrorCode(null)).toBeUndefined();
  });
});

describe('fastly sdk transport pin', () => {
  test('superagent resolves to the maintained 10.x line (the SDK declares a deprecated ^6)', async () => {
    // The SDK's own range pulls superagent 6 + formidable 1, both deprecated by
    // their maintainers (a Socket "Warn" on the PR that added the SDK). The
    // override in package.json is what keeps them out; a future SDK bump or a
    // lockfile regeneration must not silently drop it.
    // Read the installed manifests directly: superagent's `exports` map does
    // not expose package.json to `require`.
    const { readFileSync } = await import('node:fs');
    const root = new URL('../../../../../node_modules/', import.meta.url);
    const versionOf = (name: string): number =>
      Number(
        (
          JSON.parse(readFileSync(new URL(`${name}/package.json`, root), 'utf8')) as {
            version: string;
          }
        ).version.split('.')[0],
      );
    expect(versionOf('superagent')).toBeGreaterThanOrEqual(10);
    expect(versionOf('formidable')).toBeGreaterThanOrEqual(3);
  });
});
