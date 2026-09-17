/**
 * Wire-level contract for the shared Cloudflare DNS client. Every assertion is
 * made on what the real `cloudflare@7.1.0` SDK actually put on the wire (the
 * recording fetch stub is injected as the client's `fetch`), so a hand-written
 * mock and a hand-written adapter cannot silently agree on a wrong shape.
 */
import { afterEach, describe, expect, test, vi } from 'vitest';
import { errorBlob, jsonRes, mockFetch, type Captured } from '../../testing/mockFetch';
import type { CloudflareDnsConfig } from '../types';
import {
  CLOUDFLARE_API_VERSION,
  __setCloudflareApiFactory,
  cloudflareApi,
  cloudflareDnsClient,
  cloudflareError,
  normalizeDnsName,
} from './cloudflareDns';
import created from '../fixtures/cloudflare/dns_record_created.json';
import listed from '../fixtures/cloudflare/dns_records_list.json';
import listedEmpty from '../fixtures/cloudflare/dns_records_list_empty.json';
import notFound from '../fixtures/cloudflare/error_record_not_found.json';
import rateLimited from '../fixtures/cloudflare/error_rate_limited.json';

afterEach(() => {
  vi.unstubAllGlobals();
  __setCloudflareApiFactory(null);
});

/** Fixtures carry a `_source` header for reviewers; the wire body never does. */
function wire(fixture: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...fixture };
  delete copy._source;
  return copy;
}

const cfg: CloudflareDnsConfig = {
  apiToken: 'SECRET_CF',
  zoneId: '023e105f4ecef8ad9ca31a8372d0c353',
  zoneName: 'example.net',
  accountId: 'acct_1',
};

const HOSTNAME = 'k7m2x9qp4n3f.example.net';

describe('cloudflare dns client: request shapes', () => {
  test('createRecord posts a proxied record with ttl 1 and the ownership comment', async () => {
    const stub = mockFetch(() => jsonRes(wire(created)));
    const rec = await cloudflareDnsClient(cfg).createRecord({
      type: 'A',
      name: HOSTNAME.toUpperCase(),
      content: '198.51.100.7',
      proxied: true,
      comment: 'fcp:fcp-relay-o1-0badf00d',
    });
    expect(stub.calls).toHaveLength(1);
    const call = stub.calls[0] as Captured;
    expect(call.method).toBe('POST');
    expect(call.path).toBe(`/client/v4/zones/${cfg.zoneId}/dns_records`);
    expect(call.body).toEqual({
      // zone_id travels in the PATH, never in the body.
      type: 'A',
      name: HOSTNAME,
      content: '198.51.100.7',
      proxied: true,
      ttl: 1,
      comment: 'fcp:fcp-relay-o1-0badf00d',
    });
    expect(call.headers.authorization).toBe('Bearer SECRET_CF');
    expect(call.headers['api-version']).toBe(CLOUDFLARE_API_VERSION);
    expect(rec).toEqual({
      id: '372e67954025e0ba6aaa6d586b9e0b59',
      type: 'A',
      name: HOSTNAME,
      content: '198.51.100.7',
      proxied: true,
      comment: 'fcp:fcp-relay-o1-0badf00d',
    });
  });

  test('findRecordsByName is ONE request with the exact-name filter (never an N+1 iteration)', async () => {
    const stub = mockFetch(() => jsonRes(wire(listed)));
    const hits = await cloudflareDnsClient(cfg).findRecordsByName(HOSTNAME, 'A');
    expect(stub.calls).toHaveLength(1);
    const call = stub.calls[0] as Captured;
    expect(call.method).toBe('GET');
    expect(call.path).toBe(`/client/v4/zones/${cfg.zoneId}/dns_records`);
    const q = new URLSearchParams(call.query);
    // The SDK serializes nested filters with allowDots.
    expect(q.get('name.exact')).toBe(HOSTNAME);
    expect(q.get('type')).toBe('A');
    expect(q.get('per_page')).toBe('5');
    expect(hits.map((h) => h.id)).toEqual(['372e67954025e0ba6aaa6d586b9e0b59']);
  });

  test('findRecordsByName without a type omits the type filter and answers [] on an empty listing', async () => {
    const stub = mockFetch(() => jsonRes(wire(listedEmpty)));
    const hits = await cloudflareDnsClient(cfg).findRecordsByName(HOSTNAME);
    expect(hits).toEqual([]);
    expect(new URLSearchParams((stub.calls[0] as Captured).query).has('type')).toBe(false);
  });

  test('names come back lowercased: comparison is case-insensitive', async () => {
    mockFetch(() => jsonRes(wire(listed)));
    const hits = await cloudflareDnsClient(cfg).findRecordsByName(`${HOSTNAME.toUpperCase()}.`);
    expect(hits).toHaveLength(1);
    expect(normalizeDnsName('K7M2X9QP4N3F.EXAMPLE.NET.')).toBe(HOSTNAME);
  });

  test('getRecord reads one record; a 404 is null, not a throw', async () => {
    const stub = mockFetch((c) =>
      c.method === 'GET' && c.path.endsWith('/gone')
        ? jsonRes(wire(notFound), 404)
        : jsonRes(wire(created)),
    );
    const client = cloudflareDnsClient(cfg);
    const rec = await client.getRecord('372e67954025e0ba6aaa6d586b9e0b59');
    expect(rec?.id).toBe('372e67954025e0ba6aaa6d586b9e0b59');
    expect((stub.calls[0] as Captured).path).toBe(
      `/client/v4/zones/${cfg.zoneId}/dns_records/372e67954025e0ba6aaa6d586b9e0b59`,
    );
    expect(await client.getRecord('gone')).toBeNull();
  });

  test('deleteRecord is idempotent: a 404 is a success', async () => {
    const stub = mockFetch(() => jsonRes(wire(notFound), 404));
    await expect(cloudflareDnsClient(cfg).deleteRecord('gone')).resolves.toBeUndefined();
    const call = stub.calls[0] as Captured;
    expect(call.method).toBe('DELETE');
    expect(call.path).toBe(`/client/v4/zones/${cfg.zoneId}/dns_records/gone`);
  });

  test('listCaa reads CAA records at the zone apex', async () => {
    const stub = mockFetch(() =>
      jsonRes({
        result: [
          {
            id: 'caa1',
            name: 'example.net',
            type: 'CAA',
            data: { flags: 0, tag: 'issue', value: 'pki.goog' },
          },
        ],
        result_info: { page: 1, per_page: 100, count: 1, total_count: 1, total_pages: 1 },
        success: true,
        errors: [],
        messages: [],
      }),
    );
    const caa = await cloudflareDnsClient(cfg).listCaa();
    expect(caa).toEqual([{ flags: 0, tag: 'issue', value: 'pki.goog' }]);
    const q = new URLSearchParams((stub.calls[0] as Captured).query);
    expect(q.get('type')).toBe('CAA');
    expect(q.get('name.exact')).toBe('example.net');
  });
});

describe('cloudflare dns client: no retry, no leaks', () => {
  test('a 429 produces exactly ONE request (maxRetries 0: allocating calls recover through discovery)', async () => {
    const stub = mockFetch(() => jsonRes(wire(rateLimited), 429));
    await expect(
      cloudflareDnsClient(cfg).createRecord({
        type: 'A',
        name: HOSTNAME,
        content: '198.51.100.7',
        proxied: true,
        comment: 'fcp:spec',
      }),
    ).rejects.toThrow();
    expect(stub.calls).toHaveLength(1);
  });

  test('a 500 produces exactly ONE request and a retryable, body-free error', async () => {
    const stub = mockFetch(() =>
      jsonRes({ result: null, success: false, errors: [{ code: 1000, message: 'boom' }] }, 500),
    );
    const err = await cloudflareDnsClient(cfg)
      .findRecordsByName(HOSTNAME)
      .catch((e: unknown) => e);
    expect(stub.calls).toHaveLength(1);
    const blob = errorBlob(err);
    expect(blob).toContain('"retryable":true');
    expect(blob).not.toContain('boom');
  });

  test('errors never carry the token, the zone name, the origin address or any body text', async () => {
    mockFetch(() =>
      jsonRes(
        {
          result: null,
          success: false,
          errors: [
            { code: 81053, message: 'An A record with 198.51.100.7 for example.net exists' },
          ],
          messages: [],
        },
        400,
      ),
    );
    const err = await cloudflareDnsClient(cfg)
      .createRecord({
        type: 'A',
        name: HOSTNAME,
        content: '198.51.100.7',
        proxied: true,
        comment: 'fcp:spec',
      })
      .catch((e: unknown) => e);
    const blob = errorBlob(err);
    expect(blob).not.toContain('SECRET_CF');
    expect(blob).not.toContain('example.net');
    expect(blob).not.toContain('198.51.100.7');
    expect(blob).not.toContain('exists');
    expect(blob).not.toContain('api.cloudflare.com');
    // Only the status and the numeric Cloudflare error code survive.
    expect(blob).toContain('81053');
    expect(blob).toContain('400');
  });

  test('a non-SDK throwable still reduces to the body-free error class', () => {
    const err = cloudflareError('step', new Error('raw SECRET_CF leak'));
    expect(errorBlob(err)).not.toContain('SECRET_CF');
    expect(err.meta.provider).toBe('cloudflare');
  });
});

describe('cloudflare dns client: client construction', () => {
  test('the factory pins no retries, a 15 s timeout, logging off and the API version', () => {
    const client = cloudflareApi({ apiToken: 'SECRET_CF' });
    expect(client.maxRetries).toBe(0);
    expect(client.timeout).toBe(15_000);
    expect(client.logLevel).toBe('off');
    expect(client.apiVersion).toBe(CLOUDFLARE_API_VERSION);
  });

  test('__setCloudflareApiFactory replaces the client for tests and null restores it', async () => {
    const calls: string[] = [];
    __setCloudflareApiFactory((c) => {
      calls.push(c.apiToken);
      return cloudflareApi(c);
    });
    mockFetch(() => jsonRes(wire(listedEmpty)));
    await cloudflareDnsClient(cfg).findRecordsByName(HOSTNAME);
    expect(calls).toEqual(['SECRET_CF']);
    __setCloudflareApiFactory(null);
    await cloudflareDnsClient(cfg).findRecordsByName(HOSTNAME);
    expect(calls).toEqual(['SECRET_CF']);
  });
});
