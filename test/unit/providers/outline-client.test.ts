import { describe, expect, it, vi } from 'vitest';
import { OutlineClient } from '../../../src/server/providers/outline/client';
import { OutlineApiError } from '../../../src/server/providers/outline/errors';
import { Logger } from '../../../src/server/lib/logger';

function makeClient(handler: (req: Request) => Promise<Response> | Response) {
  return new OutlineClient({
    apiUrl: 'https://outline.example.org:8443/SECRET-PATH/',
    logger: new Logger('error'),
    fetcher: (input, init) => {
      const req = new Request(input as RequestInfo, init);
      return Promise.resolve(handler(req));
    },
  });
}

describe('OutlineClient', () => {
  it('preserves the secret path segment when building request URLs', async () => {
    const seen: string[] = [];
    const client = makeClient((req) => {
      seen.push(req.url);
      return new Response(JSON.stringify({ accessKeys: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    await client.listKeys();
    expect(seen[0]).toBe('https://outline.example.org:8443/SECRET-PATH/access-keys');
  });

  it('createKey returns the parsed access key', async () => {
    const client = makeClient(
      () =>
        new Response(
          JSON.stringify({
            id: '42',
            name: 'test',
            password: 'p',
            port: 8388,
            method: 'chacha20-ietf-poly1305',
            accessUrl: 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwQGV4YW1wbGUub3JnOjgzODg=#test',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const key = await client.createKey({ name: 'test' });
    expect(key.id).toBe('42');
    expect(key.accessUrl).toMatch(/^ss:\/\//);
  });

  it('createKey forwards websocket body when WSS-wrapped server is enabled', async () => {
    let lastBody: string | undefined;
    const client = makeClient(async (req) => {
      lastBody = await req.text();
      return new Response(JSON.stringify({ id: '7', accessUrl: 'ss://something' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    await client.createKey({
      name: 'wstest',
      websocket: {
        enabled: true,
        tcpPath: '/tcp',
        udpPath: '/udp',
        domain: 'ws.example.org',
        tls: true,
      },
    });
    expect(lastBody).toBeTruthy();
    const parsed = JSON.parse(lastBody!);
    expect(parsed.websocket.domain).toBe('ws.example.org');
    expect(parsed.websocket.tls).toBe(true);
  });

  it('setKeyDataLimit(bytes) PUTs the limit', async () => {
    let lastMethod = '';
    let lastBody = '';
    const client = makeClient(async (req) => {
      lastMethod = req.method;
      lastBody = await req.text();
      return new Response(null, { status: 204 });
    });
    await client.setKeyDataLimit('5', 1_000_000);
    expect(lastMethod).toBe('PUT');
    expect(JSON.parse(lastBody)).toEqual({ limit: { bytes: 1_000_000 } });
  });

  it('setKeyDataLimit(null) DELETEs the limit endpoint', async () => {
    let lastMethod = '';
    const client = makeClient((req) => {
      lastMethod = req.method;
      return new Response(null, { status: 204 });
    });
    await client.setKeyDataLimit('5', null);
    expect(lastMethod).toBe('DELETE');
  });

  it('getMetricsTransfer unwraps bytesTransferredByUserId', async () => {
    const client = makeClient(
      () =>
        new Response(JSON.stringify({ bytesTransferredByUserId: { '1': 100, '2': 250 } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const metrics = await client.getMetricsTransfer();
    expect(metrics).toEqual({ '1': 100, '2': 250 });
  });

  it('throws OutlineApiError on non-2xx responses with path + status (NOT apiUrl)', async () => {
    const client = makeClient(
      () =>
        new Response('upstream said no', {
          status: 502,
          headers: { 'content-type': 'text/plain' },
        }),
    );
    await expect(client.listKeys()).rejects.toMatchObject({
      meta: { status: 502, path: '/access-keys' },
    });
    // The error must not include the apiUrl secret anywhere.
    try {
      await client.listKeys();
    } catch (err) {
      if (err instanceof OutlineApiError) {
        const repr = `${err.message} ${JSON.stringify(err.meta)}`;
        expect(repr).not.toContain('SECRET-PATH');
      }
    }
  });

  it('healthCheck returns { ok: true, keyCount } on success', async () => {
    const client = makeClient(
      () =>
        new Response(JSON.stringify({ accessKeys: [{ id: '1', accessUrl: 'ss://x' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const result = await client.healthCheck();
    expect(result).toEqual({ ok: true, keyCount: 1 });
  });

  it('healthCheck returns { ok: false, error } on failure', async () => {
    const client = makeClient(() => new Response(null, { status: 500 }));
    const result = await client.healthCheck();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('500');
    }
  });
});
