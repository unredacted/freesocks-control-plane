import { describe, expect, it } from 'vitest';
import { RemnawaveClient } from '../../../src/server/providers/remnawave/client';
import { RemnawaveApiError } from '../../../src/server/providers/remnawave/errors';
import { Logger } from '../../../src/server/lib/logger';

const sampleUser = {
  uuid: '11111111-1111-4111-8111-111111111111',
  shortUuid: 'short-abc',
  subscriptionUuid: 'sub-uuid-1',
  username: 'freesocks-anon-abcd',
  status: 'ACTIVE',
  trafficLimitBytes: 50_000_000_000,
  trafficLimitStrategy: 'MONTH',
  usedTrafficBytes: 0,
  expireAt: '2026-12-31T00:00:00.000Z',
  hwidDeviceLimit: 1,
  subscriptionUrl: 'https://rw.example.com/short-abc',
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
};

function makeClient(handler: (req: Request) => Promise<Response> | Response) {
  return new RemnawaveClient({
    baseUrl: 'https://panel.example.com/',
    apiToken: 'super-secret-token',
    logger: new Logger('error'),
    fetcher: (input, init) => {
      const req = new Request(input as RequestInfo, init);
      return Promise.resolve(handler(req));
    },
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('RemnawaveClient', () => {
  it('createUser POSTs to /api/users with a bearer token and parses the wrapped { response } body', async () => {
    let method = '';
    let url = '';
    let auth = '';
    const client = makeClient((req) => {
      method = req.method;
      url = req.url;
      auth = req.headers.get('authorization') ?? '';
      return jsonResponse({ response: sampleUser });
    });
    const user = await client.createUser({ username: 'freesocks-anon-abcd' });
    expect(method).toBe('POST');
    expect(url).toBe('https://panel.example.com/api/users');
    expect(auth).toBe('Bearer super-secret-token');
    expect(user.uuid).toBe(sampleUser.uuid);
    expect(user.subscriptionUrl).toMatch(/^https:\/\//);
  });

  it('tolerates an unwrapped body (no { response } envelope)', async () => {
    const client = makeClient(() => jsonResponse(sampleUser));
    const user = await client.getUser(sampleUser.uuid);
    expect(user.shortUuid).toBe('short-abc');
  });

  it('throws RemnawaveApiError on non-2xx without leaking the api token', async () => {
    const client = makeClient(() => new Response('nope', { status: 500 }));
    await expect(client.getUser('x')).rejects.toBeInstanceOf(RemnawaveApiError);
    try {
      await client.getUser('x');
    } catch (err) {
      expect(err).toBeInstanceOf(RemnawaveApiError);
      if (err instanceof RemnawaveApiError) {
        const repr = `${err.message} ${JSON.stringify(err.meta)}`;
        expect(repr).not.toContain('super-secret-token');
        expect(err.meta).toMatchObject({ status: 500 });
      }
    }
  });

  it('caps the logged error body at 200 chars', async () => {
    const big = 'x'.repeat(5000);
    const client = makeClient(() => new Response(big, { status: 400 }));
    try {
      await client.getUser('x');
    } catch (err) {
      if (err instanceof RemnawaveApiError) {
        const body = (err.meta as { body?: string }).body ?? '';
        expect(body.length).toBeLessThanOrEqual(200);
      }
    }
  });

  it('throws RemnawaveApiError on a schema mismatch (missing required fields)', async () => {
    const client = makeClient(() => jsonResponse({ response: { uuid: 'not-a-uuid' } }));
    await expect(client.getUser('x')).rejects.toBeInstanceOf(RemnawaveApiError);
  });

  it('updateUser PATCHes /api/users/:uuid', async () => {
    let method = '';
    let url = '';
    const client = makeClient((req) => {
      method = req.method;
      url = req.url;
      return jsonResponse({ response: sampleUser });
    });
    await client.updateUser(sampleUser.uuid, { status: 'DISABLED' });
    expect(method).toBe('PATCH');
    expect(url).toBe(`https://panel.example.com/api/users/${sampleUser.uuid}`);
  });

  it('resetUserTraffic POSTs to the reset-traffic action', async () => {
    let method = '';
    let url = '';
    const client = makeClient((req) => {
      method = req.method;
      url = req.url;
      return jsonResponse({ response: {} });
    });
    await client.resetUserTraffic(sampleUser.uuid);
    expect(method).toBe('POST');
    expect(url).toContain(`/api/users/${sampleUser.uuid}/actions/reset-traffic`);
  });

  it('deleteUser issues a DELETE', async () => {
    let method = '';
    const client = makeClient((req) => {
      method = req.method;
      return jsonResponse({ response: {} });
    });
    await client.deleteUser(sampleUser.uuid);
    expect(method).toBe('DELETE');
  });

  it('listUserDevices returns [] on a 404 (endpoint not present on this panel version)', async () => {
    const client = makeClient(() => new Response('not found', { status: 404 }));
    const devices = await client.listUserDevices(sampleUser.uuid);
    expect(devices).toEqual([]);
  });

  it('listUserDevices parses devices on success', async () => {
    const client = makeClient(() => jsonResponse({ response: { devices: [{ hwid: 'dev-1' }] } }));
    const devices = await client.listUserDevices(sampleUser.uuid);
    expect(devices).toHaveLength(1);
    expect(devices[0]!.hwid).toBe('dev-1');
  });

  it('fetchSubscriptionContent returns the body text + content-type', async () => {
    const client = makeClient(
      () =>
        new Response('vless://node', {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }),
    );
    const out = await client.fetchSubscriptionContent('short-abc', 'TestAgent/1.0');
    expect(out.content).toContain('vless://');
    expect(out.contentType).toContain('text/plain');
  });
});
