import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  remnawaveDeleteUser,
  remnawaveFetchSubscription,
  remnawaveGetUser,
  remnawaveHealth,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveTestConnection,
  remnawaveUpdateUser,
  type RemnawaveConfig,
} from './remnawave';

// A deliberately secret-looking token + an internal host: the error path must
// never surface either (see the leak test at the bottom).
const cfg: RemnawaveConfig = {
  baseUrl: 'https://panel.internal',
  apiToken: 'SECRET_TOKEN_DO_NOT_LEAK',
};
// A valid RFC-4122 UUID (Zod 4's .uuid() enforces the version/variant bits).
const UUID = '550e8400-e29b-41d4-a716-446655440000';

interface Captured {
  path: string;
  method: string;
  headers: Record<string, string>;
  body: Record<string, unknown> | undefined;
}
let calls: Captured[] = [];

/** Install a routing fetch stub; `handler` maps (path, method) to a Response. */
function mockFetch(handler: (path: string, method: string) => Response): void {
  calls = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      const method = (init.method ?? 'GET').toUpperCase();
      calls.push({
        path: url.pathname,
        method,
        headers: (init.headers ?? {}) as Record<string, string>,
        body: init.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : undefined,
      });
      return handler(url.pathname, method);
    }),
  );
}

function jsonRes(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** A schema-valid Remnawave user, overridable per test. */
function userObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    uuid: UUID,
    shortUuid: 'short123',
    username: 'fs_user',
    status: 'ACTIVE',
    trafficLimitBytes: 1000,
    trafficLimitStrategy: 'MONTH',
    usedTrafficBytes: 0,
    expireAt: null,
    hwidDeviceLimit: null,
    subscriptionUrl: 'https://panel.internal/sub/short123',
    ...over,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('remnawaveIssueUser', () => {
  test('POSTs /api/users with a bearer token and maps the response', async () => {
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST')
        return jsonRes(userObj({ uuid: UUID, shortUuid: 'sc', subscriptionUrl: 'https://x/sub' }));
      throw new Error(`unexpected ${method} ${path}`);
    });
    const issued = await remnawaveIssueUser(cfg, {
      username: 'fs_user',
      trafficLimitBytes: 1000,
      expireAt: null,
      tag: 'free',
    });
    expect(issued).toMatchObject({
      backendUserId: UUID,
      backendShortId: 'sc',
      subscriptionUrl: 'https://x/sub',
    });
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.headers.authorization).toBe('Bearer SECRET_TOKEN_DO_NOT_LEAK');
    expect(calls[0]!.body).toMatchObject({ username: 'fs_user', tag: 'free' });
    // No strategy supplied → defaults to MONTH; no squad → field omitted.
    expect(calls[0]!.body!.trafficLimitStrategy).toBe('MONTH');
    expect(calls[0]!.body!.activeInternalSquads).toBeUndefined();
  });

  test('maps a squad uuid into activeInternalSquads', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveIssueUser(cfg, {
      username: 'u',
      trafficLimitBytes: null,
      expireAt: null,
      tag: 'member',
      remnawaveSquadUuid: 'squad-1',
    });
    expect(calls[0]!.body!.activeInternalSquads).toEqual(['squad-1']);
  });

  test('tolerates a { response: ... } envelope', async () => {
    mockFetch(() => jsonRes({ response: userObj({ shortUuid: 'wrapped' }) }));
    const issued = await remnawaveIssueUser(cfg, {
      username: 'u',
      trafficLimitBytes: null,
      expireAt: null,
      tag: 't',
    });
    expect(issued.backendShortId).toBe('wrapped');
  });

  test('throws a schema-mismatch error on a malformed response', async () => {
    mockFetch(() => jsonRes({ uuid: 'not-a-uuid' }));
    await expect(
      remnawaveIssueUser(cfg, { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 't' }),
    ).rejects.toThrow(/schema mismatch/i);
  });
});

describe('remnawaveGetUser', () => {
  function routeUserAndDevices(user: Record<string, unknown>, devicesStatus = 200): void {
    mockFetch((path, method) => {
      if (path === '/api/hwid-devices')
        return devicesStatus === 200
          ? jsonRes({ devices: [{ hwid: 'd1', firstSeenAt: '2026-01-01T00:00:00.000Z' }] })
          : jsonRes({ error: 'nope' }, devicesStatus);
      if (path.startsWith('/api/users/') && method === 'GET') return jsonRes(user);
      throw new Error(`unexpected ${method} ${path}`);
    });
  }

  test.each([
    ['ACTIVE', 'active'],
    ['DISABLED', 'disabled'],
    ['LIMITED', 'limited'],
    ['EXPIRED', 'expired'],
  ])('maps backend status %s -> %s', async (backendStatus, expected) => {
    routeUserAndDevices(userObj({ status: backendStatus }));
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.status).toBe(expected);
  });

  test('merges device list and maps traffic fields', async () => {
    routeUserAndDevices(userObj({ trafficLimitBytes: 500, usedTrafficBytes: 250 }));
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.trafficLimitBytes).toBe(500);
    expect(state.usedTrafficBytes).toBe(250);
    expect(state.devices).toEqual([{ hwid: 'd1', firstSeenAt: '2026-01-01T00:00:00.000Z' }]);
  });

  test('degrades to no devices when the hwid endpoint fails', async () => {
    routeUserAndDevices(userObj(), 404);
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.devices).toEqual([]);
    expect(state.status).toBe('active');
  });
});

describe('remnawaveUpdateUser (Bug 14: squad clear vs set vs absent)', () => {
  test('omits activeInternalSquads when the squad field is absent', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { trafficLimitBytes: 10 });
    expect(calls[0]!.method).toBe('PATCH');
    expect('activeInternalSquads' in calls[0]!.body!).toBe(false);
    expect(calls[0]!.body!.trafficLimitBytes).toBe(10);
  });

  test('clears the squad when present and null', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { remnawaveSquadUuid: null });
    expect(calls[0]!.body!.activeInternalSquads).toEqual([]);
  });

  test('sets the squad when present and a value', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { remnawaveSquadUuid: 'sq-9' });
    expect(calls[0]!.body!.activeInternalSquads).toEqual(['sq-9']);
  });

  test('maps the local status to the Remnawave enum', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { status: 'active' });
    expect(calls[0]!.body!.status).toBe('ACTIVE');
    await remnawaveUpdateUser(cfg, UUID, { status: 'disabled' });
    expect(calls[1]!.body!.status).toBe('DISABLED');
  });
});

describe('remnawaveResetTraffic / remnawaveDeleteUser', () => {
  test('reset hits the reset-traffic action endpoint', async () => {
    mockFetch(() => jsonRes({}));
    await remnawaveResetTraffic(cfg, UUID);
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.path).toBe(`/api/users/${UUID}/actions/reset-traffic`);
  });

  test('delete issues DELETE on the user', async () => {
    mockFetch(() => jsonRes({}));
    await remnawaveDeleteUser(cfg, UUID);
    expect(calls[0]!.method).toBe('DELETE');
    expect(calls[0]!.path).toBe(`/api/users/${UUID}`);
  });
});

describe('remnawaveFetchSubscription', () => {
  test('returns raw content + content-type and forwards the user-agent', async () => {
    mockFetch(
      () => new Response('vmess://node\n', { status: 200, headers: { 'content-type': 'text/yaml' } }),
    );
    const out = await remnawaveFetchSubscription(cfg, 'short123', 'Clash/1.0');
    expect(out).toEqual({ content: 'vmess://node\n', contentType: 'text/yaml' });
    expect(calls[0]!.path).toBe('/api/subscriptions/short123');
    expect(calls[0]!.headers.authorization).toBe('Bearer SECRET_TOKEN_DO_NOT_LEAK');
    expect(calls[0]!.headers['user-agent']).toBe('Clash/1.0');
  });

  test('defaults content-type to text/plain when the response omits the header', async () => {
    // A bare Response auto-stamps text/plain;charset=UTF-8, so hand-roll one with
    // no content-type to exercise the `?? 'text/plain'` fallback.
    const noCt = {
      ok: true,
      status: 200,
      text: async () => 'payload',
      headers: { get: () => null },
    } as unknown as Response;
    mockFetch(() => noCt);
    const out = await remnawaveFetchSubscription(cfg, 'short123');
    expect(out).toEqual({ content: 'payload', contentType: 'text/plain' });
  });
});

describe('remnawaveHealth / remnawaveTestConnection', () => {
  const PROBE = '/api/users/00000000-0000-4000-8000-000000000000';

  test('treats 404 (well-formed but absent id) as reachable + authed', async () => {
    mockFetch(() => new Response(null, { status: 404 }));
    const h = await remnawaveHealth(cfg);
    expect(h.keyCount).toBe(0);
    expect(typeof h.rttMs).toBe('number');
    expect(calls[0]!.path).toBe(PROBE);
    expect(calls[0]!.headers.authorization).toBe('Bearer SECRET_TOKEN_DO_NOT_LEAK');
  });

  test('treats a 2xx as healthy', async () => {
    mockFetch(() => jsonRes({}));
    await expect(remnawaveHealth(cfg)).resolves.toMatchObject({ keyCount: 0 });
  });

  test('throws on a 401 (bad credentials)', async () => {
    mockFetch(() => new Response(null, { status: 401 }));
    await expect(remnawaveHealth(cfg)).rejects.toBeInstanceOf(Error);
  });

  test('testConnection maps 404 -> ok and 401 -> error with the status', async () => {
    mockFetch(() => new Response(null, { status: 404 }));
    expect(await remnawaveTestConnection(cfg)).toEqual({ ok: true, keyCount: 0 });
    mockFetch(() => new Response(null, { status: 401 }));
    expect(await remnawaveTestConnection(cfg)).toEqual({
      ok: false,
      error: 'Remnawave returned HTTP 401',
    });
  });
});

describe('error redaction', () => {
  test('an upstream error never leaks the apiToken or the base URL host', async () => {
    mockFetch(() => new Response('upstream boom', { status: 500 }));
    let err: unknown;
    try {
      await remnawaveGetUser(cfg, UUID);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    const meta = (err as { meta?: unknown }).meta;
    const blob = `${(err as Error).message} ${JSON.stringify(meta ?? {})}`;
    expect(blob).not.toContain('SECRET_TOKEN_DO_NOT_LEAK');
    expect(blob).not.toContain('panel.internal');
    // The path alone is safe and useful for debugging.
    expect((err as Error).message).toContain(`/api/users/${UUID}`);
  });
});
