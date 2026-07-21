import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  remnawaveDeleteUser,
  remnawaveFetchSubscription,
  remnawaveGetUser,
  remnawaveHealth,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveSetStatus,
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
        return jsonRes(
          userObj({
            uuid: UUID,
            shortUuid: 'sc',
            subscriptionUrl: 'https://panel.internal/sub/sc',
          }),
        );
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
      subscriptionUrl: 'https://panel.internal/sub/sc',
    });
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.headers.authorization).toBe('Bearer SECRET_TOKEN_DO_NOT_LEAK');
    // tag is uppercased to Remnawave's [A-Z0-9_]; expireAt:null becomes a
    // far-future sentinel (Remnawave REQUIRES the field).
    expect(calls[0]!.body).toMatchObject({ username: 'fs_user', tag: 'FREE' });
    expect(typeof calls[0]!.body!.expireAt).toBe('string');
    // No strategy supplied → defaults to MONTH; no squad → field omitted.
    expect(calls[0]!.body!.trafficLimitStrategy).toBe('MONTH');
    expect(calls[0]!.body!.activeInternalSquads).toBeUndefined();
  });

  test('pins an OFF-ORIGIN panel-reported subscriptionUrl to the panel fallback (Review D-#4)', async () => {
    // A compromised panel returning an attacker-chosen URL must not make FCP
    // fetch + publicly re-serve it: anything off the instance's own origin is
    // replaced by the conventional /api/sub/<shortUuid> on the panel origin.
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST')
        return jsonRes(
          userObj({
            uuid: UUID,
            shortUuid: 'sc',
            subscriptionUrl: 'http://169.254.169.254/latest/meta-data',
          }),
        );
      throw new Error(`unexpected ${method} ${path}`);
    });
    const issued = await remnawaveIssueUser(cfg, {
      username: 'fs_user',
      trafficLimitBytes: null,
      expireAt: null,
      tag: 'free',
    });
    expect(issued.subscriptionUrl).toBe('https://panel.internal/api/sub/sc');
  });

  test('tolerates a create response that omits usedTrafficBytes (new user)', async () => {
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST') {
        const u = userObj({
          uuid: UUID,
          shortUuid: 'sc',
          subscriptionUrl: 'https://panel.internal/sub/sc',
        });
        delete u.usedTrafficBytes; // Remnawave omits it for a brand-new user.
        return jsonRes(u);
      }
      throw new Error(`unexpected ${method} ${path}`);
    });
    const issued = await remnawaveIssueUser(cfg, {
      username: 'fs_user',
      trafficLimitBytes: null,
      expireAt: null,
      tag: 'free',
    });
    expect(issued.backendUserId).toBe(UUID);
  });

  test('maps the placement handle into activeInternalSquads', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveIssueUser(cfg, {
      username: 'u',
      trafficLimitBytes: null,
      expireAt: null,
      tag: 'member',
      placement: 'squad-1',
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

  test('a schema-mismatch create attempts orphan cleanup by username, then throws', async () => {
    // The panel CREATED the user but the response can't be parsed (version
    // drift): we lost the uuid, so the only handle is the unique username.
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST') return jsonRes({ uuid: 'not-a-uuid' });
      if (path === '/api/users/by-username/u' && method === 'GET') return jsonRes({ uuid: UUID });
      if (path === `/api/users/${UUID}` && method === 'DELETE') return jsonRes({});
      throw new Error(`unexpected ${method} ${path}`);
    });
    await expect(
      remnawaveIssueUser(cfg, { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 't' }),
    ).rejects.toThrow(/schema mismatch/i);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /api/users',
      'GET /api/users/by-username/u',
      `DELETE /api/users/${UUID}`,
    ]);
  });

  test('a definitive 4xx create rejection does NOT attempt cleanup', async () => {
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST') return jsonRes({ message: 'bad' }, 422);
      throw new Error(`unexpected ${method} ${path}`);
    });
    await expect(
      remnawaveIssueUser(cfg, { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 't' }),
    ).rejects.toThrow(/422/);
    expect(calls).toHaveLength(1);
  });

  test('a cleanup lookup that finds nothing still surfaces the original error', async () => {
    mockFetch((path, method) => {
      if (path === '/api/users' && method === 'POST') return jsonRes({ uuid: 'not-a-uuid' });
      if (path.startsWith('/api/users/by-username/')) return jsonRes({ message: 'nf' }, 404);
      throw new Error(`unexpected ${method} ${path}`);
    });
    await expect(
      remnawaveIssueUser(cfg, { username: 'u', trafficLimitBytes: null, expireAt: null, tag: 't' }),
    ).rejects.toThrow(/schema mismatch/i);
  });
});

describe('remnawaveGetUser', () => {
  function routeUserAndDevices(user: Record<string, unknown>, devicesStatus = 200): void {
    mockFetch((path, method) => {
      // Real Remnawave: GET /api/hwid/devices/{userUuid}, wrapped in {response}.
      if (path.startsWith('/api/hwid/devices'))
        return devicesStatus === 200
          ? jsonRes({
              response: {
                total: 1,
                devices: [
                  {
                    hwid: 'd1',
                    platform: 'ios',
                    deviceModel: 'iPhone',
                    createdAt: '2026-01-01T00:00:00.000Z',
                    updatedAt: '2026-01-02T00:00:00.000Z',
                  },
                ],
              },
            })
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
    // createdAt -> firstSeenAt, updatedAt -> lastSeenAt; platform/model pass through.
    expect(state.devices).toEqual([
      {
        hwid: 'd1',
        platform: 'ios',
        deviceModel: 'iPhone',
        firstSeenAt: '2026-01-01T00:00:00.000Z',
        lastSeenAt: '2026-01-02T00:00:00.000Z',
      },
    ]);
  });

  test('surfaces the panel onlineAt stamp (and tolerates its absence)', async () => {
    routeUserAndDevices(userObj({ onlineAt: '2026-07-20T12:34:56.000Z' }));
    const withStamp = await remnawaveGetUser(cfg, UUID);
    expect(withStamp.onlineAt).toBe('2026-07-20T12:34:56.000Z');

    routeUserAndDevices(userObj()); // older panels omit the field entirely
    const withoutStamp = await remnawaveGetUser(cfg, UUID);
    expect(withoutStamp.onlineAt).toBeUndefined();
  });

  test('degrades to no devices when the hwid endpoint fails', async () => {
    routeUserAndDevices(userObj(), 404);
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.devices).toEqual([]);
    expect(state.status).toBe('active');
  });

  // Regression: Remnawave 2.x moved used traffic into a nested `userTraffic`
  // object on GET (no top-level `usedTrafficBytes`). The old top-level read was
  // silently coerced to 0 by `.nullish()`, freezing the account counter at "0 B".
  test('reads used traffic from the nested userTraffic (2.x GET shape)', async () => {
    const u = userObj({ trafficLimitBytes: 500 });
    delete u.usedTrafficBytes; // 2.x GET carries no top-level field
    u.userTraffic = { usedTrafficBytes: 4096, lifetimeUsedTrafficBytes: 9000, onlineAt: null };
    routeUserAndDevices(u);
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.usedTrafficBytes).toBe(4096); // not 0
    expect(state.trafficLimitBytes).toBe(500);
  });

  test('prefers nested userTraffic over a stale flat usedTrafficBytes', async () => {
    routeUserAndDevices(
      userObj({ usedTrafficBytes: 250, userTraffic: { usedTrafficBytes: 4096 } }),
    );
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.usedTrafficBytes).toBe(4096);
  });

  // 0 is the panel's UNLIMITED sentinel (the update path sends null → 0); the
  // read path must map it back to null or the member hero renders "… / 0 B"
  // instead of the Unlimited badge.
  test.each([
    [0, null],
    [null, null],
    [500, 500],
  ])('maps trafficLimitBytes %s -> %s (0 = unlimited sentinel)', async (panelValue, expected) => {
    routeUserAndDevices(userObj({ trafficLimitBytes: panelValue }));
    const state = await remnawaveGetUser(cfg, UUID);
    expect(state.trafficLimitBytes).toBe(expected);
  });
});

describe('remnawaveUpdateUser (Bug 14: squad clear vs set vs absent)', () => {
  test('omits activeInternalSquads when the squad field is absent', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { trafficLimitBytes: 10 });
    expect(calls[0]!.method).toBe('PATCH');
    // Remnawave update is PATCH /api/users with the uuid in the BODY (no path param).
    expect(calls[0]!.path).toBe('/api/users');
    expect(calls[0]!.body!.uuid).toBe(UUID);
    expect('activeInternalSquads' in calls[0]!.body!).toBe(false);
    expect(calls[0]!.body!.trafficLimitBytes).toBe(10);
  });

  test('clears the squad when placement is present and null', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { placement: null });
    expect(calls[0]!.body!.activeInternalSquads).toEqual([]);
  });

  test('sets the squad when placement is present and a value', async () => {
    mockFetch(() => jsonRes(userObj()));
    await remnawaveUpdateUser(cfg, UUID, { placement: 'sq-9' });
    expect(calls[0]!.body!.activeInternalSquads).toEqual(['sq-9']);
  });
});

describe('remnawaveSetStatus (dedicated enable/disable action)', () => {
  test('POSTs the enable/disable action endpoints (not a status PATCH)', async () => {
    mockFetch(() => jsonRes({}));
    await remnawaveSetStatus(cfg, UUID, true);
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.path).toBe(`/api/users/${UUID}/actions/enable`);
    await remnawaveSetStatus(cfg, UUID, false);
    expect(calls[1]!.path).toBe(`/api/users/${UUID}/actions/disable`);
  });

  // The panel's actions endpoints are NOT idempotent: enable on an ACTIVE user
  // 400s (A030), disable on a disabled user 400s (A029). FCP treats "already in
  // the requested state" as success — the tier push unconditionally re-enables
  // before every update, so without this every free→member upgrade of a live
  // (enabled) key failed before the traffic/expiry PATCH ever ran.
  test('swallows 400 A030 "User already enabled" on enable', async () => {
    mockFetch(() =>
      jsonRes(
        { timestamp: 'now', path: '/x', message: 'User already enabled', errorCode: 'A030' },
        400,
      ),
    );
    await expect(remnawaveSetStatus(cfg, UUID, true)).resolves.toBeUndefined();
  });

  test('swallows 400 A029 "User already disabled" on disable', async () => {
    mockFetch(() =>
      jsonRes(
        { timestamp: 'now', path: '/x', message: 'User already disabled', errorCode: 'A029' },
        400,
      ),
    );
    await expect(remnawaveSetStatus(cfg, UUID, false)).resolves.toBeUndefined();
  });

  test('a mismatched-direction "already" rejection still throws', async () => {
    // enable answered with "already disabled" is a real contract surprise, not
    // the benign no-op — it must surface.
    mockFetch(() => jsonRes({ message: 'User already disabled', errorCode: 'A029' }, 400));
    await expect(remnawaveSetStatus(cfg, UUID, true)).rejects.toThrow(/400/);
  });

  test('any other 400 still throws', async () => {
    mockFetch(() => jsonRes({ message: 'Validation failed', errorCode: 'A001' }, 400));
    await expect(remnawaveSetStatus(cfg, UUID, true)).rejects.toThrow(/400/);
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
  test('fetches the panel-provided public subscription URL (no admin token), forwards UA', async () => {
    mockFetch(
      () =>
        new Response('vmess://node\n', { status: 200, headers: { 'content-type': 'text/yaml' } }),
    );
    const out = await remnawaveFetchSubscription(
      cfg,
      'short123',
      'Clash/1.0',
      'https://panel.internal/happ/short123',
    );
    expect(out).toEqual({ content: 'vmess://node\n', contentType: 'text/yaml', headers: {} });
    expect(calls[0]!.path).toBe('/happ/short123'); // the provided URL, not the admin API
    // The subscription URL is a public capability — the admin Bearer is NOT sent.
    expect(calls[0]!.headers.authorization).toBeUndefined();
    expect(calls[0]!.headers['user-agent']).toBe('Clash/1.0');
  });

  test('captures the allowlisted subscription metadata headers (userinfo + update interval)', async () => {
    mockFetch(
      () =>
        new Response('vmess://node\n', {
          status: 200,
          headers: {
            'content-type': 'text/yaml',
            'subscription-userinfo': 'upload=0; download=10; total=100; expire=0',
            'profile-update-interval': '12',
            'x-internal': 'must-be-dropped', // not allowlisted
          },
        }),
    );
    const out = await remnawaveFetchSubscription(
      cfg,
      'short123',
      'Clash/1.0',
      'https://panel.internal/s/x',
    );
    expect(out.headers).toEqual({
      'subscription-userinfo': 'upload=0; download=10; total=100; expire=0',
      'profile-update-interval': '12',
    });
  });

  test('falls back to /api/sub/<shortId> when no subscription URL is given', async () => {
    mockFetch(() => new Response('payload', { status: 200 }));
    await remnawaveFetchSubscription(cfg, 'short123');
    expect(calls[0]!.path).toBe('/api/sub/short123');
    expect(calls[0]!.headers.authorization).toBeUndefined();
  });

  test('a stored OFF-ORIGIN subscription URL is re-pinned, never fetched (Review D-#4)', async () => {
    mockFetch(() => new Response('payload', { status: 200 }));
    await remnawaveFetchSubscription(
      cfg,
      'short123',
      undefined,
      'http://169.254.169.254/latest/meta-data',
    );
    expect(calls[0]!.path).toBe('/api/sub/short123'); // the panel-origin fallback
  });

  test('a baseUrl path prefix is preserved on every API call (Review D-#11)', async () => {
    const subpathCfg: RemnawaveConfig = { ...cfg, baseUrl: 'https://panel.internal/panel/' };
    mockFetch(() => jsonRes(userObj()));
    await remnawaveGetUser(subpathCfg, UUID);
    expect(calls[0]!.path).toBe(`/panel/api/users/${UUID}`);
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
    expect(out).toEqual({ content: 'payload', contentType: 'text/plain', headers: {} });
  });
});

describe('remnawaveHealth / remnawaveTestConnection', () => {
  const PROBE = '/api/users/00000000-0000-4000-8000-000000000000';

  test('treats 404 (well-formed but absent id) as reachable + authed', async () => {
    mockFetch(() => new Response(null, { status: 404 }));
    const h = await remnawaveHealth(cfg);
    // P2: Remnawave has no cheap key count, so health returns null (the
    // healthcheck then preserves the locally-bumped estimate).
    expect(h.keyCount).toBeNull();
    expect(typeof h.rttMs).toBe('number');
    expect(calls[0]!.path).toBe(PROBE);
    expect(calls[0]!.headers.authorization).toBe('Bearer SECRET_TOKEN_DO_NOT_LEAK');
  });

  test('treats a 2xx as healthy', async () => {
    mockFetch(() => jsonRes({}));
    await expect(remnawaveHealth(cfg)).resolves.toMatchObject({ keyCount: null });
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
