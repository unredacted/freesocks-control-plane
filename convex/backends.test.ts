/// <reference types="vite/client" />
/**
 * Generic backend dispatch tests (pass 2): instance pick on issue, the
 * delete-hint path (issuance compensation, where no subscription row exists),
 * and already-gone tolerance. The provider wire functions have their own
 * suites under lib/backends; this covers the dispatch in convex/backends.ts.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { computeExpireAtIso, gbToBytes, resolveTrafficLimitBytes } from './lib/backends/types';
import { remnawaveUpdateUser } from './lib/backends/remnawave';
import { sha256Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');

describe('issuance spec helpers', () => {
  test('gbToBytes uses binary GiB so a tier of 50 shows as "50 GiB" in Remnawave', () => {
    expect(gbToBytes(50)).toBe(50 * 1024 ** 3);
    expect(gbToBytes(0)).toBe(0);
  });

  test('gbToBytes rounds a fractional GB (donation bonus) to whole bytes', () => {
    // 2.01 GB from a 201-cent month at 1 GB/$ — the panel rejects float bytes,
    // which previously wedged the fleet re-cap cron in a fail-retry loop.
    const b = gbToBytes(50 + 2.01);
    expect(Number.isInteger(b)).toBe(true);
    expect(b).toBe(Math.round(52.01 * 1024 ** 3));
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 50, isDefaultFree: true }, 2.01)).toBe(b);
  });

  test('computeExpireAtIso: a member term wins; free falls to now + window', () => {
    const termMs = Date.UTC(2030, 0, 1);
    expect(computeExpireAtIso(termMs, 90)).toBe(new Date(termMs).toISOString());
    // Free (no membership): ~90 days out (a few seconds of slack for the clock).
    const freeMs = Date.parse(computeExpireAtIso(null, 90));
    expect(freeMs).toBeGreaterThan(Date.now() + 89 * 86_400_000);
    expect(freeMs).toBeLessThan(Date.now() + 91 * 86_400_000);
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const SPEC = {
  username: 'freesocks-test-user',
  trafficLimitBytes: null,
  expireAt: null,
  tag: 'free',
};

async function seedServer(t: ReturnType<typeof convexTest>): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'Test RW',
      slug: 'test-rw',
      config: { type: 'remnawave', baseUrl: 'https://panel.test.example', apiToken: 'tkn' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
}

describe('backends dispatch', () => {
  test('issueUser with zero active instances throws the typed pool-empty error', async () => {
    const t = convexTest(schema, modules);
    // Typed ConvexError({code:'backend.unavailable'}) → mapped to 503 by code (Review P3).
    await expect(
      t.action(internal.backends.issueUser, { backend: 'remnawave', spec: SPEC }),
    ).rejects.toThrow(/backend\.unavailable/);
  });

  test('deleteUser with no hint and no resolvable row is a tolerated no-op', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const out = await t.action(internal.backends.deleteUser, {
      backend: 'remnawave',
      backendUserId: 'ghost-user',
    });
    expect(out).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('deleteUser honors the backendServerId hint (compensation path)', async () => {
    const fetchSpy = vi.fn(
      async (..._args: unknown[]) =>
        new Response(JSON.stringify({ response: {} }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);

    // No subscription row exists — only the hint can resolve the instance.
    await t.action(internal.backends.deleteUser, {
      backend: 'remnawave',
      backendUserId: 'uuid-123',
      backendServerId: serverId,
    });
    expect(fetchSpy).toHaveBeenCalled();
    const firstUrl = String(fetchSpy.mock.calls[0]?.[0]);
    expect(firstUrl).toContain('https://panel.test.example');
    expect(firstUrl).toContain('uuid-123');
  });

  test('issueUser picks an active instance and bumps its keyCount', async () => {
    // Stub the Remnawave issue round-trip: the provider POSTs /api/users and
    // expects a {response: user} envelope matching its RemnawaveUser schema.
    const user = {
      uuid: '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b',
      shortUuid: 'short-1',
      username: SPEC.username,
      status: 'ACTIVE',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      usedTrafficBytes: 0,
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://sub.test.example/short-1',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ response: user }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);

    const issued = await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: SPEC,
    });
    expect(issued.backendServerId).toBe(serverId);
    expect(issued.backendUserId).toBe('7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b');
    await t.run(async (ctx) => {
      const row = await ctx.db.get(serverId);
      expect(row!.keyCount).toBe(1);
    });
  });

  test('issueUser sends a Remnawave-safe body: uppercased tag + non-null expireAt', async () => {
    const user = {
      uuid: '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b',
      shortUuid: 'short-1',
      username: 'freesocks-member-x',
      status: 'ACTIVE',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      usedTrafficBytes: 0,
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://sub.test.example/short-1',
    };
    const fetchSpy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ response: user }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    await seedServer(t);

    // A lowercase slug tag + null expiry — exactly what account.ts builds, and
    // what Remnawave rejected (tag regex + "expireAt is required") before the fix.
    await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: {
        username: 'freesocks-member-x',
        trafficLimitBytes: null,
        expireAt: null,
        tag: 'member',
      },
    });

    const init = (fetchSpy.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const sent = JSON.parse(String(init.body)) as { tag?: unknown; expireAt?: unknown };
    expect(sent.tag).toBe('MEMBER');
    expect(typeof sent.expireAt).toBe('string');
    expect((sent.expireAt as string).length).toBeGreaterThan(0);
  });
});

describe('refreshActiveMirrors (S3 mirror-refresh cron)', () => {
  const MOCK_CONTENT = '# mock subscription content (dev)\n';

  async function seedActiveSub(
    t: ReturnType<typeof convexTest>,
    rawContentHash: string,
    mirrors: { provider: string; publicUrl: string; objectPath: string; status: 'ok' }[] = [],
  ): Promise<Id<'users'>> {
    return t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'u1',
        backendShortId: 'short-1',
        subscriptionUrl: 'https://x/sub',
        subscriptionMirrors: mirrors,
        state: 'active',
        rawContentHash,
        updatedAt: Date.now(),
      });
      return userId;
    });
  }

  async function seedProvider(t: ReturnType<typeof convexTest>): Promise<void> {
    await t.run((ctx) =>
      ctx.db.insert('mirrorProviders', {
        name: 'p1',
        endpoint: 'https://s3.example',
        bucket: 'b1',
        publicUrl: 'https://cdn.example',
        region: 'us-east-1',
        accessKeyId: 'ak',
        secretAccessKey: 'sk',
        isActive: true,
        priority: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  const MIRROR_ON_P1 = [
    {
      provider: 'p1',
      publicUrl: 'https://cdn.example/mirrors/x',
      objectPath: 'mirrors/x',
      status: 'ok' as const,
    },
  ];

  test('no-op when no mirror provider is enabled — does not even page', async () => {
    const t = convexTest(schema, modules);
    await seedActiveSub(t, 'whatever', MIRROR_ON_P1); // a mirrored sub exists...
    const res = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(res).toEqual({ refreshed: 0, scanned: 0 }); // ...but the DB gate short-circuits.
  });

  test('refresh only scans subs that already have a mirror (never creates one)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    await seedProvider(t);
    await seedActiveSub(t, 'irrelevant', []); // opt-in: NO mirror → must be skipped
    const res = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(res.scanned).toBe(0);
  });

  test('skips a mirrored sub whose content is unchanged (no re-upload, no real S3 hit)', async () => {
    // A provider row makes the gate pass + the mock backend serves the content
    // fetch (no real Remnawave). The hash matches, so it skips BEFORE any S3 hit.
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    await seedProvider(t);
    await seedActiveSub(t, await sha256Hex(MOCK_CONTENT), MIRROR_ON_P1);
    const res = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(res.scanned).toBe(1);
    expect(res.refreshed).toBe(0);
  });

  test('the refresh cursor persists between runs (rotation) and a stale one self-heals', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    await seedProvider(t);
    await seedActiveSub(t, await sha256Hex(MOCK_CONTENT), MIRROR_ON_P1);

    // Roundtrip: a stored cursor is read back; null resets.
    await t.mutation(internal.mirrorProviders.setRefreshCursor, { cursor: 'cursor-x' });
    expect(await t.query(internal.mirrorProviders.getRefreshCursor, {})).toBe('cursor-x');

    // A STALE/bogus cursor must not wedge the sweep: it restarts from the
    // beginning, completes the pass, and clears the cursor for the next tick.
    await t.mutation(internal.mirrorProviders.setRefreshCursor, { cursor: 'bogus-cursor' });
    const res = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(res.scanned).toBe(1);
    expect(await t.query(internal.mirrorProviders.getRefreshCursor, {})).toBeNull();
  });
});

describe('provisionMirror (opt-in lazy mirror)', () => {
  const MOCK_CONTENT = '# mock subscription content (dev)\n';

  async function seedTierAndUser(
    t: ReturnType<typeof convexTest>,
    withSub: boolean,
  ): Promise<Id<'users'>> {
    return t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree: true,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      if (withSub) {
        await ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: 'u1',
          backendShortId: 'short-1',
          subscriptionUrl: 'https://x/sub',
          subscriptionMirrors: [],
          state: 'active',
          updatedAt: Date.now(),
        });
      }
      return userId;
    });
  }

  test('no_subscription when the member has no active key', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedTierAndUser(t, false);
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('no_subscription');
  });

  test('capped when mirror.maxPerUser is 0 (returns before any upload)', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedTierAndUser(t, true);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'mirror.maxPerUser',
        value: JSON.stringify(0),
        updatedAt: Date.now(),
      }),
    );
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('capped');
  });

  test('exhausted when no provider is left for the request (none configured)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    const userId = await seedTierAndUser(t, true);
    const res = await t.action(internal.storage.provisionMirror, { userId, countryCode: null });
    expect(res.status).toBe('exhausted');
  });
});

describe('remnawaveUpdateUser contract safety', () => {
  // Direct provider-fn tests against a fetch stub (like the logging suite):
  // the panel's UPDATE DTO takes .optional() NOT .nullable() for
  // trafficLimitBytes/expireAt and refuses past expiry dates — a bad body
  // 400s the WHOLE patch (re-enable + limits + placement lost).
  const cfg = { baseUrl: 'https://panel.test.example', apiToken: 'tok' };
  const okUser = {
    uuid: '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b',
    shortUuid: 'short-1',
    username: 'freesocks-x',
    status: 'ACTIVE',
    trafficLimitBytes: 0,
    trafficLimitStrategy: 'MONTH',
    usedTrafficBytes: 0,
    expireAt: null,
    hwidDeviceLimit: null,
    subscriptionUrl: 'https://sub.test.example/short-1',
  };
  const stub = (user: unknown = okUser) => {
    const spy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ response: user }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', spy);
    return spy;
  };
  const sentBody = (spy: ReturnType<typeof vi.fn>) =>
    JSON.parse(String((spy.mock.calls[0]?.[1] as RequestInit).body));

  test('null trafficLimitBytes is coerced to 0 (the panel unlimited sentinel)', async () => {
    const spy = stub();
    await remnawaveUpdateUser(cfg, okUser.uuid, { trafficLimitBytes: null });
    expect(sentBody(spy).trafficLimitBytes).toBe(0);
  });

  test('a past expireAt is clamped to a near-future date; null expireAt is omitted', async () => {
    let spy = stub();
    await remnawaveUpdateUser(cfg, okUser.uuid, { expireAt: '2020-01-01T00:00:00.000Z' });
    const clamped = Date.parse(sentBody(spy).expireAt);
    expect(clamped).toBeGreaterThan(Date.now());
    expect(clamped).toBeLessThan(Date.now() + 10 * 60_000);

    spy = stub();
    await remnawaveUpdateUser(cfg, okUser.uuid, { expireAt: null, trafficLimitBytes: 5 });
    expect('expireAt' in sentBody(spy)).toBe(false);

    // A future date passes through untouched.
    spy = stub();
    const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
    await remnawaveUpdateUser(cfg, okUser.uuid, { expireAt: future });
    expect(sentBody(spy).expireAt).toBe(future);
  });

  test('null hwidDeviceLimit is omitted (the update DTO refuses null); a number is sent', async () => {
    // Enforcement toggled off → resolveHwidLimit yields null → every tier push
    // would 400 the whole PATCH if null were sent (same class as the
    // trafficLimitBytes/expireAt refusal). Omit instead.
    let spy = stub();
    await remnawaveUpdateUser(cfg, okUser.uuid, { hwidDeviceLimit: null });
    expect('hwidDeviceLimit' in sentBody(spy)).toBe(false);

    spy = stub();
    await remnawaveUpdateUser(cfg, okUser.uuid, { hwidDeviceLimit: 3 });
    expect(sentBody(spy).hwidDeviceLimit).toBe(3);
  });

  test('tolerates additive panel values: unknown status/strategy still parse', async () => {
    stub({ ...okUser, status: 'SOME_FUTURE_STATUS', trafficLimitStrategy: 'QUARTER' });
    await expect(
      remnawaveUpdateUser(cfg, okUser.uuid, { trafficLimitBytes: 1 }),
    ).resolves.toBeUndefined();
  });
});

describe('testBackendConnection stored-credential fallback', () => {
  test('with id + blank secrets, the probe runs against the STORED config', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const spy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) => new Response('nope', { status: 500 }),
    );
    vi.stubGlobal('fetch', spy);
    // No baseUrl/apiToken supplied — they must come from the stored row.
    const res = await t.action(internal.adminApi.testBackendConnection, {
      backend: 'remnawave',
      id: serverId,
    });
    expect(res.ok).toBe(false); // the stub 500s; reachability isn't the point
    expect(spy).toHaveBeenCalled();
    expect(String(spy.mock.calls[0]?.[0])).toContain('https://panel.test.example');
    const headers = (spy.mock.calls[0]?.[1] as RequestInit).headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tkn');
  });

  test('a typed field overrides the stored one', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const spy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) => new Response('nope', { status: 500 }),
    );
    vi.stubGlobal('fetch', spy);
    await t.action(internal.adminApi.testBackendConnection, {
      backend: 'remnawave',
      id: serverId,
      baseUrl: 'https://other.test.example',
    });
    expect(String(spy.mock.calls[0]?.[0])).toContain('https://other.test.example');
  });

  test('backend-type mismatch against the stored instance is a friendly error, no fetch', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t); // stored row is remnawave
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const res = await t.action(internal.adminApi.testBackendConnection, {
      backend: 'outline',
      id: serverId,
    });
    expect(res).toEqual({ ok: false, error: 'Backend type does not match the stored instance' });
    expect(spy).not.toHaveBeenCalled();
  });
});
