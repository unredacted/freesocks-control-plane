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
import {
  applyUsageCarryover,
  computeExpireAtIso,
  farFutureExpiryIso,
  gbToBytes,
  isFarFutureExpiry,
  resolveTrafficLimitBytes,
} from './lib/backends/types';
import { remnawaveUpdateUser } from './lib/backends/remnawave';
import { sha256Hex } from './lib/crypto';
import { MIRROR_FORMATS, mirrorSetHash } from './lib/mirrorFormats';
import { readKeyCount } from './lib/serverLoad';

const modules = import.meta.glob('./**/*.*s');

describe('issuance spec helpers', () => {
  test('gbToBytes uses binary GiB so a tier of 50 shows as "50 GiB" in Remnawave', () => {
    expect(gbToBytes(50)).toBe(50 * 1024 ** 3);
    expect(gbToBytes(0)).toBe(0);
  });

  test('gbToBytes rounds a fractional GB (donation bonus) to whole bytes', () => {
    // 2.01 GB from a 201-cent month at 1 GB/$ — the backend rejects float bytes,
    // which previously wedged the fleet re-cap cron in a fail-retry loop.
    const b = gbToBytes(50 + 2.01);
    expect(Number.isInteger(b)).toBe(true);
    expect(b).toBe(Math.round(52.01 * 1024 ** 3));
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 50, isDefaultFree: true }, 2.01)).toBe(b);
  });

  test('computeExpireAtIso: a member term wins; free carries the no-expiry sentinel', () => {
    const termMs = Date.UTC(2030, 0, 1);
    expect(computeExpireAtIso(termMs)).toBe(new Date(termMs).toISOString());
    // Free (no membership): the far-future sentinel — the backend never expires a
    // free key on its own clock; the usage-based idle sweep owns reclaim.
    const freeIso = computeExpireAtIso(null);
    const freeMs = Date.parse(freeIso);
    expect(freeMs).toBeGreaterThan(Date.now() + 3649 * 86_400_000);
    expect(isFarFutureExpiry(freeIso)).toBe(true);
  });

  test('isFarFutureExpiry: sentinel dates map back to "no expiry", real terms do not', () => {
    expect(isFarFutureExpiry(farFutureExpiryIso())).toBe(true);
    // A real (even long) membership term stays a real date.
    expect(isFarFutureExpiry(new Date(Date.now() + 365 * 86_400_000).toISOString())).toBe(false);
    expect(isFarFutureExpiry('not-a-date')).toBe(false);
  });

  test('computeExpireAtIso clamps a PAST membership expiry to a near-future grace (Review D-#7)', () => {
    // A lapsed member's stored expiry is in the past; Remnawave's create DTO
    // rejects past dates, which made regenerate permanently fail for them.
    const past = Date.now() - 86_400_000;
    const clamped = Date.parse(computeExpireAtIso(past));
    expect(clamped).toBeGreaterThan(Date.now());
    expect(clamped).toBeLessThanOrEqual(Date.now() + 6 * 60_000);
  });

  test('applyUsageCarryover preserves the period quota; 0 is never emitted (Review D-M3)', () => {
    const GB = 1024 ** 3;
    expect(applyUsageCarryover(50 * GB, 10 * GB)).toBe(40 * GB);
    // A fully-spent quota carries as 1 byte, NEVER 0 (0 = unlimited on
    // Remnawave, blocked on Outline — 1 byte is "spent" on both).
    expect(applyUsageCarryover(50 * GB, 50 * GB)).toBe(1);
    expect(applyUsageCarryover(50 * GB, 999 * GB)).toBe(1);
    // Garbage/negative usage can't inflate the limit.
    expect(applyUsageCarryover(50 * GB, -5)).toBe(50 * GB);
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

  test('a key no instance resolves is refused by every op: no made-up state, no silent write', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const key = { backend: 'remnawave' as const, backendUserId: 'ghost-user' };
    // The read used to answer {status:'active', usedTrafficBytes:0}: a used-up
    // account looked fine and nothing said why its links failed.
    await expect(t.action(internal.backends.getUser, key)).rejects.toThrow(
      /backend\.key_unresolved/,
    );
    await expect(t.action(internal.backends.resetUserTraffic, key)).rejects.toThrow(
      /backend\.key_unresolved/,
    );
    await expect(
      t.action(internal.backends.updateUser, { ...key, patch: { trafficLimitBytes: 5 } }),
    ).rejects.toThrow(/backend\.key_unresolved/);
    await expect(
      t.action(internal.backends.setUserStatus, { ...key, active: true }),
    ).rejects.toThrow(/backend\.key_unresolved/);
    await expect(t.action(internal.backends.deleteUser, key)).rejects.toThrow(
      /backend\.key_unresolved/,
    );
    // The best-effort usage read keeps degrading to null.
    expect(await t.action(internal.backends.getUserUsage, key)).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('a scoped key with no subscription row (a qualification account) resolves to the instance it names', async () => {
    const user3 = {
      id: 7,
      shortUuid: 'short-q',
      username: 'fcp-qualify-node-one-abcd1234',
      status: 'LIMITED',
      trafficLimitBytes: 52428800,
      trafficLimitStrategy: 'NO_RESET',
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://panel.test.example/api/sub/short-q',
      userTraffic: { usedTrafficBytes: 706906753 },
    };
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init: RequestInit = {}) => {
        const u = new URL(String(input));
        seen.push(`${(init.method ?? 'GET').toUpperCase()} ${u.host}${u.pathname}`);
        if (u.pathname.startsWith('/api/hwid/'))
          return new Response(JSON.stringify({ response: { devices: [] } }), { status: 200 });
        return new Response(JSON.stringify({ response: user3 }), { status: 200 });
      }),
    );
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const other = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'Other RW',
        slug: 'other-rw',
        config: { type: 'remnawave', baseUrl: 'https://other.test.example', apiToken: 'tkn' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    const key = { backend: 'remnawave' as const, backendUserId: `${serverId}:7` };

    // The real counters, not the sentinel.
    const state = await t.action(internal.backends.getUser, key);
    expect(state).toMatchObject({
      status: 'limited',
      usedTrafficBytes: 706906753,
      trafficLimitBytes: 52428800,
    });
    await t.action(internal.backends.resetUserTraffic, key);
    // The caller's hint agrees with the scope: same instance.
    await t.action(internal.backends.setUserStatus, {
      ...key,
      active: true,
      backendServerId: serverId,
    });
    expect(seen).toEqual([
      'GET panel.test.example/api/users/7',
      'GET panel.test.example/api/hwid/devices/7',
      'POST panel.test.example/api/users/7/actions/reset-traffic',
      'POST panel.test.example/api/users/7/actions/enable',
    ]);

    // A hint naming another instance is refused: user 7 there is someone else.
    seen.length = 0;
    await expect(
      t.action(internal.backends.resetUserTraffic, { ...key, backendServerId: other }),
    ).rejects.toThrow(/backend\.key_unresolved/);
    expect(seen).toEqual([]);
  });

  test('a hint resolves an unscoped key that has no subscription row', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init: RequestInit = {}) => {
        const u = new URL(String(input));
        seen.push(`${(init.method ?? 'GET').toUpperCase()} ${u.pathname}`);
        return new Response(JSON.stringify({ response: {} }), { status: 200 });
      }),
    );
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const uuid = '7b51b8a0-7a4c-4f0b-9e76-0d6a4c1f2a3b';
    await t.action(internal.backends.resetUserTraffic, {
      backend: 'remnawave',
      backendUserId: uuid,
      backendServerId: serverId,
    });
    expect(seen).toEqual([`POST /api/users/${uuid}/actions/reset-traffic`]);
    // Without the hint nothing names its instance.
    await expect(
      t.action(internal.backends.resetUserTraffic, { backend: 'remnawave', backendUserId: uuid }),
    ).rejects.toThrow(/backend\.key_unresolved/);
  });

  test('a hint naming a deleted instance refuses the teardown (possible orphan)', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    await t.run((ctx) => ctx.db.delete(serverId));
    await expect(
      t.action(internal.backends.deleteUser, {
        backend: 'remnawave',
        backendUserId: 'uuid-123',
        backendServerId: serverId,
      }),
    ).rejects.toThrow(/backend\.key_unresolved/);
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
      expect(await readKeyCount(ctx.db, row!)).toBe(1);
      // The count lives in the side table; the server row itself is not written.
      expect(row!.keyCount).toBe(0);
    });
  });

  test('a Remnawave 3.x numeric id is STORED scoped to its instance and STRIPPED for the provider', async () => {
    // 3.x backends return a per-backend integer `id` and no uuid. Two backends both
    // mint user 42, so the stored form must carry the instance (the
    // by_backend_user_id index is read with .unique()), while the backend only
    // ever sees the bare integer in paths/bodies.
    const user3 = {
      id: 42,
      shortUuid: 'short-3x',
      username: SPEC.username,
      status: 'ACTIVE',
      trafficLimitBytes: null,
      trafficLimitStrategy: 'MONTH',
      expireAt: null,
      hwidDeviceLimit: null,
      subscriptionUrl: 'https://panel.test.example/api/sub/short-3x',
      userTraffic: { usedTrafficBytes: 0 },
    };
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL, init: RequestInit = {}) => {
        const u = new URL(String(input));
        seen.push(`${(init.method ?? 'GET').toUpperCase()} ${u.pathname}`);
        if (u.pathname.startsWith('/api/hwid/'))
          return new Response(JSON.stringify({ response: { devices: [] } }), { status: 200 });
        if (init.body && (init.method ?? 'GET').toUpperCase() === 'PATCH') {
          const body = JSON.parse(String(init.body)) as Record<string, unknown>;
          expect(body.id).toBe(42);
          expect(body).not.toHaveProperty('uuid');
        }
        return new Response(JSON.stringify({ response: user3 }), { status: 200 });
      }),
    );
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);

    const issued = await t.action(internal.backends.issueUser, {
      backend: 'remnawave',
      spec: SPEC,
    });
    expect(issued.backendUserId).toBe(`${serverId}:42`);
    expect(issued.backendShortId).toBe('short-3x');

    // Persist the sub the way the issuance saga does, so key→instance resolves.
    await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'free',
        name: 'Free',
        backend: 'remnawave',
        monthlyTrafficGb: 1,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: false,
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
        backendUserId: issued.backendUserId,
        backendShortId: issued.backendShortId,
        backendServerId: serverId,
        subscriptionUrl: issued.subscriptionUrl,
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
    });

    seen.length = 0;
    await t.action(internal.backends.getUser, {
      backend: 'remnawave',
      backendUserId: issued.backendUserId,
    });
    await t.action(internal.backends.updateUser, {
      backend: 'remnawave',
      backendUserId: issued.backendUserId,
      patch: { trafficLimitBytes: 5 },
    });
    await t.action(internal.backends.setUserStatus, {
      backend: 'remnawave',
      backendUserId: issued.backendUserId,
      active: false,
    });
    await t.action(internal.backends.deleteUser, {
      backend: 'remnawave',
      backendUserId: issued.backendUserId,
    });
    expect(seen).toEqual([
      'GET /api/users/42',
      'GET /api/hwid/devices/42',
      'PATCH /api/users',
      'POST /api/users/42/actions/disable',
      'DELETE /api/users/42',
    ]);

    // The fleet locate/repair path must NOT probe other backends with a scoped
    // id: the same integer on another backend is a different user.
    seen.length = 0;
    const located = await t.action(internal.backends.locateKeyInstance, {
      backend: 'remnawave',
      backendUserId: 'someOtherServerId:42',
    });
    expect(located).toBeNull();
    expect(seen).toEqual([]);
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

describe('backends dispatch: host disable + node transport discovery', () => {
  async function seedOutline(t: ReturnType<typeof convexTest>): Promise<Id<'backendServers'>> {
    return t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'outline',
        name: 'Test Outline',
        slug: 'test-outline',
        config: {
          type: 'outline',
          apiUrl: 'https://outline.test.example/secret',
          websocketEnabled: false,
        },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('setHostDisabled sends exactly { uuid, isDisabled } to the instance', async () => {
    const fetchSpy = vi.fn(
      async (..._args: unknown[]) =>
        new Response(JSON.stringify({ response: { uuid: 'h-1', isDisabled: true } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    await t.action(internal.backends.setHostDisabled, {
      backendServerId: serverId,
      uuid: 'h-1',
      disabled: true,
    });
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe('https://panel.test.example/api/hosts');
    const init = (fetchSpy.mock.calls[0]?.[1] ?? {}) as RequestInit;
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(String(init.body))).toEqual({ uuid: 'h-1', isDisabled: true });
  });

  test('listNodeInbounds dispatches to the provider and returns its projection', async () => {
    const profile = '0f1e2d3c-4b5a-4968-8776-655443322110';
    const inboundUuid = '11111111-2222-4333-8444-555555555555';
    const fetchSpy = vi.fn(async (input: string | URL) => {
      const path = new URL(String(input)).pathname;
      const body =
        path === '/api/nodes'
          ? [
              {
                uuid: 'node-1',
                name: 'node-a',
                configProfile: {
                  activeConfigProfileUuid: profile,
                  activeInbounds: [{ uuid: inboundUuid, tag: 'SS' }],
                },
              },
            ]
          : {
              uuid: profile,
              name: 'p',
              config: {
                inbounds: [
                  {
                    tag: 'SS',
                    port: 8388,
                    protocol: 'shadowsocks',
                    settings: { clients: [{ password: 'PW_SECRET' }] },
                  },
                ],
              },
              inbounds: [{ uuid: inboundUuid, tag: 'SS' }],
            };
      return new Response(JSON.stringify({ response: body }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchSpy);
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const rows = await t.action(internal.backends.listNodeInbounds, {
      backendServerId: serverId,
      nodeUuid: 'node-1',
    });
    expect(rows).toEqual([
      {
        tag: 'SS',
        configProfileUuid: profile,
        configProfileInboundUuid: inboundUuid,
        protocol: 'shadowsocks',
        port: 8388,
        network: 'tcp',
        security: 'none',
        active: true,
      },
    ]);
    expect(JSON.stringify(rows)).not.toContain('PW_SECRET');
  });

  test('a backend without the capabilities throws the typed codes; a missing instance too', async () => {
    const t = convexTest(schema, modules);
    const outlineId = await seedOutline(t);
    await expect(
      t.action(internal.backends.setHostDisabled, {
        backendServerId: outlineId,
        uuid: 'h-1',
        disabled: true,
      }),
    ).rejects.toThrow(/backend\.hosts_unsupported/);
    await expect(
      t.action(internal.backends.listNodeInbounds, { backendServerId: outlineId, nodeUuid: 'n' }),
    ).rejects.toThrow(/backend\.inbounds_unsupported/);
    const gone = await seedOutline(t);
    await t.run((ctx) => ctx.db.delete(gone));
    await expect(
      t.action(internal.backends.listNodeInbounds, { backendServerId: gone, nodeUuid: 'n' }),
    ).rejects.toThrow(/backend\.not_found/);
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

  test('the first pass gives legacy mirrors their ledger rows; later passes page the ledger', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    await seedProvider(t);
    // What the pass renders: the mock backend answers every format's fetch alike.
    const hash = await sha256Hex(MOCK_CONTENT);
    await seedActiveSub(
      t,
      await mirrorSetHash(MIRROR_FORMATS.map((format) => ({ format, hash }))),
      MIRROR_ON_P1,
    );
    expect(await t.query(internal.mirrorCopies.isSeeded, {})).toBe(false);
    const first = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(first.scanned).toBe(1);
    expect(await t.query(internal.mirrorCopies.isSeeded, {})).toBe(true);
    const rows = await t.run((ctx) => ctx.db.query('mirrorCopies').collect());
    expect(rows.map((r) => [r.provider, r.state])).toEqual([['p1', 'in_sync']]);
    // Unmirrored active keys are not visited any more: the pass pages the ledger.
    await seedActiveSub(t, 'irrelevant', []);
    const second = await t.action(internal.storage.refreshActiveMirrors, {});
    expect(second.scanned).toBe(1);
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
  // the backend's UPDATE DTO takes .optional() NOT .nullable() for
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

  test('null trafficLimitBytes is coerced to 0 (the backend unlimited sentinel)', async () => {
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

  test('tolerates additive backend values: unknown status/strategy still parse', async () => {
    stub({ ...okUser, status: 'SOME_FUTURE_STATUS', trafficLimitStrategy: 'QUARTER' });
    await expect(
      remnawaveUpdateUser(cfg, okUser.uuid, { trafficLimitBytes: 1 }),
    ).resolves.toBeUndefined();
  });
});

describe('saved Remnawave panel credentials', () => {
  test('preserves the actual mount path of a legacy URL with trailing whitespace', async () => {
    const t = convexTest(schema, modules);
    const id = await seedServer(t);
    const baseUrl = 'https://panel.test.example/tenant ';
    await t.run((ctx) =>
      ctx.db.patch(id, {
        config: { type: 'remnawave', baseUrl, apiToken: 'tkn' },
      }),
    );
    const fetch = vi.fn(async (_url: string) => new Response(null, { status: 404 }));
    vi.stubGlobal('fetch', fetch);
    const backend = 'remnawave' as const;
    for (const input of [{}, { baseUrl }, { baseUrl: '   ' }]) {
      expect(
        (await t.action(internal.adminApi.testBackendConnection, { id, backend, ...input })).ok,
      ).toBe(true);
      expect(fetch).toHaveBeenLastCalledWith(
        'https://panel.test.example/tenant%20/api/users/by-username/fcp-health-probe-absent',
        expect.anything(),
      );
    }

    fetch.mockClear();
    const changed = baseUrl.trim();
    expect(
      (await t.action(internal.adminApi.testBackendConnection, { id, backend, baseUrl: changed }))
        .ok,
    ).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    await expect(
      t.mutation(internal.adminApi.updateBackendServer, { id, baseUrl: changed }),
    ).rejects.toThrow(/changing the base URL/);
    await expect(
      t.mutation(internal.adminApi.upsertBackendServerBySlug, {
        backend,
        slug: 'test-rw',
        baseUrl: changed,
      }),
    ).rejects.toThrow(/changing the base URL/);
    expect((await t.run((ctx) => ctx.db.get(id)))?.config).toMatchObject({
      baseUrl,
      apiToken: 'tkn',
    });
  });

  test.each(['create', 'upsert'] as const)(
    '%s needs an explicit token for a new panel',
    async (method) => {
      const t = convexTest(schema, modules);
      const create =
        method === 'create'
          ? internal.adminApi.createBackendServer
          : internal.adminApi.upsertBackendServerBySlug;
      for (const apiToken of [undefined, '   ']) {
        await expect(
          t.mutation(create, {
            backend: 'remnawave',
            name: 'Panel',
            slug: 'panel',
            baseUrl: 'https://panel.example',
            apiToken,
          }),
        ).rejects.toThrow(/base URL and an API token are required/);
      }
      expect(await t.run((ctx) => ctx.db.query('backendServers').collect())).toHaveLength(0);
    },
  );

  test.each(['update', 'upsert'] as const)(
    '%s keeps health checks bound to the saved panel and token',
    async (method) => {
      const t = convexTest(schema, modules);
      const id = await seedServer(t);
      const original = 'https://panel.test.example';
      const replacement = 'https://new-panel.test.example';
      const edit = (baseUrl: string, apiToken?: string) =>
        method === 'update'
          ? t.mutation(internal.adminApi.updateBackendServer, { id, baseUrl, apiToken })
          : t.mutation(internal.adminApi.upsertBackendServerBySlug, {
              slug: 'test-rw',
              backend: 'remnawave',
              baseUrl,
              apiToken,
            });

      // A failed probe ends this cron pass before the optional fleet telemetry requests.
      const fetch = vi.fn(
        async (_url: string, _init?: RequestInit) => new Response(null, { status: 503 }),
      );
      vi.stubGlobal('fetch', fetch);
      const expectHealthProbe = async (baseUrl: string, apiToken: string) => {
        fetch.mockClear();
        await t.action(internal.backendServers.healthcheck, {});
        expect(fetch).toHaveBeenCalledTimes(1);
        const [url, init] = fetch.mock.calls[0]!;
        expect(url).toBe(baseUrl + '/api/users/by-username/fcp-health-probe-absent');
        expect(new Headers(init?.headers).get('authorization')).toBe('Bearer ' + apiToken);
      };

      await expect(edit('   ')).rejects.toThrow();
      await edit(original, ''); // unchanged URL, existing token
      for (const url of [replacement, original + ':8443', original + '/other-panel']) {
        for (const token of [undefined, '', '   ']) {
          await expect(edit(url, token)).rejects.toThrow(
            /token is required when changing the base URL/,
          );
        }
      }
      await expectHealthProbe(original, 'tkn');
      await edit(replacement, 'new-token');
      await expectHealthProbe(replacement, 'new-token');
    },
  );
});

describe.each(['outline', 'remnawave'] as const)('%s connection-test destination', (backend) => {
  function config(url: string) {
    return backend === 'outline'
      ? { type: 'outline' as const, apiUrl: url, websocketEnabled: false }
      : { type: 'remnawave' as const, baseUrl: url, apiToken: 'fixture-token' };
  }

  test('checks both supplied and stored destinations before sending a request', async () => {
    vi.stubEnv('ALLOW_INTERNAL_BACKENDS', 'false');
    const t = convexTest(schema, modules);
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    for (const url of ['http://localhost./fixture', 'http://[::ffff:127.0.0.1]/fixture']) {
      const { type, ...fields } = config(url);
      expect(
        (await t.action(internal.adminApi.testBackendConnection, { backend: type, ...fields })).ok,
      ).toBe(false);
    }

    // Existing rows may have been saved under a different operator policy.
    const id = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend,
        config: config('http://localhost/fixture'),
        name: 'Fixture',
        slug: 'fixture',
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    const probe = () => t.action(internal.adminApi.testBackendConnection, { backend, id });
    expect((await probe()).ok).toBe(false);
    expect(fetch).not.toHaveBeenCalled();

    vi.stubEnv('ALLOW_INTERNAL_BACKENDS', 'true');
    fetch.mockResolvedValue(Response.json({ accessKeys: [] }));
    expect((await probe()).ok).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  test('contacts a permitted private panel directly and reports its redirect as a failed test', async () => {
    vi.stubEnv('ALLOW_INTERNAL_BACKENDS', 'false');
    const t = convexTest(schema, modules);
    const { type, ...fields } = config('https://10.1.2.3/panel');
    const probe = () =>
      t.action(internal.adminApi.testBackendConnection, { backend: type, ...fields });
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ accessKeys: [{}, {}] }))
      .mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: '/moved' } }));
    vi.stubGlobal('fetch', fetch);
    expect(await probe()).toEqual({ ok: true, keyCount: backend === 'outline' ? 2 : 0 });
    expect(await probe()).toMatchObject({ ok: false, error: expect.stringContaining('302') });
    expect(fetch).toHaveBeenCalledTimes(2);
    for (const [url, options] of fetch.mock.calls) {
      expect(url).toMatch(/^https:\/\/10\.1\.2\.3\/panel\//);
      expect(options.redirect).toBe('manual');
    }
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

  test('explicit URL and token override the stored ones together', async () => {
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
      apiToken: 'replacement-token',
    });
    expect(String(spy.mock.calls[0]?.[0])).toContain('https://other.test.example');
    const headers = (spy.mock.calls[0]?.[1] as RequestInit).headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer replacement-token');
  });

  test('reuses the stored token when an unchanged URL is normalized by the editor', async () => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    await t.run((ctx) =>
      ctx.db.patch(serverId, {
        config: {
          type: 'remnawave',
          baseUrl: '  https://panel.test.example  ',
          apiToken: 'tkn',
        },
      }),
    );
    const spy = vi.fn(
      async (_url: string | URL, _init?: RequestInit) => new Response('nope', { status: 500 }),
    );
    vi.stubGlobal('fetch', spy);

    await t.action(internal.adminApi.testBackendConnection, {
      backend: 'remnawave',
      id: serverId,
      baseUrl: 'https://panel.test.example',
    });

    expect(spy).toHaveBeenCalled();
    const headers = (spy.mock.calls[0]?.[1] as RequestInit).headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tkn');
  });

  test.each([
    { baseUrl: 'https://other.test.example' },
    { baseUrl: 'https://panel.test.example/other-panel', apiToken: '   ' },
  ])('refuses a changed URL without an explicit token before fetching', async (overrides) => {
    const t = convexTest(schema, modules);
    const serverId = await seedServer(t);
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const res = await t.action(internal.adminApi.testBackendConnection, {
      backend: 'remnawave',
      id: serverId,
      ...overrides,
    });
    expect(res).toEqual({
      ok: false,
      error: 'An API token is required when changing the base URL',
    });
    expect(spy).not.toHaveBeenCalled();
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
