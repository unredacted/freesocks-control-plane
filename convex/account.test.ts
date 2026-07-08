/// <reference types="vite/client" />
/**
 * Regenerate / switch-backend saga tests (pass 2) — the most failure-prone
 * code in the repo had no direct suite. Uses the double-gated dev mock backend
 * (DEV_MOCK_BACKEND + ENVIRONMENT=development) so issuance short-circuits with
 * no HTTP; the no-instances failure case runs with the mock OFF.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

beforeEach(() => {
  vi.stubEnv('DEV_MOCK_BACKEND', 'true');
  vi.stubEnv('ENVIRONMENT', 'development');
});
afterEach(() => {
  vi.unstubAllEnvs();
});

async function seedTier(
  t: ReturnType<typeof convexTest>,
  over: Partial<{
    slug: string;
    backend: 'remnawave' | 'outline';
    isDefaultFree: boolean;
  }> = {},
): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: over.slug ?? 'free',
      name: over.slug ?? 'Free',
      backend: over.backend ?? 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: over.isDefaultFree ?? true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    }),
  );
}

async function seedUser(
  t: ReturnType<typeof convexTest>,
  tierId: Id<'tiers'>,
): Promise<Id<'users'>> {
  return t.run((ctx) =>
    ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
  );
}

describe('account.regenerate saga', () => {
  test('first regenerate creates an active sub and repoints the user', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    const out = await t.action(internal.account.regenerate, { userId });
    expect(out.subscriptionUrl).toBeTruthy();
    expect(out.shortUuid).toBeTruthy();

    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      expect(subs[0]!.state).toBe('active');
      const user = await ctx.db.get(userId);
      expect(user!.currentSubscriptionId).toBe(subs[0]!._id);
    });
  });

  test('re-regenerate tombstones the old sub with ~24h grace; the new one is current', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    await t.action(internal.account.regenerate, { userId });
    const before = Date.now();
    await t.action(internal.account.regenerate, { userId });

    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(2);
      const old = subs.find((s) => s.state === 'disabled')!;
      const fresh = subs.find((s) => s.state === 'active')!;
      expect(old).toBeTruthy();
      expect(fresh).toBeTruthy();
      // grace clock ≈ now + 24h
      expect(old.deletedAt!).toBeGreaterThanOrEqual(before + 24 * 3_600_000 - 5_000);
      expect(old.deletedAt!).toBeLessThanOrEqual(Date.now() + 24 * 3_600_000 + 5_000);
      const user = await ctx.db.get(userId);
      expect(user!.currentSubscriptionId).toBe(fresh._id);
    });
  });

  test('a third regenerate cannot reset an existing tombstone grace clock', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    await t.action(internal.account.regenerate, { userId });
    await t.action(internal.account.regenerate, { userId });
    const firstTombstone = await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      return subs.find((s) => s.state === 'disabled')!;
    });

    await t.action(internal.account.regenerate, { userId });
    await t.run(async (ctx) => {
      const same = await ctx.db.get(firstTombstone._id);
      // tombstoneWithGrace is a no-op on a non-active row: deletedAt unchanged.
      expect(same!.deletedAt).toBe(firstTombstone.deletedAt);
    });
  });

  test('backend failure (no instances, mock off) leaves no local state behind', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    // issueUser now throws a typed ConvexError({code:'backend.unavailable'}) (Review P3).
    await expect(t.action(internal.account.regenerate, { userId })).rejects.toThrow(
      /backend\.unavailable/,
    );
    await t.run(async (ctx) => {
      expect(await ctx.db.query('subscriptions').collect()).toHaveLength(0);
      const user = await ctx.db.get(userId);
      expect(user!.currentSubscriptionId).toBeUndefined();
    });
  });
});

describe('account issuance lock (P1-3)', () => {
  test('only one holder at a time; release frees it', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    // acquire now also returns an owner nonce (Review #7).
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      false,
    );
    await t.mutation(internal.account.releaseIssuanceLock, { userId }); // legacy tokenless release
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
  });

  test('an expired lock row self-heals (crashed saga cannot wedge the user)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: `issue-lock:${userId}`,
        value: String(Date.now() - 1_000), // legacy bare-number format, already expired
        updatedAt: Date.now(),
      });
    });
    // parseLock tolerates the legacy format → the expired lock is taken over.
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
  });

  test('release is owner-checked: a stale token cannot free another saga’s lock (Review #7)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    const held = await t.mutation(internal.account.acquireIssuanceLock, { userId });
    expect(held.acquired).toBe(true);
    // A release with the WRONG token must NOT free the lock…
    await t.mutation(internal.account.releaseIssuanceLock, { userId, token: 'not-the-holder' });
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      false,
    );
    // …but the real holder's token does.
    await t.mutation(internal.account.releaseIssuanceLock, { userId, token: held.token });
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
  });
});

describe('account.revokeDevice', () => {
  const UUID = '550e8400-e29b-41d4-a716-446655440042';
  const HWID = 'device-hwid-abcdef0123456789';

  function jsonRes(obj: unknown): Response {
    return new Response(JSON.stringify(obj), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }

  /** Seed a real (non-mock) remnawave instance + user + active subscription. */
  async function seedWithSub(
    t: ReturnType<typeof convexTest>,
    backend: 'remnawave' | 'outline' = 'remnawave',
  ): Promise<Id<'users'>> {
    const tierId = await seedTier(t, { backend });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      const instanceId = await ctx.db.insert('backendServers', {
        backend,
        name: 'test',
        slug: 'test',
        config:
          backend === 'remnawave'
            ? { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' }
            : { type: 'outline', apiUrl: 'https://outline.test/secret/', websocketEnabled: false },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend,
        backendUserId: UUID,
        backendShortId: 'short1',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/short1',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    });
    return userId;
  }

  /** Fetch stub covering getUser (user + device list) and the device delete. */
  function stubPanelFetch(devices: { hwid: string }[]): ReturnType<typeof vi.fn> {
    const fetchMock = vi.fn(async (input: string | URL) => {
      const u = typeof input === 'string' ? input : input.toString();
      if (u.includes('/api/hwid/devices/delete')) return jsonRes({ ok: true });
      if (u.includes('/api/hwid/devices'))
        return jsonRes({ response: { total: devices.length, devices } });
      return jsonRes({
        uuid: UUID,
        shortUuid: 'short1',
        username: 'u',
        status: 'ACTIVE',
        trafficLimitBytes: null,
        trafficLimitStrategy: 'MONTH',
        usedTrafficBytes: 0,
        expireAt: null,
        hwidDeviceLimit: null,
        subscriptionUrl: 'https://panel.test/sub/short1',
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  // These run against the REAL remnawave provider (stubbed fetch), not the
  // dev mock — the mock reports no devices, so ownership would never pass.
  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
  });
  afterEach(() => vi.unstubAllGlobals());

  test('revokes an owned device on the backend and audits a truncated hwid', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedWithSub(t);
    const fetchMock = stubPanelFetch([{ hwid: HWID }]);

    const res = await t.action(internal.account.revokeDevice, { userId, hwid: HWID });
    expect(res).toEqual({ ok: true });

    const deleteCall = fetchMock.mock.calls.find(([input]) =>
      String(input).includes('/api/hwid/devices/delete'),
    );
    expect(deleteCall).toBeTruthy();

    await t.run(async (ctx) => {
      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.device_revoke',
      );
      expect(audit).toBeTruthy();
      const payload = JSON.stringify(audit!.payload ?? {});
      expect(payload).toContain(HWID.slice(0, 8));
      expect(payload).not.toContain(HWID); // never the full identifier
    });
  });

  test('a hwid not on the member’s key is refused, and nothing is deleted', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedWithSub(t);
    const fetchMock = stubPanelFetch([{ hwid: HWID }]);

    const res = await t.action(internal.account.revokeDevice, {
      userId,
      hwid: 'someone-elses-device',
    });
    expect(res).toMatchObject({ ok: false, code: 'devices.not_found', status: 404 });
    expect(
      fetchMock.mock.calls.some(([input]) => String(input).includes('/api/hwid/devices/delete')),
    ).toBe(false);
  });

  test('an outline subscription is refused as unsupported', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedWithSub(t, 'outline');
    const res = await t.action(internal.account.revokeDevice, { userId, hwid: HWID });
    expect(res).toMatchObject({ ok: false, code: 'devices.unsupported', status: 409 });
  });

  test('no active subscription is a 404', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    const res = await t.action(internal.account.revokeDevice, { userId, hwid: HWID });
    expect(res).toMatchObject({ ok: false, code: 'devices.no_subscription', status: 404 });
  });
});

describe('account.switchBackend guards', () => {
  test('same-backend switch is a validation error', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    const res = await t.action(internal.account.switchBackend, {
      userId,
      target: 'remnawave',
    });
    expect(res).toMatchObject({ ok: false, code: 'validation', status: 400 });
  });

  test('a disabled target backend is refused (outline ships disabled)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    // appSettings default: outline.enabled=false
    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: false, code: 'backend.disabled', status: 503 });
  });

  test('a paid (non-default-free) tier gets the interim 409 tier.no_peer', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { slug: 'member', isDefaultFree: false });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'outline.enabled',
        value: 'true',
        updatedAt: Date.now(),
      });
    });
    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: false, code: 'tier.no_peer', status: 409 });
  });

  test('a paid tier with a linked peer switches to it (D-1 tier-linkage, forward)', async () => {
    const t = convexTest(schema, modules);
    const fromTier = await seedTier(t, {
      slug: 'member',
      backend: 'remnawave',
      isDefaultFree: false,
    });
    const peerTier = await seedTier(t, {
      slug: 'member-outline',
      backend: 'outline',
      isDefaultFree: false,
    });
    // Link the paid remnawave tier forward to its outline peer.
    await t.run((ctx) => ctx.db.patch(fromTier, { peerTierId: peerTier }));
    const userId = await seedUser(t, fromTier);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'outline.enabled',
        value: 'true',
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.account.regenerate, { userId }); // an existing key to tombstone

    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: true, backend: 'outline' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.tierId).toBe(peerTier);
    });
  });

  test('the peer link resolves in reverse (only the other tier points back)', async () => {
    const t = convexTest(schema, modules);
    const fromTier = await seedTier(t, {
      slug: 'member',
      backend: 'remnawave',
      isDefaultFree: false,
    });
    const peerTier = await seedTier(t, {
      slug: 'member-outline',
      backend: 'outline',
      isDefaultFree: false,
    });
    // Link set ONLY on the outline side; switching FROM remnawave must still find it.
    await t.run((ctx) => ctx.db.patch(peerTier, { peerTierId: fromTier }));
    const userId = await seedUser(t, fromTier);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'outline.enabled',
        value: 'true',
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.account.regenerate, { userId });

    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: true, backend: 'outline' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.tierId).toBe(peerTier);
    });
  });

  test('a free user switches via the default-free peer tier', async () => {
    const t = convexTest(schema, modules);
    const fromTier = await seedTier(t, { slug: 'free', backend: 'remnawave' });
    const peerTier = await seedTier(t, { slug: 'free-outline', backend: 'outline' });
    const userId = await seedUser(t, fromTier);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'outline.enabled',
        value: 'true',
        updatedAt: Date.now(),
      });
    });
    await t.action(internal.account.regenerate, { userId }); // existing key to tombstone

    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: true, backend: 'outline' });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user!.tierId).toBe(peerTier);
      const subs = await ctx.db.query('subscriptions').collect();
      // P1-6 ordering: the old key is tombstoned, the new one active.
      expect(subs.filter((s) => s.state === 'disabled')).toHaveLength(1);
      expect(subs.filter((s) => s.state === 'active')).toHaveLength(1);
    });
  });
});

/**
 * switchMode saga: re-issue the member's key into the chosen connection mode's
 * least-loaded node (transport choice), tombstone the old key with 24h grace,
 * record the choice — WITHIN the same backend (no tier/peer change). The squad
 * UUID (placement) must flow into issuance but never reach the audit log.
 */
describe('account.switchMode saga', () => {
  // The live-provider test stubs fetch; unstub after each so the dev-mock tests stay clean.
  afterEach(() => vi.unstubAllGlobals());

  test('choosing the mode you already have is a no-op validation error (no key churn)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'privacy' }));

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy' });
    expect(res).toMatchObject({ ok: false, code: 'validation', status: 400 });
    await t.run(async (ctx) => {
      expect(await ctx.db.query('subscriptions').collect()).toHaveLength(0);
    });
  });

  test('rejects an unknown mode id', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    const res = await t.action(internal.account.switchMode, { userId, target: 'nonsense' });
    expect(res).toMatchObject({ ok: false, code: 'validation', status: 400 });
  });

  test('re-issues into the mode placement, tombstones the old key, records the choice, audits without the squad uuid', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const SQUAD = '11111111-2222-3333-4444-555555555555';
    const NEW_UUID = '550e8400-e29b-41d4-a716-446655440077';
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      // Bind the privacy mode's placement pool — the infra detail never audited.
      await ctx.db.insert('appSettings', {
        key: 'connectionMode.privacy.squadUuids',
        value: JSON.stringify([SQUAD]),
        updatedAt: Date.now(),
      });
      const instanceId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'test',
        slug: 'test',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old-key-uuid',
        backendShortId: 'oldshort',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    });
    // The only HTTP the saga makes is the create (POST /api/users); the tombstone is DB-only.
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: NEW_UUID,
              shortUuid: 'newshort',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              usedTrafficBytes: 0,
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/newshort',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const before = Date.now();
    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy' });
    expect(res).toMatchObject({ ok: true, mode: { id: 'privacy' } });

    // The new key was issued INTO the mode's placement (single-squad pool → that squad).
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
    );
    expect(createCall).toBeTruthy();
    const body = JSON.parse(String(createCall![1]!.body));
    expect(body.activeInternalSquads).toEqual([SQUAD]);

    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user!.connectionModeId).toBe('privacy');
      const subs = await ctx.db.query('subscriptions').collect();
      const old = subs.find((s) => s.state === 'disabled')!;
      const fresh = subs.find((s) => s.state === 'active')!;
      expect(old).toBeTruthy();
      expect(fresh).toBeTruthy();
      // 24h grace, mirroring regenerate / switch-backend.
      expect(old.deletedAt!).toBeGreaterThanOrEqual(before + 24 * 3_600_000 - 5_000);
      expect(user!.currentSubscriptionId).toBe(fresh._id);
      // The key persists its placement so tier pushes never re-home it.
      expect(fresh.backendPlacement).toBe(SQUAD);

      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.switch_mode',
      );
      expect(audit).toBeTruthy();
      const payload = JSON.stringify(audit!.payload ?? {});
      expect(payload).toContain('privacy'); // toMode recorded
      expect(payload).not.toContain(SQUAD); // the squad uuid is NEVER audited
    });
  });

  test('falls back to the tier squad when the target mode has no placement pool bound', async () => {
    // dev mock ON (top-level beforeEach) → issuance short-circuits; assert it still
    // succeeds and records the choice even with no mode pool bound.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    await t.action(internal.account.regenerate, { userId }); // an existing key to tombstone

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy' });
    expect(res).toMatchObject({ ok: true, mode: { id: 'privacy' } });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('privacy');
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs.filter((s) => s.state === 'disabled')).toHaveLength(1);
      expect(subs.filter((s) => s.state === 'active')).toHaveLength(1);
    });
  });
});

/**
 * deleteSubscriptionEverywhere ordering (P1-5), driven via the tombstone sweep.
 * The invariant: the backend DELETE happens FIRST and is not swallowed — if it
 * throws, the local row must NOT be marked `deleted` (so the next sweep retries)
 * and the instance keyCount must be left alone. Runs against the REAL remnawave
 * provider with a stubbed fetch, mirroring the revokeDevice suite.
 */
describe('deleteSubscriptionEverywhere ordering (P1-5)', () => {
  const UUID = '550e8400-e29b-41d4-a716-446655440099';

  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
  });
  afterEach(() => vi.unstubAllGlobals());

  /** Seed a real remnawave instance + a DISABLED sub whose grace has elapsed. */
  async function seedDueTombstone(t: ReturnType<typeof convexTest>): Promise<{
    userId: Id<'users'>;
    subId: Id<'subscriptions'>;
    instanceId: Id<'backendServers'>;
  }> {
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    return t.run(async (ctx) => {
      const instanceId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'test',
        slug: 'test',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: UUID,
        backendShortId: 'short9',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/short9',
        subscriptionMirrors: [],
        state: 'disabled',
        deletedAt: Date.now() - 1_000, // grace elapsed → due for the sweep
        updatedAt: Date.now(),
      });
      return { userId, subId, instanceId };
    });
  }

  test('a failing backend DELETE leaves the local row disabled (not deleted) and keyCount untouched', async () => {
    const t = convexTest(schema, modules);
    const { subId, instanceId } = await seedDueTombstone(t);
    // Every DELETE to the panel returns 500 → remnawaveDeleteUser throws (a 500 is
    // NOT the idempotent 404 short-circuit), so deleteSubscriptionEverywhere must
    // propagate without marking the row.
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response('upstream boom', { status: 500 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { removed } = await t.action(internal.lifecycle.sweepTombstones, {});
    expect(removed).toBe(0); // the throw was counted as not-removed

    // A DELETE was actually attempted (ordering: backend first).
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).includes(`/api/users/${UUID}`) && init?.method === 'DELETE',
      ),
    ).toBe(true);

    await t.run(async (ctx) => {
      const sub = await ctx.db.get(subId);
      // The row is still selectable by the next sweep — NOT tombstoned to deleted.
      expect(sub!.state).toBe('disabled');
      // keyCount decrement only happens AFTER a successful backend delete.
      expect((await ctx.db.get(instanceId))!.keyCount).toBe(1);
    });
  });

  test('a succeeding backend DELETE marks the row deleted and decrements keyCount', async () => {
    const t = convexTest(schema, modules);
    const { subId, instanceId } = await seedDueTombstone(t);
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const { removed } = await t.action(internal.lifecycle.sweepTombstones, {});
    expect(removed).toBe(1);

    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.state).toBe('deleted');
      expect((await ctx.db.get(instanceId))!.keyCount).toBe(0);
    });
  });
});
