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
      // Regenerate ROTATES the fronted URL (unlike mode/backend switches, which
      // carry the token): the new row minted a fresh token, and the old row
      // keeps its own so the old URL still resolves through the grace window.
      expect(fresh.subToken).toMatch(/^[0-9a-f]{32}$/);
      expect(old.subToken).toMatch(/^[0-9a-f]{32}$/);
      expect(fresh.subToken).not.toBe(old.subToken);
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
    const first = await t.mutation(internal.account.acquireIssuanceLock, { userId });
    expect(first.acquired).toBe(true);
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      false,
    );
    // Release REQUIRES the holder's token (Review D-#9 — no tokenless escape hatch).
    await t.mutation(internal.account.releaseIssuanceLock, { userId, token: first.token! });
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
    await t.mutation(internal.account.releaseIssuanceLock, { userId, token: held.token! });
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

  test('a paid tier switches via the symmetric peerGroup (no pairwise link needed)', async () => {
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
    // One shared string on both rows — no peerTierId anywhere.
    await t.run(async (ctx) => {
      await ctx.db.patch(fromTier, { peerGroup: 'member' });
      await ctx.db.patch(peerTier, { peerGroup: 'member' });
    });
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

  test('a switch INTO remnawave is refused when the stored mode lost its pool (no silent downgrade)', async () => {
    const t = convexTest(schema, modules);
    const fromTier = await seedTier(t, { slug: 'free-outline', backend: 'outline' });
    await seedTier(t, { slug: 'free', backend: 'remnawave' }); // default-free peer
    const userId = await seedUser(t, fromTier);
    await t.run(async (ctx) => {
      // The member chose privacy (unbound); only evade has a pool bound.
      await ctx.db.patch(userId, { connectionModeId: 'privacy-reality' });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-freedom-ws'] }),
        updatedAt: Date.now(),
      });
    });

    const res = await t.action(internal.account.switchBackend, { userId, target: 'remnawave' });
    expect(res).toMatchObject({ ok: false, code: 'mode.unavailable', status: 400 });
    await t.run(async (ctx) => {
      // Tier + mode untouched, and no key was minted into the wrong pool.
      const user = await ctx.db.get(userId);
      expect(user!.tierId).toBe(fromTier);
      expect(user!.connectionModeId).toBe('privacy-reality');
      expect(await ctx.db.query('subscriptions').collect()).toHaveLength(0);
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
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'privacy-reality' }));

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
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

  test('rejects a mode an admin has DISABLED, even when its pool is bound', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    // freedom-reality ships dark. Binding a pool must not make it selectable —
    // the operator turns it on deliberately, in the admin panel.
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['11111111-2222-3333-4444-555555555555'] }),
        updatedAt: Date.now(),
      }),
    );
    const res = await t.action(internal.account.switchMode, {
      userId,
      target: 'freedom-reality',
    });
    expect(res).toMatchObject({ ok: false, code: 'validation', status: 400 });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId ?? null).not.toBe('freedom-reality');
    });
  });

  test('a member STRANDED on a disabled mode can still switch AWAY from it', async () => {
    // The guard above is one-way on purpose: disabling a mode must not trap the
    // members already on it. Only the TARGET is validated.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      await ctx.db.patch(userId, { connectionModeId: 'freedom-reality' }); // disabled
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['11111111-2222-3333-4444-555555555555'] }),
        updatedAt: Date.now(),
      });
    });
    const res = await t.action(internal.account.switchMode, { userId, target: 'freedom-ws' });
    expect(res).toMatchObject({ ok: true, mode: { id: 'freedom-ws' } });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('freedom-ws');
    });
  });

  test('switches IN PLACE: PATCHes the existing key’s squad, keeps the same sub row/URL/token, audits without the squad uuid', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const SQUAD = '11111111-2222-3333-4444-555555555555';
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      // Bind the privacy mode's placement pool — the infra detail never audited.
      await ctx.db.insert('modePlacements', {
        modeSlug: 'privacy-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD] }),
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
        subToken: 'tok-abc',
        // A stale cached body that MUST be dropped on switch (same token).
        subCache: JSON.stringify([{ ua: 'x', content: 'stale', contentType: 't', at: Date.now() }]),
        subscriptionMirrors: [],
        backendPlacement: 'old-squad',
        state: 'active',
        updatedAt: Date.now(),
      });
      // Currently on evade → switching to privacy is a real change.
      await ctx.db.patch(userId, { currentSubscriptionId: subId, connectionModeId: 'freedom-ws' });
    });
    // The only HTTP an in-place switch makes is the squad PATCH (PATCH /api/users).
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-446655440000',
              shortUuid: 'oldshort',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              userTraffic: { usedTrafficBytes: 0 },
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/oldshort',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
    // Same key returned; nothing tombstoned.
    expect(res).toMatchObject({
      ok: true,
      mode: { id: 'privacy-reality' },
      subscriptionUrl: 'https://panel.test/sub/oldshort',
      oldSubscriptionDeletedAt: null,
    });

    // The squad moved via PATCH /api/users (uuid in body) — NOT a create POST.
    const patchCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes('/api/users') && init?.method === 'PATCH',
    );
    expect(patchCall).toBeTruthy();
    const body = JSON.parse(String(patchCall![1]!.body));
    expect(body.uuid).toBe('old-key-uuid');
    expect(body.activeInternalSquads).toEqual([SQUAD]);
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
      ),
    ).toBe(false);

    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user!.connectionModeId).toBe('privacy-reality');
      // The SAME row survives: no tombstone, no new row.
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      const only = subs[0]!;
      expect(only.state).toBe('active');
      expect(only.backendUserId).toBe('old-key-uuid'); // not a re-issue
      expect(only.subToken).toBe('tok-abc'); // fronted URL unchanged
      expect(only.backendPlacement).toBe(SQUAD); // re-pointed
      expect(only.subCache).toBeUndefined(); // stale content cache dropped
      expect(user!.currentSubscriptionId).toBe(only._id); // pointer unchanged

      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.switch_mode',
      );
      expect(audit).toBeTruthy();
      const payload = JSON.stringify(audit!.payload ?? {});
      expect(payload).toContain('privacy'); // toMode recorded
      expect(payload).toContain('inPlace'); // marked in-place
      expect(payload).not.toContain(SQUAD); // the squad uuid is NEVER audited
    });
  });

  test('repairs a STALE backendServerId (re-registered panel) and still switches in place', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const SQUAD = '11111111-2222-3333-4444-555555555555';
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    const { activeInstanceId } = await t.run(async (ctx) => {
      await ctx.db.insert('modePlacements', {
        modeSlug: 'privacy-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD] }),
        updatedAt: Date.now(),
      });
      // The panel row the sub was issued against was deleted + re-registered
      // (e.g. an Ansible by-slug re-create): the sub's pointer is now stale,
      // which used to force the re-issue fallback on EVERY mode switch.
      const staleId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'old-row',
        slug: 'old-row',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.delete(staleId);
      const liveId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'panel',
        slug: 'panel',
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
        backendServerId: staleId,
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subscriptionMirrors: [],
        backendPlacement: 'old-squad',
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId, connectionModeId: 'freedom-ws' });
      return { activeInstanceId: liveId };
    });
    // The probe GETs the user off the live panel; the switch PATCHes the squad.
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-446655440000',
              shortUuid: 'oldshort',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              userTraffic: { usedTrafficBytes: 0 },
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/oldshort',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
    // In place: same key/URL, nothing tombstoned, no create POST.
    expect(res).toMatchObject({
      ok: true,
      mode: { id: 'privacy-reality' },
      subscriptionUrl: 'https://panel.test/sub/oldshort',
      oldSubscriptionDeletedAt: null,
    });
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
      ),
    ).toBe(false);
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      expect(subs[0]!.backendUserId).toBe('old-key-uuid'); // not re-issued
      expect(subs[0]!.backendPlacement).toBe(SQUAD);
      // The stale pointer was repaired to the live panel row.
      expect(subs[0]!.backendServerId).toBe(activeInstanceId);
    });
  });

  test('the re-issue path CARRIES the subToken: same fronted URL, old row vacated', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const SQUAD = '11111111-2222-3333-4444-555555555555';
    const NEW_UUID = '550e8400-e29b-41d4-a716-446655440099';
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      await ctx.db.insert('modePlacements', {
        modeSlug: 'privacy-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD] }),
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
        subToken: 'tok-carry',
        subscriptionMirrors: [],
        backendPlacement: 'old-squad',
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId, connectionModeId: 'freedom-ws' });
    });
    // Force the fallback: the in-place squad PATCH 500s, the re-issue POST works.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      if (String(input).includes('/api/users') && method === 'PATCH')
        return new Response('boom', { status: 500 });
      if (String(input).includes('/api/hwid/devices'))
        return new Response('not found', { status: 404 });
      if (String(input).includes('/api/users') && method === 'POST')
        return new Response(
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
        );
      return new Response(JSON.stringify({ response: { ok: true } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
    expect(res).toMatchObject({ ok: true, mode: { id: 'privacy-reality' } });
    // A re-issue DID happen (grace window on the old key)…
    expect((res as { oldSubscriptionDeletedAt: string | null }).oldSubscriptionDeletedAt).not.toBe(
      null,
    );
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(2);
      const fresh = subs.find((s) => s.state === 'active')!;
      const old = subs.find((s) => s.state === 'disabled')!;
      // …but the member's fronted URL is byte-identical: the token moved to
      // the new row and the old row was vacated (bySubToken is .unique()).
      expect(fresh.backendUserId).toBe(NEW_UUID);
      expect(fresh.subToken).toBe('tok-carry');
      expect(old.subToken).toBeUndefined();
      const resolved = await ctx.db
        .query('subscriptions')
        .withIndex('by_sub_token', (q) => q.eq('subToken', 'tok-carry'))
        .unique();
      expect(resolved!._id).toBe(fresh._id);
    });
  });

  test('falls back to re-issue (new key + tombstone) when there is no current key to update', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const SQUAD = '11111111-2222-3333-4444-555555555555';
    const NEW_UUID = '550e8400-e29b-41d4-a716-446655440077';
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      await ctx.db.insert('modePlacements', {
        modeSlug: 'privacy-reality',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD] }),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'test',
        slug: 'test',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      // No subscription row → nothing to update in place → the re-issue path runs.
    });
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

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
    expect(res).toMatchObject({ ok: true, mode: { id: 'privacy-reality' } });
    // A create POST happened (re-issue), homing into the mode's squad.
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
    );
    expect(createCall).toBeTruthy();
    expect(JSON.parse(String(createCall![1]!.body)).activeInternalSquads).toEqual([SQUAD]);
    await t.run(async (ctx) => {
      const fresh = (await ctx.db.query('subscriptions').collect()).find(
        (s) => s.state === 'active',
      );
      expect(fresh!.backendPlacement).toBe(SQUAD);
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('privacy-reality');
    });
  });

  test('rejects a switch to an UNBOUND mode without tombstoning the working key (WS1)', async () => {
    // mock OFF so a real issuance WOULD hit the network — the reject must fire first.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      // evade is bound; privacy is NOT — switching to privacy must be refused.
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-freedom-ws'] }),
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'live-key',
        backendShortId: 'liveshort',
        subscriptionUrl: 'https://panel.test/sub/liveshort',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    });
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) => new Response('{}', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchMode, { userId, target: 'privacy-reality' });
    expect(res).toMatchObject({ ok: false, code: 'validation', status: 400 });
    // No key was minted…
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
      ),
    ).toBe(false);
    await t.run(async (ctx) => {
      // …and the working key is untouched (not tombstoned, mode unchanged).
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      expect(subs[0]!.state).toBe('active');
      expect((await ctx.db.get(userId))!.connectionModeId ?? null).not.toBe('privacy-reality');
    });
  });

  test('regenerate into an UNBOUND mode is refused (no silent cross-mode downgrade)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      // The member chose privacy (unbound); only evade has a pool.
      await ctx.db.patch(userId, { connectionModeId: 'privacy-reality' });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-freedom-ws'] }),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'rw',
        slug: 'rw',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
    });
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-446655440099',
              shortUuid: 'sh',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              usedTrafficBytes: 0,
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/sh',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    // Refused: falling back to the bound evade pool would silently re-home a
    // 'privacy' member into the CDN-fronted pool while the UI still says privacy.
    await expect(t.action(internal.account.regenerate, { userId })).rejects.toThrow(
      /mode\.unavailable/,
    );
    // No key was minted…
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
      ),
    ).toBe(false);
    await t.run(async (ctx) => {
      // …and the member's mode + subs are untouched (nothing to tombstone).
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('privacy-reality');
      expect(await ctx.db.query('subscriptions').collect()).toHaveLength(0);
    });
  });

  test('regenerate with NO pool bound anywhere issues squad-less + audits (WS1 bring-up)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'rw',
        slug: 'rw',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-4466554400aa',
              shortUuid: 'sh',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              usedTrafficBytes: 0,
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/sh',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await t.action(internal.account.regenerate, { userId });
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
    );
    // Still issues (bring-up must not hard-fail) but with no squad…
    expect(JSON.parse(String(createCall![1]!.body)).activeInternalSquads).toBeUndefined();
    // …and it's audited loudly so an admin knows to bind a pool.
    await t.run(async (ctx) => {
      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.issued_without_placement',
      );
      expect(audit).toBeTruthy();
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
    const fetchMock = vi.fn(
      async (_input: string | URL, _init?: RequestInit) => new Response('{}', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { removed } = await t.action(internal.lifecycle.sweepTombstones, {});
    expect(removed).toBe(1);

    await t.run(async (ctx) => {
      expect((await ctx.db.get(subId))!.state).toBe('deleted');
      expect((await ctx.db.get(instanceId))!.keyCount).toBe(0);
    });
  });
});

describe('account.regenerate location preference', () => {
  test('a location arg persists as the preference; absent keeps it; null clears it', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    await t.action(internal.account.regenerate, { userId, location: 'MCI' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.preferredLocation).toBe('MCI');
    });

    // Absent = keep the stored preference.
    await t.action(internal.account.regenerate, { userId });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.preferredLocation).toBe('MCI');
    });

    // Explicit null = back to automatic.
    await t.action(internal.account.regenerate, { userId, location: null });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.preferredLocation).toBeUndefined();
    });
  });
});

describe('account.getNodeStatus', () => {
  async function seedPlacedSub(
    t: ReturnType<typeof convexTest>,
    o: { placement?: string; online?: boolean; statsAgeMs?: number; serverHealthAgeMs?: number },
  ) {
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    let serverId: Id<'backendServers'> | undefined;
    await t.run(async (ctx) => {
      serverId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'mci',
        slug: 'mci',
        location: 'MCI',
        locationLabel: 'Kansas City, MO',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 1,
        lastHealthOkAt:
          o.serverHealthAgeMs !== undefined ? Date.now() - o.serverHealthAgeMs : undefined,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'key-uuid',
        backendShortId: 'short',
        backendServerId: serverId,
        subscriptionUrl: 'https://panel.test/sub/short',
        subscriptionMirrors: [],
        backendPlacement: o.placement,
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
      if (o.placement) {
        const at = Date.now() - (o.statsAgeMs ?? 0);
        await ctx.db.insert('remnawaveNodeStats', {
          backendServerId: serverId,
          placement: o.placement,
          label: 'Node A',
          usersOnline: 3,
          online: o.online ?? true,
          nodeCount: 1,
          lastStatsAt: at,
          updatedAt: at,
        });
      }
    });
    return { userId, serverId: serverId! };
  }

  test('fresh placement stats: online + the NEUTRAL location label (never the squad name)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedPlacedSub(t, { placement: 'sq-a', online: true });
    const res = await t.action(internal.account.getNodeStatus, { userId });
    expect(res.node).toMatchObject({
      online: true,
      // The panel's squad/node name ('Node A') often encodes infra detail —
      // the member sees the curated location label instead.
      label: 'Kansas City, MO',
      location: { code: 'MCI', label: 'Kansas City, MO' },
    });
    expect(res.node!.checkedAt).toBeTruthy();
  });

  test('an offline placement reads offline', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedPlacedSub(t, { placement: 'sq-a', online: false });
    const res = await t.action(internal.account.getNodeStatus, { userId });
    expect(res.node).toMatchObject({ online: false });
  });

  test('placement-less key falls back to instance health (fresh probe = online)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedPlacedSub(t, { serverHealthAgeMs: 60_000 });
    const res = await t.action(internal.account.getNodeStatus, { userId });
    expect(res.node).toMatchObject({
      online: true,
      label: null,
      location: { code: 'MCI', label: 'Kansas City, MO' },
    });
  });

  test('never-probed instance + no placement = unknown (online: null)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedPlacedSub(t, {});
    const res = await t.action(internal.account.getNodeStatus, { userId });
    expect(res.node).toMatchObject({ online: null, checkedAt: null });
  });

  test('no subscription at all: node is null', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    const res = await t.action(internal.account.getNodeStatus, { userId });
    expect(res.node).toBeNull();
  });

  test('stale stats trigger ONE stampede-guarded refresh; a failing panel keeps the cache', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedPlacedSub(t, {
      placement: 'sq-a',
      online: true,
      statsAgeMs: 5 * 60_000, // stale (> 60s freshness window)
    });
    const fetchMock = vi.fn(async () => new Response('boom', { status: 500 }));
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.getNodeStatus, { userId });
    // Refresh attempted (claim won) but the panel failed → cached verdict kept.
    expect(fetchMock).toHaveBeenCalled();
    expect(res.node).toMatchObject({ online: true, label: 'Kansas City, MO' });

    // Second poll inside the freshness window: the claim is held → no new pull.
    fetchMock.mockClear();
    const again = await t.action(internal.account.getNodeStatus, { userId });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(again.node).toMatchObject({ online: true });
  });
});

/**
 * Mode gates around placement-less backends (flipped characterization from the
 * mode overhaul): the effective-mode gate is backend-AGNOSTIC (judged per
 * target backend from the catalog), and a mode switch on a placement-less
 * backend is a preference no-op, never a re-issue.
 */
describe('mode gates on placement-less backends', () => {
  async function createOutlineMode(t: ReturnType<typeof convexTest>) {
    await t.mutation(internal.connectionModes.createMode, {
      slug: 'outline-basic',
      label: 'Outline Basic',
      family: 'freedom',
      deliveryStyle: 'url',
      backends: ['outline'],
    });
  }

  test('switch AWAY to outline with a blocked stored mode: allowed while outline has no modes, refused once it does', async () => {
    const t = convexTest(schema, modules);
    const fromTier = await seedTier(t, { slug: 'free', backend: 'remnawave' });
    await seedTier(t, { slug: 'free-outline', backend: 'outline' }); // default-free peer
    const userId = await seedUser(t, fromTier);
    await t.action(internal.account.regenerate, { userId }); // key minted BEFORE the mode breaks
    await t.run(async (ctx) => {
      // Member sits on privacy-reality (unbound); only freedom-ws has a pool.
      await ctx.db.patch(userId, { connectionModeId: 'privacy-reality' });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['11111111-2222-3333-4444-555555555555'] }),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('appSettings', {
        key: 'outline.enabled',
        value: 'true',
        updatedAt: Date.now(),
      });
    });

    // No outline-applicable mode exists → nothing on outline to downgrade to →
    // the switch proceeds (the stored mode rides along, meaningless there).
    const res = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(res).toMatchObject({ ok: true, backend: 'outline' });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('privacy-reality');
    });

    // Switch back for the second leg (freedom-ws is bound, so the return gate
    // blocks privacy-reality — pick the bound mode first, mirroring the UX).
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'freedom-ws' }));
    await t.action(internal.account.switchBackend, { userId, target: 'remnawave' });
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'privacy-reality' }));

    // Once outline HAS a usable mode, the anti-downgrade gate applies there
    // too: the blocked stored mode must be re-picked BEFORE switching.
    await createOutlineMode(t);
    const refused = await t.action(internal.account.switchBackend, { userId, target: 'outline' });
    expect(refused).toMatchObject({ ok: false, code: 'mode.unavailable', status: 400 });
  });

  test('switch-mode on an outline tier: not-applicable target → 400; applicable target → preference no-op (no re-issue, no tombstone)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { slug: 'free-outline', backend: 'outline' });
    const userId = await seedUser(t, tierId);
    await t.action(internal.account.regenerate, { userId });

    // freedom-ws declares remnawave only → not available on outline → refused.
    const refused = await t.action(internal.account.switchMode, {
      userId,
      target: 'freedom-ws',
    });
    expect(refused).toMatchObject({ ok: false, code: 'validation', status: 400 });

    // An outline-applicable mode: the switch records the preference and leaves
    // the working key untouched (the old behavior tombstoned it for zero
    // functional change).
    await createOutlineMode(t);
    const before = await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      return { count: subs.length, url: subs[0]!.subscriptionUrl, token: subs[0]!.subToken };
    });
    const res = await t.action(internal.account.switchMode, { userId, target: 'outline-basic' });
    expect(res).toMatchObject({
      ok: true,
      mode: { id: 'outline-basic' },
      oldSubscriptionDeletedAt: null,
    });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('outline-basic');
      const subs = await ctx.db.query('subscriptions').collect();
      // Same single subscription, same URL/token — nothing was re-issued.
      expect(subs).toHaveLength(before.count);
      expect(subs[0]!.state).toBe('active');
      expect(subs[0]!.subscriptionUrl).toBe(before.url);
      expect(subs[0]!.subToken).toBe(before.token);
    });
  });
});

describe('account.switchServer', () => {
  afterEach(() => vi.unstubAllGlobals());

  const SQUAD_A = '11111111-2222-3333-4444-555555555555';
  const SQUAD_B = '99999999-8888-7777-6666-555555555555';

  /** The healthcheck cron's cached node-load row. `nodeCount` is what tells a
   *  pin-only switch whether there is another node to land on at all. */
  async function seedNodeStats(
    t: ReturnType<typeof convexTest>,
    placement: string,
    nodeCount: number,
  ) {
    await t.run(async (ctx) => {
      const server = (await ctx.db.query('backendServers').collect())[0]!;
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: server._id,
        placement,
        usersOnline: 1,
        online: true,
        nodeCount,
        lastStatsAt: Date.now(),
        updatedAt: Date.now(),
      });
    });
  }

  /** A live Remnawave key on `placement`, optionally pinned to a node. */
  async function seedKey(
    t: ReturnType<typeof convexTest>,
    userId: Id<'users'>,
    over: { placement?: string; pinnedNode?: string; instanceId?: Id<'backendServers'> } = {},
  ) {
    return t.run(async (ctx) => {
      const instanceId =
        over.instanceId ??
        (await ctx.db.insert('backendServers', {
          backend: 'remnawave',
          name: 'test',
          slug: 'test',
          config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
          isActive: true,
          priority: 0,
          keyCount: 1,
          updatedAt: Date.now(),
        }));
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'old-key-uuid',
        backendShortId: 'oldshort',
        backendServerId: instanceId,
        subscriptionUrl: 'https://panel.test/sub/oldshort',
        subToken: 'tok-abc',
        subCache: JSON.stringify([{ ua: 'x', content: 'stale', contentType: 't', at: Date.now() }]),
        subscriptionMirrors: [],
        ...(over.placement ? { backendPlacement: over.placement } : {}),
        ...(over.pinnedNode ? { pinnedNode: over.pinnedNode } : {}),
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId, connectionModeId: 'freedom-ws' });
      return { subId, instanceId };
    });
  }

  /** Panel stub: answers the squad PATCH with a plausible user record. */
  function panelStub() {
    return vi.fn(
      async (_input: string | URL, _init?: RequestInit) =>
        new Response(
          JSON.stringify({
            response: {
              uuid: '550e8400-e29b-41d4-a716-446655440000',
              shortUuid: 'oldshort',
              username: 'u',
              status: 'ACTIVE',
              trafficLimitBytes: null,
              trafficLimitStrategy: 'MONTH',
              userTraffic: { usedTrafficBytes: 0 },
              expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
              hwidDeviceLimit: null,
              subscriptionUrl: 'https://panel.test/sub/oldshort',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
  }

  test('moves to another squad IN PLACE, keeping the key, URL and token', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A, SQUAD_B] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({
      ok: true,
      inPlace: true,
      subscriptionUrl: 'https://panel.test/sub/oldshort',
      oldSubscriptionDeletedAt: null,
    });

    // The move is a PATCH onto the SAME panel user, never a create.
    const patchCall = fetchMock.mock.calls.find(
      ([input, init]) => String(input).includes('/api/users') && init?.method === 'PATCH',
    );
    expect(JSON.parse(String(patchCall![1]!.body)).activeInternalSquads).toEqual([SQUAD_B]);
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).includes('/api/users') && init?.method === 'POST',
      ),
    ).toBe(false);

    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1); // no re-issue, no tombstone
      const only = subs[0]!;
      expect(only.backendUserId).toBe('old-key-uuid');
      expect(only.subToken).toBe('tok-abc'); // saved link unchanged
      expect(only.backendPlacement).toBe(SQUAD_B);
      // The node pin is rotated too: the new squad may still span nodes.
      expect(only.excludeNode).toBe('xray1');
      expect(only.pinnedNode).toBeUndefined();
      expect(only.subCache).toBeUndefined();
      // The member's connection mode is untouched — this is not a mode switch.
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('freedom-ws');
    });
  });

  test('records the reason and the node left, never the squad uuid', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A, SQUAD_B] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    vi.stubGlobal('fetch', panelStub());

    await t.action(internal.account.switchServer, { userId, reason: 'blocked' });

    await t.run(async (ctx) => {
      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.switch_server',
      );
      expect(audit).toBeTruthy();
      expect(audit!.payload).toMatchObject({
        reason: 'blocked',
        inPlace: true,
        movedPlacement: true,
        movedNodePin: true,
        fromNode: 'xray1',
      });
      expect(JSON.stringify(audit!.payload)).not.toContain(SQUAD_A);
      expect(JSON.stringify(audit!.payload)).not.toContain(SQUAD_B);
    });
  });

  test('with only one squad, rotates the NODE PIN instead (no panel call at all)', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    await seedNodeStats(t, SQUAD_A, 3); // the squad really does span other nodes
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'disconnects' });
    expect(res).toMatchObject({ ok: true, inPlace: true });
    // A single-squad pool has nowhere to PATCH to — the pin does the work.
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/api/users'))).toBe(
      false,
    );
    await t.run(async (ctx) => {
      const sub = (await ctx.db.query('subscriptions').collect())[0]!;
      expect(sub.excludeNode).toBe('xray1');
      expect(sub.pinnedNode).toBeUndefined();
      expect(sub.backendPlacement).toBe(SQUAD_A); // unchanged
      const audit = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'subscription.switch_server',
      );
      expect(audit!.payload).toMatchObject({ movedPlacement: false, movedNodePin: true });
    });
  });

  test('refuses instead of claiming a move when the squad has only ONE node', async () => {
    // The pin is set, so the old code rotated it and reported success — but
    // pickNode drops the exclusion rather than empty a one-node pool, so the very
    // next fetch serves the SAME server. Telling the member their key moved was a
    // lie; the honest answer is that there is nowhere to go.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    await seedNodeStats(t, SQUAD_A, 1); // one squad, ONE node behind it
    vi.stubGlobal('fetch', panelStub());

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative', status: 409 });
    await t.run(async (ctx) => {
      const sub = (await ctx.db.query('subscriptions').collect())[0]!;
      // The pin is left exactly as it was — no phantom rotation.
      expect(sub.pinnedNode).toBe('xray1');
      expect(sub.excludeNode).toBeUndefined();
      expect(sub.subCache).toBeTruthy();
    });
  });

  test('refuses on a STALE node count, even when it says multiple nodes', async () => {
    // A squad that has since shrunk to one node still reads >1 from an old
    // snapshot; trusting it would put us right back to promising a move that
    // cannot happen. Same staleness bar pickByNodeLoad applies.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A] }),
        updatedAt: Date.now(),
      }),
    );
    const { instanceId } = await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    await t.run((ctx) =>
      ctx.db.insert('remnawaveNodeStats', {
        backendServerId: instanceId,
        placement: SQUAD_A,
        usersOnline: 1,
        online: true,
        nodeCount: 4,
        lastStatsAt: Date.now() - 61 * 60_000, // an hour old: past the 30 min bar
        updatedAt: Date.now(),
      }),
    );
    vi.stubGlobal('fetch', panelStub());

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative' });
    await t.run(async (ctx) => {
      expect((await ctx.db.query('subscriptions').collect())[0]!.pinnedNode).toBe('xray1');
    });
  });

  test('refuses when the node count is unknown (no stats row observed yet)', async () => {
    // Bring-up, or a placement the healthcheck cron has not reached. We cannot
    // prove another node exists, so we do not assert a move; the next cron pass
    // makes the switch work.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    vi.stubGlobal('fetch', panelStub());

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative' });
    await t.run(async (ctx) => {
      expect((await ctx.db.query('subscriptions').collect())[0]!.pinnedNode).toBe('xray1');
    });
  });

  test('refuses with server.no_alternative when there is nowhere to go, changing nothing', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A] }),
        updatedAt: Date.now(),
      }),
    );
    // One squad AND no pin yet (the key has never been served).
    await seedKey(t, userId, { placement: SQUAD_A });
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative', status: 409 });
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1);
      expect(subs[0]!.state).toBe('active'); // the working key is untouched
      expect(subs[0]!.backendPlacement).toBe(SQUAD_A);
      expect(subs[0]!.subCache).toBeTruthy(); // not even the cache was dropped
    });
  });

  test("re-issues across panels when the member's own panel is a dead end", async () => {
    // One squad on this panel, one node behind it — both cheap levers are out.
    // But the mode pool has a squad on ANOTHER panel, which the same-panel lookup
    // deliberately hides (`onlyServerId` is a hard pin). Without the cross-panel
    // probe the member could never leave, despite a whole other location bound.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    const { instanceId } = await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    const otherPanel = await t.run(async (ctx) => {
      const other = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'other',
        slug: 'other',
        config: { type: 'remnawave', baseUrl: 'https://panel2.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A, SQUAD_B] }),
        updatedAt: Date.now(),
      });
      // Attribute each squad to its own panel; SQUAD_A is single-node, so the pin
      // rotation is not an option either.
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: instanceId,
        placement: SQUAD_A,
        usersOnline: 1,
        online: true,
        nodeCount: 1,
        lastStatsAt: Date.now(),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: other,
        placement: SQUAD_B,
        usersOnline: 0,
        online: true,
        nodeCount: 2,
        lastStatsAt: Date.now(),
        updatedAt: Date.now(),
      });
      return other;
    });

    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              response: {
                uuid: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
                shortUuid: 'newshort',
                username: 'u2',
                status: 'ACTIVE',
                trafficLimitBytes: null,
                trafficLimitStrategy: 'MONTH',
                userTraffic: { usedTrafficBytes: 0 },
                expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
                hwidDeviceLimit: null,
                subscriptionUrl: 'https://panel2.test/sub/newshort',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );

    const res = await t.action(internal.account.switchServer, { userId, reason: 'blocked' });
    expect(res).toMatchObject({ ok: true, inPlace: false });
    await t.run(async (ctx) => {
      const fresh = (await ctx.db.query('subscriptions').collect()).find(
        (x) => x.state === 'active',
      )!;
      expect(fresh.backendPlacement).toBe(SQUAD_B); // the other panel's squad
      expect(fresh.backendServerId).toBe(otherPanel);
      expect(fresh.subToken).toBe('tok-abc'); // saved link still works
    });
  });

  test('a failed panel PATCH falls back to a re-issue that CARRIES the sub token', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A, SQUAD_B] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    // PATCH fails (e.g. the panel user was deleted by hand); POST (create) works.
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      if (String(input).includes('/api/users') && init?.method === 'PATCH') {
        return new Response('{"message":"not found"}', { status: 404 });
      }
      return new Response(
        JSON.stringify({
          response: {
            uuid: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
            shortUuid: 'newshort',
            username: 'u2',
            status: 'ACTIVE',
            trafficLimitBytes: null,
            trafficLimitStrategy: 'MONTH',
            userTraffic: { usedTrafficBytes: 0 },
            expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
            hwidDeviceLimit: null,
            subscriptionUrl: 'https://panel.test/sub/newshort',
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: true, inPlace: false });

    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(2); // new key + the tombstoned old one
      const fresh = subs.find((s) => s.state === 'active')!;
      const old = subs.find((s) => s._id !== fresh._id)!;
      // The member's saved link survives a re-issue: the token moved across.
      expect(fresh.subToken).toBe('tok-abc');
      expect(old.subToken).toBeUndefined();
      expect(old.deletedAt).toBeGreaterThan(Date.now()); // 24h grace, still routing
      // The failed PATCH must not leave the DB claiming a move that didn't land.
      expect(old.backendPlacement).toBe(SQUAD_A);
    });
  });

  test("never re-homes into ANOTHER mode when the member's own mode is unbound", async () => {
    // resolvePlacementPool falls back across modes (own -> default -> any bound),
    // which is right at issuance but would silently move this key into a
    // different mode's squad — changing the transport the member chose while the
    // UI still shows the original. regenerate/switch-backend refuse here; so must
    // this. No pin either, so there is nothing safe left to do.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      // The member sits on privacy-reality; only freedom-ws is bound.
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_B] }),
        updatedAt: Date.now(),
      });
    });
    await seedKey(t, userId, { placement: SQUAD_A });
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'privacy-reality' }));
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'mode.unavailable' });
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1); // nothing re-issued, nothing tombstoned
      expect(subs[0]!.backendPlacement).toBe(SQUAD_A); // never moved to freedom-ws
      expect((await ctx.db.get(userId))!.connectionModeId).toBe('privacy-reality');
    });
  });

  test('an unbound mode still permits the transport-safe NODE PIN rotation', async () => {
    // Rotating the pin moves inside the member's CURRENT squad, so it cannot
    // change their transport — no reason to withhold it just because an admin
    // unbound their mode.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_B] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    await seedNodeStats(t, SQUAD_A, 3);
    await t.run((ctx) => ctx.db.patch(userId, { connectionModeId: 'privacy-reality' }));
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: true, inPlace: true });
    await t.run(async (ctx) => {
      const sub = (await ctx.db.query('subscriptions').collect())[0]!;
      expect(sub.excludeNode).toBe('xray1');
      expect(sub.backendPlacement).toBe(SQUAD_A); // squad untouched → transport intact
    });
    // No panel PATCH: the pin is a local move.
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/api/users'))).toBe(
      false,
    );
  });

  test('a key retained on Remnawave can still rotate after its TIER flips to Outline', async () => {
    // The tier editor leaves existing users on their current backend until they
    // switch or regenerate, and docs/backends.md is explicit that the SUB's
    // backend governs later reads/writes. Gating the pin on the tier's backend
    // stranded every retained key: no placement move (correct — the pool belongs
    // to the other backend) and no rotation either (wrong — it is purely local).
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'outline' }); // flipped by an admin
    const userId = await seedUser(t, tierId);
    // ...while the live key is still the Remnawave one they were issued.
    await seedKey(t, userId, { placement: SQUAD_A, pinnedNode: 'xray1' });
    await seedNodeStats(t, SQUAD_A, 3);
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: true, inPlace: true });
    await t.run(async (ctx) => {
      const sub = (await ctx.db.query('subscriptions').collect())[0]!;
      expect(sub.excludeNode).toBe('xray1');
      expect(sub.pinnedNode).toBeUndefined();
      expect(sub.backendPlacement).toBe(SQUAD_A); // no placement move attempted
    });
    // Purely local: no panel call at all.
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/api/users'))).toBe(
      false,
    );
  });

  test('a LEGACY key with no recorded squad refuses on a single-panel deployment', async () => {
    // With no source placement AND no second panel, nothing can prove a move:
    // the resolved squad may be the one the key already sits in, so re-issuing
    // would tombstone a working key and re-register the member's devices to land
    // them on the same server. Refuse instead. (regenerate still records a
    // placement for such a row, after which its switches are provable.)
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_A, SQUAD_B] }),
        updatedAt: Date.now(),
      }),
    );
    await seedKey(t, userId); // legacy: no backendPlacement, no pinnedNode
    const fetchMock = panelStub();
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_alternative' });
    await t.run(async (ctx) => {
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(1); // working key untouched
      expect(subs[0]!.state).toBe('active');
    });
    // Neither a squad PATCH nor a create was attempted.
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/api/users'))).toBe(
      false,
    );
  });

  test('a LEGACY key DOES re-issue when another panel is available', async () => {
    // A different panel is the one proof that survives an unknown squad: a key
    // created on panel B is by definition not on panel A.
    vi.stubEnv('DEV_MOCK_BACKEND', '');
    vi.stubEnv('ENVIRONMENT', 'production');
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'remnawave' });
    const userId = await seedUser(t, tierId);
    const { instanceId } = await seedKey(t, userId); // legacy: no placement
    await t.run(async (ctx) => {
      const other = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'other',
        slug: 'other',
        config: { type: 'remnawave', baseUrl: 'https://panel2.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: [SQUAD_B] }),
        updatedAt: Date.now(),
      });
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: other,
        placement: SQUAD_B,
        usersOnline: 0,
        online: true,
        nodeCount: 2,
        lastStatsAt: Date.now(),
        updatedAt: Date.now(),
      });
      return { other, instanceId };
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              response: {
                uuid: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
                shortUuid: 'newshort',
                username: 'u2',
                status: 'ACTIVE',
                trafficLimitBytes: null,
                trafficLimitStrategy: 'MONTH',
                userTraffic: { usedTrafficBytes: 0 },
                expireAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
                hwidDeviceLimit: null,
                subscriptionUrl: 'https://panel2.test/sub/newshort',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: true, inPlace: false });
    await t.run(async (ctx) => {
      const fresh = (await ctx.db.query('subscriptions').collect()).find(
        (x) => x.state === 'active',
      )!;
      expect(fresh.backendPlacement).toBe(SQUAD_B); // recorded → next switch provable
      expect(fresh.subToken).toBe('tok-abc');
    });
  });

  test('refuses server.unsupported on a backend with no placement AND no node pinning', async () => {
    // Outline has neither lever, so no deployment shape makes this work — say so
    // distinctly instead of `no_alternative`, which invites a pointless retry.
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t, { backend: 'outline', slug: 'free-outline' });
    const userId = await seedUser(t, tierId);
    await t.run(async (ctx) => {
      const instanceId = await ctx.db.insert('backendServers', {
        backend: 'outline',
        name: 'ol',
        slug: 'ol',
        config: {
          type: 'outline',
          apiUrl: 'https://outline.test/secret/',
          websocketEnabled: false,
        },
        isActive: true,
        priority: 0,
        keyCount: 1,
        updatedAt: Date.now(),
      });
      const subId = await ctx.db.insert('subscriptions', {
        userId,
        backend: 'outline',
        backendUserId: 'ol-key',
        backendShortId: 'ol-key',
        backendServerId: instanceId,
        subscriptionUrl: 'ss://x',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(userId, { currentSubscriptionId: subId });
    });

    const res = await t.action(internal.account.switchServer, { userId, reason: 'slow' });
    expect(res).toMatchObject({ ok: false, code: 'server.unsupported', status: 409 });
  });

  test('refuses when the member has no key to move', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);
    const res = await t.action(internal.account.switchServer, { userId, reason: 'other' });
    expect(res).toMatchObject({ ok: false, code: 'server.no_subscription', status: 409 });
  });
});
