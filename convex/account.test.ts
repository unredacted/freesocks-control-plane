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

    await expect(t.action(internal.account.regenerate, { userId })).rejects.toThrow(
      /No active remnawave instances/,
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

    expect(await t.mutation(internal.account.acquireIssuanceLock, { userId })).toEqual({
      acquired: true,
    });
    expect(await t.mutation(internal.account.acquireIssuanceLock, { userId })).toEqual({
      acquired: false,
    });
    await t.mutation(internal.account.releaseIssuanceLock, { userId });
    expect(await t.mutation(internal.account.acquireIssuanceLock, { userId })).toEqual({
      acquired: true,
    });
  });

  test('an expired lock row self-heals (crashed saga cannot wedge the user)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await seedUser(t, tierId);

    await t.run(async (ctx) => {
      await ctx.db.insert('appState', {
        key: `issue-lock:${userId}`,
        value: String(Date.now() - 1_000), // already expired
        updatedAt: Date.now(),
      });
    });
    expect(await t.mutation(internal.account.acquireIssuanceLock, { userId })).toEqual({
      acquired: true,
    });
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
