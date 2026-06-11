/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test, vi, afterEach } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

afterEach(() => vi.useRealTimers());

describe('retention sweeps (P2)', () => {
  test('sweepFreeGrants deletes grants past the window, keeps recent ones', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
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
        updatedAt: now,
      });
      const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      // Old grant (100 days ago) + recent grant (1 day ago).
      await ctx.db.insert('freeGrants', {
        userId,
        ipHash: 'old',
        grantedAt: now - 100 * DAY,
        grantedDayBucket: Math.floor((now - 100 * DAY) / DAY),
      });
      await ctx.db.insert('freeGrants', {
        userId,
        ipHash: 'recent',
        grantedAt: now - DAY,
        grantedDayBucket: Math.floor((now - DAY) / DAY),
      });
    });

    const { removed } = await t.mutation(internal.retention.sweepFreeGrants, {});
    expect(removed).toBe(1);
    const remaining = await t.run((ctx) => ctx.db.query('freeGrants').collect());
    expect(remaining.map((r) => r.ipHash)).toEqual(['recent']);
  });

  test('sweepAuditLog deletes only entries older than the window', async () => {
    const t = convexTest(schema, modules);
    // Insert an "old" row, then advance the clock so it's beyond 180 days.
    await t.run(async (ctx) => {
      await ctx.db.insert('auditLog', { actorType: 'system', action: 'old.event' });
    });
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 200 * DAY);
    await t.run(async (ctx) => {
      await ctx.db.insert('auditLog', { actorType: 'system', action: 'fresh.event' });
    });
    const { removed } = await t.mutation(internal.retention.sweepAuditLog, {});
    expect(removed).toBe(1);
    const left = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(left.map((r) => r.action)).toEqual(['fresh.event']);
  });
});

describe('deleteTier referential guard (P2)', () => {
  async function seedTier(
    t: ReturnType<typeof convexTest>,
    isDefaultFree: boolean,
  ): Promise<Id<'tiers'>> {
    return t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: isDefaultFree ? 'free' : 'patron',
        name: isDefaultFree ? 'Free' : 'Patron',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('refuses to delete the default-free tier', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, true);
    await expect(t.mutation(internal.adminApi.deleteTier, { id })).rejects.toThrow();
  });

  test('refuses to delete a tier that still has users', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, false);
    await t.run((ctx) =>
      ctx.db.insert('users', { tierId: id, status: 'active', updatedAt: Date.now() }),
    );
    await expect(t.mutation(internal.adminApi.deleteTier, { id })).rejects.toThrow();
  });

  test('deletes an unreferenced non-default tier', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, false);
    expect(await t.mutation(internal.adminApi.deleteTier, { id })).toEqual({ ok: true });
    expect(await t.run((ctx) => ctx.db.get(id))).toBeNull();
  });
});

describe('retention.sweepDeletedSubscriptions (pass 2)', () => {
  test('removes long-deleted rows; keeps recent-deleted and tombstoned ones', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    const { oldId, recentId, tombstoneId } = await t.run(async (ctx) => {
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
        updatedAt: now,
      });
      const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      const base = {
        userId,
        backend: 'remnawave' as const,
        backendShortId: 's',
        subscriptionUrl: 'https://sub.example/s',
        subscriptionMirrors: [],
        updatedAt: now,
      };
      const oldId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'old',
        state: 'deleted',
        deletedAt: now - 100 * DAY,
      });
      const recentId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'recent',
        state: 'deleted',
        deletedAt: now - DAY,
      });
      // A live tombstone (disabled, grace pending) must NOT be touched.
      const tombstoneId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'tomb',
        state: 'disabled',
        deletedAt: now - 100 * DAY,
      });
      return { oldId, recentId, tombstoneId };
    });

    const out = await t.mutation(internal.retention.sweepDeletedSubscriptions, {});
    expect(out.removed).toBe(1);
    await t.run(async (ctx) => {
      expect(await ctx.db.get(oldId)).toBeNull();
      expect(await ctx.db.get(recentId)).not.toBeNull();
      expect(await ctx.db.get(tombstoneId)).not.toBeNull();
    });
  });
});
