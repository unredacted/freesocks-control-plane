/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seedTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
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
    }),
  );
}

function subFields(
  userId: Id<'users'>,
  backendUserId: string,
  state: 'active' | 'disabled' | 'deleted',
) {
  return {
    userId,
    backend: 'remnawave' as const,
    backendUserId,
    backendShortId: `short-${backendUserId}`,
    subscriptionUrl: `https://sub.example/${backendUserId}`,
    subscriptionMirrors: [],
    state,
    updatedAt: Date.now(),
  };
}

describe('subscriptions.resolveCurrentOrActive', () => {
  test('prefers the user.currentSubscriptionId when it is active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, currentId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      // Newest row is "other"; current points at an older but active row.
      const currentId = await ctx.db.insert('subscriptions', subFields(userId, 'cur', 'active'));
      await ctx.db.insert('subscriptions', subFields(userId, 'newer', 'active'));
      await ctx.db.patch(userId, { currentSubscriptionId: currentId });
      return { userId, currentId };
    });
    const res = await t.query(api.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(currentId);
    expect(res?.backendUserId).toBe('cur');
  });

  test('falls back to the newest active row when currentSubscriptionId is unset', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, newerId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', subFields(userId, 'older', 'active'));
      const newerId = await ctx.db.insert('subscriptions', subFields(userId, 'newer', 'active'));
      return { userId, newerId };
    });
    const res = await t.query(api.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(newerId);
  });

  test('ignores a deleted currentSubscriptionId and falls back to active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const { userId, activeId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const deletedId = await ctx.db.insert('subscriptions', subFields(userId, 'gone', 'deleted'));
      const activeId = await ctx.db.insert('subscriptions', subFields(userId, 'live', 'active'));
      await ctx.db.patch(userId, { currentSubscriptionId: deletedId });
      return { userId, activeId };
    });
    const res = await t.query(api.subscriptions.resolveCurrentOrActive, { userId });
    expect(res?._id).toBe(activeId);
    expect(res?.state).toBe('active');
  });

  test('returns null when the user has only deleted subscriptions', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedTier(t);
    const userId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', subFields(userId, 'd1', 'deleted'));
      return userId;
    });
    expect(await t.query(api.subscriptions.resolveCurrentOrActive, { userId })).toBeNull();
  });
});
