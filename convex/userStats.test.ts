/// <reference types="vite/client" />
/**
 * User-status counter tests (M2 / WS3): the maintained `appState` counter that
 * feeds `adminApi.statusSummary` must exactly track transitions and be exactly
 * recomputable by `reconcileUserCounts` (the self-heal).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { readUserCounts } from './lib/statusCounters';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

async function seedFreeTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
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
const counts = (t: ReturnType<typeof convexTest>) => t.run((ctx) => readUserCounts(ctx.db));

describe('userStats counters (WS3)', () => {
  test('reconcileUserCounts recomputes exact counts + is idempotent', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', {
        tierId,
        status: 'active',
        backendPushFailedAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('users', { tierId, status: 'grace', updatedAt: now });
      await ctx.db.insert('users', {
        tierId,
        status: 'inactive',
        freeKeyExpiresAt: now,
        updatedAt: now,
      });
    });
    const c1 = await t.action(internal.userStats.reconcileUserCounts, {});
    expect(c1).toEqual({
      active: 2,
      grace: 1,
      disabled: 0,
      deleted: 0,
      inactive: 1,
      backendDrift: 1,
      freeActive: 2, // both active users sit on the default-free tier
    });
    expect(await counts(t)).toEqual(c1);
    // Idempotent: a second reconcile yields the same exact result.
    expect(await t.action(internal.userStats.reconcileUserCounts, {})).toEqual(c1);
  });

  test('grace/disable transitions move the buckets', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {}); // baseline active:1
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId });
    expect(await counts(t)).toMatchObject({ active: 0, grace: 1 });
    await t.mutation(internal.lifecycle.applyDisableTransition, { userId });
    expect(await counts(t)).toMatchObject({ grace: 0, disabled: 1 });
  });

  test('deactivate + reactivate move inactive/active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        freeKeyExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {}); // active:1
    await t.mutation(internal.lifecycle.markUserInactive, { userId });
    expect(await counts(t)).toMatchObject({ active: 0, inactive: 1 });
    await t.mutation(internal.lifecycle.refreshFreeWindow, { userId });
    expect(await counts(t)).toMatchObject({ active: 1, inactive: 0 });
  });

  test('freeActive tallies only active users on default-free tiers, and survives status bumps', async () => {
    const t = convexTest(schema, modules);
    const freeTierId = await seedFreeTier(t);
    const paidTierId = await t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 3,
        hwidLimit: 3,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 30,
        updatedAt: Date.now(),
      }),
    );
    const graceFreeId = await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', { tierId: paidTierId, status: 'active', updatedAt: now }); // paid active — excluded
      await ctx.db.insert('users', { tierId: freeTierId, status: 'inactive', updatedAt: now }); // free but idle — excluded
      return ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: now });
    });
    const c = await t.action(internal.userStats.reconcileUserCounts, {});
    expect(c).toMatchObject({ active: 3, freeActive: 2 });
    // A status transition bump (read-full/write-full) must not clobber freeActive.
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId: graceFreeId });
    expect(await counts(t)).toMatchObject({ active: 2, grace: 1, freeActive: 2 });
  });

  test('backend drift bumps exactly once (no double-count across setters)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {});
    await t.mutation(internal.lifecycle.setBackendDrift, { userId, failed: true });
    expect((await counts(t)).backendDrift).toBe(1);
    // Already drifted → a second signal (via recordPushFailure) must NOT re-count.
    await t.mutation(internal.lifecycle.recordPushFailure, { userId, detail: 'x' });
    expect((await counts(t)).backendDrift).toBe(1);
    // Clearing drops it back to 0.
    await t.mutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
    expect((await counts(t)).backendDrift).toBe(0);
  });
});
