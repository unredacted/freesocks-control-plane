/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

const DAY = 86_400_000;

async function seedTiers(
  t: ReturnType<typeof convexTest>,
): Promise<{ freeTierId: Id<'tiers'>; memberTierId: Id<'tiers'> }> {
  return t.run(async (ctx) => {
    const freeTierId = await ctx.db.insert('tiers', {
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
    const memberTierId = await ctx.db.insert('tiers', {
      slug: 'member',
      name: 'Member',
      backend: 'remnawave',
      monthlyTrafficGb: 500,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
    return { freeTierId, memberTierId };
  });
}

describe('lifecycle grace/disable transitions', () => {
  test('findGraceTransitions returns an active user whose membership lapsed', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const now = Date.now();
    const lapsedId = await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        membershipExpiresAt: now - DAY, // lapsed yesterday
        updatedAt: now,
      }),
    );
    // A still-valid active member must NOT be returned.
    await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        membershipExpiresAt: now + DAY,
        updatedAt: now,
      }),
    );

    const due = await t.query(internal.lifecycle.findGraceTransitions, { now });
    expect(due.map((u) => u._id)).toEqual([lapsedId]);
  });

  test('applyGraceTransition flips status to grace and audits', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))?.status).toBe('grace');
      const audits = await ctx.db
        .query('auditLog')
        .withIndex('by_action', (q) => q.eq('action', 'membership.transition.grace'))
        .collect();
      expect(audits).toHaveLength(1);
    });
  });

  test('findDisableTransitions returns a grace user past its tier window', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t); // member window = 7 days
    const now = Date.now();
    // Grace user whose expiry + 7d window is already in the past.
    const dueId = await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'grace',
        membershipExpiresAt: now - 10 * DAY,
        updatedAt: now,
      }),
    );
    // Grace user still inside the 7-day window — must NOT be returned.
    await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'grace',
        membershipExpiresAt: now - 2 * DAY,
        updatedAt: now,
      }),
    );

    const due = await t.query(internal.lifecycle.findDisableTransitions, { now });
    expect(due.map((u) => u._id)).toEqual([dueId]);
  });

  test('applyDisableTransition disables with the lapsed reason', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'grace',
        membershipExpiresAt: Date.now() - 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.applyDisableTransition, { userId });
    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u?.status).toBe('disabled');
      expect(u?.disabledReason).toBe('membership_lapsed');
      expect(u?.suspendedAt).toBeGreaterThan(0);
    });
  });
});

describe('lifecycle.setMembership', () => {
  test('changes tierId, sets expiry, and writes tierHistory', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId, memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) =>
      ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: Date.now() }),
    );
    const expiresAtMs = Date.now() + 30 * DAY;

    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs,
      reason: 'test.upgrade',
      triggeredBy: 'webhook',
    });

    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u?.tierId).toBe(memberTierId);
      expect(u?.membershipExpiresAt).toBe(expiresAtMs);
      const history = await ctx.db
        .query('tierHistory')
        .withIndex('by_user', (q) => q.eq('userId', userId))
        .collect();
      expect(history).toHaveLength(1);
      expect(history[0]!.fromTierId).toBe(freeTierId);
      expect(history[0]!.toTierId).toBe(memberTierId);
      expect(history[0]!.reason).toBe('test.upgrade');
    });
  });

  test('is a no-op for tierHistory when the tier is unchanged', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: Date.now() + DAY,
      reason: 'test.renew',
    });
    await t.run(async (ctx) => {
      const history = await ctx.db
        .query('tierHistory')
        .withIndex('by_user', (q) => q.eq('userId', userId))
        .collect();
      expect(history).toHaveLength(0);
    });
  });
});
