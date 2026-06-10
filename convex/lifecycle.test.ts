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
    // Free users (no expiry) must NOT be returned, and — critically for P1-4 —
    // must not occupy the page and crowd lapsed members out (the exact index
    // range excludes them entirely).
    await t.run(async (ctx) => {
      for (let i = 0; i < 5; i++) {
        await ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: now });
      }
    });

    // findGraceTransitions now returns just the due user ids (exact index range).
    const due = await t.query(internal.lifecycle.findGraceTransitions, { now });
    expect(due).toEqual([lapsedId]);
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
    // Grace user still inside the 7-day window; must NOT be returned.
    await t.run(async (ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'grace',
        membershipExpiresAt: now - 2 * DAY,
        updatedAt: now,
      }),
    );

    // findDisableTransitions now pages by expiry cursor and returns { due, ... }.
    const res = await t.query(internal.lifecycle.findDisableTransitions, { now, afterExpiry: 0 });
    expect(res.due).toEqual([dueId]);
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

  test('re-activates a lapsed (disabled) user on renewal', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: Date.now() + 30 * DAY,
      reason: 'test.renew',
    });
    expect((await t.run((ctx) => ctx.db.get(userId)))?.status).toBe('active');
  });
});

describe('lifecycle.findExpiredFree (P1-4 per-tier cursor)', () => {
  test('returns only pre-cutoff active free users with a live sub, and pages via the cursor', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId, memberTierId } = await seedTiers(t);
    const cutoff = Date.now() - 90 * DAY;

    // Helper: insert a user with a controllable _creationTime by inserting then
    // can't set _creationTime directly; convex-test stamps it. So insert in order
    // and rely on ascending creation order. We make 3 "old" free users (with subs)
    // by inserting them, then patch nothing — instead assert via the query with a
    // cutoff in the FUTURE so all inserted users count as "before cutoff".
    const futureCutoff = Date.now() + DAY;
    const ids: Id<'users'>[] = [];
    await t.run(async (ctx) => {
      for (let i = 0; i < 3; i++) {
        const uid = await ctx.db.insert('users', {
          tierId: freeTierId,
          status: 'active',
          updatedAt: Date.now(),
        });
        await ctx.db.insert('subscriptions', {
          userId: uid,
          backend: 'remnawave',
          backendUserId: `bu-${i}`,
          backendShortId: `bs-${i}`,
          subscriptionUrl: 'https://x/sub',
          subscriptionMirrors: [],
          state: 'active',
          updatedAt: Date.now(),
        });
        ids.push(uid);
      }
      // A paid member on the member tier must never be returned by a free scan.
      await ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        updatedAt: Date.now(),
      });
    });

    // Page 1 (limit 2): the two oldest free users.
    const page1 = await t.query(internal.lifecycle.findExpiredFree, {
      tierId: freeTierId,
      cutoff: futureCutoff,
      limit: 2,
      afterCreation: 0,
    });
    expect(page1.expired.map((e) => e.userId)).toEqual(ids.slice(0, 2));
    expect(page1.nextCursor).not.toBeNull();

    // Page 2: the third, then drained.
    const page2 = await t.query(internal.lifecycle.findExpiredFree, {
      tierId: freeTierId,
      cutoff: futureCutoff,
      limit: 2,
      afterCreation: page1.nextCursor!,
    });
    expect(page2.expired.map((e) => e.userId)).toEqual([ids[2]]);

    // With the REAL (past) cutoff, none of the just-created users qualify.
    const none = await t.query(internal.lifecycle.findExpiredFree, {
      tierId: freeTierId,
      cutoff,
      limit: 10,
      afterCreation: 0,
    });
    expect(none.expired).toHaveLength(0);
  });
});

describe('account issuance lock (P1-3)', () => {
  test('a second acquire is refused until released', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: Date.now() }),
    );
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      false,
    );
    await t.mutation(internal.account.releaseIssuanceLock, { userId });
    expect((await t.mutation(internal.account.acquireIssuanceLock, { userId })).acquired).toBe(
      true,
    );
  });
});
