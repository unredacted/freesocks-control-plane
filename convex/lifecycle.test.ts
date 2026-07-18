/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
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

  test('re-guards (M2): a renewal landing mid-sweep is never flipped', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t); // member window = 7 days

    // Grace leg: the user RENEWED between the page read and the apply (expiry
    // back in the future) — applyGraceTransition must no-op.
    const renewedActive = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId: renewedActive });
    expect((await t.run((ctx) => ctx.db.get(renewedActive)))?.status).toBe('active');

    // Disable leg: a grace user whose renewal landed mid-sweep (expiry+window
    // back in the future) — applyDisableTransition must no-op…
    const renewedGrace = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'grace',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.applyDisableTransition, { userId: renewedGrace });
    expect((await t.run((ctx) => ctx.db.get(renewedGrace)))?.status).toBe('grace');

    // …and the action's pre-backend-disable re-check agrees on both directions.
    const now = Date.now();
    expect(await t.query(internal.lifecycle.isDisableDue, { userId: renewedGrace, now })).toBe(
      false,
    );
    await t.run((ctx) => ctx.db.patch(renewedGrace, { membershipExpiresAt: now - 30 * DAY }));
    expect(await t.query(internal.lifecycle.isDisableDue, { userId: renewedGrace, now })).toBe(
      true,
    );
    // A non-grace user is never due (an active user can't skip the grace leg).
    expect(await t.query(internal.lifecycle.isDisableDue, { userId: renewedActive, now })).toBe(
      false,
    );
  });

  test('findTombstonedDue returns only disabled subs past their deletedAt (Review #6)', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const now = Date.now();
    const dueId = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        updatedAt: now,
      });
      const mk = (buid: string, state: 'disabled' | 'active', deletedAt?: number) =>
        ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: buid,
          backendShortId: `${buid}-s`,
          subscriptionUrl: 'https://x/sub',
          subscriptionMirrors: [],
          state,
          ...(deletedAt !== undefined ? { deletedAt } : {}),
          updatedAt: now,
        });
      const due = await mk('bu-due', 'disabled', now - 1000); // past grace → due
      await mk('bu-future', 'disabled', now + 100_000); // grace not elapsed → excluded
      await mk('bu-nodel', 'disabled'); // no deletedAt → excluded (gt(...,0) guard)
      await mk('bu-active', 'active', now - 1000); // wrong state → excluded
      return due;
    });

    const res = await t.query(internal.lifecycle.findTombstonedDue, { now, limit: 100 });
    expect(res).toHaveLength(1);
    expect(res[0]!.backendUserId).toBe('bu-due');
    expect(dueId).toBeDefined();
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
        disabledReason: 'membership_lapsed',
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

  test('paid-through advances on billing/admin grants, never on referral rewards (M4)', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    const exp1 = Date.now() + 30 * DAY;
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: exp1,
      reason: 'billing.nowpayments',
    });
    expect((await t.run((ctx) => ctx.db.get(userId)))?.membershipPaidThroughAt).toBe(exp1);

    // A referral reward extends the effective expiry but NOT the paid-through.
    const exp2 = exp1 + 14 * DAY;
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: exp2,
      reason: 'referral.referrer_bonus',
    });
    const afterBonus = await t.run((ctx) => ctx.db.get(userId));
    expect(afterBonus?.membershipExpiresAt).toBe(exp2);
    expect(afterBonus?.membershipPaidThroughAt).toBe(exp1);

    // An admin grant counts as paid value…
    const exp3 = exp2 + 10 * DAY;
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: exp3,
      reason: 'admin_grant',
    });
    expect((await t.run((ctx) => ctx.db.get(userId)))?.membershipPaidThroughAt).toBe(exp3);

    // …and paid-through never moves BACKWARD on a shorter grant.
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: exp1,
      reason: 'billing.stripe',
    });
    expect((await t.run((ctx) => ctx.db.get(userId)))?.membershipPaidThroughAt).toBe(exp3);
  });
});

describe('lifecycle idle-free deactivate + retain (WS2)', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('findIdleFree pages ALL due users incl. a same-freeKeyExpiresAt collision', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId, memberTierId } = await seedTiers(t);
    const now = Date.now();
    const stale = now - DAY; // key expired yesterday
    const ids = await t.run(async (ctx) => {
      const out: Id<'users'>[] = [];
      // 5 idle free users, ALL sharing the same freeKeyExpiresAt (the exact
      // collision the old bare-_creationTime keyset skipped at a page boundary).
      for (let i = 0; i < 5; i++) {
        out.push(
          await ctx.db.insert('users', {
            tierId: freeTierId,
            status: 'active',
            freeKeyExpiresAt: stale,
            updatedAt: now,
          }),
        );
      }
      // Not due: a future key window; and a paid member (wrong tier).
      await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        freeKeyExpiresAt: now + 30 * DAY,
        updatedAt: now,
      });
      await ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: now });
      return out;
    });

    const seen: string[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < 10; i++) {
      // Annotated to break the same-module self-referential inference.
      const res: {
        idle: { userId: Id<'users'> }[];
        isDone: boolean;
        continueCursor: string;
      } = await t.query(internal.lifecycle.findIdleFree, {
        tierId: freeTierId,
        now,
        cursor,
        numItems: 2,
      });
      seen.push(...res.idle.map((e) => String(e.userId)));
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    // All 5 due users returned exactly once; the future + paid users excluded.
    expect(seen.sort()).toEqual(ids.map(String).sort());
  });

  test('deactivateIdleFree RETAINS the row (status→inactive, key reclaimed), never deletes', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    const now = Date.now();
    const userId = await t.run(async (ctx) => {
      const uid = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        freeKeyExpiresAt: now - DAY,
        updatedAt: now,
      });
      await ctx.db.insert('subscriptions', {
        userId: uid,
        backend: 'remnawave',
        backendUserId: 'bu-idle',
        backendShortId: 'bs-idle',
        subscriptionUrl: 'https://x/sub',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: now,
      });
      return uid;
    });

    const res = await t.action(internal.lifecycle.deactivateIdleFree, {});
    expect(res.deactivated).toBe(1);
    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u).not.toBeNull(); // RETAINED
      expect(u!.status).toBe('inactive'); // NOT 'deleted'
      expect(u!.tierId).toBe(freeTierId); // kept on the free tier
    });
    // Idempotent: a second run finds nothing (the row left the active range).
    expect((await t.action(internal.lifecycle.deactivateIdleFree, {})).deactivated).toBe(0);
    await t.run(async (ctx) => {
      const all = await ctx.db.query('users').collect();
      expect(all.every((u) => u.status !== 'deleted')).toBe(true);
    });
  });

  test('refreshFreeWindow reactivates an inactive user + pushes the window forward', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'inactive',
        suspendedAt: Date.now(),
        freeKeyExpiresAt: Date.now() - 10 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.refreshFreeWindow, { userId });
    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u!.status).toBe('active');
      expect(u!.suspendedAt).toBeUndefined();
      expect(u!.freeKeyExpiresAt!).toBeGreaterThan(Date.now());
      const reactivated = (await ctx.db.query('auditLog').collect()).find(
        (r) => r.action === 'account.reactivate',
      );
      expect(reactivated).toBeTruthy();
    });
  });

  test('markUserInactive is a no-op if the user was refreshed between read and apply (race)', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    // freeKeyExpiresAt in the FUTURE → the guard must refuse to deactivate.
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        freeKeyExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.markUserInactive, { userId });
    expect((await t.run((ctx) => ctx.db.get(userId)))!.status).toBe('active');
  });

  test('purgeInactiveFree removes only over-threshold inactive rows', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    const now = Date.now();
    const { oldId, recentId } = await t.run(async (ctx) => {
      const oldId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'inactive',
        freeKeyExpiresAt: now - 200 * DAY, // idle long ago
        updatedAt: now,
      });
      const recentId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'inactive',
        freeKeyExpiresAt: now - 5 * DAY, // recently inactive
        updatedAt: now,
      });
      return { oldId, recentId };
    });

    const res = await t.action(internal.lifecycle.purgeInactiveFree, { olderThanDays: 180 });
    expect(res.removed).toBe(1);
    await t.run(async (ctx) => {
      expect(await ctx.db.get(oldId)).toBeNull(); // purged
      expect(await ctx.db.get(recentId)).not.toBeNull(); // kept
    });
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

// Review #2/#3: a tier push (renewal, downgrade, upgrade) must re-enable a key the
// grace sweep disabled and preserve the member's connection-profile squad.
describe('lifecycle push: re-enable + profile squad (Review #2/#3)', () => {
  beforeEach(() => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
  });
  afterEach(() => vi.unstubAllEnvs());

  async function seedActiveSub(
    t: ReturnType<typeof convexTest>,
    userId: Id<'users'>,
    backendUserId: string,
    placement?: string,
  ): Promise<void> {
    await t.run(async (ctx) => {
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId,
        backendShortId: `${backendUserId}-s`,
        subscriptionUrl: 'https://x/sub',
        subscriptionMirrors: [],
        ...(placement ? { backendPlacement: placement } : {}),
        state: 'active',
        updatedAt: Date.now(),
      });
    });
  }

  test('activeSubAndTier returns the mode placement (from the mode pool) + userStatus', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.privacy.squads',
        value: JSON.stringify(['PRIVACY_SQUAD']),
        updatedAt: Date.now(),
      });
      return ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionModeId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      });
    });
    await seedActiveSub(t, userId, 'bu-squad');

    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.placement).toBe('PRIVACY_SQUAD');
    expect(st?.userStatus).toBe('active');
  });

  test('activeSubAndTier placement is null when the mode has no pool bound', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionModeId: 'evade',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-fallback');

    // No mode pool + no persisted placement → null (Remnawave then leaves
    // activeInternalSquads unset; there is no longer a tier-squad fallback).
    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.placement).toBeNull();
  });

  test('device-limit toggle: OFF (default) forces hwidDeviceLimit null; ON uses the tier limit', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t); // member tier: hwidEnabled, hwidLimit 3
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-hwid');

    // No enforcement row → the default OFF → unlimited (null) despite hwidEnabled.
    const off = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(off?.hwidDeviceLimit).toBeNull();

    // Flip enforcement ON → the tier's limit is sent.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'devices.enforcementEnabled',
        value: JSON.stringify(true),
        updatedAt: Date.now(),
      }),
    );
    const on = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(on?.hwidDeviceLimit).toBe(3);
  });

  test('activeSubAndTier PRESERVES the subscription-persisted placement (no re-pick thrash)', async () => {
    // Node pools: the key was issued into SQUAD_A (persisted on the sub row).
    // Even though the mode's pool now prefers a different node (SQUAD_B, fewer
    // users), a tier push must re-send SQUAD_A — re-homing a live key on every
    // renewal would thrash users across nodes.
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'remnawave.modePlacement.privacy.squads',
        value: JSON.stringify(['SQUAD_A', 'SQUAD_B']),
        updatedAt: Date.now(),
      });
      const serverId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'rw',
        slug: 'rw-squads',
        config: { type: 'remnawave', baseUrl: 'https://rw.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      });
      // SQUAD_B is currently the least-loaded (a fresh pick would choose it).
      const now = Date.now();
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: serverId,
        placement: 'SQUAD_A',
        usersOnline: 40,
        online: true,
        nodeCount: 1,
        lastStatsAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('remnawaveNodeStats', {
        backendServerId: serverId,
        placement: 'SQUAD_B',
        usersOnline: 1,
        online: true,
        nodeCount: 1,
        lastStatsAt: now,
        updatedAt: now,
      });
      return ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionModeId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      });
    });
    await seedActiveSub(t, userId, 'bu-pinned', 'SQUAD_A');

    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.placement).toBe('SQUAD_A'); // pinned, NOT re-picked to SQUAD_B

    // A pre-pool row (no persisted placement) falls back to the pool's first
    // squad deterministically (stablePlacement, not least-loaded) — stable across pushes.
    const legacyUserId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionModeId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, legacyUserId, 'bu-legacy');
    const stLegacy = await t.query(internal.lifecycle.activeSubAndTier, { userId: legacyUserId });
    expect(stLegacy?.placement).toBe('SQUAD_A'); // pool[0], not least-loaded
  });

  test('pushTierToBackend runs cleanly for an active user and clears drift (mock backend)', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        backendPushFailedAt: Date.now(), // pretend a prior push drifted
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-push');

    await t.action(internal.lifecycle.pushTierToBackend, { userId });
    // Push succeeded against the mock (incl. the setUserStatus(active) re-enable
    // branch) → the drift flag is cleared.
    expect((await t.run((ctx) => ctx.db.get(userId)))?.backendPushFailedAt).toBeUndefined();
  });

  test('same-tier renewal of a disabled member re-activates locally + schedules a push', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        disabledReason: 'membership_lapsed',
        suspendedAt: Date.now(),
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-renew');

    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId, // SAME tier — the common monthly re-up
      expiresAtMs: Date.now() + 30 * DAY,
      reason: 'test.renew',
    });
    const afterLocal = await t.run((ctx) => ctx.db.get(userId));
    expect(afterLocal?.status).toBe('active');
    expect(afterLocal?.disabledReason).toBeUndefined();

    // The fix (Review #2): the same-tier branch now SCHEDULES a backend push. It
    // previously returned without one, so the re-enable never reached the backend.
    // (pushTierToBackend's re-enable + drift-clear is covered by the direct-call
    // test above.)
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((f) => f.name.includes('pushTierToBackend'))).toBe(true);
  });

  test('a grant does NOT lift an admin disable (payment is not an un-ban)', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        disabledReason: 'admin_action',
        suspendedAt: Date.now(),
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-banned');

    // Same-tier renewal arrives (webhook/code) for a banned account.
    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: Date.now() + 30 * DAY,
      reason: 'test.renew',
    });
    const after = await t.run((ctx) => ctx.db.get(userId));
    // The purchase is RECORDED (honored when an admin later lifts the ban)…
    expect(after?.membershipExpiresAt).toBeGreaterThan(Date.now());
    // …but the ban stands, and NO backend push is scheduled (the key stays off).
    expect(after?.status).toBe('disabled');
    expect(after?.disabledReason).toBe('admin_action');
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((f) => f.name.includes('pushTierToBackend'))).toBe(false);
  });

  test('a tier-change grant on an admin-disabled user records the tier, stays disabled, no push', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId, memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'disabled',
        disabledReason: 'admin_action',
        suspendedAt: Date.now(),
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-banned-free');

    await t.mutation(internal.lifecycle.setMembership, {
      userId,
      tierId: memberTierId,
      expiresAtMs: Date.now() + 30 * DAY,
      reason: 'test.upgrade',
    });
    const after = await t.run((ctx) => ctx.db.get(userId));
    // Tier + expiry recorded (history kept)…
    expect(after?.tierId).toBe(memberTierId);
    expect(after?.membershipExpiresAt).toBeGreaterThan(Date.now());
    // …but the ban stands and the backend key is NOT re-enabled.
    expect(after?.status).toBe('disabled');
    expect(after?.disabledReason).toBe('admin_action');
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    expect(scheduled.some((f) => f.name.includes('pushTierToBackend'))).toBe(false);
    const history = await t.run((ctx) =>
      ctx.db
        .query('tierHistory')
        .withIndex('by_user', (q) => q.eq('userId', userId))
        .collect(),
    );
    expect(history).toHaveLength(1);
  });

  test('downgradeLapsedToFree moves a lapsed member to the free tier', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId, memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        disabledReason: 'membership_lapsed',
        suspendedAt: Date.now(),
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-downgrade');

    await t.mutation(internal.lifecycle.downgradeLapsedToFree, { userId });
    await t.finishInProgressScheduledFunctions();
    const u = await t.run((ctx) => ctx.db.get(userId));
    expect(u?.tierId).toBe(freeTierId);
    expect(u?.status).toBe('active');
    expect(u?.disabledReason).toBeUndefined();
  });

  test('downgradeLapsedToFree is a no-op for an admin-disabled member', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        disabledReason: 'admin_action',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.lifecycle.downgradeLapsedToFree, { userId });
    const u = await t.run((ctx) => ctx.db.get(userId));
    expect(u?.tierId).toBe(memberTierId);
    expect(u?.status).toBe('disabled');
  });

  test('downgradeLapsedToFree lifts a member already ON a free tier (not left disabled)', async () => {
    const t = convexTest(schema, modules);
    const { freeTierId } = await seedTiers(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'disabled',
        disabledReason: 'membership_lapsed',
        suspendedAt: Date.now(),
        membershipExpiresAt: Date.now() - DAY, // odd lapsed-free state
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, userId, 'bu-freelapsed');

    await t.mutation(internal.lifecycle.downgradeLapsedToFree, { userId });
    const u = await t.run((ctx) => ctx.db.get(userId));
    expect(u?.tierId).toBe(freeTierId); // stays free…
    expect(u?.status).toBe('active'); // …but is lifted in place, not left disabled
    expect(u?.disabledReason).toBeUndefined();
    expect(u?.membershipExpiresAt).toBeUndefined(); // lapsed expiry cleared
  });
});
