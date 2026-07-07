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
    remnawaveSquadUuid?: string,
  ): Promise<void> {
    await t.run(async (ctx) => {
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId,
        backendShortId: `${backendUserId}-s`,
        subscriptionUrl: 'https://x/sub',
        subscriptionMirrors: [],
        ...(remnawaveSquadUuid ? { remnawaveSquadUuid } : {}),
        state: 'active',
        updatedAt: Date.now(),
      });
    });
  }

  test('activeSubAndTier returns the profile squad (not the tier squad) + userStatus', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) => {
      await ctx.db.patch(memberTierId, { remnawaveSquadUuid: 'TIER_SQUAD' });
      await ctx.db.insert('appSettings', {
        key: 'connectionProfile.privacy.squadUuid',
        value: JSON.stringify('PRIVACY_SQUAD'),
        updatedAt: Date.now(),
      });
      return ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionProfileId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      });
    });
    await seedActiveSub(t, userId, 'bu-squad');

    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.remnawaveSquadUuid).toBe('PRIVACY_SQUAD');
    expect(st?.userStatus).toBe('active');
  });

  test('activeSubAndTier falls back to the tier squad when no profile squad is bound', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) => {
      await ctx.db.patch(memberTierId, { remnawaveSquadUuid: 'TIER_SQUAD' });
      return ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionProfileId: 'evade',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      });
    });
    await seedActiveSub(t, userId, 'bu-fallback');

    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.remnawaveSquadUuid).toBe('TIER_SQUAD');
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

  test('activeSubAndTier PRESERVES the subscription-persisted squad (no pool re-pick thrash)', async () => {
    // Squad pools: the key was issued into squadA (persisted on the sub row).
    // Even though the profile's pool now prefers a different squad (squadB,
    // fewer members), a tier push must re-send squadA — re-homing a live key
    // on every renewal would thrash users across squads.
    const t = convexTest(schema, modules);
    const { memberTierId } = await seedTiers(t);
    const userId = await t.run(async (ctx) => {
      await ctx.db.patch(memberTierId, { remnawaveSquadUuid: 'TIER_SQUAD' });
      await ctx.db.insert('appSettings', {
        key: 'connectionProfile.privacy.squadUuids',
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
      await ctx.db.insert('remnawaveSquadStats', {
        backendServerId: serverId,
        squadUuid: 'SQUAD_A',
        membersCount: 40,
        lastStatsAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('remnawaveSquadStats', {
        backendServerId: serverId,
        squadUuid: 'SQUAD_B',
        membersCount: 1,
        lastStatsAt: now,
        updatedAt: now,
      });
      return ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionProfileId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      });
    });
    await seedActiveSub(t, userId, 'bu-pinned', 'SQUAD_A');

    const st = await t.query(internal.lifecycle.activeSubAndTier, { userId });
    expect(st?.remnawaveSquadUuid).toBe('SQUAD_A'); // pinned, NOT re-picked to SQUAD_B

    // A pre-pool row (no persisted squad) falls back to the pool's first squad,
    // deterministically — stable across pushes.
    const legacyUserId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'active',
        connectionProfileId: 'privacy',
        membershipExpiresAt: Date.now() + 30 * DAY,
        updatedAt: Date.now(),
      }),
    );
    await seedActiveSub(t, legacyUserId, 'bu-legacy');
    const stLegacy = await t.query(internal.lifecycle.activeSubAndTier, { userId: legacyUserId });
    expect(stLegacy?.remnawaveSquadUuid).toBe('SQUAD_A'); // pool[0], not least-loaded
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
