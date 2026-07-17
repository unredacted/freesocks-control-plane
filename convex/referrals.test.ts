/// <reference types="vite/client" />
/**
 * Referral program: code minting (uniqueness + idempotency), signup binding
 * (unknown/self/dup codes), the conversion hook (paid-only, once, instant
 * referee bonus, no cascades), and vesting (live-referee / referrer-gone /
 * monthly cap / tier-unavailable voids). Also pins config sanitize.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { generateReferralCode, normalizeReferralCode } from './lib/referralCode';
import { REFERRAL_DEFAULTS, REFERRAL_KEYS, resolveReferralConfig } from './lib/referralConfig';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

async function seedTier(
  t: TestConvex<typeof schema>,
  o: { slug: string; isDefaultFree?: boolean },
): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: o.slug,
      name: o.slug,
      backend: 'remnawave',
      monthlyTrafficGb: o.isDefaultFree ? 5 : 0,
      deviceLimit: 1,
      hwidLimit: 0,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: o.isDefaultFree ?? false,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    }),
  );
}

async function seedUser(
  t: TestConvex<typeof schema>,
  tierId: Id<'tiers'>,
  o: { referralCode?: string; status?: 'active' | 'deleted'; membershipExpiresAt?: number } = {},
): Promise<Id<'users'>> {
  return t.run((ctx) =>
    ctx.db.insert('users', {
      tierId,
      status: o.status ?? 'active',
      referralCode: o.referralCode,
      membershipExpiresAt: o.membershipExpiresAt,
      updatedAt: Date.now(),
    }),
  );
}

async function getUser(t: TestConvex<typeof schema>, id: Id<'users'>) {
  return t.run((ctx) => ctx.db.get(id));
}

describe('referral codes', () => {
  test('normalize: case/separator/alias-tolerant', () => {
    const code = generateReferralCode();
    expect(normalizeReferralCode(code.toLowerCase().replace(/-/g, ''))).toBe(code);
    expect(normalizeReferralCode('fsr-' + code.slice(4).toLowerCase())).toBe(code);
    expect(normalizeReferralCode('garbage')).not.toBe(code);
  });

  test('ensureForUser mints once and is idempotent', async () => {
    const t = convexTest(schema, modules);
    const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
    const u = await seedUser(t, free);
    const a = await t.action(internal.referrals.ensureForUser, { userId: u });
    const b = await t.action(internal.referrals.ensureForUser, { userId: u });
    expect(a.code).toMatch(/^FSR-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    expect(b.code).toBe(a.code);
  });
});

describe('bindReferral', () => {
  test('binds on a valid code; unknown/self/dup/deleted all no-op', async () => {
    const t = convexTest(schema, modules);
    const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
    const referrer = await seedUser(t, free, { referralCode: 'FSR-AAAA-BBBB' });
    const referee = await seedUser(t, free);
    const other = await seedUser(t, free);

    // Unknown code
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referee,
        code: 'FSR-NOPE-0000',
      }),
    ).toEqual({ bound: false });
    // Valid (normalized input: lowercase, no dashes)
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referee,
        code: 'fsraaaabbbb',
      }),
    ).toEqual({ bound: true });
    // Second bind of the same referee is ignored
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referee,
        code: 'FSR-AAAA-BBBB',
      }),
    ).toEqual({ bound: false });
    // Self-referral
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referrer,
        code: 'FSR-AAAA-BBBB',
      }),
    ).toEqual({ bound: false });
    // Deleted referrer
    const gone = await seedUser(t, free, { referralCode: 'FSR-GONE-0000', status: 'deleted' });
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: other,
        code: 'FSR-GONE-0000',
      }),
    ).toEqual({ bound: false });

    const row = await t.run((ctx) =>
      ctx.db
        .query('referrals')
        .withIndex('by_referee', (q) => q.eq('refereeUserId', referee))
        .unique(),
    );
    expect(row?.status).toBe('pending');
    expect(row?.referrerUserId).toBe(referrer);
  });

  test('disabled program never binds', async () => {
    const t = convexTest(schema, modules);
    const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
    await seedUser(t, free, { referralCode: 'FSR-AAAA-BBBB' });
    const referee = await seedUser(t, free);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', { key: REFERRAL_KEYS.enabled, value: 'false', updatedAt: 0 }),
    );
    expect(
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referee,
        code: 'FSR-AAAA-BBBB',
      }),
    ).toEqual({ bound: false });
  });
});

describe('maybeConvert', () => {
  async function setup(t: TestConvex<typeof schema>) {
    const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
    const member = await seedTier(t, { slug: 'member' });
    const referrer = await seedUser(t, free, { referralCode: 'FSR-AAAA-BBBB' });
    const referee = await seedUser(t, free);
    await t.mutation(internal.referrals.bindReferral, {
      refereeUserId: referee,
      code: 'FSR-AAAA-BBBB',
    });
    return { free, member, referrer, referee };
  }

  test('paid grant converts once + grants the referee bonus instantly', async () => {
    const t = convexTest(schema, modules);
    const { member, referee } = await setup(t);
    const expiry = Date.now() + 30 * DAY;
    // The real flow: the paid grant commits first, the hook runs after.
    await t.mutation(internal.lifecycle.setMembership, {
      userId: referee,
      tierId: member,
      expiresAtMs: expiry,
      reason: 'billing.order.paid',
    });
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: member,
      reason: 'billing.order.paid',
    });
    const refereeAfter = await getUser(t, referee);
    expect(refereeAfter?.membershipExpiresAt).toBe(
      expiry + REFERRAL_DEFAULTS.refereeBonusDays * DAY,
    );

    // Second conversion attempt no-ops (expiry unchanged).
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: member,
      reason: 'billing.order.paid',
    });
    expect((await getUser(t, referee))?.membershipExpiresAt).toBe(
      expiry + REFERRAL_DEFAULTS.refereeBonusDays * DAY,
    );
  });

  test('no-op on free-tier targets, referral rewards, and when disabled', async () => {
    const t = convexTest(schema, modules);
    const { free, member, referee } = await setup(t);
    // Free target
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: free,
      reason: 'admin.grant',
    });
    // Referral-reward grant
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: member,
      reason: 'referral.referrer_bonus',
    });
    let row = await t.run((ctx) =>
      ctx.db
        .query('referrals')
        .withIndex('by_referee', (q) => q.eq('refereeUserId', referee))
        .unique(),
    );
    expect(row?.status).toBe('pending');
    // Disabled
    await t.run((ctx) =>
      ctx.db.insert('appSettings', { key: REFERRAL_KEYS.enabled, value: 'false', updatedAt: 0 }),
    );
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: member,
      reason: 'billing.order.paid',
    });
    row = await t.run((ctx) =>
      ctx.db
        .query('referrals')
        .withIndex('by_referee', (q) => q.eq('refereeUserId', referee))
        .unique(),
    );
    expect(row?.status).toBe('pending');
  });
});

describe('vestReferrerReward', () => {
  async function converted(t: TestConvex<typeof schema>) {
    const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
    const member = await seedTier(t, { slug: 'member' });
    const referrer = await seedUser(t, free, { referralCode: 'FSR-AAAA-BBBB' });
    const referee = await seedUser(t, free, {
      membershipExpiresAt: Date.now() + 30 * DAY,
    });
    await t.mutation(internal.referrals.bindReferral, {
      refereeUserId: referee,
      code: 'FSR-AAAA-BBBB',
    });
    await t.mutation(internal.referrals.maybeConvert, {
      userId: referee,
      toTierId: member,
      reason: 'billing.order.paid',
    });
    const referral = await t.run((ctx) =>
      ctx.db
        .query('referrals')
        .withIndex('by_referee', (q) => q.eq('refereeUserId', referee))
        .unique(),
    );
    return { free, member, referrer, referee, referralId: referral!._id };
  }

  test('vests: referrer moves to the paid tier with bonus days', async () => {
    const t = convexTest(schema, modules);
    const { member, referrer, referralId } = await converted(t);
    const before = Date.now();
    await t.mutation(internal.referrals.vestReferrerReward, { referralId });
    const referrerAfter = await getUser(t, referrer);
    expect(referrerAfter?.tierId).toBe(member);
    expect(referrerAfter?.membershipExpiresAt).toBeGreaterThanOrEqual(
      before + REFERRAL_DEFAULTS.referrerBonusDays * DAY,
    );
    const row = await t.run((ctx) => ctx.db.get(referralId));
    expect(row?.status).toBe('rewarded');
    expect(row?.referrerBonusDaysGranted).toBe(REFERRAL_DEFAULTS.referrerBonusDays);
  });

  test('extends an already-paid referrer from their current expiry', async () => {
    const t = convexTest(schema, modules);
    const { member, referrer, referralId } = await converted(t);
    const existing = Date.now() + 90 * DAY;
    await t.run((ctx) => ctx.db.patch(referrer, { tierId: member, membershipExpiresAt: existing }));
    await t.mutation(internal.referrals.vestReferrerReward, { referralId });
    expect((await getUser(t, referrer))?.membershipExpiresAt).toBe(
      existing + REFERRAL_DEFAULTS.referrerBonusDays * DAY,
    );
  });

  test('voids when the referee lapsed before vesting', async () => {
    const t = convexTest(schema, modules);
    const { referee, referralId } = await converted(t);
    // The referee lets their membership lapse AFTER converting (before vesting).
    await t.run((ctx) => ctx.db.patch(referee, { membershipExpiresAt: Date.now() - DAY }));
    await t.mutation(internal.referrals.vestReferrerReward, { referralId });
    const row = await t.run((ctx) => ctx.db.get(referralId));
    expect(row?.status).toBe('void');
    expect(row?.voidReason).toBe('referee_lapsed');
  });

  test('voids past the monthly cap', async () => {
    const t = convexTest(schema, modules);
    const { free, referrer, referralId } = await converted(t);
    // Backfill maxRewardsPerMonth already-vested rows this month.
    for (let i = 0; i < REFERRAL_DEFAULTS.maxRewardsPerMonth; i++) {
      const fakeReferee = await seedUser(t, free);
      await t.run((ctx) =>
        ctx.db.insert('referrals', {
          referrerUserId: referrer,
          refereeUserId: fakeReferee,
          status: 'rewarded',
          rewardedAt: Date.now(),
          updatedAt: Date.now(),
        }),
      );
    }
    await t.mutation(internal.referrals.vestReferrerReward, { referralId });
    const row = await t.run((ctx) => ctx.db.get(referralId));
    expect(row?.status).toBe('void');
    expect(row?.voidReason).toBe('cap_exceeded');
  });

  test('voids when the reward tier is missing', async () => {
    const t = convexTest(schema, modules);
    const { referralId } = await converted(t);
    // billing.tierSlug defaults to 'member'; point it at a slug with no tier.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.membership.tierSlug',
        value: JSON.stringify('no-such-tier'),
        updatedAt: 0,
      }),
    );
    await t.mutation(internal.referrals.vestReferrerReward, { referralId });
    const row = await t.run((ctx) => ctx.db.get(referralId));
    expect(row?.status).toBe('void');
    expect(row?.voidReason).toBe('tier_unavailable');
  });
});

describe('the applyMembership hook', () => {
  test('a paid setMembership runs the whole referral loop (convert → vest → reward)', async () => {
    vi.useFakeTimers();
    try {
      const t = convexTest(schema, modules);
      const free = await seedTier(t, { slug: 'free', isDefaultFree: true });
      const member = await seedTier(t, { slug: 'member' });
      const referrer = await seedUser(t, free, { referralCode: 'FSR-AAAA-BBBB' });
      const referee = await seedUser(t, free);
      await t.mutation(internal.referrals.bindReferral, {
        refereeUserId: referee,
        code: 'FSR-AAAA-BBBB',
      });
      await t.mutation(internal.lifecycle.setMembership, {
        userId: referee,
        tierId: member,
        expiresAtMs: Date.now() + 30 * DAY,
        reason: 'billing.order.paid',
      });
      // Fire the runAfter(0) hook + the referral chain it schedules (including
      // the 30-day vesting timer under fake timers), then drain.
      await vi.runAllTimersAsync();
      await t.finishAllScheduledFunctions(() => vi.runAllTimers());
      const row = await t.run((ctx) =>
        ctx.db
          .query('referrals')
          .withIndex('by_referee', (q) => q.eq('refereeUserId', referee))
          .unique(),
      );
      expect(row?.status).toBe('rewarded');
      // The referrer ends on the paid tier via the vested reward.
      const referrerAfter = await getUser(t, referrer);
      expect(referrerAfter?.tierId).toBe(member);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('resolveReferralConfig', () => {
  test('defaults; per-field overrides with bounds', async () => {
    const t = convexTest(schema, modules);
    expect(await t.run((ctx) => resolveReferralConfig(ctx.db))).toEqual(REFERRAL_DEFAULTS);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: REFERRAL_KEYS.referrerBonusDays,
        value: '45',
        updatedAt: 0,
      });
      await ctx.db.insert('appSettings', {
        key: REFERRAL_KEYS.vestingDays,
        value: '99999',
        updatedAt: 0, // out of bounds → default
      });
    });
    const cfg = await t.run((ctx) => resolveReferralConfig(ctx.db));
    expect(cfg.referrerBonusDays).toBe(45);
    expect(cfg.vestingDays).toBe(REFERRAL_DEFAULTS.vestingDays);
  });
});
