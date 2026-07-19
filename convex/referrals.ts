/**
 * Referral program (word-of-mouth growth). A member's `FSR-…` code binds a new
 * account to them at signup; rewards vest ONLY on the referee's first paid-tier
 * grant (any rail — billing, gift/redemption code, admin grant — anything that
 * flows through applyMembership with a non-referral reason):
 *
 *   pending → converted → rewarded
 *                  └────────→ void
 *
 * The referee's bonus lands at conversion; the referrer's vests after the
 * configured holding period while the referee is still a PAYING member (their
 * paid-through date — referral bonuses don't count, so a self-referral can't
 * farm leverage off its own instant bonus), and is bounded per calendar month.
 * Grants made BY referral rewards (reason 'referral.*') deliberately do NOT
 * cascade conversions — no multi-level reward chains without real money.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { ConvexError, v } from 'convex/values';
import type { Id } from './_generated/dataModel';
import { generateReferralCode, normalizeReferralCode } from './lib/referralCode';
import { REFERRAL_FIELD_LIMITS, REFERRAL_KEYS, resolveReferralConfig } from './lib/referralConfig';
import { resolveBillingConfig } from './lib/billingConfig';
import { applyMembership } from './lifecycle';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';

const DAY = 86_400_000;

// --- code minting (supportId pattern) ---------------------------------------

/** Mint a referral code for a user if it lacks one; returns the (existing or new) value. */
export const ensureForUser = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ code: string }> => {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      const candidate = generateReferralCode();
      try {
        const result = await ctx.runMutation(internal.referrals.setReferralCode, {
          userId,
          code: candidate,
        });
        return { code: result.code };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error('referral-code mint failed after retries');
  },
});

/**
 * Assign a referral code, enforcing uniqueness. Idempotent: a user that already
 * has one keeps it (lazy backfill races safely). Throws on a collision with a
 * DIFFERENT user so the action retries with a fresh candidate.
 */
export const setReferralCode = internalMutation({
  args: { userId: v.id('users'), code: v.string() },
  handler: async (ctx, { userId, code }) => {
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('user not found');
    if (user.referralCode) return { code: user.referralCode };
    const clash = await ctx.db
      .query('users')
      .withIndex('by_referral_code', (q) => q.eq('referralCode', code))
      .unique();
    if (clash && clash._id !== userId) throw new Error('referral-code collision');
    await ctx.db.patch(userId, { referralCode: code, updatedAt: Date.now() });
    return { code };
  },
});

// --- binding (signup) --------------------------------------------------------

/**
 * Bind a freshly-created account to the referrer whose code was supplied.
 * NEVER throws on a bad/unusable code — an invalid referral must not block
 * account creation (and the caller reports `bound` so the response can carry
 * `referralApplied`). One referrer per referee: an existing row wins silently.
 */
export const bindReferral = internalMutation({
  args: { refereeUserId: v.id('users'), code: v.string() },
  handler: async (ctx, { refereeUserId, code }): Promise<{ bound: boolean }> => {
    const cfg = await resolveReferralConfig(ctx.db);
    if (!cfg.enabled) return { bound: false };
    const normalized = normalizeReferralCode(code);
    const referrer = await ctx.db
      .query('users')
      .withIndex('by_referral_code', (q) => q.eq('referralCode', normalized))
      .unique();
    if (!referrer || referrer._id === refereeUserId || referrer.status === 'deleted') {
      return { bound: false };
    }
    const existing = await ctx.db
      .query('referrals')
      .withIndex('by_referee', (q) => q.eq('refereeUserId', refereeUserId))
      .unique();
    if (existing) return { bound: false };
    await ctx.db.insert('referrals', {
      referrerUserId: referrer._id,
      refereeUserId,
      status: 'pending',
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'member',
      actorId: refereeUserId,
      action: 'referral.bound',
      targetType: 'referral',
      targetId: refereeUserId,
      payload: { referrerUserId: referrer._id },
    });
    return { bound: true };
  },
});

// --- conversion + rewards ----------------------------------------------------

/**
 * The applyMembership hook (scheduled runAfter(0) at the end of every grant).
 * Converts a referee's PENDING row on their first paid-tier grant: flips to
 * 'converted' FIRST (the re-entry guard — each referee converts exactly once),
 * applies the referee's instant bonus days, and schedules the referrer's
 * vested reward. No-ops on: feature disabled, no row, already consumed, a
 * free-tier target, or a grant that is itself a referral reward (no cascades).
 */
export const maybeConvert = internalMutation({
  args: { userId: v.id('users'), toTierId: v.id('tiers'), reason: v.string() },
  handler: async (ctx, { userId, toTierId, reason }) => {
    if (reason.startsWith('referral.')) return null;
    const cfg = await resolveReferralConfig(ctx.db);
    if (!cfg.enabled) return null;
    const referral = await ctx.db
      .query('referrals')
      .withIndex('by_referee', (q) => q.eq('refereeUserId', userId))
      .unique();
    if (!referral || referral.status !== 'pending') return null;
    const toTier = await ctx.db.get(toTierId);
    if (!toTier || toTier.isDefaultFree) return null;

    const now = Date.now();
    await ctx.db.patch(referral._id, {
      status: 'converted',
      convertedAt: now,
      refereeBonusDaysGranted: cfg.refereeBonusDays,
      // Pin the referrer reward promised at conversion — a mid-vest config edit
      // must not retroactively change it (vest falls back to live config only
      // for rows converted before this field existed).
      referrerBonusDaysPlanned: cfg.referrerBonusDays,
      updatedAt: now,
    });

    // Referee bonus (instant): extend the just-granted membership. The granting
    // applyMembership already committed (we're a runAfter(0) child), so the
    // user's expiry reflects the paid grant.
    const referee = await ctx.db.get(userId);
    if (referee) {
      const base = Math.max(now, referee.membershipExpiresAt ?? now);
      await applyMembership(ctx, {
        userId,
        tierId: toTierId,
        expiresAtMs: base + cfg.refereeBonusDays * DAY,
        reason: 'referral.referee_bonus',
        triggeredBy: 'referral',
      });
    }

    // Referrer reward (vested after the holding period).
    await ctx.scheduler.runAfter(cfg.vestingDays * DAY, internal.referrals.vestReferrerReward, {
      referralId: referral._id,
    });

    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'referral.converted',
      targetType: 'referral',
      targetId: referral._id,
      payload: { referrerUserId: referral.referrerUserId, refereeBonusDays: cfg.refereeBonusDays },
    });
    return null;
  },
});

/**
 * Vest + grant the referrer's reward. Voids (with reason, audited) when the
 * program has been disabled since conversion, the referee lapsed before
 * vesting, the referrer is gone/deleted, the paid tier can't be resolved, or
 * the referrer hit the monthly reward cap. The granted days are the ones PINNED
 * at conversion (referrerBonusDaysPlanned), not the live config.
 */
export const vestReferrerReward = internalMutation({
  args: { referralId: v.id('referrals') },
  handler: async (ctx, { referralId }) => {
    const referral = await ctx.db.get(referralId);
    if (!referral || referral.status !== 'converted') return null;
    const cfg = await resolveReferralConfig(ctx.db);
    const now = Date.now();

    const voidIt = async (reason: string) => {
      await ctx.db.patch(referralId, { status: 'void', voidReason: reason, updatedAt: now });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'referral.void',
        targetType: 'referral',
        targetId: referralId,
        payload: { reason, referrerUserId: referral.referrerUserId },
      });
      return null;
    };

    // Disabling the program stops pending vests too (mirrors maybeConvert's gate)
    // — the off switch is the abuse-response lever and must actually bite.
    if (!cfg.enabled) return voidIt('program_disabled');

    // The referee must still be a PAYING member: the check keys off
    // `membershipPaidThroughAt` (real-value grants only), NOT the effective
    // expiry — otherwise a self-referral satisfies the holding period with its
    // own instant referee bonus and farms ~2.4× the purchased days (M4). With
    // the bonus excluded, a buy-and-vanish self-referral voids at vest; only a
    // referee who RENEWS past the window pays out. Pre-paidThrough rows fall
    // back to the effective expiry.
    const referee = await ctx.db.get(referral.refereeUserId);
    const refereePaidThrough =
      referee?.membershipPaidThroughAt ?? referee?.membershipExpiresAt ?? 0;
    const refereeLive =
      referee &&
      (referee.status === 'active' || referee.status === 'grace') &&
      refereePaidThrough > now;
    if (!refereeLive) return voidIt('referee_lapsed');

    const referrer = await ctx.db.get(referral.referrerUserId);
    // A deleted OR admin-banned referrer does not accrue reward days: for a
    // banned account applyMembership correctly keeps the ban, but the grant
    // would still record the tier + extend membershipExpiresAt, quietly banking
    // days the account keeps if ever un-banned. A merely LAPSED referrer
    // (membership ran out) is fine — the reward re-activates them, the same as
    // any grant. (Review C-F6.)
    if (!referrer || referrer.status === 'deleted') return voidIt('referrer_gone');
    if (referrer.status === 'disabled' && referrer.disabledReason === 'admin_action') {
      return voidIt('referrer_gone');
    }

    // Monthly cap: rewards VESTED to this referrer since the 1st (UTC).
    const monthStart = new Date(now);
    monthStart.setUTCDate(1);
    monthStart.setUTCHours(0, 0, 0, 0);
    const vestedThisMonth = await ctx.db
      .query('referrals')
      .withIndex('by_referrer_rewarded', (q) =>
        q.eq('referrerUserId', referral.referrerUserId).gte('rewardedAt', monthStart.getTime()),
      )
      .collect();
    if (vestedThisMonth.length >= cfg.maxRewardsPerMonth) return voidIt('cap_exceeded');

    // The reward tier: the deployment's membership tier (billing.tierSlug).
    const billing = await resolveBillingConfig(ctx.db);
    const paidTier = await ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', billing.tierSlug))
      .unique();
    if (!paidTier) return voidIt('tier_unavailable');

    // Grant what conversion PROMISED, not today's config (pre-pin rows fall back).
    const bonusDays = referral.referrerBonusDaysPlanned ?? cfg.referrerBonusDays;
    const base = Math.max(now, referrer.membershipExpiresAt ?? 0);
    await applyMembership(ctx, {
      userId: referral.referrerUserId,
      tierId: paidTier._id,
      expiresAtMs: base + bonusDays * DAY,
      reason: 'referral.referrer_bonus',
      triggeredBy: 'referral',
    });
    await ctx.db.patch(referralId, {
      status: 'rewarded',
      rewardedAt: now,
      referrerBonusDaysGranted: bonusDays,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'referral.rewarded',
      targetType: 'referral',
      targetId: referralId,
      payload: {
        referrerUserId: referral.referrerUserId,
        refereeUserId: referral.refereeUserId,
        referrerBonusDays: bonusDays,
      },
    });
    return null;
  },
});

// --- member stats ------------------------------------------------------------

/** The member's referral card data (code minted lazily by the HTTP handler). */
export const getStats = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    const rows = await ctx.db
      .query('referrals')
      .withIndex('by_referrer', (q) => q.eq('referrerUserId', userId))
      .collect();
    let pending = 0;
    let converted = 0;
    let bonusDaysEarned = 0;
    for (const r of rows) {
      if (r.status === 'pending') pending++;
      if (r.status === 'converted' || r.status === 'rewarded') converted++;
      if (r.status === 'rewarded') bonusDaysEarned += r.referrerBonusDaysGranted ?? 0;
    }
    return {
      code: user.referralCode ?? null,
      stats: { invited: rows.length, converted, pending, bonusDaysEarned },
    };
  },
});

// --- admin config ------------------------------------------------------------

/** Cheap feature-flag probe for the member stats route (hides the card when off). */
export const isEnabled = internalQuery({
  args: {},
  handler: async (ctx) => (await resolveReferralConfig(ctx.db)).enabled,
});

export const getConfig = internalQuery({
  args: {},
  handler: (ctx) => resolveReferralConfig(ctx.db),
});

export const setConfig = internalMutation({
  args: {
    enabled: v.optional(v.boolean()),
    refereeBonusDays: v.optional(v.number()),
    referrerBonusDays: v.optional(v.number()),
    vestingDays: v.optional(v.number()),
    maxRewardsPerMonth: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const L = REFERRAL_FIELD_LIMITS;
    const writes: Array<[string, unknown]> = [];
    if (a.enabled !== undefined) writes.push([REFERRAL_KEYS.enabled, a.enabled]);
    for (const [field, key, limits] of [
      ['refereeBonusDays', REFERRAL_KEYS.refereeBonusDays, L.refereeBonusDays],
      ['referrerBonusDays', REFERRAL_KEYS.referrerBonusDays, L.referrerBonusDays],
      ['vestingDays', REFERRAL_KEYS.vestingDays, L.vestingDays],
      ['maxRewardsPerMonth', REFERRAL_KEYS.maxRewardsPerMonth, L.maxRewardsPerMonth],
    ] as const) {
      const val = a[field];
      if (val === undefined) continue;
      if (!Number.isInteger(val) || val < limits.min || val > limits.max) {
        throw new ConvexError({
          code: 'validation',
          message: `${field} must be an integer in [${limits.min}, ${limits.max}]`,
        });
      }
      writes.push([key, val]);
    }
    if (writes.length === 0) {
      throw new ConvexError({ code: 'validation', message: 'no recognized referral fields' });
    }
    for (const [key, val] of writes) {
      await upsertSettingRow(ctx, key, JSON.stringify(val), a.actorAdminId);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'referral.config.update',
      targetType: 'referral_config',
      payload: Object.fromEntries(writes.map(([k, val]) => [k, val])),
    });
    return resolveReferralConfig(ctx.db);
  },
});
