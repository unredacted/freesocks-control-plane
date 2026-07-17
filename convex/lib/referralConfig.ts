/**
 * Referral-program config: the `appSettings` `referral.*` namespace, resolved
 * fail-safe (deliberately NOT in SETTINGS_DEFAULTS — typed validation here).
 * Edited from Admin → Billing (the growth surface).
 *
 * Reward economics: bonuses vest ONLY on the referee's first paid-tier grant,
 * so farming free accounts is worthless by construction. The referee's bonus
 * lands immediately; the referrer's vests after `vestingDays` while the
 * referee is still a live member (kills buy-and-vanish self-referrals), and is
 * bounded per calendar month by `maxRewardsPerMonth`.
 */
import type { DatabaseReader } from '../_generated/server';

export interface ReferralConfig {
  /** Master switch: the signup field, the account-page card, and rewards. */
  enabled: boolean;
  /** Bonus membership days the REFEREE gets instantly on their first paid grant. */
  refereeBonusDays: number;
  /** Bonus membership days the REFERRER gets once the reward vests. */
  referrerBonusDays: number;
  /** Holding period before the referrer's reward vests (0 = instant). */
  vestingDays: number;
  /** Max referrer rewards that may VEST per calendar month per referrer. */
  maxRewardsPerMonth: number;
}

export const REFERRAL_DEFAULTS: ReferralConfig = {
  // Unlike the billing rails, referrals need no external keys/prices to
  // function (the reward tier resolves from billing.tierSlug and a missing
  // tier fail-softs to void + audit), so the program ships ON.
  enabled: true,
  refereeBonusDays: 14,
  referrerBonusDays: 30,
  vestingDays: 30,
  maxRewardsPerMonth: 10,
};

export const REFERRAL_KEYS = {
  enabled: 'referral.enabled',
  refereeBonusDays: 'referral.refereeBonusDays',
  referrerBonusDays: 'referral.referrerBonusDays',
  vestingDays: 'referral.vestingDays',
  maxRewardsPerMonth: 'referral.maxRewardsPerMonth',
} as const;

function intIn(raw: unknown, min: number, max: number, fallback: number): number {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= min && raw <= max
    ? raw
    : fallback;
}

async function readSetting(db: DatabaseReader, key: string): Promise<unknown> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return undefined;
  try {
    return JSON.parse(row.value);
  } catch {
    return undefined;
  }
}

/** Per-field validators, shared by the resolver and the admin write path. */
export const REFERRAL_FIELD_LIMITS = {
  refereeBonusDays: { min: 1, max: 365 },
  referrerBonusDays: { min: 1, max: 365 },
  vestingDays: { min: 0, max: 365 },
  maxRewardsPerMonth: { min: 1, max: 1000 },
} as const;

export async function resolveReferralConfig(db: DatabaseReader): Promise<ReferralConfig> {
  const [enabled, refereeBonusDays, referrerBonusDays, vestingDays, maxRewardsPerMonth] =
    await Promise.all([
      readSetting(db, REFERRAL_KEYS.enabled),
      readSetting(db, REFERRAL_KEYS.refereeBonusDays),
      readSetting(db, REFERRAL_KEYS.referrerBonusDays),
      readSetting(db, REFERRAL_KEYS.vestingDays),
      readSetting(db, REFERRAL_KEYS.maxRewardsPerMonth),
    ]);
  const L = REFERRAL_FIELD_LIMITS;
  return {
    enabled: typeof enabled === 'boolean' ? enabled : REFERRAL_DEFAULTS.enabled,
    refereeBonusDays: intIn(
      refereeBonusDays,
      L.refereeBonusDays.min,
      L.refereeBonusDays.max,
      REFERRAL_DEFAULTS.refereeBonusDays,
    ),
    referrerBonusDays: intIn(
      referrerBonusDays,
      L.referrerBonusDays.min,
      L.referrerBonusDays.max,
      REFERRAL_DEFAULTS.referrerBonusDays,
    ),
    vestingDays: intIn(
      vestingDays,
      L.vestingDays.min,
      L.vestingDays.max,
      REFERRAL_DEFAULTS.vestingDays,
    ),
    maxRewardsPerMonth: intIn(
      maxRewardsPerMonth,
      L.maxRewardsPerMonth.min,
      L.maxRewardsPerMonth.max,
      REFERRAL_DEFAULTS.maxRewardsPerMonth,
    ),
  };
}
