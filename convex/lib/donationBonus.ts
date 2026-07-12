/**
 * Donation → free-user bandwidth accumulator. Donations in a calendar month
 * accumulate into a SHARED pool; every free user's monthly cap is raised by
 * `min(monthlyBonusCapGb, monthDonatedUSD × bonusGbPerUsd)` for that month, then
 * resets to base next month. State is a single `appState` row (key
 * `donation:freeBonus`), read-modify-write inside the caller's transaction —
 * mirrors lib/statusCounters.ts. Pure helpers so the checkout grant, the fleet
 * apply action, issuance, and publicConfig share one source of truth.
 */
import type { MutationCtx, DatabaseReader } from '../_generated/server';
import { resolveBillingConfig, type DonationConfig } from './billingConfig';

export const DONATION_STATE_KEY = 'donation:freeBonus';

export interface DonationState {
  /** Calendar month (UTC) the `donatedCents` total belongs to, 'YYYY-MM'. */
  monthKey: string;
  /** Cents donated so far THIS month (all kinds) — the shared pool's input. */
  donatedCents: number;
  /** Bonus GB last pushed to the free fleet — the idempotence marker applyFreeBonus
   *  compares against so it only re-pushes when the effective bonus actually moves. */
  appliedBonusGb: number;
}

const ZERO: DonationState = { monthKey: '', donatedCents: 0, appliedBonusGb: 0 };

/** 'YYYY-MM' in UTC for a ms timestamp (the donation-accounting month bucket). */
export function currentMonthKey(now: number): string {
  const d = new Date(now);
  const m = d.getUTCMonth() + 1;
  return `${d.getUTCFullYear()}-${m < 10 ? '0' : ''}${m}`;
}

export async function readDonationState(db: DatabaseReader): Promise<DonationState> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', DONATION_STATE_KEY))
    .unique();
  if (!row) return { ...ZERO };
  try {
    return { ...ZERO, ...(JSON.parse(row.value) as Partial<DonationState>) };
  } catch {
    return { ...ZERO };
  }
}

export async function writeDonationState(ctx: MutationCtx, state: DonationState): Promise<void> {
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', DONATION_STATE_KEY))
    .unique();
  const value = JSON.stringify(state);
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: DONATION_STATE_KEY, value, updatedAt: Date.now() });
}

/**
 * Effective shared bonus GB for `now`'s month: the accumulated donations converted
 * at the configured rate and clamped to the cap — but 0 once the stored month has
 * rolled over (so a new month starts back at base until fresh donations land).
 */
export function effectiveBonusGb(
  state: DonationState,
  cfg: Pick<DonationConfig, 'bonusGbPerUsd' | 'monthlyBonusCapGb'>,
  now: number,
): number {
  if (state.monthKey !== currentMonthKey(now)) return 0;
  const raw = (state.donatedCents / 100) * cfg.bonusGbPerUsd;
  return Math.max(0, Math.min(cfg.monthlyBonusCapGb, raw));
}

/**
 * Add a settled donation to this month's pool (resetting the total + the applied
 * marker when the calendar month has rolled). Caller schedules applyFreeBonus after.
 */
export async function recordDonation(
  ctx: MutationCtx,
  donationCents: number,
  now: number,
): Promise<void> {
  if (!Number.isFinite(donationCents) || donationCents <= 0) return;
  const state = await readDonationState(ctx.db);
  const mk = currentMonthKey(now);
  const next: DonationState =
    state.monthKey === mk
      ? { ...state, donatedCents: state.donatedCents + donationCents }
      : { monthKey: mk, donatedCents: donationCents, appliedBonusGb: 0 };
  await writeDonationState(ctx, next);
}

/** Live effective bonus GB (accumulator + config), for issuance + publicConfig.
 *  0 when donations are disabled. */
export async function resolveCurrentBonusGb(db: DatabaseReader, now: number): Promise<number> {
  const [state, cfg] = await Promise.all([readDonationState(db), resolveBillingConfig(db)]);
  if (!cfg.donation.enabled) return 0;
  return effectiveBonusGb(state, cfg.donation, now);
}
