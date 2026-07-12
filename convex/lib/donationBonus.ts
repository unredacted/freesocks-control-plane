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
export const DONATION_HISTORY_KEY = 'donation:history';

/** Bounded per-month impact ledger (last {@link HISTORY_CAP} months) backing the
 *  impact displays — the live accumulator alone forgets a month once it rolls. */
export interface DonationHistoryEntry {
  /** Calendar month (UTC), 'YYYY-MM'. */
  monthKey: string;
  /** Cumulative cents donated that month (internal only — never projected publicly). */
  donatedCents: number;
  /** Bonus GB the month's pool reached, frozen at write time (rate changes don't
   *  rewrite past months). */
  bonusGb: number;
  /** Active free users at the last reconcile that month, when stamped. */
  freeUsers?: number;
}

const HISTORY_CAP = 24;

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

export async function readDonationHistory(db: DatabaseReader): Promise<DonationHistoryEntry[]> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', DONATION_HISTORY_KEY))
    .unique();
  if (!row) return [];
  try {
    const parsed = JSON.parse(row.value) as unknown;
    return Array.isArray(parsed) ? (parsed as DonationHistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export async function writeDonationHistory(
  ctx: MutationCtx,
  entries: DonationHistoryEntry[],
): Promise<void> {
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', DONATION_HISTORY_KEY))
    .unique();
  const value = JSON.stringify(entries);
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: DONATION_HISTORY_KEY, value, updatedAt: Date.now() });
}

/**
 * Pure upsert for a month's ledger entry: replace-or-append by `monthKey`, sorted
 * ascending, capped to the newest {@link HISTORY_CAP} — bounded by construction, so
 * the ledger needs no retention sweep. Values are cumulative month totals (not
 * deltas); `freeUsers` is preserved from the existing entry unless the update
 * carries its own (the reconcile stamps it; the donation path doesn't).
 */
export function upsertHistoryEntry(
  entries: DonationHistoryEntry[],
  entry: DonationHistoryEntry,
): DonationHistoryEntry[] {
  const existing = entries.find((e) => e.monthKey === entry.monthKey);
  const merged: DonationHistoryEntry = {
    ...entry,
    ...(entry.freeUsers === undefined && existing?.freeUsers !== undefined
      ? { freeUsers: existing.freeUsers }
      : {}),
  };
  const next = entries.filter((e) => e.monthKey !== entry.monthKey);
  next.push(merged);
  next.sort((a, b) => (a.monthKey < b.monthKey ? -1 : a.monthKey > b.monthKey ? 1 : 0));
  return next.slice(-HISTORY_CAP);
}

/** Read-modify-write one month's ledger entry inside the caller's transaction. */
export async function upsertHistoryForMonth(
  ctx: MutationCtx,
  entry: DonationHistoryEntry,
): Promise<void> {
  const entries = await readDonationHistory(ctx.db);
  await writeDonationHistory(ctx, upsertHistoryEntry(entries, entry));
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
 * Also upserts the month's ledger entry — keyed per month, so a roll preserves the
 * prior month's totals in the ledger even as the live accumulator resets.
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
  const cfg = await resolveBillingConfig(ctx.db);
  await upsertHistoryForMonth(ctx, {
    monthKey: mk,
    donatedCents: next.donatedCents,
    bonusGb: effectiveBonusGb(next, cfg.donation, now),
  });
}

/** Live effective bonus GB (accumulator + config), for issuance + publicConfig.
 *  0 when donations are disabled. */
export async function resolveCurrentBonusGb(db: DatabaseReader, now: number): Promise<number> {
  const [state, cfg] = await Promise.all([readDonationState(db), resolveBillingConfig(db)]);
  if (!cfg.donation.enabled) return 0;
  return effectiveBonusGb(state, cfg.donation, now);
}
