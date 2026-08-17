/**
 * Donation → free-user bandwidth accumulator. Each settled donation funds a
 * SHARED pool for `donation.bonusWindowDays` (default 30) from the moment it
 * settles; every free user's cap is raised by
 * `min(monthlyBonusCapGb, liveDonatedUSD × bonusGbPerUsd)` while it lasts. State
 * is a single `appState` row (key `donation:freeBonus`), read-modify-write inside
 * the caller's transaction — mirrors lib/statusCounters.ts. Pure helpers so the
 * checkout grant, the fleet apply action, issuance, and publicConfig share one
 * source of truth.
 *
 * The pool used to be a calendar-month bucket that reset at 00:00 UTC on the 1st,
 * which paid a gift on the 29th barely two days of bonus. It is now a list of
 * per-day buckets, each carrying its own expiry — so the window is continuous and
 * the hourly reconcile cron is what rolls expired money off the fleet.
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

/**
 * One UTC day's donations and the instant they stop funding the pool. Buckets are
 * per-day (not per-donation) so the list stays small however many gifts land.
 */
export interface DonationBucket {
  /** UTC day the donations landed, 'YYYY-MM-DD'. */
  d: string;
  /** Cents donated that day. */
  c: number;
  /** Epoch ms after which this bucket no longer funds the pool. */
  x: number;
}

export interface DonationState {
  /** Calendar month (UTC) the `donatedCents` total belongs to, 'YYYY-MM'. */
  monthKey: string;
  /** Cents donated so far THIS month (all kinds) — feeds the per-month ledger. */
  donatedCents: number;
  /** Bonus GB last pushed to the free fleet — the idempotence marker applyFreeBonus
   *  compares against so it only re-pushes when the effective bonus actually moves. */
  appliedBonusGb: number;
  /**
   * The live pool: one entry per UTC day with its own expiry. Sum of the unexpired
   * entries IS the bonus (see {@link effectiveBonusGb}); the current month's
   * entries also build the member-facing impact graph. Bounded by the prune in
   * {@link pruneBuckets}.
   */
  buckets?: DonationBucket[];
  /**
   * LEGACY (pre-window): per-day cumulative `donatedCents` snapshots for the stored
   * month. Converted to {@link buckets} on read and never written again — kept on
   * the type so the conversion can see it.
   */
  days?: Record<string, number>;
}

const ZERO: DonationState = { monthKey: '', donatedCents: 0, appliedBonusGb: 0 };

const DAY_MS = 86_400_000;

/** 'YYYY-MM' in UTC for a ms timestamp (the donation-accounting month bucket). */
export function currentMonthKey(now: number): string {
  const d = new Date(now);
  const m = d.getUTCMonth() + 1;
  return `${d.getUTCFullYear()}-${m < 10 ? '0' : ''}${m}`;
}

/** 'YYYY-MM-DD' in UTC (its first 7 chars equal {@link currentMonthKey}). */
export function currentDayKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** Midnight UTC opening the month `monthKey` ('YYYY-MM') belongs to, in ms. */
function monthStartMs(monthKey: string): number {
  const [y, m] = monthKey.split('-').map(Number);
  return Number.isFinite(y) && Number.isFinite(m) ? Date.UTC(y!, m! - 1, 1) : 0;
}

/** Midnight UTC opening the month AFTER `monthKey` — the legacy expiry instant. */
function monthEndMs(monthKey: string): number {
  const [y, m] = monthKey.split('-').map(Number);
  return Number.isFinite(y) && Number.isFinite(m) ? Date.UTC(y!, m!, 1) : 0;
}

/**
 * When a gift made on `dayKey` stops funding the pool, under a `windowDays`
 * window. Measured from the END of the gift's UTC day, so the expiry is a
 * function of (day, window) alone rather than of the exact second the payment
 * settled. Two consequences, both wanted: same-day gifts under an unchanged
 * window land in ONE bucket (the list stays day-granular instead of growing per
 * donation), and every donor gets at least their full window — up to a day
 * extra, rounding in their favour rather than against.
 */
function bucketExpiryMs(dayKey: string, windowDays: number): number {
  return Date.parse(`${dayKey}T00:00:00Z`) + DAY_MS + windowDays * DAY_MS;
}

/** Days in the UTC month containing `now`. */
export function daysInMonth(now: number): number {
  const d = new Date(now);
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
}

/**
 * Convert a legacy `days` map (per-day CUMULATIVE cents within the stored month)
 * into buckets of per-day deltas, each expiring when that month ended — the rule
 * those donations were made under. Deliberately NOT `now + bonusWindowDays`: a
 * config change must not retroactively extend money that was already spent.
 * A month with donations but no snapshots (pre-`days` rows) lands as one bucket
 * on the 1st, so its total still shows up.
 */
function bucketsFromLegacyDays(state: DonationState): DonationBucket[] {
  if (!state.monthKey) return [];
  const x = monthEndMs(state.monthKey);
  const snapshots = Object.entries(state.days ?? {})
    .filter(([day]) => day.startsWith(state.monthKey))
    .sort(([a], [b]) => (a < b ? -1 : 1));
  if (snapshots.length === 0) {
    return state.donatedCents > 0 ? [{ d: `${state.monthKey}-01`, c: state.donatedCents, x }] : [];
  }
  const out: DonationBucket[] = [];
  let prev = 0;
  for (const [day, total] of snapshots) {
    const delta = total - prev;
    prev = total;
    if (delta > 0) {
      out.push({ d: day, c: delta, x });
    } else if (delta < 0) {
      // A DECREASE is a refund: the old subtractDonation wrote the reduced
      // running total into `days`. Keeping only the positive deltas would
      // reconstruct the original gift and resurrect a refunded bonus for the
      // whole free fleet on the first read after deploy. Take it back off the
      // most recent money, mirroring how a refund with no recorded bucket
      // unwinds today.
      let owed = -delta;
      for (let i = out.length - 1; i >= 0 && owed > 0; i--) {
        const take = Math.min(out[i]!.c, owed);
        out[i] = { ...out[i]!, c: out[i]!.c - take };
        owed -= take;
      }
    }
  }
  // Invariant: the surviving cents equal the last snapshot's running total.
  return out.filter((b) => b.c > 0);
}

/** Coerce a stored bucket list, dropping anything malformed (fail-safe read). */
function sanitizeBuckets(raw: unknown): DonationBucket[] | null {
  if (!Array.isArray(raw)) return null;
  const out: DonationBucket[] = [];
  for (const e of raw) {
    if (!e || typeof e !== 'object') continue;
    const { d, c, x } = e as Record<string, unknown>;
    if (typeof d === 'string' && typeof c === 'number' && typeof x === 'number' && c > 0) {
      out.push({ d, c, x });
    }
  }
  return out.sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0));
}

export async function readDonationState(db: DatabaseReader): Promise<DonationState> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', DONATION_STATE_KEY))
    .unique();
  if (!row) return { ...ZERO };
  let parsed: Partial<DonationState>;
  try {
    parsed = JSON.parse(row.value) as Partial<DonationState>;
  } catch {
    return { ...ZERO };
  }
  const state: DonationState = { ...ZERO, ...parsed };
  // Read-time migration: a row written before the rolling window carries `days`
  // instead of `buckets`. Converting here (rather than in a migration script)
  // means the first write persists the new shape and no deploy ordering matters.
  const stored = sanitizeBuckets(parsed.buckets);
  state.buckets = stored ?? bucketsFromLegacyDays(state);
  delete state.days;
  return state;
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

/** Cents → bonus GB at the configured rate, clamped to the cap. */
export function bonusGbFromCents(
  cents: number,
  cfg: Pick<DonationConfig, 'bonusGbPerUsd' | 'monthlyBonusCapGb'>,
): number {
  return Math.max(0, Math.min(cfg.monthlyBonusCapGb, (cents / 100) * cfg.bonusGbPerUsd));
}

/** Cents still funding the pool at `now` (buckets whose window hasn't closed). */
export function liveDonatedCents(state: DonationState, now: number): number {
  let sum = 0;
  for (const b of state.buckets ?? []) if (b.x > now) sum += b.c;
  return sum;
}

/**
 * Effective shared bonus GB at `now`: every donation still inside its window,
 * converted at the configured rate and clamped to the cap. Expiries are
 * continuous — nothing special happens at a month boundary.
 */
export function effectiveBonusGb(
  state: DonationState,
  cfg: Pick<DonationConfig, 'bonusGbPerUsd' | 'monthlyBonusCapGb'>,
  now: number,
): number {
  return bonusGbFromCents(liveDonatedCents(state, now), cfg);
}

/**
 * Drop buckets that are BOTH expired and older than the current month — the
 * month's own entries stay so the impact graph keeps its full staircase even
 * after the money behind it has rolled off. Bounded: at most one entry per day
 * of the window plus the current month.
 */
function pruneBuckets(buckets: DonationBucket[], now: number): DonationBucket[] {
  const monthStart = monthStartMs(currentMonthKey(now));
  return buckets.filter((b) => b.x > now || monthStartMs(b.d.slice(0, 7)) >= monthStart);
}

/**
 * Add `cents` to the bucket for (`dayKey`, `expiresAt`), or append one.
 *
 * Buckets merge on the day AND the expiry, never the day alone: an admin who
 * retunes `bonusWindowDays` between two gifts on the same UTC day would
 * otherwise have one of them silently re-dated — dropping 365→1 would leave the
 * later gift funding the pool for a year, and raising it would extend the
 * earlier one retroactively, which is exactly the promise the read-time legacy
 * conversion exists to keep. Same-day gifts under an UNCHANGED window still
 * collapse into one entry, so the list stays short in the normal case.
 */
function addToBucket(
  buckets: DonationBucket[],
  dayKey: string,
  cents: number,
  expiresAt: number,
): DonationBucket[] {
  const next = [...buckets];
  const i = next.findIndex((b) => b.d === dayKey && b.x === expiresAt);
  if (i >= 0) {
    next[i] = { ...next[i]!, c: next[i]!.c + cents };
  } else {
    next.push({ d: dayKey, c: cents, x: expiresAt });
    next.sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : a.x - b.x));
  }
  return next;
}

/**
 * Add a settled donation to the pool, stamped to expire `bonusWindowDays` after
 * its day (see {@link bucketExpiryMs}). Caller schedules applyFreeBonus after.
 * Also upserts the month's ledger
 * entry — that ledger stays calendar-month-keyed (it is the historical record of
 * what each month raised), independently of how long a donation funds the pool.
 */
export async function recordDonation(
  ctx: MutationCtx,
  donationCents: number,
  now: number,
): Promise<number | null> {
  if (!Number.isFinite(donationCents) || donationCents <= 0) return null;
  const state = await readDonationState(ctx.db);
  const cfg = await resolveBillingConfig(ctx.db);
  const mk = currentMonthKey(now);
  const day = currentDayKey(now);
  const expiresAt = bucketExpiryMs(day, cfg.donation.bonusWindowDays);
  const next: DonationState = {
    ...state,
    // `donatedCents` is the MONTH's running total for the ledger, so it still
    // resets on a month roll; the pool itself lives in `buckets`.
    monthKey: mk,
    donatedCents: state.monthKey === mk ? state.donatedCents + donationCents : donationCents,
    buckets: pruneBuckets(addToBucket(state.buckets ?? [], day, donationCents, expiresAt), now),
  };
  await writeDonationState(ctx, next);
  await upsertHistoryForMonth(ctx, {
    monthKey: mk,
    donatedCents: next.donatedCents,
    // What THIS month raised, not the live pool — the pool can carry money from
    // the previous month now that windows straddle month boundaries.
    bonusGb: bonusGbFromCents(next.donatedCents, cfg.donation),
  });
  // The bucket this landed in, so the caller can record which funding a refund
  // would have to take back (a day can hold several buckets).
  return expiresAt;
}

/**
 * Reverse a donation (refund/chargeback unwind): take the refunded cents out of
 * the bucket that ACTUALLY funded them, identified by the order's settle time
 * (`fundedAt` = the order's `paidAt`).
 *
 * Attribution is the whole point. Draining the newest bucket instead would cancel
 * later, legitimate funding while leaving the refunded contribution live — and
 * since the surviving older bucket expires sooner, the shared bonus would then
 * fall off early. For the same reason there is NO spill to other buckets when the
 * funding bucket is gone (expired and pruned): money that already stopped funding
 * the pool has nothing left to reclaim, and reaching into a live bucket to
 * "balance the books" would take bandwidth from free users over a refund that
 * costs the pool nothing.
 *
 * Without `fundedAt` (a legacy order with no timestamp) it degrades to
 * newest-first, the best guess available.
 */
export async function subtractDonation(
  ctx: MutationCtx,
  donationCents: number,
  now: number,
  fundedAt?: number,
  fundedBucketExpiresAt?: number,
): Promise<void> {
  if (!Number.isFinite(donationCents) || donationCents <= 0) return;
  const state = await readDonationState(ctx.db);
  let remaining = donationCents;
  const buckets = [...(state.buckets ?? [])];
  const drain = (i: number) => {
    const b = buckets[i]!;
    if (b.x <= now) return; // already expired: not part of the live pool
    const take = Math.min(b.c, remaining);
    buckets[i] = { ...b, c: b.c - take };
    remaining -= take;
  };
  const known = fundedAt !== undefined && Number.isFinite(fundedAt);
  if (known) {
    const fundedDay = currentDayKey(fundedAt!);
    const exact =
      fundedBucketExpiresAt !== undefined && Number.isFinite(fundedBucketExpiresAt)
        ? buckets.findIndex((b) => b.d === fundedDay && b.x === fundedBucketExpiresAt)
        : -1;
    if (exact >= 0) {
      // The precise bucket this order funded. Necessary once a day can hold
      // several: refunding a 365-day gift must not drain the 1-day gift that
      // happened to land the same day and leave the refunded money live.
      drain(exact);
    } else {
      // No recorded bucket (an order granted before the field existed) or it has
      // since been pruned: fall back to the day, soonest-expiring first.
      for (let i = 0; i < buckets.length && remaining > 0; i++) {
        if (buckets[i]!.d === fundedDay) drain(i);
      }
    }
  } else {
    for (let i = buckets.length - 1; i >= 0 && remaining > 0; i--) drain(i);
  }

  const mk = currentMonthKey(now);
  // Decrement the month's running total only when the REFUNDED money was raised
  // in the month that total belongs to. Subtracting a previous month's refund
  // from this month would under-report what this month actually raised.
  const fundedThisMonth = !known || currentMonthKey(fundedAt!) === mk;
  const touchesLedger = state.monthKey === mk && fundedThisMonth;

  // Second pass, HISTORICAL only. A short window can expire a gift before its
  // month ends, and pruneBuckets deliberately keeps that bucket so the month's
  // impact chart keeps its staircase. `drain` skips expired buckets — right for
  // the live pool — but then a refund would zero the ledger while
  // currentMonthDailyGb went on charting the refunded money. Deduct it here
  // too: an expired bucket contributes nothing to `liveDonatedCents`, so this
  // cannot move the live bonus.
  if (touchesLedger && remaining > 0) {
    const fundedDay = known ? currentDayKey(fundedAt!) : null;
    for (let i = 0; i < buckets.length && remaining > 0; i++) {
      const b = buckets[i]!;
      if (b.x > now) continue; // still live — the pass above owns it
      if (!b.d.startsWith(mk)) continue; // a finished month's record is frozen
      if (fundedDay !== null && b.d !== fundedDay) continue;
      const take = Math.min(b.c, remaining);
      buckets[i] = { ...b, c: b.c - take };
      remaining -= take;
    }
  }

  const next: DonationState = {
    ...state,
    buckets: pruneBuckets(
      buckets.filter((b) => b.c > 0),
      now,
    ),
    ...(touchesLedger ? { donatedCents: Math.max(0, state.donatedCents - donationCents) } : {}),
  };
  await writeDonationState(ctx, next);
  // Only rewrite the ledger when the running total belongs to the current month —
  // a finished month's recorded impact is frozen and must not be restated.
  if (!touchesLedger) return;
  const cfg = await resolveBillingConfig(ctx.db);
  await upsertHistoryForMonth(ctx, {
    monthKey: mk,
    donatedCents: next.donatedCents,
    bonusGb: bonusGbFromCents(next.donatedCents, cfg.donation),
  });
}

/** Live effective bonus GB (accumulator + config), for issuance + publicConfig.
 *  0 when donations are disabled. */
export async function resolveCurrentBonusGb(db: DatabaseReader, now: number): Promise<number> {
  const [state, cfg] = await Promise.all([readDonationState(db), resolveBillingConfig(db)]);
  if (!cfg.donation.enabled) return 0;
  return effectiveBonusGb(state, cfg.donation, now);
}

/**
 * The impact graph's series: one GB value per UTC day for the WHOLE current month
 * (1st → last day), cumulative — each day adds that day's donations to the running
 * total, so the line only ever steps up. Days after today hold today's total flat,
 * so the x-axis is a stable month rather than one that rescales daily.
 *
 * This is what the month RAISED, which is why it doesn't drop when a donation's
 * window closes — the live figure beside the chart is `currentBonusGb`. GB only,
 * never cents (the public no-dollar-figures rule).
 */
export function currentMonthDailyGb(
  state: DonationState,
  cfg: Pick<DonationConfig, 'bonusGbPerUsd' | 'monthlyBonusCapGb'>,
  now: number,
): number[] {
  const mk = currentMonthKey(now);
  const toGb = (cents: number) =>
    Math.max(0, Math.min(cfg.monthlyBonusCapGb, (cents / 100) * cfg.bonusGbPerUsd));
  const perDay = new Map<string, number>();
  for (const b of state.buckets ?? []) {
    if (b.d.startsWith(mk)) perDay.set(b.d, (perDay.get(b.d) ?? 0) + b.c);
  }
  const today = new Date(now).getUTCDate();
  const series: number[] = [];
  let cumulative = 0;
  for (let day = 1; day <= daysInMonth(now); day++) {
    if (day <= today) {
      cumulative += perDay.get(`${mk}-${day < 10 ? '0' : ''}${day}`) ?? 0;
    }
    series.push(toGb(cumulative));
  }
  return series;
}
