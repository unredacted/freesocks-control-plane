import { describe, expect, test } from 'vitest';
import {
  currentMonthKey,
  currentDayKey,
  currentMonthDailyGb,
  effectiveBonusGb,
  upsertHistoryEntry,
  type DonationHistoryEntry,
  type DonationState,
} from './lib/donationBonus';
import { gbToBytes, resolveTrafficLimitBytes } from './lib/backends/types';
import { sanitizeAmountsList, BILLING_DEFAULTS, billingConfigWrites } from './lib/billingConfig';

const JULY = Date.UTC(2026, 6, 12); // month index 6 = July
const AUGUST = Date.UTC(2026, 7, 3);

describe('currentMonthKey', () => {
  test('formats YYYY-MM in UTC, zero-padded', () => {
    expect(currentMonthKey(JULY)).toBe('2026-07');
    expect(currentMonthKey(Date.UTC(2026, 11, 31))).toBe('2026-12');
    expect(currentMonthKey(Date.UTC(2027, 0, 1))).toBe('2027-01');
  });
});

/** A state whose whole pool is one bucket landing on `day` and expiring at `x`. */
const poolState = (
  day: string,
  cents: number,
  x: number,
  over: Partial<DonationState> = {},
): DonationState => ({
  monthKey: day.slice(0, 7),
  donatedCents: cents,
  appliedBonusGb: 0,
  buckets: [{ d: day, c: cents, x }],
  ...over,
});

describe('effectiveBonusGb', () => {
  const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
  const thirtyDays = 30 * 86_400_000;

  test('converts live donations at the rate', () => {
    expect(effectiveBonusGb(poolState('2026-07-12', 5000, JULY + thirtyDays), cfg, JULY)).toBe(50);
    expect(
      effectiveBonusGb(
        poolState('2026-07-12', 250, JULY + thirtyDays),
        { ...cfg, bonusGbPerUsd: 2 },
        JULY,
      ),
    ).toBe(5); // $2.50 × 2
  });

  test('clamps to the monthly cap', () => {
    expect(effectiveBonusGb(poolState('2026-07-12', 1_000_00, JULY + thirtyDays), cfg, JULY)).toBe(
      100, // $1000 → capped
    );
  });

  test('survives the calendar-month roll while the window is open', () => {
    // A gift on Jul 12 with a 30-day window still funds the pool on Aug 3.
    expect(effectiveBonusGb(poolState('2026-07-12', 5000, JULY + thirtyDays), cfg, AUGUST)).toBe(
      50,
    );
  });

  test('is 0 once the funding window has closed', () => {
    const shortWindow = JULY + 86_400_000; // expires Jul 13
    expect(effectiveBonusGb(poolState('2026-07-12', 5000, shortWindow), cfg, AUGUST)).toBe(0);
  });

  test('sums the live buckets and ignores the expired ones', () => {
    const state: DonationState = {
      monthKey: '2026-07',
      donatedCents: 9000,
      appliedBonusGb: 0,
      buckets: [
        { d: '2026-06-20', c: 4000, x: JULY - 1 }, // expired
        { d: '2026-07-02', c: 2000, x: JULY + thirtyDays },
        { d: '2026-07-11', c: 3000, x: JULY + thirtyDays },
      ],
    };
    expect(effectiveBonusGb(state, cfg, JULY)).toBe(50); // $20 + $30
  });

  test('never negative', () => {
    expect(effectiveBonusGb(poolState('2026-07-12', 0, JULY + thirtyDays), cfg, JULY)).toBe(0);
  });
});

describe('currentDayKey', () => {
  test('formats YYYY-MM-DD in UTC; prefix matches the month key', () => {
    expect(currentDayKey(JULY)).toBe('2026-07-12');
    expect(currentDayKey(JULY).slice(0, 7)).toBe(currentMonthKey(JULY));
  });
});

describe('currentMonthDailyGb', () => {
  const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
  const thirtyDays = 30 * 86_400_000;
  const state = (buckets: DonationState['buckets'], over: Partial<DonationState> = {}) =>
    ({
      monthKey: '2026-07',
      donatedCents: (buckets ?? []).reduce((s, b) => s + b.c, 0),
      appliedBonusGb: 0,
      buckets,
      ...over,
    }) satisfies DonationState;

  test('spans the WHOLE month and steps up cumulatively', () => {
    const series = currentMonthDailyGb(
      state([
        { d: '2026-07-03', c: 1000, x: JULY + thirtyDays },
        { d: '2026-07-09', c: 2000, x: JULY + thirtyDays },
      ]),
      cfg,
      JULY, // July 12, in a 31-day month
    );
    expect(series).toHaveLength(31);
    expect(series.slice(0, 2)).toEqual([0, 0]); // Jul 1-2
    expect(series[2]).toBe(10); // Jul 3: $10
    expect(series[7]).toBe(10); // Jul 8: carried
    expect(series[8]).toBe(30); // Jul 9: $10 + $20 cumulative
    expect(series[11]).toBe(30); // today
    // Days after today hold today's total, so the axis is a stable month.
    expect(series.slice(12)).toEqual(Array.from({ length: 19 }, () => 30));
    // Never steps down.
    for (let i = 1; i < series.length; i++)
      expect(series[i]!).toBeGreaterThanOrEqual(series[i - 1]!);
  });

  test('counts a month with 30 days as 30 points', () => {
    const JUNE = Date.UTC(2026, 5, 10);
    expect(currentMonthDailyGb(state([], { monthKey: '2026-06' }), cfg, JUNE)).toHaveLength(30);
  });

  test('clamps each day at the monthly cap', () => {
    const series = currentMonthDailyGb(
      state([{ d: '2026-07-05', c: 50_000, x: JULY + thirtyDays }]),
      cfg,
      JULY,
    );
    expect(series[4]).toBe(100); // $500 → capped at 100 GB
    expect(series[30]).toBe(100);
  });

  test('keeps the month staircase after the money has expired', () => {
    // The graph reports what the month RAISED; the live bonus is reported
    // separately, so an expired bucket must not erase the step.
    const series = currentMonthDailyGb(
      state([{ d: '2026-07-03', c: 1000, x: JULY - 1 }]),
      cfg,
      JULY,
    );
    expect(series[2]).toBe(10);
    expect(series[30]).toBe(10);
  });

  test('an empty pool yields a flat zero series over the full month', () => {
    expect(currentMonthDailyGb(state([]), cfg, JULY)).toEqual(Array.from({ length: 31 }, () => 0));
  });

  test('ignores buckets from other months', () => {
    const series = currentMonthDailyGb(
      state([{ d: '2026-06-20', c: 5000, x: JULY + thirtyDays }], { monthKey: '2026-06' }),
      cfg,
      JULY,
    );
    expect(series).toEqual(Array.from({ length: 31 }, () => 0));
  });
});

describe('resolveTrafficLimitBytes', () => {
  test('adds the bonus for the default-free tier', () => {
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 50, isDefaultFree: true }, 10)).toBe(
      gbToBytes(60),
    );
  });
  test('no bonus for a capped non-free tier', () => {
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 50, isDefaultFree: false }, 10)).toBe(
      gbToBytes(50),
    );
  });
  test('unlimited (null) when the tier has no monthly cap — bonus ignored', () => {
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 0, isDefaultFree: false }, 10)).toBeNull();
  });
  test('bonus 0 = the plain tier limit', () => {
    expect(resolveTrafficLimitBytes({ monthlyTrafficGb: 50, isDefaultFree: true }, 0)).toBe(
      gbToBytes(50),
    );
  });
});

describe('upsertHistoryEntry', () => {
  const entry = (
    monthKey: string,
    over: Partial<DonationHistoryEntry> = {},
  ): DonationHistoryEntry => ({
    monthKey,
    donatedCents: 1000,
    bonusGb: 10,
    ...over,
  });

  test('appends a new month, sorted ascending', () => {
    const out = upsertHistoryEntry([entry('2026-07')], entry('2026-06'));
    expect(out.map((e) => e.monthKey)).toEqual(['2026-06', '2026-07']);
  });

  test('replaces the same-month entry with the cumulative totals (no duplicate)', () => {
    const out = upsertHistoryEntry(
      [entry('2026-07', { donatedCents: 500, bonusGb: 5 })],
      entry('2026-07', { donatedCents: 1500, bonusGb: 15 }),
    );
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ donatedCents: 1500, bonusGb: 15 });
  });

  test('a month roll preserves the prior month as its own entry', () => {
    const july = upsertHistoryEntry([], entry('2026-07', { donatedCents: 5000, bonusGb: 50 }));
    const august = upsertHistoryEntry(july, entry('2026-08', { donatedCents: 200, bonusGb: 2 }));
    expect(august.map((e) => e.monthKey)).toEqual(['2026-07', '2026-08']);
    expect(august[0]).toMatchObject({ donatedCents: 5000, bonusGb: 50 });
  });

  test('caps at 24 months, dropping the oldest', () => {
    let entries: DonationHistoryEntry[] = [];
    for (let i = 0; i < 30; i++) {
      const mk = currentMonthKey(Date.UTC(2024, i, 1));
      entries = upsertHistoryEntry(entries, entry(mk));
    }
    expect(entries).toHaveLength(24);
    expect(entries[0].monthKey).toBe('2024-07'); // 2024-01..06 dropped
    expect(entries[23].monthKey).toBe('2026-06');
  });

  test('preserves an existing freeUsers stamp when the update carries none', () => {
    const stamped = upsertHistoryEntry([], entry('2026-07', { freeUsers: 1234 }));
    const afterDonation = upsertHistoryEntry(stamped, entry('2026-07', { donatedCents: 9999 }));
    expect(afterDonation[0].freeUsers).toBe(1234);
    const restamped = upsertHistoryEntry(afterDonation, entry('2026-07', { freeUsers: 2000 }));
    expect(restamped[0].freeUsers).toBe(2000);
  });
});

describe('sanitizeAmountsList', () => {
  test('keeps positive integer cents, dedupes, sorts ascending', () => {
    expect(sanitizeAmountsList([1000, 300, 300, 500])).toEqual([300, 500, 1000]);
  });
  test('drops non-positive / non-integer, caps length at 8', () => {
    expect(sanitizeAmountsList([0, -5, 2.5, 200])).toEqual([200]);
    expect(sanitizeAmountsList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).length).toBe(8);
  });
  test('empty / non-array falls back to the compiled defaults', () => {
    expect(sanitizeAmountsList([])).toEqual(BILLING_DEFAULTS.donation.suggestedAmountsCents);
    expect(sanitizeAmountsList('nope')).toEqual(BILLING_DEFAULTS.donation.suggestedAmountsCents);
  });
});

describe('donation.bonusWindowDays (admin tunable)', () => {
  test('defaults to 30 days', () => {
    expect(BILLING_DEFAULTS.donation.bonusWindowDays).toBe(30);
  });

  test('an admin edit round-trips through the write/resolve pair', () => {
    const writes = billingConfigWrites({ donation: { bonusWindowDays: 45 } });
    const row = writes.find((w) => w.key === 'billing.donation.bonusWindowDays');
    expect(row).toBeTruthy();
    expect(JSON.parse(row!.value)).toBe(45);
  });

  test('rejects junk and out-of-range values, falling back to the default', () => {
    const write = (v: unknown) =>
      JSON.parse(
        billingConfigWrites({ donation: { bonusWindowDays: v } }).find(
          (w) => w.key === 'billing.donation.bonusWindowDays',
        )!.value,
      );
    expect(write(0)).toBe(30); // a zero-day window would kill every bonus instantly
    expect(write(-5)).toBe(30);
    expect(write(400)).toBe(30); // past the 365-day ceiling
    expect(write(1.5)).toBe(30); // whole days only
    expect(write('30')).toBe(30);
    expect(write(1)).toBe(1); // the tightest legal window is honored
    expect(write(365)).toBe(365);
  });
});
