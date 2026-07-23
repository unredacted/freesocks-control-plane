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
import { sanitizeAmountsList, BILLING_DEFAULTS } from './lib/billingConfig';

const JULY = Date.UTC(2026, 6, 12); // month index 6 = July
const AUGUST = Date.UTC(2026, 7, 3);

describe('currentMonthKey', () => {
  test('formats YYYY-MM in UTC, zero-padded', () => {
    expect(currentMonthKey(JULY)).toBe('2026-07');
    expect(currentMonthKey(Date.UTC(2026, 11, 31))).toBe('2026-12');
    expect(currentMonthKey(Date.UTC(2027, 0, 1))).toBe('2027-01');
  });
});

describe('effectiveBonusGb', () => {
  const cfg = { bonusGbPerUsd: 1, monthlyBonusCapGb: 100 };
  const state = (over: Partial<DonationState> = {}): DonationState => ({
    monthKey: '2026-07',
    donatedCents: 0,
    appliedBonusGb: 0,
    ...over,
  });

  test('converts this-month donations at the rate', () => {
    expect(effectiveBonusGb(state({ donatedCents: 5000 }), cfg, JULY)).toBe(50); // $50 × 1
    expect(effectiveBonusGb(state({ donatedCents: 250 }), { ...cfg, bonusGbPerUsd: 2 }, JULY)).toBe(
      5, // $2.50 × 2
    );
  });

  test('clamps to the monthly cap', () => {
    expect(effectiveBonusGb(state({ donatedCents: 1_000_00 }), cfg, JULY)).toBe(100); // $1000 → capped
  });

  test('is 0 once the calendar month has rolled', () => {
    expect(effectiveBonusGb(state({ donatedCents: 5000 }), cfg, AUGUST)).toBe(0);
  });

  test('never negative', () => {
    expect(effectiveBonusGb(state({ donatedCents: 0 }), cfg, JULY)).toBe(0);
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
  const state = (over: Partial<DonationState> = {}): DonationState => ({
    monthKey: '2026-07',
    donatedCents: 0,
    appliedBonusGb: 0,
    ...over,
  });

  test('carries snapshots forward: 0 before the first donation, staircase after', () => {
    const series = currentMonthDailyGb(
      state({
        donatedCents: 3000,
        days: { '2026-07-03': 1000, '2026-07-09': 3000 },
      }),
      cfg,
      JULY, // July 12 → 12 points
    );
    expect(series).toHaveLength(12);
    expect(series.slice(0, 2)).toEqual([0, 0]); // Jul 1-2
    expect(series[2]).toBe(10); // Jul 3: $10
    expect(series[7]).toBe(10); // Jul 8: carried
    expect(series[8]).toBe(30); // Jul 9: $30 cumulative
    expect(series[11]).toBe(30); // today: matches the live bonus
  });

  test('clamps each day at the monthly cap', () => {
    const series = currentMonthDailyGb(
      state({ donatedCents: 50_000, days: { '2026-07-05': 50_000 } }),
      cfg,
      JULY,
    );
    expect(series[4]).toBe(100); // $500 → capped at 100 GB
    expect(series[11]).toBe(100);
  });

  test('rolled or unset accumulator yields a flat zero series through today', () => {
    expect(
      currentMonthDailyGb(state({ monthKey: '2026-06', donatedCents: 999 }), cfg, JULY),
    ).toEqual(Array.from({ length: 12 }, () => 0));
  });

  test('pre-feature month totals (no day snapshots) pin the live bonus on today', () => {
    const series = currentMonthDailyGb(state({ donatedCents: 2500 }), cfg, JULY);
    expect(series.slice(0, 11)).toEqual(Array.from({ length: 11 }, () => 0));
    expect(series[11]).toBe(25);
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
