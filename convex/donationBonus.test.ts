import { describe, expect, test } from 'vitest';
import { currentMonthKey, effectiveBonusGb, type DonationState } from './lib/donationBonus';
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
