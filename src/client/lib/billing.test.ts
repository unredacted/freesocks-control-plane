import { describe, expect, test } from 'vitest';
import { perMonthCents, baselinePerMonth, savingsPct } from './billing';

// $5.00/mo baseline; 3mo at $4.50/mo (10% off); 12mo at ~$4.17/mo (17% off).
const durations = [
  { months: 1, amountCents: 500 },
  { months: 3, amountCents: 1350 },
  { months: 12, amountCents: 5000 },
];

describe('billing pricing helpers', () => {
  test('perMonthCents divides total by months', () => {
    expect(perMonthCents({ months: 1, amountCents: 500 })).toBe(500);
    expect(perMonthCents({ months: 12, amountCents: 5000 })).toBeCloseTo(416.67, 1);
  });

  test('perMonthCents falls back to raw amount for non-recurring terms', () => {
    expect(perMonthCents({ months: 0, amountCents: 999 })).toBe(999);
  });

  test('baselinePerMonth is the shortest term per-month rate', () => {
    expect(baselinePerMonth(durations)).toBe(500);
  });

  test('baselinePerMonth is null with no recurring terms', () => {
    expect(baselinePerMonth([])).toBeNull();
    expect(baselinePerMonth([{ months: 0, amountCents: 999 }])).toBeNull();
  });

  test('savingsPct is the whole-percent saved vs baseline', () => {
    expect(savingsPct({ months: 1, amountCents: 500 }, durations)).toBe(0);
    expect(savingsPct({ months: 3, amountCents: 1350 }, durations)).toBe(10);
    expect(savingsPct({ months: 12, amountCents: 5000 }, durations)).toBe(17);
  });

  test('savingsPct is 0 when there is no baseline', () => {
    expect(savingsPct({ months: 12, amountCents: 5000 }, [])).toBe(0);
  });
});
