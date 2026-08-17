import { describe, expect, test } from 'vitest';
import { dailyImpactSeries, dailyImpactBounds, daysInMonth, niceCeil } from './impact';

const JULY_12 = Date.UTC(2026, 6, 12); // 31-day month
const JUNE_10 = Date.UTC(2026, 5, 10); // 30-day month
const FEB_5_LEAP = Date.UTC(2028, 1, 5); // 29-day month

describe('daysInMonth', () => {
  test('handles 31, 30 and leap-February months', () => {
    expect(daysInMonth(JULY_12)).toBe(31);
    expect(daysInMonth(JUNE_10)).toBe(30);
    expect(daysInMonth(FEB_5_LEAP)).toBe(29);
  });
});

describe('dailyImpactSeries', () => {
  test('a full-month series passes through unchanged', () => {
    const daily = Array.from({ length: 31 }, (_, i) => i);
    expect(dailyImpactSeries(daily, JULY_12)).toEqual(daily);
  });

  test('an empty series becomes a flat zero baseline over the whole month', () => {
    expect(dailyImpactSeries([], JULY_12)).toEqual(Array.from({ length: 31 }, () => 0));
  });

  test('a short series (older backend, 1..today) is padded by holding its last value', () => {
    const series = dailyImpactSeries([0, 0, 10, 10, 30], JULY_12);
    expect(series).toHaveLength(31);
    expect(series.slice(0, 5)).toEqual([0, 0, 10, 10, 30]);
    expect(series.slice(5)).toEqual(Array.from({ length: 26 }, () => 30));
  });

  test('a longer series is trimmed to the month', () => {
    expect(
      dailyImpactSeries(
        Array.from({ length: 40 }, () => 1),
        JULY_12,
      ),
    ).toHaveLength(31);
  });
});

describe('dailyImpactBounds', () => {
  test('spans the 1st to the LAST day of the month, not to today', () => {
    const [start, end] = dailyImpactBounds(JULY_12);
    expect(start.toISOString().slice(0, 10)).toBe('2026-07-01');
    expect(end.toISOString().slice(0, 10)).toBe('2026-07-31');
  });

  test('tracks a 30-day month', () => {
    expect(dailyImpactBounds(JUNE_10)[1].toISOString().slice(0, 10)).toBe('2026-06-30');
  });
});

describe('niceCeil', () => {
  test('lands strictly above the value, so the series never touches the top edge', () => {
    for (const v of [0.4, 1, 3, 10, 15, 42, 99, 250]) {
      expect(niceCeil(v)).toBeGreaterThan(v);
    }
  });

  test('picks round steps', () => {
    expect(niceCeil(10)).toBe(15);
    expect(niceCeil(15)).toBe(20);
    expect(niceCeil(12)).toBe(15);
    expect(niceCeil(0.4)).toBe(0.5);
  });

  test('degenerate inputs fall back to 1', () => {
    expect(niceCeil(0)).toBe(1);
    expect(niceCeil(-5)).toBe(1);
    expect(niceCeil(Number.NaN)).toBe(1);
  });
});
