import { describe, expect, test } from 'vitest';
import { dailyImpactSeries, dailyImpactBounds, daysInMonth, giftMarks, niceCeil } from './impact';

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

describe('giftMarks', () => {
  const gifts = (days: string[]) =>
    days.map((day) => ({ day, gb: 5, expiresAt: Date.UTC(2026, 8, 1) }));

  test('marks current-month gifts at their day-slot centers, merging same days', () => {
    const marks = giftMarks(
      [
        { day: '2026-06-30', gb: 3, expiresAt: Date.UTC(2026, 7, 1) }, // last month → no mark
        { day: '2026-07-10', gb: 2, expiresAt: Date.UTC(2026, 7, 10) },
        { day: '2026-07-10', gb: 4, expiresAt: Date.UTC(2026, 8, 10) }, // same day, merged
        { day: '2026-07-20', gb: 1, expiresAt: Date.UTC(2026, 8, 20) },
      ],
      JULY_12,
    );
    expect(marks).toHaveLength(2);
    expect(marks[0]).toMatchObject({ frac: 9.5 / 31, gb: 6 });
    expect(marks[0]!.date.toISOString().slice(0, 10)).toBe('2026-07-10');
    expect(marks[1]).toMatchObject({ frac: 19.5 / 31, gb: 1 });
  });

  test('caps to the newest N so labels cannot crowd the axis', () => {
    const days = Array.from({ length: 10 }, (_, i) => `2026-07-${String(i + 1).padStart(2, '0')}`);
    const marks = giftMarks(gifts(days), JULY_12, 6);
    expect(marks).toHaveLength(6);
    expect(marks[0]!.date.getUTCDate()).toBe(5);
    expect(marks[5]!.date.getUTCDate()).toBe(10);
  });

  test('empty in a month with no gifts', () => {
    expect(giftMarks(gifts(['2026-05-01']), JULY_12)).toEqual([]);
    expect(giftMarks([], JULY_12)).toEqual([]);
  });
});
