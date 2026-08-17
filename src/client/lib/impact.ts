/**
 * Donation-impact chart series helpers. The public config ships a per-month
 * `{month, bonusGb}` history and a per-day cumulative series for the current
 * month, both EMPTY until the first settled donation; the impact charts still
 * render then - as a flat zero baseline over the full month - so the graph is
 * always present rather than a blank slot.
 */
export interface ImpactPoint {
  month: string;
  bonusGb: number;
}

/** The last `n` calendar months (UTC), oldest first, as 'YYYY-MM'. */
export function lastMonthKeys(n: number, now = Date.now()): string[] {
  const d = new Date(now);
  const out: string[] = [];
  for (let i = n - 1; i >= 0; i--) {
    const m = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1));
    out.push(`${m.getUTCFullYear()}-${String(m.getUTCMonth() + 1).padStart(2, '0')}`);
  }
  return out;
}

/** The series a chart renders: the real history, or a zero baseline over the
 *  last `placeholderMonths` months while there is none yet. */
export function impactChartSeries(history: ImpactPoint[], placeholderMonths = 6): ImpactPoint[] {
  if (history.length > 0) return history;
  return lastMonthKeys(placeholderMonths).map((month) => ({ month, bonusGb: 0 }));
}

/** Days in the UTC month containing `now`. */
export function daysInMonth(now = Date.now()): number {
  const d = new Date(now);
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
}

/**
 * Cumulative daily series for the WHOLE current month (one GB value per UTC day,
 * 1st → last day): the server's `currentMonthDaily`, or a flat zero baseline
 * while there is none yet. A short array (an older backend sending 1..today) is
 * padded by holding its last value, so the x-axis is always a full month and
 * stops silently rescaling itself every day.
 */
export function dailyImpactSeries(daily: number[], now = Date.now()): number[] {
  const len = daysInMonth(now);
  if (daily.length === 0) return Array.from({ length: len }, () => 0);
  if (daily.length >= len) return daily.slice(0, len);
  const last = daily[daily.length - 1] ?? 0;
  return [...daily, ...Array.from({ length: len - daily.length }, () => last)];
}

/** Endcap labels for the daily chart: the month's 1st and last day (UTC), as
 *  Date objects for the caller's locale-aware formatter. */
export function dailyImpactBounds(now = Date.now()): [Date, Date] {
  const d = new Date(now);
  return [
    new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)),
    new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)),
  ];
}

const NICE_STEPS = [1, 1.5, 2, 3, 5, 7.5, 10];

/**
 * A round ceiling STRICTLY above `value`, for a chart's y-scale. Strictly, because
 * a ceiling equal to the series max puts the last point exactly on the top edge —
 * which is why a rising month currently reads as a full block that never grows.
 */
export function niceCeil(value: number): number {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = NICE_STEPS.find((s) => s > normalized) ?? 10;
  return step * magnitude;
}
