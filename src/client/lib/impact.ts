/**
 * Donation-impact chart series helpers. The public config ships a per-month
 * `{month, bonusGb}` history that is EMPTY until the first settled donation;
 * the impact charts still render then - as a flat zero baseline over the last
 * few months - so the graph is always present rather than a blank slot.
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

/** Month-to-date cumulative daily series (one GB value per UTC day, 1st →
 *  today): the server's `currentMonthDaily`, or a flat zero baseline through
 *  today while there is none yet — the chart is always present. */
export function dailyImpactSeries(daily: number[], now = Date.now()): number[] {
  if (daily.length > 0) return daily;
  return Array.from({ length: new Date(now).getUTCDate() }, () => 0);
}

/** Endcap labels for the daily chart: the month's 1st and today (UTC), as Date
 *  objects for the caller's locale-aware formatter. */
export function dailyImpactBounds(now = Date.now()): [Date, Date] {
  const d = new Date(now);
  return [new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)), d];
}
