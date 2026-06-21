/**
 * Shared membership pricing math, derived entirely from the DB duration prices
 * (Admin → Billing). The self-upgrade panel, the gift-code panel, and the tier
 * comparison card all render a per-month rate (and a "save X%" badge) from these,
 * so the savings recompute when an admin edits a price — there is no separate
 * stored discount field to keep in sync.
 *
 * The baseline is the SHORTEST configured term's per-month rate (e.g. the 1-month
 * plan at $5/mo), so longer terms show their discount vs the standard monthly rate
 * — NOT the cheapest amortized term (which would read as a pricing bug).
 */
export interface Duration {
  months: number;
  amountCents: number;
}

/** Per-month price for a term, in cents. Non-recurring (months <= 0) → the raw amount. */
export function perMonthCents(d: Duration): number {
  return d.months > 0 ? d.amountCents / d.months : d.amountCents;
}

/**
 * The standard monthly rate = the shortest configured recurring term's per-month
 * price, or null when there are no recurring terms.
 */
export function baselinePerMonth(durations: Duration[]): number | null {
  const ds = durations.filter((d) => d.months > 0);
  if (ds.length === 0) return null;
  const shortest = ds.reduce((a, b) => (b.months < a.months ? b : a));
  return shortest.amountCents / shortest.months;
}

/** Whole-percent saved vs the baseline monthly rate (0 when no saving / no baseline). */
export function savingsPct(d: Duration, durations: Duration[]): number {
  const baseline = baselinePerMonth(durations);
  if (baseline === null || baseline <= 0) return 0;
  return Math.round((1 - perMonthCents(d) / baseline) * 100);
}
