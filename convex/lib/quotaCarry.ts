/**
 * Quota carryover across re-issues (Review D-M3). A re-issued key starts a fresh
 * provider counter, so each key carries the bytes earlier keys spent in the same
 * traffic period (`subscriptions.periodCarryBytes`) until the period ends
 * (`periodCarryUntil`). Every writer of a key's provider limit (issuance, the
 * tier push, the donation re-cap, the grace settlement) goes through
 * `keyTrafficLimit`, so none of them hands the spent bytes back mid-period, and
 * the `quota-carry-expire` cron restores the full limit once the period ends.
 * See docs/backends.md "Traffic quota across re-issues".
 */
import { applyUsageCarryover, type TrafficLimitStrategy } from './backends/types';

/** When a carry recorded at `now` stops counting: the start of the next UTC period. */
export function carryPeriodEnd(strategy: TrafficLimitStrategy | undefined, now: number): number {
  const d = new Date(now);
  const y = d.getUTCFullYear();
  const m = d.getUTCMonth();
  const day = d.getUTCDate();
  switch (strategy) {
    case 'NO_RESET':
      return Number.MAX_SAFE_INTEGER;
    case 'DAY':
      return Date.UTC(y, m, day + 1);
    case 'WEEK':
      // Weeks start on Monday.
      return Date.UTC(y, m, day - ((d.getUTCDay() + 6) % 7) + 7);
    default:
      return Date.UTC(y, m + 1, 1);
  }
}

export interface CarryFields {
  periodCarryBytes?: number;
  periodCarryUntil?: number;
}

/** Bytes earlier keys spent that still count against this key. */
export function liveCarryBytes(sub: CarryFields, now: number): number {
  const bytes = Math.floor(sub.periodCarryBytes ?? 0);
  if (bytes <= 0 || sub.periodCarryUntil === undefined || sub.periodCarryUntil <= now) return 0;
  return bytes;
}

/** A key's provider limit: the tier limit less what earlier keys spent this period. */
export function keyTrafficLimit(
  tierLimit: number | null,
  sub: CarryFields,
  now: number,
): number | null {
  if (tierLimit === null) return null;
  const carry = liveCarryBytes(sub, now);
  return carry > 0 ? applyUsageCarryover(tierLimit, carry) : tierLimit;
}
