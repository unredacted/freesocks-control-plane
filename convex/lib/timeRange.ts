/**
 * Shared admin-chart range resolution: an explicit [sinceMs, untilMs) pair when
 * given (the admin's custom date picker), else the trailing `windowMs` ending
 * now. Span clamped to [1h, 366d]. Used by the telemetry summary and the
 * billing revenue series so their pickers behave identically.
 */
const DAY_MS = 86_400_000;
const MIN_SPAN = 3_600_000;
const MAX_SPAN = 366 * DAY_MS;

export interface ResolvedRange {
  since: number;
  until: number;
  /** until - since. */
  spanMs: number;
  /** Start of the equal-length range immediately before (the trend baseline). */
  prevSince: number;
  /** Hourly buckets for short ranges (≤ 3 days), else daily. */
  bucketMs: number;
}

export function resolveRange(
  a: { windowMs?: number; sinceMs?: number; untilMs?: number },
  now = Date.now(),
): ResolvedRange {
  let since: number;
  let until: number;
  if (a.sinceMs !== undefined && Number.isFinite(a.sinceMs)) {
    since = a.sinceMs;
    until = a.untilMs !== undefined && Number.isFinite(a.untilMs) ? a.untilMs : now;
    if (until <= since) until = since + MIN_SPAN;
    if (until - since > MAX_SPAN) until = since + MAX_SPAN;
  } else {
    const w = Math.min(Math.max(a.windowMs ?? 7 * DAY_MS, MIN_SPAN), MAX_SPAN);
    until = now;
    since = now - w;
  }
  const spanMs = until - since;
  return {
    since,
    until,
    spanMs,
    prevSince: since - spanMs,
    bucketMs: spanMs <= 3 * DAY_MS ? 3_600_000 : DAY_MS,
  };
}
