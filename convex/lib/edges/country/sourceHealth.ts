/**
 * Whether each probe source is working (pure; unit-tested). A source that
 * errors gives no evidence, so a country checked only through a failing
 * source silently reads "not known": this makes the failure itself visible
 * (Probes page, attention `probe_source_failing`).
 */

/**
 * A short class for why a run could not measure. Stored on the run, so it
 * never carries service text, an address or a name. Every class is "the
 * vantages could not test" (lib/edges/probes/types.ts `RunOutcome`), never
 * evidence about the address: `no_route` is FCP's own host without a route for
 * the family, `request_refused` covers a service that rejects the input
 * (check-host's `invalid_url`), and `timeout` is the measurement job's own.
 */
export function failureCode(message: string): string {
  const m = message.toLowerCase();
  if (m.includes('no_route')) return 'no_route';
  if (/\b(401|403)\b/.test(m) || m.includes('unauthor') || m.includes('forbidden')) return 'auth';
  if (
    /\b429\b/.test(m) ||
    m.includes('rate limit') ||
    m.includes('too many') ||
    m.includes('limit_exceeded')
  )
    return 'rate_limited';
  if (m.includes('invalid_url')) return 'request_refused';
  if (m.includes('globalping_limit')) return 'globalping_limit';
  if (m.includes('key not set')) return 'no_key';
  if (m.includes('no nodes') || m.includes('no probes')) return 'no_vantages';
  if (m.includes('timeout') || m.includes('timed out')) return 'timeout';
  if (/\b5\d\d\b/.test(m)) return 'service_error';
  if (/\b4\d\d\b/.test(m)) return 'request_refused';
  if (m.includes('fetch failed') || m.includes('enotfound') || m.includes('econn'))
    return 'network';
  return 'error';
}

export interface SourceRun {
  source: string;
  status: 'requested' | 'running' | 'finished' | 'failed' | 'timeout';
  requestedAt: number;
  finishedAt?: number;
  /** Results the run brought back (a finished run with none is no evidence either). */
  results: number;
  error?: string;
}

export interface SourceHealth {
  source: string;
  /** Settled runs in the window. */
  runs: number;
  withEvidence: number;
  failed: number;
  empty: number;
  /** Settled runs, newest first, that brought no evidence before the newest one that did. */
  streak: number;
  lastOkAt: number | null;
  lastFailAt: number | null;
  lastError: string | null;
  failing: boolean;
}

/** A source is failing after this many settled runs without evidence in a row... */
export const FAILING_STREAK = 3;
/** ...with nothing that worked for at least this long. */
export const FAILING_QUIET_MS = 6 * 60 * 60_000;

/**
 * Per source, from its runs of the window (any order). A run that failed with
 * `no_route` is left out: the source works, FCP's own host just has no route
 * for that family (no IPv6), and every IPv6 target would otherwise read as a
 * failing source.
 */
export function sourceHealth(
  sources: readonly string[],
  runs: readonly SourceRun[],
  now: number,
): SourceHealth[] {
  return sources.map((source) => {
    const mine = runs
      .filter(
        (r) =>
          r.source === source &&
          (r.status === 'finished' || r.status === 'failed' || r.status === 'timeout') &&
          r.error !== 'no_route',
      )
      .sort((a, b) => b.requestedAt - a.requestedAt);
    const good = (r: SourceRun) => r.status === 'finished' && r.results > 0;
    let streak = 0;
    while (streak < mine.length && !good(mine[streak]!)) streak++;
    const ok = mine.filter(good);
    const bad = mine.filter((r) => !good(r));
    const lastOkAt = ok.length > 0 ? (ok[0]!.finishedAt ?? ok[0]!.requestedAt) : null;
    const lastFail = bad[0] ?? null;
    return {
      source,
      runs: mine.length,
      withEvidence: ok.length,
      failed: mine.filter((r) => r.status !== 'finished').length,
      empty: mine.filter((r) => r.status === 'finished' && r.results === 0).length,
      streak,
      lastOkAt,
      lastFailAt: lastFail ? (lastFail.finishedAt ?? lastFail.requestedAt) : null,
      lastError: lastFail
        ? (lastFail.error ?? (lastFail.status === 'finished' ? 'no_results' : lastFail.status))
        : null,
      failing:
        streak >= FAILING_STREAK && (lastOkAt === null || now - lastOkAt >= FAILING_QUIET_MS),
    };
  });
}
