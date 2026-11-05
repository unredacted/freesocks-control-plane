/**
 * Globalping's own view of FCP's allowance, as FCP last read it, and the part
 * of FCP's hourly Globalping cap kept for the name checks (pure; unit-tested;
 * docs/edges.md "Probe sources and verdicts", **Budget and failing sources**).
 *
 * Two numbers are easy to confuse, and this keeps them apart:
 *  - FCP's cap, `probe.globalpingTestsPerHour`: every Globalping test FCP asks
 *    in an hour (probe rounds, in-country name checks, the hunt's timing).
 *    The probe rounds may use it less the name checks' share, so a busy probe
 *    hour never takes the tests the name checks are allowed; a cap below that
 *    share shrinks the name checks' own budgets to fit (`namesShare`).
 *  - Globalping's allowance: the free tests of its hour window (500 with a
 *    token) and then credits, one per test. Read from its own answers (the
 *    `/v1/limits` preflight and every create's headers) into one `appState`
 *    row, so the Probes page shows what Globalping says, not what FCP guesses.
 */
import type { GlobalpingReading } from './globalping';
import { TIMING_PROBES } from '../sni/hunt/evidence';

/** The `appState` key the account row lives under. */
export const GLOBALPING_ACCOUNT_KEY = 'probe:globalping:account';

const DAY_MS = 86_400_000;
/** Days of credit spending kept (today plus a week). */
const KEEP_DAYS = 8;

export interface GlobalpingAccount {
  /** When Globalping last answered about the window. */
  at: number;
  type?: 'user' | 'ip';
  limit: number;
  remaining: number;
  /** When that window resets; equal to `at` when no window was open (nothing spent). */
  resetAt: number;
  /** Credits left, as Globalping last said (approximate in a create's headers). */
  credits?: number;
  creditsAt?: number;
  /** Credits FCP's own requests spent, per UTC day (`X-Credits-Consumed`), newest first. */
  spent: Array<{ day: string; credits: number }>;
}

/** `YYYY-MM-DD` in UTC. */
export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Fold one reading into the stored row. Readings come from concurrent actions
 * and can land out of order: the window and the credits follow the newest
 * reading of each, while spent credits always add up.
 */
export function mergeReading(
  prev: GlobalpingAccount | null,
  r: GlobalpingReading,
  at: number,
): GlobalpingAccount {
  const newer = !prev || at >= prev.at;
  const type = (newer ? r.type : prev?.type) ?? (newer ? prev?.type : r.type);
  const window = newer
    ? { at, limit: r.limit, remaining: r.remaining, resetAt: at + r.resetSec * 1000 }
    : { at: prev!.at, limit: prev!.limit, remaining: prev!.remaining, resetAt: prev!.resetAt };
  const creditsNewer =
    r.credits !== undefined && (prev?.creditsAt === undefined || at >= prev.creditsAt);
  const credits = creditsNewer
    ? { credits: r.credits, creditsAt: at }
    : prev?.credits !== undefined
      ? { credits: prev.credits, creditsAt: prev.creditsAt }
      : {};
  let spent = [...(prev?.spent ?? [])];
  if (r.creditsConsumed && r.creditsConsumed > 0) {
    const day = utcDay(at);
    const i = spent.findIndex((s) => s.day === day);
    if (i >= 0) spent[i] = { day, credits: spent[i]!.credits + r.creditsConsumed };
    else spent.push({ day, credits: r.creditsConsumed });
  }
  spent = spent.sort((a, b) => (a.day < b.day ? 1 : a.day > b.day ? -1 : 0)).slice(0, KEEP_DAYS);
  return { ...window, ...(type ? { type } : {}), ...credits, spent };
}

export interface GlobalpingAccountView {
  /** When Globalping last answered. */
  at: number;
  type: 'user' | 'ip' | null;
  limit: number;
  /** Free tests left now: the whole allowance once the window it was read in has reset. */
  remaining: number;
  /** When the open window resets; null when none is open. */
  resetAt: number | null;
  credits: number | null;
  creditsAt: number | null;
  /** Credits spent since 00:00 UTC. */
  spentToday: number;
  /** Credits spent on the last full UTC day. */
  spentYesterday: number;
  /** Whole days the credits last at the last full day's pace; null when it spent none. */
  runwayDays: number | null;
}

export function accountView(a: GlobalpingAccount, now: number): GlobalpingAccountView {
  const open = a.resetAt > a.at && now < a.resetAt;
  const reset = a.resetAt > a.at && now >= a.resetAt;
  const spentOn = (day: string) => a.spent.find((s) => s.day === day)?.credits ?? 0;
  const spentYesterday = spentOn(utcDay(now - DAY_MS));
  const credits = a.credits ?? null;
  return {
    at: a.at,
    type: a.type ?? null,
    limit: a.limit,
    remaining: reset ? a.limit : a.remaining,
    resetAt: open ? a.resetAt : null,
    credits,
    creditsAt: a.creditsAt ?? null,
    spentToday: spentOn(utcDay(now)),
    spentYesterday,
    runwayDays:
      credits !== null && spentYesterday > 0 ? Math.floor(credits / spentYesterday) : null,
  };
}

export interface NamesShareInputs {
  /** `probe.globalpingTestsPerHour`: every Globalping test FCP asks in an hour. */
  perHour: number;
  /**
   * The checks of names from inside countries: `on` when they run with
   * Globalping among their usable sources; their hourly budget (measurement
   * rows, every source), the vantages each, and how many sources a batch asks.
   */
  vantage: { on: boolean; hourlyBudget: number; perCountryLimit: number; sources: number };
  /**
   * The hunt's checks of candidates' real sites from inside countries: they
   * use Globalping only and may fill whatever the vantage budget leaves.
   */
  huntChecks: boolean;
  /** The hunt's timing from a network's place (`TIMING_PROBES` vantages each). */
  huntTiming: { on: boolean; perHour: number };
}

export interface NamesShare {
  /** Globalping tests an hour kept for the name checks: out of the probe rounds' part. */
  reserved: number;
  /** The name checks' hourly budget under the cap (measurement rows, every source). */
  vantageBudget: number;
  /**
   * The cap leaves the name checks no Globalping test: their batches run
   * without it (the other sources keep the whole budget).
   */
  vantageWithoutGlobalping: boolean;
  /** Timing measurements an hour under the cap. */
  timingPerHour: number;
}

/**
 * What the name checks may ask of Globalping within `perHour`, and the
 * budgets that keeps them to it. Uncapped, the most their own budgets allow:
 * a batch asks every source, so only its Globalping rows count (all of the
 * budget once the hunt's Globalping-only checks may fill it), each row
 * `perCountryLimit` vantages, then the hunt's timing. A cap below that
 * shrinks the checks first and the timing with what is left, so the setting
 * bounds every Globalping test FCP asks.
 */
export function namesShare(i: NamesShareInputs): NamesShare {
  const cap = Math.max(0, i.perHour);
  const pcl = Math.max(1, i.vantage.perCountryLimit);
  const sources = Math.max(1, i.vantage.sources);
  const budget = i.vantage.hourlyBudget;
  // Globalping rows an hour at most: a batch puts one row per source on each
  // name; the hunt's own rows are Globalping only.
  const rowsMax = !i.vantage.on ? 0 : i.huntChecks ? budget : Math.ceil(budget / sources);
  const rows = Math.min(rowsMax, Math.floor(cap / pcl));
  const vantageWithoutGlobalping = i.vantage.on && rowsMax > 0 && rows === 0;
  let vantageBudget = budget;
  if (i.vantage.on && rows < rowsMax && !vantageWithoutGlobalping)
    vantageBudget = i.huntChecks ? rows : rows * sources;
  const left = cap - rows * pcl;
  const timingPerHour = i.huntTiming.on
    ? Math.min(i.huntTiming.perHour, Math.floor(left / TIMING_PROBES))
    : i.huntTiming.perHour;
  return {
    reserved: rows * pcl + (i.huntTiming.on ? timingPerHour * TIMING_PROBES : 0),
    vantageBudget,
    vantageWithoutGlobalping,
    timingPerHour,
  };
}

/** What the probe rounds may use of the hourly cap. */
export function probeShare(perHour: number, reserved: number): number {
  return Math.max(0, perHour - Math.max(0, reserved));
}
