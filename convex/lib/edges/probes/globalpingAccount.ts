/**
 * Globalping's own view of FCP's allowance, as FCP last read it, and the part
 * of FCP's hourly Globalping cap kept for the name checks (pure; unit-tested;
 * docs/edges.md "Probe sources and verdicts", **Budget and failing sources**).
 *
 * Two numbers are easy to confuse, and this keeps them apart:
 *  - FCP's cap, `probe.globalpingTestsPerHour`: every Globalping test FCP asks
 *    in an hour (probe rounds, in-country name checks, the hunt's timing).
 *    The probe rounds may use it less the name checks' share, so a busy probe
 *    hour never takes the tests the name checks are allowed.
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
  /** In-country name checks (candidates' real-site checks included) run through Globalping. */
  vantage: { on: boolean; hourlyBudget: number; perCountryLimit: number };
  /** The hunt's timing from a network's place. */
  huntTiming: { on: boolean; perHour: number };
}

/**
 * Globalping tests an hour the name checks may ask: the most their own
 * budgets allow (measurements x vantages each). Kept out of what the probe
 * rounds may use of `probe.globalpingTestsPerHour`.
 */
export function namesShare(i: NamesShareInputs): number {
  const vantage = i.vantage.on ? i.vantage.hourlyBudget * i.vantage.perCountryLimit : 0;
  const timing = i.huntTiming.on ? i.huntTiming.perHour * TIMING_PROBES : 0;
  return vantage + timing;
}

/** What the probe rounds may use of the hourly cap. */
export function probeShare(perHour: number, reserved: number): number {
  return Math.max(0, perHour - Math.max(0, reserved));
}
