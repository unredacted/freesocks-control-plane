/**
 * Checks of server names from inside a country: what the measurements say,
 * and what they may suggest (pure; unit-tested). docs/edges.md "Checks from
 * inside a country".
 *
 * The one fact a mark records is "the censor there treats THIS name
 * differently". Two other facts look the same from a single vantage and must
 * never be mistaken for it: the address is blocked (every name fails), and
 * the target stopped serving the name (qualification's business). So a batch
 * measures several names of one address from the same vantages, and a failure
 * counts against a name only when the same batch got through for another name:
 *
 *  - `singled`: that vantage's network completed another name of the batch;
 *  - `unpaired`: another network of the batch did, this one did not (weaker);
 *  - `path`: no name of the batch got through at all (the address, not the name).
 *
 * A suggestion is only ever a proposal. `decide` compares it with the mark
 * standing today and never lets it replace an operator's.
 */
import type { NameOutcome } from '../probes/nameCheck';

/** Outcomes that are what interference looks like. */
export const NAME_FAILURES: ReadonlySet<NameOutcome> = new Set<NameOutcome>([
  'reset',
  'timeout',
  'cert_mismatch',
]);
/** Outcomes that show the path to the address is open for that name. */
const reached = (o: NameOutcome) => o === 'ok' || o === 'answered';

/** Two batches closer than this are one look, not a repeat. */
export const REPEAT_GAP_MS = 3_600_000;

export interface VantageReading {
  asn?: string;
  network?: string;
  outcome: NameOutcome;
}

/** One stored measurement: one name, one source, one batch (one address, one country). */
export interface Measurement {
  batch: string;
  source: string;
  /** `<kind>:<ref>` of the address measured. */
  target: string;
  name: string;
  /** When it finished. */
  at: number;
  results: readonly VantageReading[];
}

export interface Streak {
  /** Name-specific failing vantages (`singled` + `unpaired`) over the streak. */
  nameFailures: number;
  /** Distinct networks among them. */
  networks: number;
  singled: number;
  /** Failures where no name of the batch got through. */
  pathFailures: number;
  /** Distinct batches in the streak at least REPEAT_GAP_MS apart. */
  batches: number;
  startedAt: number;
  /** The name worked from there before the streak began. */
  transition: boolean;
}

export interface NameEvidence {
  /** Measurements of the name inside the window. */
  measurements: number;
  okVantages: number;
  okNetworks: number;
  lastOkAt: number | null;
  lastFailAt: number | null;
  lastAt: number | null;
  /** The newest checks of every address the name was measured on, together. */
  latest: 'ok' | 'failing' | 'mixed' | 'none';
  streak: Streak | null;
}

/** The network a vantage belongs to (what the scoring counts). */
export function networkOf(r: { asn?: string; network?: string }): string {
  return r.asn ?? r.network ?? 'unknown';
}

interface Group {
  key: string;
  batch: string;
  target: string;
  at: number;
  ok: number;
  singled: number;
  unpaired: number;
  path: number;
  okNetworks: Set<string>;
  failNetworks: Set<string>;
}

const evidenceIn = (g: Group) => g.ok + g.singled + g.unpaired + g.path > 0;
const nameFailing = (g: Group) => g.singled + g.unpaired;

/**
 * Aggregate one name's evidence for one country. `measurements` holds the
 * name's own measurements AND the other names' measurements of the same
 * batches (the controls). `everOkAt` is the newest working check ever, kept
 * past the window, so a transition survives retention.
 */
export function aggregateEvidence(
  name: string,
  measurements: readonly Measurement[],
  everOkAt: number | null,
): NameEvidence {
  const byGroup = new Map<string, Measurement[]>();
  for (const m of measurements) {
    const key = `${m.batch}|${m.source}`;
    byGroup.set(key, [...(byGroup.get(key) ?? []), m]);
  }
  const groups: Group[] = [];
  let measured = 0;
  for (const [key, ms] of byGroup) {
    const own = ms.filter((m) => m.name === name);
    if (own.length === 0) continue;
    measured += own.length;
    const controls = ms.filter((m) => m.name !== name).flatMap((m) => m.results);
    const controlNetworks = new Set(controls.filter((r) => reached(r.outcome)).map(networkOf));
    const g: Group = {
      key,
      batch: own[0]!.batch,
      target: own[0]!.target,
      at: Math.max(...own.map((m) => m.at)),
      ok: 0,
      singled: 0,
      unpaired: 0,
      path: 0,
      okNetworks: new Set(),
      failNetworks: new Set(),
    };
    for (const r of own.flatMap((m) => m.results)) {
      const net = networkOf(r);
      if (r.outcome === 'ok') {
        g.ok++;
        g.okNetworks.add(net);
      } else if (NAME_FAILURES.has(r.outcome)) {
        if (controlNetworks.has(net)) g.singled++;
        else if (controlNetworks.size > 0) g.unpaired++;
        else g.path++;
        if (controlNetworks.size > 0) g.failNetworks.add(net);
      }
    }
    groups.push(g);
  }
  // One LOOK = one batch, every source of it together. Controls pair within a
  // source (its vantages), but the sources measured the same names at the same
  // time: the newest look is judged as a whole, never by whichever source
  // happened to finish last.
  const byBatch = new Map<string, Group>();
  for (const g of groups) {
    const l = byBatch.get(g.batch);
    if (!l) {
      byBatch.set(g.batch, {
        ...g,
        key: g.batch,
        okNetworks: new Set(g.okNetworks),
        failNetworks: new Set(g.failNetworks),
      });
      continue;
    }
    l.at = Math.max(l.at, g.at);
    l.ok += g.ok;
    l.singled += g.singled;
    l.unpaired += g.unpaired;
    l.path += g.path;
    for (const n of g.okNetworks) l.okNetworks.add(n);
    for (const n of g.failNetworks) l.failNetworks.add(n);
  }
  const looks = [...byBatch.values()].sort((a, b) => b.at - a.at);
  const withEvidence = looks.filter(evidenceIn);

  const okNetworks = new Set(withEvidence.flatMap((g) => [...g.okNetworks]));
  const okGroups = withEvidence.filter((g) => g.ok > 0);
  const failGroups = withEvidence.filter((g) => nameFailing(g) + g.path > 0);

  // Per address: its newest look decides its state; a failing address
  // collects its streak (the newest looks with no success at all).
  const targets = [...new Set(withEvidence.map((g) => g.target))];
  const states: Array<'ok' | 'failing' | 'mixed'> = [];
  const streakGroups: Group[] = [];
  let okBeforeStreak = false;
  for (const target of targets) {
    const mine = withEvidence.filter((g) => g.target === target);
    const newest = mine[0]!;
    if (newest.ok > 0) {
      states.push(nameFailing(newest) > 0 ? 'mixed' : 'ok');
      continue;
    }
    states.push('failing');
    let i = 0;
    while (i < mine.length && mine[i]!.ok === 0) streakGroups.push(mine[i++]!);
    if (i < mine.length) okBeforeStreak = true;
  }
  const latest: NameEvidence['latest'] =
    states.length === 0
      ? 'none'
      : states.includes('mixed') || (states.includes('ok') && states.includes('failing'))
        ? 'mixed'
        : states.includes('failing')
          ? 'failing'
          : 'ok';

  let streak: Streak | null = null;
  if (latest === 'failing' && streakGroups.length > 0) {
    const startedAt = Math.min(...streakGroups.map((g) => g.at));
    // Repeats: looks at least REPEAT_GAP_MS apart (two requests a minute apart
    // are one look; two sources of one batch already are).
    const times = streakGroups
      .filter((g) => nameFailing(g) > 0)
      .map((g) => g.at)
      .sort((a, b) => a - b);
    let batches = 0;
    let last = -Infinity;
    for (const at of times) {
      if (at - last >= REPEAT_GAP_MS) {
        batches++;
        last = at;
      }
    }
    streak = {
      nameFailures: streakGroups.reduce((n, g) => n + nameFailing(g), 0),
      networks: new Set(streakGroups.flatMap((g) => [...g.failNetworks])).size,
      singled: streakGroups.reduce((n, g) => n + g.singled, 0),
      pathFailures: streakGroups.reduce((n, g) => n + g.path, 0),
      batches,
      startedAt,
      transition: okBeforeStreak || (everOkAt !== null && everOkAt < startedAt),
    };
  }

  return {
    measurements: measured,
    okVantages: withEvidence.reduce((n, g) => n + g.ok, 0),
    okNetworks: okNetworks.size,
    lastOkAt: okGroups[0]?.at ?? null,
    lastFailAt: failGroups[0]?.at ?? null,
    lastAt: withEvidence[0]?.at ?? looks[0]?.at ?? null,
    latest,
    streak,
  };
}

// --- what it may suggest ------------------------------------------------------------------------------

export type SuggestReason =
  | 'no_data'
  | 'not_enough_vantages'
  | 'not_enough_networks'
  | 'not_paired'
  | 'needs_repeat'
  | 'no_control'
  | 'mixed'
  | 'reports_disagree';
export const SUGGEST_REASONS: readonly SuggestReason[] = [
  'no_data',
  'not_enough_vantages',
  'not_enough_networks',
  'not_paired',
  'needs_repeat',
  'no_control',
  'mixed',
  'reports_disagree',
];

export type MarkState = 'proven' | 'blocked';

export interface Suggestion {
  suggestion: MarkState | null;
  /** Why nothing is suggested (null when something is). */
  reason: SuggestReason | null;
  /** What a `blocked` suggestion rests on. */
  basis: { transition: boolean; repeated: boolean; reports: boolean } | null;
}

export interface SuggestOptions {
  /** Member reports single this name out in this country (`suspectNames`). */
  reportSuspect: boolean;
  minVantages: number;
  minNetworks: number;
}

const none = (reason: SuggestReason): Suggestion => ({ suggestion: null, reason, basis: null });

/**
 * The rule (docs/edges.md "Scoring"). Blocked: the newest checks fail, the
 * failing streak is name-specific from enough vantages and networks with at
 * least one same-network control, and it is a transition, a repeat, or what
 * member reports say too. Proven: enough working vantages and networks, the
 * newest checks do not fail, and reports do not single the name out.
 */
export function suggest(e: NameEvidence, o: SuggestOptions): Suggestion {
  if (e.latest === 'none') return none('no_data');
  if (e.latest === 'mixed') return none('mixed');
  if (e.latest === 'failing') {
    const s = e.streak;
    if (!s || s.nameFailures === 0) return none('no_control');
    if (s.nameFailures < o.minVantages) return none('not_enough_vantages');
    if (s.networks < o.minNetworks) return none('not_enough_networks');
    if (s.singled === 0) return none('not_paired');
    const repeated = s.batches >= 2;
    if (!s.transition && !repeated && !o.reportSuspect) return none('needs_repeat');
    return {
      suggestion: 'blocked',
      reason: null,
      basis: { transition: s.transition, repeated, reports: o.reportSuspect },
    };
  }
  if (o.reportSuspect) return none('reports_disagree');
  if (e.okVantages < o.minVantages) return none('not_enough_vantages');
  if (e.okNetworks < o.minNetworks) return none('not_enough_networks');
  return { suggestion: 'proven', reason: null, basis: null };
}

export interface Mark {
  state: MarkState;
  source: 'operator' | 'probe';
}

/**
 * A suggestion against the mark standing today. An operator's mark is never
 * replaced by evidence: a different suggestion is a `conflict` for the
 * operator to look at. A mark the checks wrote themselves may be replaced.
 */
export type Decision = 'suggest' | 'agrees' | 'conflict' | 'none';
export function decide(suggestion: MarkState | null, mark: Mark | null): Decision {
  if (!suggestion) return 'none';
  if (!mark) return 'suggest';
  if (mark.state === suggestion) return 'agrees';
  return mark.source === 'operator' ? 'conflict' : 'suggest';
}

// --- planning ---------------------------------------------------------------------------------------

export interface PlanName {
  name: string;
  seq: number;
  /** Due from this country AND this is the address it is due on (`preferredTarget`). */
  due: boolean;
  /**
   * May serve as this batch's control: not checked from this country within
   * the interval either (a control is a check like any other; it must never
   * make a name be checked more often than the interval allows).
   */
  spare: boolean;
  /** Member reports point at it there: checked first. */
  priority: boolean;
  /** When it was last put into a batch for this country (null = never). */
  lastRequestedAt: number | null;
  /** The newest working check from this country, for choosing a control. */
  lastOkAt: number | null;
}

/**
 * The names of one batch: the due ones, reported first, then the longest
 * waiting (never checked first), up to `size`, so no name starves behind
 * lower `seq`s. A lone due name needs a control, because a failure means
 * nothing about a name unless another name of the same address got through:
 * the spare that most recently worked from there. With no spare the batch
 * WAITS (an empty answer) until another name is due, unless the address
 * carries no other name at all, in which case the name goes alone.
 */
export function pickBatchNames(candidates: readonly PlanName[], size: number): string[] {
  const waited = (c: PlanName) => c.lastRequestedAt ?? -Infinity;
  const due = candidates
    .filter((c) => c.due)
    .sort(
      (a, b) => Number(b.priority) - Number(a.priority) || waited(a) - waited(b) || a.seq - b.seq,
    )
    .slice(0, Math.max(1, size));
  if (due.length !== 1) return due.map((c) => c.name);
  const lone = due[0]!;
  const others = candidates.filter((c) => c.name !== lone.name);
  if (others.length === 0) return [lone.name];
  const control = others
    .filter((c) => c.due || c.spare)
    .sort(
      (a, b) => (b.lastOkAt ?? -1) - (a.lastOkAt ?? -1) || waited(a) - waited(b) || a.seq - b.seq,
    )[0];
  return control ? [lone.name, control.name] : [];
}

/**
 * Which of a name's addresses it is checked on next: the one it was checked on
 * longest ago (never = first), ties in the given stable order. A name on
 * several addresses therefore takes them in turn, one look per interval, so a
 * block that depends on the address shows up as `mixed` instead of one
 * address speaking for all of them.
 */
export function preferredTarget(
  keys: readonly string[],
  lastByKey: ReadonlyMap<string, number>,
): string | null {
  let best: string | null = null;
  let bestAt = Infinity;
  for (const k of keys) {
    const at = lastByKey.get(k) ?? -Infinity;
    if (at < bestAt) {
      best = k;
      bestAt = at;
    }
  }
  return best;
}

/** A list rotated by tick, so a bounded scan starts somewhere else each time. */
export function rotateForTick<T>(items: readonly T[], now: number, tickMs: number): T[] {
  if (items.length === 0) return [];
  const start = Math.floor(now / tickMs) % items.length;
  return [...items.slice(start), ...items.slice(0, start)];
}

export type AddressVerdict = 'reachable' | 'unreachable' | 'mixed' | 'unknown' | null;

/**
 * Which address to check a name on: never one the address-level probes find
 * unreachable from there (that is the block detector's business, and checking
 * it from inside teaches nothing about names); reachable ones first, in the
 * given (stable) order.
 */
export function pickTargetIndex(verdicts: readonly AddressVerdict[]): number {
  const rank = (v: AddressVerdict) => (v === 'reachable' ? 0 : v === 'unreachable' ? -1 : 1);
  let best = -1;
  for (let i = 0; i < verdicts.length; i++) {
    const r = rank(verdicts[i]!);
    if (r < 0) continue;
    if (best < 0 || r < rank(verdicts[best]!)) best = i;
  }
  return best;
}

/** The country a tick looks at first: the opted-in list rotated by tick, so each gets its turn. */
export function countriesForTick(
  countries: readonly string[],
  now: number,
  tickMs: number,
): string[] {
  return rotateForTick(countries, now, tickMs);
}
