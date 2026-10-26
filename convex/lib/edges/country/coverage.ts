/**
 * Which outside probe sources answer from a country (pure; unit-tested).
 * docs/edges.md "The country view".
 *
 * A target's reachability summary keeps only fresh rows (probes.ts
 * `refreshTargetSummary`: two probe intervals), so a country whose only
 * source stopped answering drops out of it, and the view alone would read "no
 * evidence" without a word on why. This reads the per-source rollup rows
 * themselves (`probeReachability`, whose `updatedAt` moves only when that
 * source brought an answer from that country): each source's newest answer
 * from the country, per address and over every address the view shows, and
 * whether it still counts.
 *
 * The internal source is left out: it answers from FCP's own host (`XX`),
 * never from a country.
 */

/** One rollup row, as read: a source's last answer from a country about one target. */
export interface AnswerRow {
  country: string;
  source: string;
  updatedAt: number;
}

/** `<country>|<source>` -> the newest answer over every row given. */
export type NewestAnswers = Map<string, number>;

const answerKey = (country: string, source: string) => `${country}|${source}`;

/** Fold rows into each (country, source)'s newest answer. */
export function newestAnswers(rows: Iterable<AnswerRow>, into: NewestAnswers = new Map()) {
  for (const r of rows) {
    if (r.source === 'internal') continue;
    const k = answerKey(r.country, r.source);
    if (r.updatedAt > (into.get(k) ?? -Infinity)) into.set(k, r.updatedAt);
  }
  return into;
}

export interface SourceCoverage {
  source: string;
  /** Its newest answer from the country (null: none on record). */
  lastAt: number | null;
  /** Newer than the window: the summaries still count it. */
  fresh: boolean;
}

export interface CountryCoverage {
  /** The probes ask vantages there: probes on and "check edges" on for the country. */
  asked: boolean;
  /** How long an answer counts (two probe intervals). */
  windowMs: number;
  /** Every outside source in use, in the order given. */
  sources: SourceCoverage[];
}

/**
 * Each outside source in use (enabled, with its key) and its newest answer
 * from the country, in the order given; a source switched off says nothing
 * here, whatever its old rows hold.
 */
export function answersFor(
  answers: NewestAnswers,
  country: string,
  sources: readonly string[],
  o: { windowMs: number; now: number },
): SourceCoverage[] {
  return sources
    .filter((s) => s !== 'internal')
    .map((source) => {
      const lastAt = answers.get(answerKey(country, source)) ?? null;
      return { source, lastAt, fresh: lastAt !== null && lastAt >= o.now - o.windowMs };
    });
}

/** One country's coverage over every address folded into `answers`. */
export function coverageOf(
  answers: NewestAnswers,
  country: string,
  sources: readonly string[],
  o: { asked: boolean; windowMs: number; now: number },
): CountryCoverage {
  return {
    asked: o.asked,
    windowMs: o.windowMs,
    sources: answersFor(answers, country, sources, o),
  };
}
