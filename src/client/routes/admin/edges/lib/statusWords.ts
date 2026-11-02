/**
 * The server's origin status in words (pure; unit-tested). The judgement
 * (which kind, which dot, which reason wins) is the server's ONE projection
 * (`convex/lib/edges/originStatus.ts`: the attention response's `origins[]`
 * and `fleet`, setup-status's `delivery`); every page reads it and only words
 * it here, so the Edges home, the node page, All origins and the Servers node
 * page always agree.
 *
 * Exports:
 *   originSentence(status)       one plain sentence for one origin
 *   fleetSentence(fleet)         the Edges home's headline
 *   oneAddressNote(desired)      the node page's note while one address is in use
 *   deliveryWords(delivery)      the Delivery card: tone, headline, what members get, why, the fix
 *   statusOf(origins, slug)      one origin's status from the attention response, or null
 *
 * The checks from each country (docs/edges.md "Checks from each country"), in
 * the same one place: every round result, every reason the server records and
 * every probe failure class has a sentence here (pinned by statusWords.test.ts,
 * which reads the server's rules for the literals they write).
 *   ROUND_RESULT_WORDS / COUNTRY_REASON_WORDS / PROBE_FAILURE_WORDS / GROUP_GRADE_WORDS
 *   STATE_FROM_WORDS / MARK_WORDS
 *   countryReasonSentence(code), probeFailureWords(code)
 *   countryLine(line, now)       one edge in one country: label, tone, reason, where from, age, conflict
 *   countryChip(line, now, waiting)  the same as a short chip ("checking" while its round is out)
 *   gradeWords(cell, now)        one location in one country: label, tone, age, mark, conflict
 *   sourceWords(health, now)     one probe source: working, failing or capped, and why
 *   capHoldsBack(health), capClause(cap)   Globalping's hourly cap left it out of rounds, and how
 */
import type {
  FleetStatus,
  OriginDelivery,
  OriginStatus,
  OriginStatusRow,
  ProbeSourceHealth,
} from '../../../../../shared/contracts/edges';
import type {
  CountryGroupGrade,
  CountryReason,
  CountryRoundResult,
  CountryStateFrom,
  ProbeFailureClass,
} from '../../../../../shared/contracts/edgeCodes';
import {
  codeExplain,
  codeFix,
  codeLabel,
  humanizeCode,
  plainWords,
  type Tone,
} from '../../../../lib/edgeCodes';
import type { EdgeCountryLine, LocationGradeCell } from './countryChecks';
import { RUN_NEED_STEP, runNeedStep } from './runNeedWords';
import { durationLabel, relativeTime } from './time';

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function runSentence(s: OriginStatus): string {
  const step = s.step ?? 1;
  const again = s.runKind === 'reprotect';
  const lead = again ? `Protecting again, step ${step} of 4` : `Setting up, step ${step} of 4`;
  if (s.kind === 'needs-you') {
    if (s.code === 'node_not_approved')
      return 'Every address works. Waiting for you to approve go-live.';
    return `${lead}. ${runNeedStep(s.code)}`;
  }
  return again ? `${lead}. Members keep what they have.` : `${lead}.`;
}

/** What to do about an attention item: the first sentence of its fix, in plain words. */
function nextStep(code: string): string {
  const fix = codeFix(code);
  const first = fix ? /^.+?[.!?](?=\s|$)/.exec(plainWords(fix))?.[0] : undefined;
  return first ?? 'Open the node to see what to do.';
}

export function originSentence(s: OriginStatus): string {
  if (s.runId) return runSentence(s);
  switch (s.kind) {
    case 'removing':
      return s.code === 'restore' ? 'Removing protection.' : 'Being removed.';
    case 'paused':
      return RUN_NEED_STEP.quarantined;
    case 'needs-you': {
      if (s.code === 'offline')
        return `${plural(s.offline, 'address is', 'addresses are')} offline.`;
      // Any run (a spare, a new address, a replacement), not only a replacement.
      if (s.code === 'rotation_failed')
        return 'The last run on this node failed. Open the node to see the step that failed.';
      // What is wrong, then what to do: never only that something waits.
      const code = s.code ?? 'needs_operator';
      return `${plainWords(codeLabel(code))}. ${nextStep(code)}`;
    }
    case 'off':
      return 'Protection is switched off (Advanced).';
    case 'not-live':
      // A fronted node has no direct address to fall back on.
      if (s.fronted)
        return s.published > 0
          ? 'Address ready, not live yet. Members get no address for this node until it goes live.'
          : 'Not protected yet. Members get no address for this node until it goes live.';
      return s.published > 0
        ? 'Address ready, not live yet. Members still use the direct address.'
        : 'Not protected yet. Members use the direct address.';
    case 'unprotected':
      return 'No address in use. Members get nothing.';
    case 'setting-up':
      return runSentence(s);
    case 'protected': {
      const spare = s.standbys > 0 ? `, ${plural(s.standbys, 'spare', 'spares')}` : '';
      return `Protected. ${plural(s.published, 'address', 'addresses')} in use${spare}.`;
    }
  }
}

export function fleetSentence(f: FleetStatus | null): string {
  if (!f) return '';
  switch (f.kind) {
    case 'empty':
      return 'No node is protected yet.';
    case 'needs-you':
      return `${plural(f.count, 'node needs', 'nodes need')} attention.`;
    case 'setting-up':
      return `Setting up ${plural(f.count, 'node', 'nodes')}.`;
    case 'not-live':
      return `${plural(f.count, 'node is', 'nodes are')} not live yet.`;
    case 'protected':
      return f.total === 1 ? 'Your node is protected.' : `All ${f.total} nodes protected.`;
    case 'partial':
      return `${f.protected} of ${plural(f.total, 'node', 'nodes')} protected.`;
  }
}

/**
 * The node page's note while one address is in use and FCP's own client check
 * replaces blocked ones. One address is a valid choice: a node set to one
 * states the tradeoff and asks for nothing; one set to more says what it lacks.
 */
export function oneAddressNote(desired: number): string {
  return desired <= 1
    ? 'One address in use, as set for this node. There is no backup address: if it is blocked, members in that country wait about 10 to 15 minutes for FCP to replace it.'
    : `1 of the ${desired} addresses wanted is in use. Until another one is, members have no backup address while FCP replaces a blocked one.`;
}

export interface DeliveryWords {
  tone: Tone;
  headline: string;
  /** What members on this origin get right now. */
  detail: string;
  /** Why, and what fixes it (null while nothing is wrong). */
  reason: string | null;
  fix: string | null;
}

const why = (code: string | null) =>
  code ? `${codeLabel(code)}. ${codeExplain(code)}`.trim() : null;

export function deliveryWords(d: OriginDelivery): DeliveryWords {
  switch (d.kind) {
    case 'manual':
      return {
        tone: 'muted',
        headline: 'Nothing to deliver',
        detail:
          'A manual origin has no subscriptions that FCP serves. Wire clients from the connection plan on this page.',
        reason: null,
        fix: null,
      };
    case 'direct':
      return {
        tone: 'muted',
        headline: 'Members use the direct address',
        detail:
          'Nothing is live through edges for this node yet, so members receive its own address. Going live switches them over.',
        reason: null,
        fix: null,
      };
    case 'serving':
      return {
        tone: 'success',
        headline: 'Serving through edges',
        detail:
          'Members on this origin receive edge addresses only. The origin address is never handed out.',
        reason: null,
        fix: null,
      };
    case 'degraded':
      return {
        tone: 'warning',
        headline: 'Serving, with a problem',
        detail:
          'Edges are published, but a sample subscription did not render cleanly. Members whose subscription hits the same problem are answered "temporarily unavailable".',
        reason: why(d.code),
        fix: d.code ? (codeFix(d.code) ?? null) : null,
      };
    case 'dark':
      return {
        tone: 'danger',
        headline: 'Members get nothing',
        detail:
          'Subscriptions on this origin are answered "temporarily unavailable" instead of the direct address. Clients keep their last configuration until something can be served.',
        reason: why(d.code),
        fix: d.code ? (codeFix(d.code) ?? null) : null,
      };
  }
}

export function statusOf(
  origins: readonly OriginStatusRow[] | undefined,
  slug: string,
): OriginStatus | null {
  return origins?.find((o) => o.relaySlug === slug)?.status ?? null;
}

// --- checks from each country -----------------------------------------------------------------

export interface WordsWithTone {
  label: string;
  sentence: string;
  tone: Tone;
}

/** What one round said about an edge from one country. */
export const ROUND_RESULT_WORDS: Record<CountryRoundResult, WordsWithTone> = {
  proven: {
    label: 'Works',
    sentence: 'Enough vantages there reached it, on more than one network.',
    tone: 'success',
  },
  blocked: {
    label: 'Blocked',
    sentence: 'Every vantage there failed while the control countries reached it.',
    tone: 'danger',
  },
  down: {
    label: 'Down',
    sentence: 'It failed from there and from the control countries too: broken, not blocked.',
    tone: 'warning',
  },
  unknown: {
    label: 'Not known',
    sentence: 'The checks from there did not decide anything.',
    tone: 'muted',
  },
};

/** Every reason the server records on a round or a track, as one sentence. */
export const COUNTRY_REASON_WORDS: Record<CountryReason, string> = {
  too_few: 'Too few vantages there answered, or they sat on too few networks, to decide anything.',
  no_evidence: 'No vantage there gave an answer: the probe services failed or had no probe there.',
  mixed: 'Some vantages there reached it and more than a third failed, so nothing is decided.',
  controls_failed:
    'Every vantage there failed, and so did the control countries: it looks broken, not blocked.',
  tls_unchecked:
    'It answers from there, but FCP has not yet checked its TLS handshake with the real name.',
  tls_failed: 'It answers from there, but FCP’s own TLS check with the real name failed.',
  needs_repeat:
    'One check said blocked. FCP checks again at least 30 minutes later before it counts.',
  group_blocked:
    'Blocked on its first check, because other addresses in its location are blocked there too.',
  country_wide:
    'Held as not known: most addresses checked from there failed at once, which looks like an outage or a probe problem, not a censor.',
  expired: 'Its last decided result is older than the checks keep, so it is not known again.',
  handshake:
    'Connections reach it from there, but no name gets through the handshake: it is blocked by name.',
  no_tcp_pairing:
    'A name check failed from there, but no fresh working connection check pairs with it, so it does not count yet.',
  recovered: 'Names get through from there again.',
  blocked:
    'Every vantage there failed in checks at least 30 minutes apart while the control countries reached it.',
  never_reached:
    'No check from there has ever reached it, from several networks over hours, while the node’s other addresses are reached from there.',
};

/** An edge with nothing decided of its own, in a location blocked there. */
const INHERITED_SENTENCE =
  'Nothing is decided for it yet, and other addresses in its location are blocked there.';

export function countryReasonSentence(code: string | null | undefined): string | null {
  if (!code) return null;
  return COUNTRY_REASON_WORDS[code as CountryReason] ?? `${humanizeCode(code)}.`;
}

/** Why a probe run could not measure. */
export const PROBE_FAILURE_WORDS: Record<ProbeFailureClass, { label: string; sentence: string }> = {
  auth: { label: 'Credential refused', sentence: 'The service refused the credential.' },
  rate_limited: {
    label: 'Rate limited',
    sentence: 'The service answered that too many requests were made.',
  },
  globalping_limit: {
    label: 'Out of Globalping credits',
    sentence:
      'The measurement would not fit in what Globalping allows this hour, so it was not started.',
  },
  no_key: { label: 'No key set', sentence: 'The source needs a key that is not set.' },
  no_vantages: {
    label: 'No probe there',
    sentence: 'The service had no probe in the places asked for.',
  },
  timeout: { label: 'Timed out', sentence: 'The service did not answer in time.' },
  service_error: { label: 'Service error', sentence: 'The service failed on its side.' },
  request_refused: { label: 'Request refused', sentence: 'The service refused the request.' },
  network: { label: 'Not reachable', sentence: 'FCP could not reach the service.' },
  no_route: {
    label: 'Not tested',
    sentence:
      'FCP’s own server has no route for this address family, so it could not test the address.',
  },
  error: { label: 'Failed', sentence: 'The run failed for another reason.' },
  no_results: { label: 'Nothing came back', sentence: 'The run finished without a single result.' },
  failed: { label: 'Failed', sentence: 'The run failed without saying why.' },
};

export function probeFailureWords(code: string | null | undefined): {
  label: string;
  sentence: string;
} {
  if (!code) return PROBE_FAILURE_WORDS.error;
  return (
    PROBE_FAILURE_WORDS[code as ProbeFailureClass] ?? {
      label: humanizeCode(code),
      sentence: PROBE_FAILURE_WORDS.error.sentence,
    }
  );
}

/** A provider location's grade in one country. */
export const GROUP_GRADE_WORDS: Record<CountryGroupGrade, WordsWithTone> = {
  proven: {
    label: 'Works',
    sentence: 'At least one address there works and none is blocked.',
    tone: 'success',
  },
  blocked: {
    label: 'Blocked',
    sentence:
      'At least two addresses there are blocked, at least half of those decided, none works.',
    tone: 'danger',
  },
  mixed: {
    label: 'Some addresses blocked',
    sentence: 'Some addresses there work and some are blocked.',
    tone: 'warning',
  },
  unknown: {
    label: 'Not checked yet',
    sentence: 'No address there has a decided result yet.',
    tone: 'muted',
  },
};

/** Where an edge's state in a country comes from. */
export const STATE_FROM_WORDS: Record<CountryStateFrom, string> = {
  edge: 'From its own checks',
  group: 'From its location',
  mark: 'Your mark',
};

/** The mark menu, and a mark in words. */
export const MARK_WORDS = {
  proven: 'Works there',
  blocked: 'Blocked there',
  clear: 'Use the checks',
} as const;

export interface CountryLineWords {
  country: string;
  label: string;
  tone: Tone;
  /** Why, in one sentence (null when the label says it all). */
  reason: string | null;
  /** Where the state comes from (null: nothing decided). */
  from: string | null;
  /** "Checked 12 min ago" (null: never checked from there). */
  checked: string | null;
  /** A mark that disagrees with the edge's own checks, in one sentence. */
  conflict: string | null;
}

const ago = (at: string | number | null | undefined, now: number) =>
  at === null || at === undefined ? null : relativeTime(at, now);

/**
 * One edge in one checked country: works / blocked since / down / not checked,
 * the reason, and where it comes from (its own checks, its location, a mark).
 * "Blocked for 5 h" counts from when its own state turned blocked there.
 */
export function countryLine(line: EdgeCountryLine, now: number): CountryLineWords {
  const { country, row } = line;
  const mark = line.edgeMark ?? line.groupMark;
  const lastAt = row?.lastRound?.at ?? row?.handshake.lastBatchAt ?? null;
  const checked = lastAt ? `Checked ${ago(lastAt, now)}` : null;
  const out = (
    label: string,
    tone: Tone,
    reason: string | null,
    from: string | null,
    conflict: string | null = null,
  ): CountryLineWords => ({ country, label, tone, reason, from, checked, conflict });

  if (mark) {
    const own = row?.combined ?? 'unknown';
    const conflict =
      own !== 'unknown' && own !== mark.state
        ? `The checks say ${own === 'blocked' ? 'blocked' : 'it works'}.`
        : null;
    return out(
      mark.state === 'proven' ? 'Works' : 'Blocked',
      mark.state === 'proven' ? 'success' : 'danger',
      null,
      line.edgeMark ? STATE_FROM_WORDS.mark : 'Your mark on its location',
      conflict,
    );
  }
  if (!row) return out('Not checked yet', 'muted', null, null);
  const eff = row.effective;
  if (eff?.state === 'blocked') {
    if (eff.from === 'group')
      return out('Blocked', 'danger', INHERITED_SENTENCE, STATE_FROM_WORDS.group);
    // How long it has been blocked: since its own state turned blocked there.
    const since = row.blockedSince
      ? ` for ${durationLabel(Math.max(0, now - new Date(row.blockedSince).getTime()))}`
      : '';
    const why =
      row.handshake.state === 'blocked'
        ? (row.handshake.reason ?? 'handshake')
        : (row.address.reason ?? 'blocked');
    return out(`Blocked${since}`, 'danger', countryReasonSentence(why), STATE_FROM_WORDS[eff.from]);
  }
  if (eff?.state === 'proven')
    return out(
      'Works',
      'success',
      countryReasonSentence(row.address.reason ?? row.handshake.reason),
      STATE_FROM_WORDS[eff.from],
    );
  // Nothing decided: say what the newest checks found.
  if (row.address.reason === 'needs_repeat' || row.handshake.reason === 'needs_repeat')
    return out('Blocked once, checking again', 'warning', COUNTRY_REASON_WORDS.needs_repeat, null);
  if (row.address.reason === 'country_wide')
    return out('Held, not known', 'warning', COUNTRY_REASON_WORDS.country_wide, null);
  if (row.lastRound?.result === 'down')
    return out(
      'Down',
      'warning',
      countryReasonSentence(row.lastRound.reason) ?? ROUND_RESULT_WORDS.down.sentence,
      null,
    );
  return out(
    'Not known',
    'muted',
    countryReasonSentence(row.address.reason ?? row.lastRound?.reason ?? row.handshake.reason),
    null,
  );
}

export interface CountryChip {
  country: string;
  /** Lower case, for "IR: works". */
  label: string;
  tone: Tone;
  /** The country's name, the reason and where it comes from, for a tooltip. */
  title: string;
}

/**
 * One address in one country as a short chip; `waiting` = its first round is
 * still out (a setup run checking the new address), so "checking" instead of
 * "not checked yet".
 */
export function countryChip(line: EdgeCountryLine, now: number, waiting: boolean): CountryChip {
  const w = countryLine(line, now);
  const fresh = !line.row && !line.edgeMark && !line.groupMark;
  return {
    country: line.country,
    label: fresh && waiting ? 'checking' : w.label.toLowerCase(),
    tone: w.tone,
    title: [w.from, w.reason, w.conflict].filter(Boolean).join(' '),
  };
}

export interface GradeWords {
  country: string;
  label: string;
  tone: Tone;
  /** "checked 2 h ago" (null: never). */
  age: string | null;
  /** The operator's mark in words ("Marked: blocked there"), or null. */
  mark: string | null;
  /** The mark itself (it wins over the grade wherever a short chip has room for one word). */
  markState: 'proven' | 'blocked' | null;
  /** The mark disagrees with the checks, in one sentence. */
  conflict: string | null;
}

/** One provider location in one country: Works, Blocked, Some addresses blocked, Not checked yet. */
export function gradeWords(cell: LocationGradeCell, now: number): GradeWords {
  const state = cell.grade?.state ?? 'unknown';
  const words = GROUP_GRADE_WORDS[state];
  // Checked but nothing decided is not the same as never checked.
  const label = state === 'unknown' && cell.checkedEdges > 0 ? 'Not known yet' : words.label;
  return {
    country: cell.country,
    label,
    tone: words.tone,
    age: cell.checkedAt ? `checked ${ago(cell.checkedAt, now)}` : null,
    mark: cell.mark ? `Marked: ${MARK_WORDS[cell.mark.state].toLowerCase()}` : null,
    markState: cell.mark?.state ?? null,
    conflict: cell.conflict
      ? `Your mark says ${cell.mark?.state === 'blocked' ? 'blocked' : 'it works'}; the checks say ${words.label.toLowerCase()}.`
      : null,
  };
}

export interface SourceWords {
  label: string;
  tone: Tone;
  detail: string;
}

type GlobalpingCap = NonNullable<ProbeSourceHealth['cap']>;

/**
 * Globalping's hourly cap holds it back: it left Globalping out of a round in
 * the last hour, or no further run fits (or not even one ever does).
 */
export function capHoldsBack(h: Pick<ProbeSourceHealth, 'cap'>): boolean {
  const c = h.cap;
  return !!c && (c.skipped > 0 || c.used + c.perRun > c.perHour);
}

/** How the cap holds Globalping back, in one sentence (the Probes page). */
function capSentence(c: GlobalpingCap): string {
  if (c.perHour < c.perRun)
    return `Its hourly cap (${c.perHour} tests) is smaller than one run (${c.perRun} tests), so it never runs.`;
  const use = `${c.used} of the ${c.perHour} tests allowed an hour were used in the last hour, and a run asks ${c.perRun}`;
  return c.skipped > 0
    ? `${c.skipped} of the ${c.rounds} rounds in the last hour ran without it: ${use}.`
    : `The next round runs without it: ${use}.`;
}

/** The same, as a clause for "Globalping last answered ..., and ..." (the Countries pages). */
export function capClause(c: GlobalpingCap): string {
  if (c.perHour < c.perRun) return 'its hourly cap is smaller than one run, so it never runs';
  return c.skipped > 0
    ? `its hourly cap left it out of ${c.skipped} of the ${c.rounds} rounds in the last hour`
    : `its hourly cap leaves no room for another run (${c.used} of ${c.perHour} tests used in the last hour, ${c.perRun} a run)`;
}

/** One probe source: working, failing (with its last failure in words), capped, or idle. */
export function sourceWords(h: ProbeSourceHealth, now: number): SourceWords {
  const counted = `${h.withEvidence} of ${h.runs} recent ${h.runs === 1 ? 'run' : 'runs'} brought evidence.`;
  const capUse = h.cap
    ? ` Its hourly cap: ${h.cap.used} of ${h.cap.perHour} tests used in the last hour, ${h.cap.perRun} a run.`
    : '';
  const last = h.lastError ? probeFailureWords(h.lastError) : null;
  if (h.failing)
    return {
      label: `Failing: ${last?.label.toLowerCase() ?? 'no evidence'}`,
      tone: 'danger',
      detail: `${last?.sentence ?? ''} ${h.streak} runs in a row brought nothing${
        h.lastOkAt ? `; the last good one was ${ago(h.lastOkAt, now)}` : ''
      }. The countries it alone covers read as not known.`.trim(),
    };
  // Before "no runs yet": a cap below one run is why nothing ever ran.
  if (h.cap && capHoldsBack(h))
    return {
      label:
        h.cap.perHour < h.cap.perRun ? 'Hourly cap below one run' : 'Held back by its hourly cap',
      tone: 'warning',
      detail: `${capSentence(h.cap)} The countries only it reaches go quiet until it runs again. Raise "Globalping tests per hour" (within what your Globalping account allows) or lower "Vantage points per country".${h.runs > 0 ? ` ${counted}` : ''}`,
    };
  if (h.runs === 0)
    return { label: 'No runs yet', tone: 'muted', detail: `Nothing has run yet.${capUse}` };
  if (h.streak > 0 && last)
    return {
      label: 'Working, with failures',
      tone: 'warning',
      detail: `The newest ${h.streak === 1 ? 'run' : `${h.streak} runs`} failed: ${last.label.toLowerCase()}. ${counted}${capUse}`,
    };
  return {
    label: 'Working',
    tone: 'success',
    detail: `${counted}${h.lastOkAt ? ` The last good run was ${ago(h.lastOkAt, now)}.` : ''}${capUse}`,
  };
}
