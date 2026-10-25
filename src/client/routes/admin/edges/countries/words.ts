/**
 * The country view's words (pure; unit-tested). Every sentence the Countries
 * pages show lives here: what an address or a name counts as from a country
 * and why, how old that is, and what a member there is handed.
 *
 * Exports:
 *   STATE_WORDS                      proven / blocked / unknown as a label, a dot and a tone
 *   ADDRESS_BASIS_WORDS / addressWhy  why an address counts as it does, in one sentence
 *   NAME_BASIS_WORDS / nameWhy        why a name counts as it does
 *   probesLine / roundLine / checksLine / reportsLine   one piece of evidence each
 *   handedWords                      what a member there is handed on one transport
 *   switchNotes                      what is off, and what that leaves the view without
 *   countryLabel / percent           display helpers
 */
import type {
  CountryViewAddress,
  CountryViewHanded,
  CountryViewName,
  CountryViewSwitches,
  CountryViewTotals,
} from '@shared/contracts/edges';
import type {
  CountryTrackState,
  CountryViewAddressBasis,
  CountryViewHandedReason,
  CountryViewNameBasis,
} from '@shared/contracts/edgeCodes';
import { countryName } from '@client/lib/countries';
import { durationLabel, relativeTime } from '../lib/time';
import { countryReasonSentence, GROUP_GRADE_WORDS, ROUND_RESULT_WORDS } from '../lib/statusWords';
import { VANTAGE_REASON_WORDS } from '../names/lib/words';
import type { Dot } from '../simple/runStages';
import type { Tone } from '@client/lib/edgeCodes';

export const STATE_WORDS: Record<CountryTrackState, { label: string; dot: Dot; tone: Tone }> = {
  proven: { label: 'Works', dot: 'green', tone: 'success' },
  blocked: { label: 'Blocked', dot: 'red', tone: 'danger' },
  unknown: { label: 'Not known', dot: 'grey', tone: 'muted' },
};

/** "Iran (IR)"; an unknown code stays the code. */
export function countryLabel(code: string): string {
  const name = countryName(code, 'en');
  return name && name !== code ? `${name} (${code})` : code;
}

/** 0.4167 -> "42%"; tiny non-zero shares never read as 0%. */
export function percent(share: number): string {
  if (share <= 0) return '0%';
  if (share < 0.01) return 'under 1%';
  return `${Math.round(share * 100)}%`;
}

const plural = (n: number, word: string, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/** How long a graded state still stands, e.g. "Stands for another 12 d 23 h." */
export function untilLine(until: number | null, now = Date.now()): string | null {
  if (until === null) return null;
  return until > now ? `Stands for another ${durationLabel(until - now)}.` : 'Due to lapse now.';
}

/** One sentence per basis: why an address counts as it does from there. */
export const ADDRESS_BASIS_WORDS: Record<CountryViewAddressBasis, string> = {
  mark: 'An operator marked this address for this country.',
  location_mark: 'An operator marked its whole provider location for this country.',
  checks: 'Its own checks from there, with control countries beside them, decided it.',
  handshake:
    'Connections reach it from there, but no server name gets through the handshake: blocked by name.',
  never_reached:
    'Nothing from there has ever reached it, over hours and from several networks, while it is reached elsewhere.',
  location: 'Nothing is decided for it yet, and its provider location is blocked there.',
  probes:
    'Not graded: this is what the outside probes alone see from there. Nothing acts on it until the country checks decide.',
  none: 'Nothing has checked it from there yet.',
};

/** Why an address counts as it does, with the reason the checks recorded when there is one. */
export function addressWhy(a: CountryViewAddress): string {
  const base = ADDRESS_BASIS_WORDS[a.basis];
  if (a.basis === 'probes' && a.evidence.probes) {
    const p = a.evidence.probes;
    if (a.state === 'blocked')
      return `${base} Every probe there failed while other countries reached it.`;
    if (p.verdict === 'unreachable')
      return `${base} Probes there failed, but it fails elsewhere too: broken, not blocked.`;
  }
  if (a.basis === 'checks') {
    const reason = countryReasonSentence(a.evidence.address?.reason);
    if (reason && a.state === 'blocked') return `${base} ${reason}`;
  }
  return base;
}

/** One sentence per basis: why a name counts as it does from there. */
export const NAME_BASIS_WORDS: Record<CountryViewNameBasis, string> = {
  mark: 'An operator marked it for this country.',
  checks_mark: 'The checks from inside the country marked it by themselves.',
  checks:
    'The checks from inside the country suggest this. Not applied: members are not affected yet.',
  none: 'Nobody has judged it there.',
};

export function nameWhy(n: CountryViewName): string {
  return NAME_BASIS_WORDS[n.basis];
}

/** The outside probes from there, in one line (null: none on record). */
export function probesLine(a: CountryViewAddress, now = Date.now()): string | null {
  const p = a.evidence.probes;
  if (!p) return null;
  const when = relativeTime(p.lastAt, now);
  const verdict =
    p.verdict === 'reachable'
      ? 'reached it'
      : p.verdict === 'unreachable'
        ? 'could not reach it'
        : p.verdict === 'mixed'
          ? 'gave mixed answers'
          : 'decided nothing';
  const counts = `${plural(p.okVantages, 'vantage')} reached it, ${p.failVantages} failed`;
  const never = p.neverReached
    ? ` Never reached from there: ${plural(p.neverReached.checks, 'failing check')} on ${plural(p.neverReached.networks, 'network')} since ${relativeTime(p.neverReached.since, now)}.`
    : '';
  return `Probes ${verdict} (${counts}), ${when}.${never}`;
}

/** The last round with controls, in one line (null: no round on record). */
export function roundLine(a: CountryViewAddress, now = Date.now()): string | null {
  const r = a.evidence.round;
  if (!r) return null;
  const words = ROUND_RESULT_WORDS[r.result as keyof typeof ROUND_RESULT_WORDS];
  const label = words?.label ?? r.result;
  return `Last round: ${label.toLowerCase()}, ${r.ok} reached and ${r.fail} failed on ${plural(r.networks, 'network')}, ${plural(r.controlsOk, 'control')} reached it, ${relativeTime(r.at, now)}.`;
}

/** The handshake track (name batches paired with working connections), in one line. */
export function handshakeLine(a: CountryViewAddress, now = Date.now()): string | null {
  const h = a.evidence.handshake;
  if (!h) return null;
  if (h.state === 'blocked')
    return `Name checks: no name got through in ${plural(h.batches, 'paired check')}, last ${relativeTime(h.lastBatchAt ?? null, now)}.`;
  return h.lastBatchAt
    ? `Name checks: names got through, last ${relativeTime(h.lastBatchAt, now)}.`
    : null;
}

/** Its provider location's grade there, in one line (null: not graded). */
export function gradeLine(a: CountryViewAddress, now = Date.now()): string | null {
  const g = a.evidence.grade;
  if (!g) return null;
  const words = GROUP_GRADE_WORDS[g.state as keyof typeof GROUP_GRADE_WORDS];
  const label = (words?.label ?? g.state).toLowerCase();
  const until = g.until && g.until > now ? `, for another ${durationLabel(g.until - now)}` : '';
  return `Its provider location here: ${label}, ${g.counts.blocked} of ${plural(g.counts.edges, 'address', 'addresses')} blocked and ${g.counts.proven} working${until}.`;
}

/** A mark, in one line. */
export function markLine(a: CountryViewAddress, now = Date.now()): string | null {
  const m = a.evidence.mark;
  if (!m) return null;
  const what = m.scope === 'edge' ? 'this address' : 'its provider location';
  return `An operator marked ${what} ${m.state === 'proven' ? 'working' : 'blocked'} here, ${relativeTime(m.at, now)}.`;
}

/** What the checks from inside saw for a name, in one line (null: never checked from there). */
export function checksLine(n: CountryViewName, now = Date.now()): string | null {
  const c = n.checks;
  if (!c) return null;
  const when = c.lastAt ? `last ${relativeTime(c.lastAt, now)}` : 'none finished yet';
  let seen: string;
  if (c.latest === 'ok')
    seen = `the handshake completed from ${plural(c.okVantages, 'vantage')} on ${plural(c.okNetworks, 'network')}`;
  else if (c.latest === 'failing')
    seen =
      c.failVantages > 0
        ? `failed from ${plural(c.failVantages, 'vantage')} on ${plural(c.failNetworks, 'network')} while other names got through`
        : 'no name of that address got through, so the address may be the problem';
  else if (c.latest === 'mixed') seen = 'some checks got through and some did not';
  else seen = 'nothing conclusive yet';
  const reason =
    !c.suggestion && c.reason
      ? ` ${VANTAGE_REASON_WORDS[c.reason as keyof typeof VANTAGE_REASON_WORDS] ?? ''}`
      : '';
  return `Checks from inside: ${seen} (${when}).${reason}`.trimEnd();
}

/** Member reports about a name from there (null: none in the window). */
export function reportsLine(n: CountryViewName): string | null {
  const r = n.reports;
  if (!r) return null;
  const weight = Number.isInteger(r.weight) ? String(r.weight) : r.weight.toFixed(1);
  return r.suspect
    ? `Members there report problems with it more than with its other names (${weight} reports).`
    : `Members there reported problems that may involve it (${weight} reports), no more than its other names.`;
}

const HANDED_REASON_WORDS: Record<CountryViewHandedReason, string> = {
  render_off: 'Members are not handed protected addresses: rendering is off.',
  origin_disabled: 'This origin is switched off.',
  no_published: 'No published address serves this transport, so members get nothing through it.',
};

/**
 * What a member there is handed on one transport. The sample is the
 * assignment itself run over synthetic keys, so the shares are approximate.
 */
export function handedWords(m: CountryViewHanded): string[] {
  if (!m.computed) return [m.reason ? HANDED_REASON_WORDS[m.reason] : 'Nothing is handed out.'];
  const out: string[] = [];
  const addresses = m.primary.length;
  out.push(
    m.steered
      ? `Addresses are chosen for this country: members here are spread over ${plural(addresses, 'address', 'addresses')}, blocked ones only when nothing else is left.`
      : `Addresses are not chosen by country here: members here are spread over ${plural(addresses, 'address', 'addresses')}, whatever they count as here.`,
  );
  if (m.onBlockedAddress > 0)
    out.push(
      m.onBlockedFirst > 0
        ? `${percent(m.onBlockedAddress)} of members here hold an address blocked here (${percent(m.onBlockedFirst)} as their first one).`
        : `${percent(m.onBlockedAddress)} of members here hold an address blocked here, as their backup only.`,
    );
  if (m.none > 0)
    out.push(`${percent(m.none)} of members here get no address at all on this transport.`);
  out.push(
    m.namesByCountry
      ? 'Server names are chosen for this country: never one blocked here.'
      : 'Server names are not chosen for this country here (a transport on the legacy pick, or a country off the list).',
  );
  if (m.onBlockedName > 0)
    out.push(`${percent(m.onBlockedName)} of members here hold a server name blocked here.`);
  return out;
}

/** Said once per country page: who the "handed" lines describe. */
export const HANDED_SCOPE =
  'What a member is handed below is for members of the freedom modes whose country is set to this one, worked out by the same assignment their subscriptions use over a sample of keys. Members of other modes get names and addresses chosen without a country.';

/** What is switched off, and what the view lacks because of it. */
export function switchNotes(s: CountryViewSwitches, nameChecksHere: boolean | null): string[] {
  const out: string[] = [];
  if (!s.probes) out.push('Probes are off: nothing measures the addresses from outside.');
  if (!s.countryChecks)
    out.push(
      'Country checks are off: no address is graded, so the states below come from the outside probes alone and delivery does not act on them.',
    );
  if (!s.render) out.push('Rendering is off: members are not handed protected addresses.');
  if (s.render && !s.steering)
    out.push('Delivery by country is off: members are not steered away from blocked addresses.');
  if (!s.names) out.push('Server name families are off: names are not judged per country.');
  else if (nameChecksHere === false)
    out.push(
      'Names are not checked from inside this country (opt in under Settings, Censored countries).',
    );
  return out;
}

/** One country's totals in a sentence (the countries list). */
export function totalsLine(t: CountryViewTotals): string {
  const a = t.addresses;
  const n = t.names;
  const total = a.proven + a.blocked + a.unknown;
  const addr = `${a.proven} of ${plural(total, 'published address', 'published addresses')} ${a.proven === 1 ? 'works' : 'work'}, ${a.blocked} blocked`;
  const names = `${plural(n.proven, 'server name', 'server names')} ${n.proven === 1 ? 'works' : 'work'}, ${n.blocked} blocked, ${n.unknown} not judged`;
  return `${addr}. ${names}.`;
}

/** The dot of a country in the list: red when a node is at risk, amber when anything is blocked. */
export function countryDot(t: CountryViewTotals): Dot {
  if (t.originsAtRisk > 0) return 'red';
  if (t.addresses.blocked > 0 || t.names.blocked > 0) return 'amber';
  if (t.addresses.proven > 0) return 'green';
  return 'grey';
}
