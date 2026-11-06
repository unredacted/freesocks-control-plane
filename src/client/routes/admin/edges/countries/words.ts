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
 *   staleAnswersLine                 probe sources whose last answer about an address is too old
 *   REAL_HOST_WORDS / realHostLine / addressRealHostLine   the real-host controls
 *   targetAddsLine / addressTimingLine   the handshake gap per transport and per address
 *   handedWords                      what a member there is handed on one transport
 *   switchNotes                      what is off, and what that leaves the view without
 *   coverageNote / coverageLines     which outside probes answer from there, and why one went quiet
 *   namePoolLines                    whether Globalping has enough probes there to judge a name
 *   addressListsLine / namesOnListsLine   what the watched allowlists say about the addresses, and
 *                                    how many of a transport's names the lists hold
 *   countryLabel / percent           display helpers
 */
import type {
  CountryViewAddress,
  CountryViewCoverage,
  CountryViewHanded,
  CountryViewListener,
  CountryViewMeantFor,
  CountryViewName,
  CountryViewNamePool,
  CountryViewSwitches,
  CountryViewTotals,
  ProbeSourceHealth,
} from '@shared/contracts/edges';
import type {
  CountryListMarkState,
  CountryTrackState,
  CountryViewAddressBasis,
  CountryViewHandedReason,
  CountryViewNameBasis,
  RealHostReading,
} from '@shared/contracts/edgeCodes';
import { countryName } from '@client/lib/countries';
import { durationLabel, relativeTime } from '../lib/time';
import {
  capClause,
  capHoldsBack,
  countryReasonSentence,
  GROUP_GRADE_WORDS,
  probeFailureWords,
  ROUND_RESULT_WORDS,
} from '../lib/statusWords';
import { VANTAGE_REASON_WORDS } from '../names/lib/words';
import { PROBE_SOURCE_LABELS } from '../probes/matrix';
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
    if (p.verdict === 'mixed')
      return `${base} Some vantages there reached it and some did not, so it is not judged.`;
    if (p.verdict === 'unknown' && p.okVantages > 0 && p.failVantages === 0)
      return `${base} Too few vantages there reached it to call it working: that takes one on a residential network, or two others.`;
    if (p.verdict === 'unknown' && p.failVantages > 0)
      return `${base} Probes there failed, but from too few networks to call it blocked.`;
  }
  if (a.basis === 'checks') {
    const reason = countryReasonSentence(a.evidence.address?.reason);
    if (reason && a.state === 'blocked') return `${base} ${reason}`;
  }
  // Probes did answer about it from there, but too long ago to count.
  if (a.basis === 'none' && a.evidence.answers.some((x) => x.lastAt !== null))
    return 'No probe answer about it from there is recent enough to count.';
  return base;
}

/**
 * Latency ordering on: how far the whole path is from the country through the
 * address to the node (null: no figure, or latency ordering is off).
 */
export function pathLine(a: Pick<CountryViewAddress, 'path'>, country: string): string | null {
  if (!a.path) return null;
  const how = a.path.measured
    ? `timed from ${countryLabel(country)} to the address, the rest from the map`
    : 'from the map';
  return `About ${a.path.ms} ms over the whole path to the node (${how}).`;
}

/**
 * When the country dropped out of the address's probe summary: the sources
 * whose last answer about it from there is too old to count (null: the
 * summary still holds the country, which `probesLine` shows with its age, or
 * no source ever answered). The summary is judged when it was last refreshed,
 * so an answer it still holds may already be past the window now.
 */
export function staleAnswersLine(a: CountryViewAddress, now = Date.now()): string | null {
  if (a.evidence.probes) return null;
  const stale = a.evidence.answers.filter((x) => x.lastAt !== null && !x.fresh);
  if (stale.length === 0) return null;
  return stale
    .map(
      (x) =>
        `${sourceLabel(x.source)} last answered about it from here ${relativeTime(x.lastAt, now)}, too long ago to count.`,
    )
    .join(' ');
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

/**
 * The real-host controls: the same name presented to FCP's address and to the
 * name's real site, from the same vantages, read together.
 */
export const REAL_HOST_WORDS: Record<RealHostReading, { short: string; sentence: string }> = {
  works: {
    short: 'works',
    sentence: 'The name gets through to its real site and to this address alike.',
  },
  name_blocked: {
    short: 'the name is blocked',
    sentence:
      'The name fails on its real site too, from vantages that reach other names: the name itself is blocked here.',
  },
  address_blocked: {
    short: 'the address is blocked',
    sentence:
      'Its real site works from the same vantages, but this address does not even connect: the address is blocked here, not the name.',
  },
  ip_name_match: {
    short: 'the name is checked against its real address',
    sentence:
      'Its real site works from the same vantages, and this address connects, but the handshake with the name fails: the censor likely checks the name against its real address or network.',
  },
  ours_only: {
    short: 'works only here',
    sentence:
      'Its real site cannot be reached from here, but the name gets through on this address.',
  },
  mixed: { short: 'mixed', sentence: 'The vantages disagree.' },
  thin: { short: 'too few answers', sentence: 'Too few vantages answered to say anything.' },
};

/** A name's real-host reading in one line (null: never checked against its real site). */
export function realHostLine(n: CountryViewName, now = Date.now()): string | null {
  const r = n.realHost;
  if (!r) return null;
  const site = r.realAddress ? ` against ${r.realAddress}` : '';
  const timed = r.timing
    ? ` Beyond one round trip, its handshake took ${r.timing.oursMs} ms on this address and ${r.timing.realMs} ms on the real site (${plural(r.timing.pairs, 'vantage')}).`
    : '';
  return `Real-site check${site}: ${REAL_HOST_WORDS[r.reading].sentence} ${plural(r.vantages, 'vantage')} on ${plural(r.networks, 'network')}, ${relativeTime(r.at, now)}.${timed}`;
}

/** The flag's threshold in ms (`TARGET_ADDS_FLAG_MS` in convex/lib/edges/sni/realHost.ts; a test keeps them equal). */
export const TARGET_ADDS_FLAG_MS = 50;

/** The proposed threshold the page states with the figure (the owner decides). */
export const TARGET_ADDS_FLAG_WORDS =
  'Over 50 ms on at least 3 vantages is flagged: a gap that size is something a censor can measure (a proposed threshold).';

/**
 * How much longer a handshake takes from here on a transport's addresses than
 * on its names' real sites, in one line (null: no timed real-host pair yet).
 * The gap is an address's leg to the node plus the node's leg to the target,
 * so the flag names the leg the addresses point at: one address under the
 * flag shows the node's leg is short.
 */
export function targetAddsLine(l: CountryViewListener, now = Date.now()): string | null {
  const t = l.targetAdds;
  if (!t) return null;
  const head =
    t.ms <= 0
      ? 'A handshake on this transport’s addresses takes no measurably longer from here than on its names’ real sites'
      : `A handshake on this transport’s addresses takes about ${t.ms} ms longer from here than on its names’ real sites`;
  const a = t.addresses;
  const spread =
    a && a.timed > 1 && a.highMs - a.lowMs >= TARGET_ADDS_FLAG_MS
      ? ` By address it ranges from ${a.lowMs} to ${a.highMs} ms (see each address’s evidence).`
      : '';
  const flag = !t.flagged
    ? ''
    : a && a.clear > 0
      ? ' Flagged: the slow addresses sit far from the node. An address under the threshold shows the node’s own leg to its target is short.'
      : ' Flagged: the node sits far from its target, or every address measured sits far from the node.';
  return `${head} (the addresses ${t.oursMs} ms beyond one round trip, the names’ real sites ${t.realMs} ms; ${plural(t.pairs, 'vantage')}, ${plural(t.names, 'name')}, ${relativeTime(t.at, now)}).${spread}${flag}`;
}

/**
 * The handshake gap on one address, in one line (null: no timed pair on it).
 * On an edge it is the edge's leg to the node plus the node's leg to the
 * target; on the node itself only the latter.
 */
export function addressTimingLine(a: CountryViewAddress, now = Date.now()): string | null {
  const t = a.evidence.realHost?.timing;
  if (!t) return null;
  const head =
    t.ms <= 0
      ? 'A handshake on it takes no measurably longer from here than on the names’ real sites'
      : `A handshake on it takes about ${t.ms} ms longer from here than on the names’ real sites`;
  const flag = !t.flagged
    ? ''
    : a.kind === 'origin'
      ? ' Flagged: the node sits far from its target.'
      : ' Flagged: this address sits far from the node (an address that accepts the connection itself puts its leg to the node inside the handshake), or the node far from its target.';
  return `${head} (it ${t.oursMs} ms beyond one round trip, the real sites ${t.realMs} ms; ${plural(t.pairs, 'vantage')}, ${plural(t.names, 'name')}, ${relativeTime(t.at, now)}).${flag}`;
}

/** What the real-host controls of the names checked on an address say about it. */
export function addressRealHostLine(a: CountryViewAddress, now = Date.now()): string | null {
  const r = a.evidence.realHost;
  if (!r || r.names.length === 0) return null;
  const by = new Map<RealHostReading, number>();
  for (const n of r.names) by.set(n.reading, (by.get(n.reading) ?? 0) + 1);
  const parts = [...by.entries()]
    .sort((x, y) => y[1] - x[1])
    .map(([reading, count]) => `${count} ${REAL_HOST_WORDS[reading].short}`);
  return `Real-site checks of ${plural(r.names.length, 'name')} on it: ${parts.join(', ')}, ${relativeTime(r.at, now)}.`;
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

/** What the country lists for this country say about a name (null: none holds it). */
export function listsLine(n: CountryViewName): string | null {
  const l = n.lists;
  if (!l) return null;
  if (l.allow && l.block) return 'Country lists for here disagree about this name.';
  if (l.block)
    return l.suggestion
      ? 'A block list for here holds this name, so it may be blocked here. Mark it on its family page.'
      : 'A block list for here holds this name.';
  return 'A list of what works here holds this name. That is about the name only, not the address.';
}

/** One watched allowlist about one address (docs/edges.md "Edge addresses against allowlists"). */
export const LIST_MARK_WORDS: Record<CountryListMarkState, string> = {
  listed: 'on the list',
  left: 'left the list',
  not_listed: 'not on the list',
  checking: 'not checked yet against the list',
};

/**
 * What this country's watched allowlists say about an address, or null when
 * none watches it. The family is said only when the row shows both.
 */
export function addressListsLine(a: CountryViewAddress, now: number): string | null {
  if (a.lists.length === 0) return null;
  const parts = a.lists.map((m) => {
    const when = m.state === 'left' && m.at !== null ? ` ${relativeTime(m.at, now)}` : '';
    const family = a.v6 ? ` (${m.family === 'v6' ? 'IPv6' : 'IPv4'})` : '';
    return `${LIST_MARK_WORDS[m.state]} ${m.label}${when}${family}`;
  });
  const line = parts.join('; ');
  return `${line.charAt(0).toUpperCase()}${line.slice(1)}.`;
}

/**
 * How many of a transport's active server names a list of what works here
 * holds, once a list for here says anything about its names or addresses.
 */
export function namesOnListsLine(l: CountryViewListener): string | null {
  const active = l.names.filter((n) => n.status === 'active');
  if (active.length === 0) return null;
  if (!l.addresses.some((a) => a.lists.length > 0) && !active.some((n) => n.lists)) return null;
  const held = active.filter((n) => n.lists?.allow).length;
  return `${held} of ${active.length} server ${active.length === 1 ? 'name is' : 'names are'} on a list of what works here. Where only listed addresses and names get through, only those work.`;
}

const HANDED_REASON_WORDS: Record<CountryViewHandedReason, string> = {
  render_off: 'Members are not handed fronted addresses: rendering is off.',
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
  if (m.steered && m.onMeantFirst > 0)
    out.push(
      `${percent(m.onMeantFirst)} of members here start on a location meant for this country.`,
    );
  return out;
}

/**
 * One location meant for this country (docs/edges.md "Locations meant for a
 * country"): its state here and its addresses in use, per node.
 */
export function meantForWords(l: CountryViewMeantFor): { state: string; detail: string } {
  const inUse = l.nodes.reduce((n, x) => n + x.published, 0);
  const state = l.blocked
    ? 'Blocked here: members here get other addresses.'
    : l.grade === 'proven' || l.mark === 'proven'
      ? 'Works here.'
      : 'Not known here yet.';
  const why =
    l.mark === 'blocked'
      ? ' Marked blocked here.'
      : l.mark === 'proven'
        ? ' Marked working here.'
        : l.grade === 'blocked'
          ? ' Its addresses are graded blocked here.'
          : '';
  const detail =
    inUse === 0
      ? 'No node has an address in use there yet.'
      : l.nodes
          .map(
            (n) =>
              `${n.label ?? n.relaySlug}: ${plural(n.published, 'address', 'addresses')} in use${
                n.blocked > 0 ? `, ${n.blocked} blocked here` : ''
              }`,
          )
          .join('; ') + '.';
  return { state: `${state}${why}`, detail };
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
  if (!s.render) out.push('Rendering is off: members are not handed fronted addresses.');
  if (s.render && !s.steering)
    out.push('Delivery by country is off: members are not steered away from blocked addresses.');
  if (!s.names) out.push('Server name families are off: names are not judged per country.');
  else if (nameChecksHere === false)
    out.push(
      'Names are not checked from inside this country (opt in under Settings, Censored countries).',
    );
  else if (nameChecksHere && !s.realHost)
    out.push(
      'Real-site checks are off: a failing name is not compared with its real site (Server names, Checks from inside countries).',
    );
  return out;
}

// --- which outside probes answer from there -----------------------------------------------------

const sourceLabel = (s: string) => PROBE_SOURCE_LABELS[s] ?? s;

/** "A", "A and B", "A, B and C". */
function andList(xs: readonly string[]): string {
  return xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`;
}

/** Why a source in use went quiet, from its health (null: nothing known). */
function quietWhy(source: string, health: readonly ProbeSourceHealth[]): string | null {
  const h = health.find((x) => x.source === source);
  if (!h) return null;
  if (h.failing) return `it is failing (${probeFailureWords(h.lastError).label.toLowerCase()})`;
  if (h.cap && capHoldsBack(h)) return capClause(h.cap);
  return null;
}

type SourceCoverage = CountryViewCoverage['sources'][number];

function quietPart(s: SourceCoverage, health: readonly ProbeSourceHealth[], now: number): string {
  const why = quietWhy(s.source, health);
  return `${sourceLabel(s.source)} last answered ${relativeTime(s.lastAt, now)}${why ? `, and ${why}` : ''}`;
}

const NOT_ASKED =
  'Edges are not checked from here: "Check edges from here" is off for this country (Settings, Censored countries).';

/**
 * One sentence for the countries list when the outside probes from there fall
 * short (null: every source in use that ever answered from there still does,
 * or the probes are off, which the page says once).
 */
export function coverageNote(
  c: CountryViewCoverage,
  health: readonly ProbeSourceHealth[],
  probesOn: boolean,
  now = Date.now(),
): string | null {
  if (!probesOn) return null;
  if (!c.asked) return 'Edges are not checked from here.';
  if (c.sources.length === 0) return 'No outside probe source is in use.';
  const fresh = c.sources.filter((s) => s.fresh);
  const quiet = c.sources.filter((s) => !s.fresh && s.lastAt !== null);
  if (fresh.length === 0 && quiet.length === 0)
    return 'No probe has answered from here yet: the sources in use may have no vantage here.';
  const parts = quiet.map((s) => quietPart(s, health, now)).join('; ');
  if (fresh.length === 0)
    return `No probe has answered from here in the last ${durationLabel(c.windowMs)}: ${parts}.`;
  if (quiet.length === 0) return null;
  return `Only ${andList(fresh.map((s) => sourceLabel(s.source)))} answers from here now: ${parts}.`;
}

/** The outside probes from there, source by source (the country page; empty: probes off). */
export function coverageLines(
  c: CountryViewCoverage,
  health: readonly ProbeSourceHealth[],
  probesOn: boolean,
  now = Date.now(),
): string[] {
  if (!probesOn) return [];
  if (!c.asked) return [NOT_ASKED];
  if (c.sources.length === 0)
    return ['No outside probe source is in use, so nothing measures the addresses from here.'];
  const out: string[] = [];
  const fresh = c.sources.filter((s) => s.fresh);
  const window = durationLabel(c.windowMs);
  if (fresh.length === 0)
    out.push(
      `No probe has answered from here in the last ${window}, so the probes judge nothing here.`,
    );
  else
    out.push(
      `Answering from here: ${andList(fresh.map((s) => `${sourceLabel(s.source)} (${relativeTime(s.lastAt, now)})`))}.`,
    );
  for (const s of c.sources) {
    if (s.fresh) continue;
    out.push(
      s.lastAt === null
        ? `${sourceLabel(s.source)} has never answered from here: it may have no vantage here.`
        : `${quietPart(s, health, now)}; an answer counts for ${window}.`,
    );
  }
  return out;
}

// --- whether a name can be judged from there --------------------------------------------------

/**
 * Which Globalping probes the newest name-check batch from there used, in
 * words (empty: nothing to say, no batch yet, or the note no longer describes
 * the checks). Too few home-network probes for a verdict: the checks also use
 * other probes. Fewer probes there in all than a verdict needs: names checked
 * from there stay not judged, and the page says why (the floor is not lowered
 * for one country).
 */
export function namePoolLines(p: CountryViewNamePool | null | undefined): string[] {
  if (!p) return [];
  const out: string[] = [];
  const needs = plural(p.needs, 'vantage');
  const home =
    p.eyeball === 0
      ? 'no home-network probe'
      : p.eyeball === 1
        ? 'only one home-network probe'
        : `only ${p.eyeball} home-network probes`;
  if (p.mode === 'topped_up')
    out.push(
      `Globalping has ${home} here, fewer than the ${needs} a name verdict needs, so the name checks here also use data-centre probes.`,
    );
  else if (p.mode === 'any' && p.preferEyeball)
    out.push(
      `Globalping has ${home} here, fewer than the ${needs} a name verdict needs, so the name checks here use any probe there.`,
    );
  if (p.total < p.needs)
    out.push(
      `Globalping has ${p.total === 0 ? 'no probe' : p.total === 1 ? 'only one probe' : `only ${p.total} probes`} here in all and a name verdict needs ${needs}, so server names checked from here stay not judged on Globalping alone. The floor is not lowered for one country: so few probes cannot tell a blocked name from a broken probe or network.`,
    );
  return out;
}

/** One country's totals in a sentence (the countries list). */
export function totalsLine(t: CountryViewTotals): string {
  const a = t.addresses;
  const n = t.names;
  const total = a.proven + a.blocked + a.unknown;
  const addr = `${a.proven} of ${plural(total, 'published address', 'published addresses')} ${a.proven === 1 ? 'works' : 'work'}, ${a.blocked} blocked${a.unknown > 0 ? `, ${a.unknown} not known` : ''}`;
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
