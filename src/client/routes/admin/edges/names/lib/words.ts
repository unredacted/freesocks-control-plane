/**
 * Wording and small decisions for Admin -> Servers -> SNIs (pure;
 * unit-tested). A name goes through three separate facts and the page never
 * blurs them: the cover site serves it (checked), a node accepts it (proven
 * by a test link), and it works from a country (the operator's judgement).
 */
import type {
  EdgeNetworkView,
  SniImportResult,
  SniNameRow,
  SniVantageApplied,
  SniVantageRequested,
  SniVantageRow,
} from '../../../../../../shared/contracts/sni';
import { SNI_VANTAGE_REASONS } from '../../../../../../shared/contracts/sni';

export type Dot = 'green' | 'amber' | 'red' | 'grey';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// --- networks (docs/edges.md "Networks") ---------------------------------------------------

/** One line under a network: its ASNs, how many ranges, when they were read, what uses it. */
export function networkLine(n: EdgeNetworkView, now = Date.now()): string {
  const parts: string[] = [];
  if (n.asns.length > 0) parts.push(n.asns.map((a) => `AS${a}`).join(', '));
  const count = n.ranges.v4 + n.ranges.v6;
  parts.push(
    count === 0
      ? 'no ranges yet'
      : `${plural(count, 'range')}${n.truncated ? ' (more were announced than are kept)' : ''}`,
  );
  if (n.manualPrefixes.length > 0) parts.push(`${n.manualPrefixes.length} by hand`);
  if (n.refreshError)
    parts.push(`the last read failed (${NETWORK_REFRESH_WORDS[n.refreshError] ?? n.refreshError})`);
  else if (n.refreshedAt) parts.push(`read ${ago(n.refreshedAt, now)}`);
  else if (n.asns.length > 0) parts.push('not read yet');
  parts.push(
    n.families.length === 0
      ? 'no SNI list on it'
      : `${plural(n.families.length, 'SNI list')} on it`,
  );
  if (n.locations.length > 0) parts.push(`${plural(n.locations.length, 'location')} on it`);
  return parts.join(' · ');
}

/** Why a read of a network's ranges failed (convex/edgeNetworks.ts `announcedOf`). */
export const NETWORK_REFRESH_WORDS: Record<string, string> = {
  timeout: 'no answer in time',
  rate_limited: 'asked too often',
  service_error: 'the service refused',
  too_large: 'the answer was too large',
  bad_answer: 'the answer was not a list of ranges',
  unreachable: 'the service could not be reached',
};

/** ASNs typed as `AS64500 64501, as64502`: numbers, or null when one is not an ASN. */
export function parseAsns(text: string, max = 8): number[] | null {
  const out: number[] = [];
  for (const t of text.split(/[\s,]+/).filter(Boolean)) {
    const m = /^(?:as)?(\d{1,10})$/i.exec(t);
    const n = m ? Number(m[1]) : NaN;
    if (!Number.isInteger(n) || n <= 0 || n > 4_294_967_295) return null;
    if (!out.includes(n)) out.push(n);
  }
  return out.length > max ? null : out;
}

/** Ranges typed one per line (or separated by spaces): kept as typed, or null when one is not a range. */
export function parseRanges(text: string): string[] | null {
  const out: string[] = [];
  for (const t of text.split(/[\s,]+/).filter(Boolean)) {
    const m = /^([0-9a-fA-F.:]+)\/(\d{1,3})$/.exec(t);
    if (!m || (!m[1]!.includes('.') && !m[1]!.includes(':'))) return null;
    if (!out.includes(t)) out.push(t);
  }
  return out;
}

/** Why a name failed its check (`judgeHandshake` in convex/lib/edges/sni/family.ts). */
export const CHECK_WORDS: Record<string, string> = {
  q_timeout: 'The cover site did not answer in time.',
  q_private_target: 'The cover site resolves to a private address.',
  q_resolve: 'The cover site could not be looked up.',
  q_cert: 'The cover site has no valid certificate for this SNI.',
  q_unreachable: 'The cover site could not be reached.',
  q_tls12: 'The cover site does not offer TLS 1.3 for this SNI.',
  q_no_h2: 'The cover site does not offer HTTP/2 for this SNI.',
  q_off_network:
    'This SNI resolves outside the list’s network, so it does not match the network of the address it is shown on.',
  q_target_off_network: 'The cover site resolves outside the list’s network.',
  q_name_unresolved:
    'This SNI does not resolve, so it is not a site on the list’s network. It is not used until it resolves.',
};

/** The few fields of a row "Use anyway" reads (`SniNameRow`). */
interface UseAnywayRow {
  status: string;
  code: string | null;
  offNetwork: boolean;
  useAnyway: { at: string; by: string | null; reason: string | null } | null;
}

/**
 * Whether a row offers "Use anyway": it failed only because it resolves
 * outside the list's network, and nobody said "use anyway" yet. A burned or
 * retired server name is out of use for other reasons.
 */
export function offersUseAnyway(n: UseAnywayRow): boolean {
  return (
    !n.useAnyway &&
    n.code === 'q_off_network' &&
    (n.status === 'active' || n.status === 'suspended')
  );
}

/**
 * The line that keeps a "use anyway" in sight on its row, or null without one:
 * what it is, who said so and when, and the reason they gave.
 */
export function useAnywayWords(n: UseAnywayRow, now = Date.now()): string | null {
  const u = n.useAnyway;
  if (!u) return null;
  const head = n.offNetwork
    ? 'Used anyway: it resolves outside the list’s network.'
    : 'Use anyway is on: it may resolve outside the list’s network.';
  const who = `Set by ${u.by ?? 'an admin'} ${ago(u.at, now)}.`;
  return [head, who, u.reason ? `Reason: ${u.reason}` : null].filter(Boolean).join(' ');
}

/** What "Use anyway" or "Stop using anyway" did. */
export function useAnywayDoneWords(on: boolean, count: number): string {
  if (count === 0) return 'Nothing changed.';
  return on
    ? 'Used anyway. It is checked again in a few minutes.'
    : 'Back to the normal check. It is checked again in a few minutes.';
}

/** The report hint under a name. It suggests; the operator judges. */
export function suspectWords(countries: readonly string[]): string {
  return `Members in ${countries.join(', ')} report this SNI more than the others. It may be blocked there.`;
}

// --- checks from inside a country ---------------------------------------------------------------

/** "today", "yesterday", "3 days ago" (UTC days are close enough for a hint). */
export function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return 'never';
  const days = Math.floor((now - Date.parse(iso)) / 86_400_000);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  return `${days} days ago`;
}

/** Why the checks suggest nothing yet, in words. */
export const VANTAGE_REASON_WORDS: Record<(typeof SNI_VANTAGE_REASONS)[number], string> = {
  no_data: 'No check from there has finished yet.',
  not_enough_vantages: 'Too few vantages so far to say.',
  not_enough_networks: 'Seen from too few networks so far to say.',
  not_paired: 'No vantage on the same network got through with another SNI. It may be the network.',
  needs_repeat: 'Failed once. It is checked again before anything is suggested.',
  no_control: 'No SNI got through from there. The address may be blocked, not this SNI.',
  mixed: 'Some checks got through and some did not.',
  reports_disagree:
    'Member reports from there single out this SNI, so it is not suggested as working.',
};

/** Under the "Run checks" switch: what runs right now, and what is missing. */
export function vantageState(
  familiesOn: boolean,
  checksOn: boolean,
  countries: readonly string[],
): string {
  if (!familiesOn) return 'SNI lists are off, so nothing runs.';
  if (countries.length === 0) return 'Nothing runs until at least one country below is turned on.';
  if (!checksOn) return `Off. Turned on, it checks from ${countries.join(', ')}.`;
  return `Checking from ${countries.join(', ')}.`;
}

/** What the checks from one country saw, in one sentence. */
export function vantageLine(r: SniVantageRow, now = Date.now()): string {
  const when = `last checked ${ago(r.lastAt, now)}`;
  const from = `From ${r.country}`;
  if (r.latest === 'none')
    return r.lastAt
      ? `${from}: nothing conclusive yet (${when}).`
      : `${from}: waiting for its first check.`;
  if (r.latest === 'failing') {
    if (r.failVantages === 0) return `${from}: no SNI on that address got through (${when}).`;
    return `${from}: failed from ${plural(r.failVantages, 'vantage')} on ${plural(r.failNetworks, 'network')} while other SNIs got through (${when}).`;
  }
  if (r.latest === 'mixed') return `${from}: some checks got through and some did not (${when}).`;
  return `${from}: the handshake completed from ${plural(r.okVantages, 'vantage')} on ${plural(r.okNetworks, 'network')} (${when}).`;
}

/** What the checks (or a block list) suggest against the mark standing today. Null: nothing to say. */
export function vantageSuggestionWords(r: SniVantageRow): string | null {
  const claim =
    r.suggestion === 'blocked' ? `it is blocked in ${r.country}` : `it works in ${r.country}`;
  const who = r.provenance === 'list' ? `A block list for ${r.country}` : 'The checks';
  switch (r.decision) {
    case 'suggest':
      return r.provenance === 'list'
        ? `${who} holds it, so it may be blocked there.`
        : `The checks suggest ${claim}.`;
    case 'conflict':
      return r.provenance === 'list'
        ? `${who} holds it, which disagrees with the mark an operator set.`
        : `The checks disagree with the mark an operator set: they suggest ${claim}.`;
    case 'agrees':
      return null;
    case 'none':
      return r.reason ? VANTAGE_REASON_WORDS[r.reason] : null;
  }
}

/** An SNI the checks want an operator to look at: a block suggestion, or a conflict. */
export function vantageWantsLook(n: SniNameRow): boolean {
  return n.vantage.some(
    (r) => r.decision === 'conflict' || (r.decision === 'suggest' && r.suggestion === 'blocked'),
  );
}

export function vantageRequestedWords(r: SniVantageRequested): string {
  const skipped = r.skipped
    ? ` ${plural(r.skipped, 'SNI')} skipped: checked in the last hour, or on no published address.`
    : '';
  return `${plural(r.measurements, 'check')} started. Results arrive in a few minutes.${skipped}`;
}

export function vantageAppliedWords(r: SniVantageApplied): string {
  const parts: string[] = [];
  if (r.proven) parts.push(`${plural(r.proven, 'SNI')} marked as working`);
  if (r.blocked) parts.push(`${plural(r.blocked, 'SNI')} marked as blocked`);
  if (parts.length === 0) return 'Nothing to apply. The checks suggest nothing new for those SNIs.';
  return `${parts.join(', ')}.${r.skipped ? ` ${plural(r.skipped, 'SNI')} left unchanged.` : ''}`;
}

/** What an import did, in one sentence per kind of line. */
export function importWords(r: SniImportResult): string[] {
  const count = (v: SniImportResult['lines'][number]['verdict']) =>
    r.lines.filter((l) => l.verdict === v).length;
  const out = [`${plural(r.added, 'SNI')} added. Each is checked against the cover site first.`];
  const dup = count('duplicate');
  if (dup) out.push(`${plural(dup, 'line')} skipped: already in this list, or repeated.`);
  const other = count('in_other_family');
  if (other) out.push(`${plural(other, 'SNI')} skipped: already in another list.`);
  const burned = count('burned');
  if (burned) out.push(`${plural(burned, 'SNI')} skipped: burned SNIs are never used again.`);
  const invalid = count('invalid');
  if (invalid) out.push(`${plural(invalid, 'line')} skipped: not a plain hostname.`);
  return out;
}

/** Refusals of this section, in words. */
const ERROR_WORDS: Record<string, string> = {
  'edge.sni.bad_target': 'The cover site has to be a public hostname and a port.',
  'edge.sni.cap': 'This SNI list is full.',
  'edge.sni.disabled': 'SNI lists are turned off. Turn them on first.',
  'edge.sni.family_in_use': 'A port still uses this SNI list. Stop managing it there first.',
  // Renaming a list moves its address (docs/edges.md "Renaming a list").
  'edge.sni.slug_taken':
    'Another SNI list has, or had, the address this name gives. Pick another name.',
  'edge.sni.slug_reserved': 'That name gives the address of an SNIs page. Pick another name.',
  'edge.sni.slug_empty': "The list's address comes from its name. Use a letter or a digit in it.",
  'edge.sni.target_mismatch': "The port's cover site is not this list's cover site.",
  'edge.sni.binding_changed': 'This port changed since the page loaded. Reload and look again.',
  'edge.sni.profile_moved':
    'The profile changed on the backend. Send the SNIs again before testing.',
  'edge.sni.rollout_not_confirmed': 'The SNIs are not on the backend yet.',
  'edge.sni.receipt_expired': 'That test link has expired. Make a new one.',
  'edge.sni.superseded': 'A newer write replaced this one. Test against the newer one.',
  'edge.sni.country_not_curated': 'SNIs are not judged for that country.',
  'edge.sni.vantage_off': 'Checks from inside countries are turned off. Turn them on first.',
  'edge.sni.vantage_country': 'That country is not turned on for checks.',
  'edge.sni.vantage_no_source':
    'No measurement service can run. Turn one on, and for RIPE Atlas set its key under Settings.',
  'edge.sni.vantage_too_soon': 'Those SNIs were checked from there in the last hour.',
  'edge.sni.vantage_no_target': 'None of those SNIs is on a published address yet.',
  'edge.sni.vantage_budget': 'The hourly budget for checks is spent. Try again later.',
  // Networks (docs/edges.md "Networks").
  'edge.sni.network_bound':
    'A port uses this SNI list. Stop managing it there before changing its network.',
  'edge.sni.network_unknown':
    "The list's network has no address ranges yet. Read them again, or add ranges by hand.",
  'edge.sni.network_edges_off':
    "Some addresses in use on this port are not on the list's network. Replace them first.",
  'edge.sni.no_network': 'This list has no network, so every SNI is on it already.',
  'edge.network.bad_asn': 'Each ASN is a number, at most eight of them.',
  'edge.network.bad_prefix': 'Each range is an address and a length, like 192.0.2.0/24.',
  'edge.network.empty': 'A network needs an ASN or a range.',
  'edge.network.in_use': 'An SNI list or a port is on this network. Change them first.',
  'edge.network.bad_place': 'A place is a two-letter country code and, if you like, a city.',
  // Finding names (docs/edges.md "Finding names").
  'edge.sni.hunt.off': 'Finding SNIs is turned off. Turn it on first.',
  'edge.sni.hunt.no_scope': 'Pick a network or an SNI list first.',
  'edge.sni.hunt.bad_seed': 'That is not a seed file. Paste the whole file as it was written.',
  'edge.sni.hunt.too_many': 'That is too many at once. Split it up.',
  'edge.sni.hunt.sweep_running': 'A sweep is already running.',
  'edge.sni.hunt.no_sweep': 'No sweep is running.',
  'edge.sni.hunt.no_network':
    'No network is searched yet. Include a network with address ranges in the top-sites search.',
  'edge.sni.hunt.no_servername':
    'The cover site is an IP address and the list has no SNI yet. Add one SNI first.',
  'edge.sni.hunt.ct_off': 'Certificate log reads are set to zero an hour.',
  'edge.maintenance': 'Edges are in maintenance. Nothing new starts until it ends.',
  'servers.manage_disabled': 'Changing backends is turned off under Servers.',
  'servers.handoff_missing': 'The node role has not handed this backend over yet.',
  'servers.op_running': 'Another change to this profile is still running.',
  'servers.op_uncertain':
    'An earlier change to this profile has an unknown outcome. Settle it under Servers.',
  'servers.name_in_use': 'Members are still given one of the SNIs being removed.',
  // Binding to a transport reads the Servers cache.
  'servers.unknown_inbound':
    'That port is not on this backend as last read. Refresh under Servers, then pick again.',
  'servers.not_reality': 'Only a REALITY port takes an SNI list.',
  'edge.panel_op_running': 'A server change is still running on this origin.',
  conflict: 'That already exists, or it is already settled. Reload and look again.',
  not_found: 'That no longer exists. Reload and look again.',
  validation: 'Something in the form is not valid.',
};
export const WORDED_CODES: readonly string[] = Object.keys(ERROR_WORDS);
export function sniErrorWords(code: string | null | undefined): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again in a moment.';
}
