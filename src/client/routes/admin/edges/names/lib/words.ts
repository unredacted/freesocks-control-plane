/**
 * Wording and small decisions for Admin -> Edges -> Server names (pure;
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
      ? 'no name list on it'
      : `${plural(n.families.length, 'name list')} on it`,
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
export function parseAsns(text: string): number[] | null {
  const out: number[] = [];
  for (const t of text.split(/[\s,]+/).filter(Boolean)) {
    const m = /^(?:as)?(\d{1,10})$/i.exec(t);
    const n = m ? Number(m[1]) : NaN;
    if (!Number.isInteger(n) || n <= 0 || n > 4_294_967_295) return null;
    if (!out.includes(n)) out.push(n);
  }
  return out.length > 8 ? null : out;
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
  q_cert: 'The cover site has no valid certificate for this name.',
  q_unreachable: 'The cover site could not be reached.',
  q_tls12: 'The cover site does not offer TLS 1.3 for this name.',
  q_no_h2: 'The cover site does not offer HTTP/2 for this name.',
  q_off_network:
    'This name resolves outside the list’s network, or not at all: someone looking it up would see another network than the address it is shown to.',
  q_target_off_network: 'The cover site resolves outside the list’s network.',
};

/** The report hint under a name. It suggests; the operator judges. */
export function suspectWords(countries: readonly string[]): string {
  return `Members in ${countries.join(', ')} report this name more than the others. It may be blocked there.`;
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
  not_paired:
    'No vantage got through for another name from the same network, so it may be the network.',
  needs_repeat: 'It failed once. It is checked again before anything is suggested.',
  no_control:
    'No name got through from there, so the address itself may be blocked. That is not about this name.',
  mixed: 'Some checks got through and some did not.',
  reports_disagree:
    'Member reports from there single this name out, so working there is not suggested.',
};

/** Under the "Run checks" switch: what runs right now, and what is missing. */
export function vantageState(
  familiesOn: boolean,
  checksOn: boolean,
  countries: readonly string[],
): string {
  if (!familiesOn) return 'Server names are off, so nothing runs either way.';
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
    if (r.failVantages === 0) return `${from}: no name of that address got through (${when}).`;
    return `${from}: failed from ${plural(r.failVantages, 'vantage')} on ${plural(r.failNetworks, 'network')} while other names got through (${when}).`;
  }
  if (r.latest === 'mixed') return `${from}: some checks got through and some did not (${when}).`;
  return `${from}: the handshake completed from ${plural(r.okVantages, 'vantage')} on ${plural(r.okNetworks, 'network')} (${when}).`;
}

/** What the checks suggest against the mark standing today. Null: nothing to say. */
export function vantageSuggestionWords(r: SniVantageRow): string | null {
  const claim =
    r.suggestion === 'blocked' ? `it is blocked in ${r.country}` : `it works in ${r.country}`;
  switch (r.decision) {
    case 'suggest':
      return `The checks suggest ${claim}.`;
    case 'conflict':
      return `The checks disagree with the mark an operator set: they suggest ${claim}.`;
    case 'agrees':
      return null;
    case 'none':
      return r.reason ? VANTAGE_REASON_WORDS[r.reason] : null;
  }
}

/** A name the checks want an operator to look at: a block suggestion, or a conflict. */
export function vantageWantsLook(n: SniNameRow): boolean {
  return n.vantage.some(
    (r) => r.decision === 'conflict' || (r.decision === 'suggest' && r.suggestion === 'blocked'),
  );
}

export function vantageRequestedWords(r: SniVantageRequested): string {
  const skipped = r.skipped
    ? ` ${plural(r.skipped, 'name')} skipped: checked within the last hour, or on no published address.`
    : '';
  return `${plural(r.measurements, 'check')} started. Results arrive in a few minutes.${skipped}`;
}

export function vantageAppliedWords(r: SniVantageApplied): string {
  const parts: string[] = [];
  if (r.proven) parts.push(`${plural(r.proven, 'name')} marked as working`);
  if (r.blocked) parts.push(`${plural(r.blocked, 'name')} marked as blocked`);
  if (parts.length === 0)
    return 'Nothing to apply: the checks suggest nothing new for those names.';
  return `${parts.join(', ')}.${r.skipped ? ` ${plural(r.skipped, 'name')} left unchanged.` : ''}`;
}

/** What an import did, in one sentence per kind of line. */
export function importWords(r: SniImportResult): string[] {
  const count = (v: SniImportResult['lines'][number]['verdict']) =>
    r.lines.filter((l) => l.verdict === v).length;
  const out = [`${plural(r.added, 'name')} added. Each is checked against the cover site first.`];
  const dup = count('duplicate');
  if (dup) out.push(`${plural(dup, 'line')} skipped: already in this list, or repeated.`);
  const other = count('in_other_family');
  if (other) out.push(`${plural(other, 'name')} skipped: already in another list.`);
  const burned = count('burned');
  if (burned) out.push(`${plural(burned, 'name')} skipped: burned names are never used again.`);
  const invalid = count('invalid');
  if (invalid) out.push(`${plural(invalid, 'line')} skipped: not a plain host name.`);
  return out;
}

/** Refusals of this section, in words. */
const ERROR_WORDS: Record<string, string> = {
  'edge.sni.bad_target': 'The cover site has to be a public host name and a port.',
  'edge.sni.cap': 'This name list is full.',
  'edge.sni.disabled': 'Server names are turned off. Turn them on first.',
  'edge.sni.family_in_use': 'A port still uses this name list. Stop managing it there first.',
  'edge.sni.target_mismatch':
    "The port's cover site is not this list's cover site. Every name must be one the cover site really serves.",
  'edge.sni.binding_changed': 'This port changed since the page loaded. Reload and look again.',
  'edge.sni.profile_moved':
    'The profile changed on the backend since this was written. Write the names again before testing.',
  'edge.sni.rollout_not_confirmed': 'The names are not on the backend yet.',
  'edge.sni.receipt_expired': 'That test link has expired. Make a new one.',
  'edge.sni.superseded': 'A newer write replaced this one. Test against the newer one.',
  'edge.sni.country_not_curated':
    'That country is not on the list of countries names are judged for.',
  'edge.sni.vantage_off': 'Checks from inside countries are turned off. Turn them on first.',
  'edge.sni.vantage_country': 'That country is not turned on for checks.',
  'edge.sni.vantage_no_source':
    'No measurement service can run. Turn one on, and for RIPE Atlas set its key under Settings.',
  'edge.sni.vantage_too_soon': 'Those names were checked from there within the last hour.',
  'edge.sni.vantage_no_target': 'None of those names is on a published address yet.',
  'edge.sni.vantage_budget': 'The hourly budget for checks is spent. Try again later.',
  // Networks (docs/edges.md "Networks").
  'edge.sni.network_bound':
    'A port uses this name list. Stop managing it there before changing its network.',
  'edge.sni.network_unknown':
    "The list's network has no address ranges yet. Read them again, or add ranges by hand.",
  'edge.sni.network_edges_off':
    "Some addresses in use on this port are not on the list's network. Replace them first.",
  'edge.network.bad_asn': 'Each ASN is a number, at most eight of them.',
  'edge.network.bad_prefix': 'Each range is an address and a length, like 192.0.2.0/24.',
  'edge.network.empty': 'A network needs an ASN or a range.',
  'edge.network.in_use': 'A name list or a port is on this network. Change them first.',
  'edge.network.bad_place': 'A place is a two-letter country code and, if you like, a city.',
  // Finding names (docs/edges.md "Finding names").
  'edge.sni.hunt.off': 'Finding names is turned off. Turn it on first.',
  'edge.sni.hunt.no_scope': 'Pick a network or a name list first.',
  'edge.sni.hunt.bad_seed': 'That is not a seed file. Paste the whole file as it was written.',
  'edge.sni.hunt.too_many': 'That is too many at once. Split it up.',
  'edge.sni.hunt.sweep_running': 'A sweep is already running.',
  'edge.sni.hunt.no_sweep': 'No sweep is running.',
  'edge.sni.hunt.no_network':
    'No network is being searched yet. Turn on finding names for a network that has address ranges.',
  'edge.sni.hunt.no_servername':
    'The cover site is an address and the list has no name yet. Add one name first.',
  'edge.sni.hunt.ct_off': 'Certificate log reads are set to none an hour.',
  'edge.maintenance': 'Edges are in maintenance. Nothing new starts until it ends.',
  'servers.manage_disabled': 'Changing backends is turned off under Servers.',
  'servers.handoff_missing': 'The node role has not handed this backend over yet.',
  'servers.op_running': 'Another change to this profile is still running.',
  'servers.op_uncertain':
    'An earlier change to this profile has an unknown outcome. Settle it under Servers.',
  'servers.name_in_use': 'Members are still given one of the names being removed.',
  // Binding to a transport reads the Servers cache.
  'servers.unknown_inbound':
    'That port is not on this backend as last read. Refresh under Servers, then pick again.',
  'servers.not_reality': 'Only a REALITY port takes a name list.',
  'edge.panel_op_running': 'A server change is still running on this origin.',
  conflict: 'That already exists, or it is already settled. Reload and look again.',
  not_found: 'That no longer exists. Reload and look again.',
  validation: 'Something in the form is not valid.',
};
export const WORDED_CODES: readonly string[] = Object.keys(ERROR_WORDS);
export function sniErrorWords(code: string | null | undefined): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again in a moment.';
}
