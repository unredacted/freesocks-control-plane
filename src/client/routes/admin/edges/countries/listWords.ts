/**
 * The country-list pages' words (pure; unit-tested). Every sentence the list
 * pages show lives here: what a list is, why a version waits, what the last
 * fetch said, and what a list holds.
 */
import type {
  CountryListFeed,
  CountryListHoldReason,
  CountryListRegime,
  CountryListVersion,
  CountryListView,
  EdgeListMarks,
} from '@shared/contracts/countryLists';
import { relativeTime } from '../lib/time';

export const REGIME_WORDS: Record<CountryListRegime, { label: string; explain: string }> = {
  allowlist: {
    label: 'Works there',
    explain:
      'Hostnames and addresses reported to work in the country, such as those still let through during a shutdown.',
  },
  blocklist: {
    label: 'Blocked there',
    explain: 'Hostnames and addresses reported to be blocked in the country.',
  },
};

export const HOLD_REASON_WORDS: Record<CountryListHoldReason, string> = {
  first_version: 'This is the first version. Look it over before FCP uses it.',
  emptied: 'The list came back empty.',
  jump: 'It grew or shrank by more than the factor set in Settings.',
  replaced: 'Most of it is new, so it may be a different list.',
  too_broad:
    'It has ranges wider than /8 (IPv4) or /16 (IPv6), or a wildcard over a whole domain ending.',
  invalid: 'Many lines could not be read.',
  capped: 'It holds more than FCP keeps. The rest was left out.',
};

export function holdReasonWords(code: string): string {
  return (
    HOLD_REASON_WORDS[code as CountryListHoldReason] ?? 'It looks different from the last one.'
  );
}

/** What the last fetch or paste came to. */
export const OUTCOME_WORDS: Record<string, string> = {
  published: 'A new version is in use.',
  held: 'A new version waits for you.',
  unchanged: 'Nothing changed.',
  not_modified: 'Nothing changed.',
  held_same: 'The same as the version waiting for you.',
  busy: 'Another read was running. It is tried again later.',
  stale_base: 'The list changed while this was read. It is tried again later.',
  bad_url: 'The address is not one FCP fetches.',
  dns_failed: 'The address could not be looked up.',
  private_address: 'The address leads to a private network. FCP does not fetch it.',
  redirect_refused: 'The address sends FCP somewhere else. Enter the final address.',
  not_found: 'The address answered that there is no such file.',
  http_error: 'The address answered with an error.',
  too_large: 'The file is larger than FCP reads.',
  timeout: 'The address took too long to answer.',
  tls_failed: 'The address’s certificate could not be trusted.',
  unreachable: 'The address could not be reached.',
  stage_failed: 'The list could not be stored. It is tried again later.',
  not_url: 'This list has no address to fetch.',
  error: 'The list could not be read.',
};

export function outcomeWords(code: string): string {
  return OUTCOME_WORDS[code] ?? 'The list could not be read.';
}

/** Whether an outcome is a failure worth showing in red. */
export function outcomeFailed(code: string): boolean {
  return !['published', 'held', 'unchanged', 'not_modified', 'held_same', 'busy'].includes(code);
}

const plural = (n: number, one: string, many: string) =>
  `${n.toLocaleString('en')} ${n === 1 ? one : many}`;

/** "2 hostnames, 1 wildcard, 1 IPv4 range (256 addresses), 1 IPv6 range". */
export function countsLine(c: CountryListVersion['counts']): string {
  const parts: string[] = [];
  if (c.names) parts.push(plural(c.names, 'hostname', 'hostnames'));
  if (c.wildcards) parts.push(plural(c.wildcards, 'wildcard', 'wildcards'));
  if (c.v4Ranges)
    parts.push(
      `${plural(c.v4Ranges, 'IPv4 range', 'IPv4 ranges')} (${plural(c.v4, 'address', 'addresses')})`,
    );
  if (c.v6Ranges) parts.push(plural(c.v6Ranges, 'IPv6 range', 'IPv6 ranges'));
  return parts.length ? `${parts.join(', ')}.` : 'Nothing usable.';
}

/** What was left out and why; null when nothing was. */
export function droppedLine(c: CountryListVersion['counts']): string | null {
  const parts: string[] = [];
  if (c.invalid)
    parts.push(plural(c.invalid, 'line that could not be read', 'lines that could not be read'));
  if (c.nonPublic)
    parts.push(plural(c.nonPublic, 'private or reserved range', 'private or reserved ranges'));
  if (c.tooBroad)
    parts.push(plural(c.tooBroad, 'entry that is too wide', 'entries that are too wide'));
  if (c.capped) parts.push(plural(c.capped, 'entry past the limit', 'entries past the limit'));
  return parts.length ? `Left out: ${parts.join(', ')}.` : null;
}

/** "Hostnames: 1 hostname new, none gone. IPv4: 256 addresses new, none gone." */
export function diffLine(d: CountryListVersion['diff']): string | null {
  if (!d) return null;
  const side = (label: string, p: { added: number; removed: number }, one: string, many: string) =>
    p.added || p.removed
      ? `${label}: ${p.added ? `${plural(p.added, one, many)} new` : 'none new'}, ${
          p.removed ? `${p.removed.toLocaleString('en')} gone` : 'none gone'
        }.`
      : null;
  const parts = [
    side('Hostnames', d.names, 'hostname', 'hostnames'),
    side('IPv4', d.v4, 'address', 'addresses'),
    side('IPv6', d.v6, '/64', '/64s'),
  ].filter(Boolean);
  return parts.length ? parts.join(' ') : 'The same hostnames and ranges as before.';
}

/** Where a list comes from. */
export function sourceLine(l: Pick<CountryListView, 'source' | 'fetchEveryHours'>): string {
  if (l.source.kind === 'paste') return 'Pasted by hand.';
  let host = l.source.url;
  try {
    host = new URL(l.source.url).host;
  } catch {
    // Shown as stored.
  }
  return `Fetched from ${host} every ${plural(l.fetchEveryHours, 'hour', 'hours')}.`;
}

/** Whether the source still says what the list holds. */
export function freshnessLine(
  l: Pick<CountryListView, 'confirmedAt' | 'fresh' | 'active'>,
  staleDays: number,
  now: number,
): string {
  if (!l.active) return 'No version in use yet.';
  if (!l.confirmedAt) return 'Never confirmed.';
  return l.fresh
    ? `Confirmed ${relativeTime(l.confirmedAt, now)}.`
    : `Stale: not confirmed for over ${plural(staleDays, 'day', 'days')}, so nothing reads it.`;
}

export type ListBadge = { label: string; tone: 'success' | 'warning' | 'muted' | 'danger' };

/** One badge for a list's state. */
export function listBadge(l: CountryListView): ListBadge {
  if (l.held) return { label: 'Waiting for you', tone: 'warning' };
  if (!l.enabled) return { label: 'Off', tone: 'muted' };
  if (!l.active) return { label: 'Not read yet', tone: 'muted' };
  if (!l.fresh) return { label: 'Stale', tone: 'danger' };
  return { label: 'In use', tone: 'success' };
}

export const STATUS_WORDS: Record<CountryListVersion['status'], string> = {
  staging: 'Being stored',
  held: 'Waiting for you',
  active: 'In use',
  superseded: 'Replaced',
  rejected: 'Thrown away',
  failed: 'Failed',
};

/** The API's refusals, in words. */
const ERROR_WORDS: Record<string, string> = {
  'edge.list.bad_url':
    'That address is not one FCP fetches. Use https, the standard port, and no user name.',
  'edge.list.bad_asn': 'Each network is an ASN number, like AS64500.',
  'edge.list.busy': 'This list is being read now. Try again in a minute.',
  'edge.list.not_paste': 'This list is fetched from its address. It takes no paste.',
  'edge.list.not_url': 'A pasted list has no address to fetch. Paste it again instead.',
  'edge.list.version_stale':
    'The list changed since this version was read. Fetch or paste it again.',
  'edge.list.not_held': 'That version is no longer waiting for a decision.',
  'edge.list.part_order': 'The paste went out of order. Send it again.',
  'edge.list.part_too_large': 'A part of the paste was too large. Send it again.',
  'edge.list.upload_too_large': 'A paste holds at most 4 MB. Give the list an address instead.',
  'edge.list.upload_closed': 'The paste took too long. Send it again.',
  'edge.list.upload_empty': 'Nothing was pasted.',
  'edge.list.cap': 'FCP follows at most 50 lists.',
  'edge.list.feeds_cap': 'A list feeds at most 10 networks and SNI lists.',
  'edge.list.no_feeds': 'This list feeds nothing. Choose where its hostnames go first.',
  'edge.list.not_feedable':
    'Only a list that is on, fresh and has a version in use can feed hostnames.',
  'edge.list.watch_allowlist_only': 'Only a list of what works can check edge addresses.',
  'edge.list.mark_not_left': 'That address is on the list again, or never was.',
  'edge.list.mark_moved': 'That address was listed and left again since. Look at it again.',
  'edge.list.watch_cap': 'At most 5 lists check edge addresses. Turn one off first.',
  'edge.list.prefer_allowlist_only': 'Only a list of what works can prefer its SNIs.',
  not_found: 'That list is gone.',
  validation: 'Something in the form is not right. Check the fields.',
};

export function listErrorWords(code: string | null): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again shortly.';
}

/** Lookup lines: how a list holds an entry. */
export const HOW_WORDS = {
  exact: 'by exact hostname',
  wildcard: 'by a wildcard',
  range: 'in a range',
} as const;

/** Entries typed one per line or separated by spaces or commas (at most 50, as the server takes). */
export function parseLookup(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))].slice(0, 50);
}

const STOPPED_WORDS: Record<string, string> = {
  superseded: 'A newer version took over.',
  feed_removed: 'It was taken off the list.',
  list_removed: 'The list is gone.',
  not_feedable: 'The list is off or stale, so it stopped.',
  scope_gone: 'The network or SNI list is gone.',
  restarted: 'A new run took over.',
};

/** A feed's last run, in one line. */
export function feedLine(f: CountryListFeed): string {
  const r = f.run;
  if (!r) return 'Not fed yet.';
  const c = r.counts;
  const parts = [`${plural(c.added, 'hostname', 'hostnames')} added`];
  if (c.known) parts.push(`${c.known.toLocaleString('en')} already there`);
  if (c.inFamily) parts.push(`${c.inFamily.toLocaleString('en')} already in an SNI list`);
  if (c.ignored) parts.push(`${c.ignored.toLocaleString('en')} ignored`);
  if (c.capped) parts.push(`${c.capped.toLocaleString('en')} past the 2,000 limit`);
  const counts = `${parts.join(', ')}.`;
  if (r.state === 'running') return `Feeding now. So far: ${counts}`;
  if (r.state === 'stopped')
    return `Stopped: ${STOPPED_WORDS[r.stopped ?? ''] ?? 'it stopped.'} ${counts}`;
  return r.current ? counts : `${counts} That was an older version.`;
}

// --- edge addresses against the list ---------------------------------------------------------------

/** Under the switch: what is true now. */
export function watchLine(watch: boolean): string {
  return watch
    ? 'On. FCP checks every edge address in use or ready against the version in use, hourly and after each new version. An address that leaves the list asks for a look.'
    : 'Off. Edge addresses are not checked against this list.';
}

/** Why a watched list's checks wait, or null when they run. */
export function watchWaitsLine(
  l: Pick<CountryListView, 'enabled' | 'fresh' | 'active'>,
  switchOn: boolean,
): string | null {
  if (!switchOn) return 'Country lists are off: nothing is checked until they are on.';
  if (!l.enabled) return 'This list is off: nothing is checked until it is on.';
  if (!l.active) return 'No version is in use yet: nothing is checked until one is.';
  if (!l.fresh) return 'This list is stale: nothing is checked until its source confirms it.';
  return null;
}

/** How the edge addresses stand against the list. */
export function edgeCountsLine(c: {
  listed: number;
  not_listed: number;
  left: number;
  checking: number;
}): string {
  const total = c.listed + c.not_listed + c.left + c.checking;
  if (total === 0) return 'No edge has an IP address to check.';
  const parts = [`${plural(c.listed, 'address', 'addresses')} on it`];
  if (c.left) parts.push(`${c.left.toLocaleString('en')} left it`);
  if (c.not_listed) parts.push(`${c.not_listed.toLocaleString('en')} never on it`);
  if (c.checking) parts.push(`${c.checking.toLocaleString('en')} not checked yet`);
  return `Of ${plural(total, 'edge address', 'edge addresses')}: ${parts.join(', ')}.`;
}

type MarkRow = EdgeListMarks['lists'][number]['addresses'][number];

/** One address against one watched list, on the edge's sheet. */
export function markRowWords(m: MarkRow, now: number): string {
  switch (m.state) {
    case 'listed':
      return m.since ? `On it, first seen there ${relativeTime(m.since, now)}.` : 'On it.';
    case 'left':
      return m.since ? `Left it ${relativeTime(m.since, now)}.` : 'Left it.';
    case 'not_listed':
      return 'Not on it, and never was.';
    case 'checking':
      return 'Not checked against the version in use yet.';
  }
}

/** Why a watched list's marks on the sheet are not current, or null when they are. */
export function marksWaitLine(
  l: Pick<EdgeListMarks['lists'][number], 'checked' | 'enabled' | 'fresh'>,
  switchOn: boolean,
): string | null {
  if (l.checked) return null;
  if (!switchOn) return 'Not checked now: country lists are off.';
  if (!l.enabled) return 'Not checked now: this list is off.';
  if (!l.fresh) return 'Not checked now: this list is stale.';
  return 'Not checked now.';
}
