/**
 * The country-list pages' words (pure; unit-tested). Every sentence the list
 * pages show lives here: what a list is, why a version waits, what the last
 * fetch said, and what a list holds.
 */
import type {
  CountryListHoldReason,
  CountryListRegime,
  CountryListVersion,
  CountryListView,
} from '@shared/contracts/countryLists';
import { relativeTime } from '../lib/time';

export const REGIME_WORDS: Record<CountryListRegime, { label: string; explain: string }> = {
  allowlist: {
    label: 'Works there',
    explain:
      'Names and addresses reported to work in the country, such as the ones a network still lets through when it shuts down.',
  },
  blocklist: {
    label: 'Blocked there',
    explain: 'Names and addresses reported to be blocked in the country.',
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

/** "2 names, 1 wildcard, 1 IPv4 range (256 addresses), 1 IPv6 range". */
export function countsLine(c: CountryListVersion['counts']): string {
  const parts: string[] = [];
  if (c.names) parts.push(plural(c.names, 'name', 'names'));
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

/** "Names: 1 name new, none gone. IPv4: 256 addresses new, none gone." */
export function diffLine(d: CountryListVersion['diff']): string | null {
  if (!d) return null;
  const side = (label: string, p: { added: number; removed: number }, one: string, many: string) =>
    p.added || p.removed
      ? `${label}: ${p.added ? `${plural(p.added, one, many)} new` : 'none new'}, ${
          p.removed ? `${p.removed.toLocaleString('en')} gone` : 'none gone'
        }.`
      : null;
  const parts = [
    side('Names', d.names, 'name', 'names'),
    side('IPv4', d.v4, 'address', 'addresses'),
    side('IPv6', d.v6, '/64', '/64s'),
  ].filter(Boolean);
  return parts.length ? parts.join(' ') : 'The same names and ranges as before.';
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
  not_found: 'That list is gone.',
  validation: 'Something in the form is not right. Check the fields.',
};

export function listErrorWords(code: string | null): string {
  return (code && ERROR_WORDS[code]) || 'That did not work. Try again shortly.';
}

/** Lookup lines: how a list holds an entry. */
export const HOW_WORDS = {
  exact: 'by name',
  wildcard: 'by a wildcard',
  range: 'in a range',
} as const;

/** Entries typed one per line or separated by spaces or commas (at most 50, as the server takes). */
export function parseLookup(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))].slice(0, 50);
}
