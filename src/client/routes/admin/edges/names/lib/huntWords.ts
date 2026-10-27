/**
 * Wording for Find names (docs/edges.md "Finding names"; pure, unit-tested).
 * A candidate is only ever shown: the page keeps apart what was checked here
 * (qualification's own verdict), what was measured (near the node, from
 * inside countries, OONI) and what adding does (the family's normal path).
 */
import {
  usableCandidate,
  type SniCandidateRow,
  type SniHuntCtRow,
  type SniHuntImported,
  type SniHuntOverview,
} from '../../../../../../shared/contracts/sni';
import { CHECK_WORDS, type Dot } from './words';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const num = (n: number) => n.toLocaleString('en-US');

export const HUNT_SOURCE_WORDS: Record<SniCandidateRow['sources'][number], string> = {
  cert: 'target certificate',
  seed: 'seed file',
  pasted: 'pasted',
  toplist: 'top sites',
  ct: 'certificate logs',
};

export const HUNT_FILTERS = [
  'ready',
  'failing',
  'unchecked',
  'unmeasured',
  'gone',
  'ignored',
  'added',
  'all',
] as const;
export type HuntFilter = (typeof HUNT_FILTERS)[number];
export const HUNT_FILTER_LABEL: Record<HuntFilter, string> = {
  ready: 'Ready',
  failing: 'Failing',
  unchecked: 'Not checked yet',
  unmeasured: 'Not measured',
  gone: 'Left its network',
  ignored: 'Ignored',
  added: 'In a family',
  all: 'All',
};

/** The same rule as every count of found names (`usableCandidate`). */
const ready = (c: SniCandidateRow) => usableCandidate(c);

/** Which state's pages a filter reads (the rest is narrowed on the page). */
export const HUNT_FILTER_STATE: Record<
  HuntFilter,
  'new' | 'failing' | 'gone' | 'ignored' | 'added' | 'all'
> = {
  ready: 'new',
  failing: 'failing',
  unchecked: 'new',
  unmeasured: 'new',
  gone: 'gone',
  ignored: 'ignored',
  added: 'added',
  all: 'all',
};

export function matchesHuntFilter(c: SniCandidateRow, f: HuntFilter): boolean {
  switch (f) {
    case 'ready':
      return ready(c);
    case 'failing':
      return c.state === 'failing';
    case 'unchecked':
      return c.state === 'new' && !c.check;
    case 'unmeasured':
      return ready(c) && !c.timing && !c.ooni && c.countries.length === 0;
    case 'gone':
      return c.state === 'gone';
    case 'ignored':
      return c.state === 'ignored';
    case 'added':
      return c.state === 'added';
    case 'all':
      return true;
  }
}

/** A candidate's state, as a dot and a sentence. */
export function candidateWords(c: SniCandidateRow): { dot: Dot; sentence: string } {
  if (c.state === 'added')
    return {
      dot: 'green',
      sentence: c.inFamily ? `In the family ${c.inFamily.label}.` : 'In a family.',
    };
  if (c.state === 'ignored') return { dot: 'grey', sentence: 'Ignored.' };
  if (c.state === 'gone')
    return { dot: 'grey', sentence: 'It left its network: it now resolves outside it.' };
  if (!c.check) return { dot: 'grey', sentence: 'Not checked yet.' };
  if (!ready(c))
    return {
      dot: 'red',
      sentence:
        (c.check.code && CHECK_WORDS[c.check.code]) ??
        'It fails the check this family would run on it.',
    };
  return { dot: 'green', sentence: checkPassWords(c) };
}

function checkPassWords(c: SniCandidateRow): string {
  const tls = [
    c.check?.tlsVersion === 'TLSv1.3' ? 'TLS 1.3' : null,
    c.check?.alpn === 'h2' ? 'HTTP/2' : null,
  ]
    .filter(Boolean)
    .join(', ');
  return `It would qualify${tls ? ` (${tls})` : ''}.`;
}

/** The two extra handshakes, in words; never part of the verdict. */
export function extraWords(c: SniCandidateRow): string | null {
  if (!c.extra) return null;
  const word = (v: boolean | null, what: string) =>
    v === null ? null : v ? `takes ${what}` : `refuses ${what}`;
  const parts = [
    word(c.extra.x25519, 'an X25519-only offer'),
    word(c.extra.mlkem, 'ML-KEM'),
  ].filter((x): x is string => !!x);
  if (c.extra.error && parts.length < 2) parts.push('one extra check did not get an answer');
  return parts.length > 0 ? `It ${parts.join(', ')}.` : null;
}

/** Near the node: the leg REALITY relays to, from the network's place. */
export function nearWords(c: SniCandidateRow, family: boolean): string {
  if (!c.timing) return 'Not measured from the node’s place yet.';
  const to = family ? 'the family’s target' : 'its own address';
  const own = family && c.own ? ` Its own site answers there in about ${c.own.connectMs} ms.` : '';
  return `About ${c.timing.connectMs} ms from ${placeWords(c.timing.place)} to ${to}.${own}`;
}

function placeWords(place: string): string {
  const [country, city] = place.split('/');
  return city ? `${city} (${country})` : (country ?? place);
}

export const COUNTRY_READING_WORDS: Record<
  SniCandidateRow['countries'][number]['reading'],
  string
> = {
  ok: 'works there',
  interference: 'interfered with there',
  inconclusive: 'unclear there',
  path: 'nothing got through from there',
};

/** What the checks from inside countries and OONI say, one phrase per country. */
export function countryWords(c: SniCandidateRow): string[] {
  const out: string[] = [];
  for (const r of c.countries)
    out.push(`${r.cc}: ${COUNTRY_READING_WORDS[r.reading]} (${plural(r.vantages, 'vantage')})`);
  for (const o of c.ooni?.exact ?? []) {
    if (c.countries.some((r) => r.cc === o.cc)) continue;
    if (o.status === 'blocked' || o.status === 'likely_blocked')
      out.push(`${o.cc}: OONI sees it blocked`);
    else if (o.status === 'ok') out.push(`${o.cc}: OONI sees it working`);
  }
  return out;
}

/** OONI for the site (apex and www): context only, never scored for another name. */
export function siteOoniWords(c: SniCandidateRow): string | null {
  const blocked = (c.ooni?.site ?? [])
    .filter((o) => o.status === 'blocked' || o.status === 'likely_blocked')
    .map((o) => o.cc);
  return blocked.length > 0
    ? `OONI sees the site ${c.site} blocked in ${blocked.join(', ')} (its main address, not necessarily this name).`
    : null;
}

export function scoreWords(c: SniCandidateRow): string {
  if (!c.check) return 'No score until it is checked.';
  if (!ready(c) && c.state !== 'ignored' && c.state !== 'added')
    return 'No score: it would not qualify.';
  return `Score ${Math.round(c.score)} of 100 (${Math.round(c.baseScore)} before measurements).`;
}

export function sourcesWords(c: SniCandidateRow): string {
  const parts = c.sources.map((s) => HUNT_SOURCE_WORDS[s]);
  if (c.rank) parts.push(`rank ${num(c.rank)}`);
  return parts.join(' · ');
}

// --- the sweep and certificate logs ---------------------------------------------------------------

export function sweepWords(s: SniHuntOverview['sweep']): string {
  if (!s) return 'No sweep has run yet.';
  const found = plural(s.hits, 'name');
  switch (s.state) {
    case 'downloading':
      return 'Downloading the top-sites list.';
    case 'running':
      return `Looking up the top-sites list: ${num(s.cursor)} of ${num(s.total)} names, ${found} found on a network.`;
    case 'done':
      return `The last sweep looked up ${num(s.total)} names and found ${found} on a network.`;
    case 'cancelled':
      return `The last sweep was cancelled after ${num(s.cursor)} names.`;
    case 'failed':
      return `The last sweep failed (${SWEEP_ERROR_WORDS[s.error ?? ''] ?? 'an error'}).`;
  }
}

export const SWEEP_ERROR_WORDS: Record<string, string> = {
  list_unavailable: 'the list service refused',
  list_unreachable: 'the list service could not be reached',
  list_bad_answer: 'the list was not readable',
  list_too_large: 'the list was too large',
  list_lost: 'the stored list was lost',
  store_failed: 'the list could not be stored',
  download_timeout: 'the download did not finish',
  no_network: 'no network was being searched any more',
};

export const CT_STATE_WORDS: Record<SniHuntCtRow['state'], string> = {
  partial: 'reading',
  complete: 'read in full',
  truncated: 'stopped at the page limit (ask again to read further)',
  rate_limited: 'waiting: the log service asked to slow down',
  error: 'failed, tried again later',
};

export function ctWords(r: SniHuntCtRow): string {
  return `${r.domain}: ${CT_STATE_WORDS[r.state]}, ${plural(r.pages, 'page')}, ${plural(r.names, 'name')} found.`;
}

/** What an import did. */
export function huntImportWords(r: SniHuntImported): string {
  const parts = [`${plural(r.added, 'name')} added`];
  if (r.known) parts.push(`${r.known} already here`);
  if (r.inFamily) parts.push(`${r.inFamily} already in a family`);
  if (r.ignored) parts.push(`${r.ignored} ignored before`);
  if (r.invalid) parts.push(`${r.invalid} not a host name`);
  if (r.capped) parts.push(`${r.capped} over the limit`);
  return `${parts.join(', ')}.`;
}

/** A place typed as a country code and an optional city. */
export function parsePlace(
  country: string,
  city: string,
): { country: string; city?: string } | null {
  const cc = country.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return null;
  const c = city.trim().replace(/\s+/g, ' ');
  return c ? { country: cc, city: c } : { country: cc };
}

/** A family's short id from a site name: `www.example.com` -> `example-com`. */
export function familySlugFor(name: string): string {
  return name
    .replace(/^www\./, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}
