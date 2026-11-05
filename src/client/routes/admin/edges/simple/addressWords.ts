/**
 * The words of one address row on a node page (AddressRow.svelte), pure and
 * unit-tested. A row is one line: its addresses (IPv4, IPv6 or a name), what
 * it is (In use, Spare, Retiring), whether it is tested, and the countries in
 * one short line grouped by what it counts as there. The full per-country
 * lines (CountryLines) sit behind the row's Details.
 *
 * No em-dashes, no codes, no API paths.
 */
import type { EdgeAdmin } from '@shared/contracts/edges';
import {
  OUTSIDE_REACH_LABELS,
  healthLabel,
  outsideReachOf,
  type Tone,
} from '@client/lib/edgeCodes';
import { countryName } from '@client/lib/countries';
import type { EdgeCountryLine } from '../lib/countryChecks';
import { countryLine } from '../lib/statusWords';
import { providerLabel } from '../lib/format';
import type { Dot } from './runStages';

type Addressed = Pick<EdgeAdmin, 'addresses' | 'name'>;

/**
 * What the row shows of an address: the name a CDN front answers on, else
 * its IPv4, then every other form beside it (IPv6 for a load balancer that
 * has one). Never empty: an address with none of them shows its own name.
 */
export function addressForms(e: Addressed): { main: string; others: string[] } {
  const { hostname, v4, v6 } = e.addresses;
  const main = hostname ?? v4 ?? v6 ?? e.name;
  const others = [v4, v6].filter((a): a is string => !!a && a !== main);
  return { main, others };
}

/** One address in a sentence or a dialog title: its main form. */
export const addressText = (e: Addressed): string => addressForms(e).main;

/**
 * The row's dot: red when the provider reports it offline or nothing outside
 * reaches it, amber when it is degraded or reached from some places only,
 * green when it is online and reached from outside (or not checked from
 * outside yet), grey while the provider has not said.
 */
export function addressDot(e: Pick<EdgeAdmin, 'health' | 'reachability'>): Dot {
  const reach = outsideReachOf(e.reachability);
  if (e.health === 'offline' || reach === 'unreachable') return 'red';
  if (e.health === 'degraded' || reach === 'partly') return 'amber';
  if (e.health === 'online') return 'green';
  return 'grey';
}

/** What the provider's check and the outside checks say, for the row's Details. */
export function addressHealthLine(e: Pick<EdgeAdmin, 'health' | 'reachability'>): string {
  const reach = OUTSIDE_REACH_LABELS[outsideReachOf(e.reachability)];
  return `Provider check: ${healthLabel(e.health).toLowerCase()}. ${reach}.`;
}

const STATE_WORD = { published: 'In use', unpublished: 'Spare', draining: 'Retiring' } as const;

/**
 * "In use", "In use (trusted)" while address lanes are on, "Spare", "Retiring",
 * and "(only for Iran, Russia)" for an address handed only to members in some
 * countries (`audience`, docs/edges.md).
 */
export function addressStateWord(
  e: Pick<EdgeAdmin, 'publication' | 'lane' | 'audience'>,
  lanes: boolean,
): string {
  const word = STATE_WORD[e.publication];
  const lane =
    lanes && e.publication === 'published' ? ` (${e.lane === 'trusted' ? 'trusted' : 'open'})` : '';
  const only =
    e.audience.length > 0
      ? ` (only for ${e.audience.map((c) => countryName(c, 'en')).join(', ')})`
      : '';
  return `${word}${lane}${only}`;
}

export const CHECKED_BY_FCP = "checked by FCP's client";

/**
 * Whether members may be handed it yet, in two words or so; null when no
 * test is asked of this address (or it is retiring).
 */
export function testedWord(
  e: Pick<EdgeAdmin, 'verification'>,
  retiring: boolean,
): { word: string; needsTest: boolean } | null {
  if (!e.verification.required || retiring) return null;
  // A second address the provider reported later: served only once tested.
  if (e.verification.current && e.verification.learnedAddress)
    return {
      word: `new address ${e.verification.learnedAddress} not served until tested`,
      needsTest: true,
    };
  if (e.verification.current)
    return {
      word: e.verification.record?.method === 'client_check' ? CHECKED_BY_FCP : 'tested',
      needsTest: false,
    };
  if (e.verification.stale) return { word: 'retest needed', needsTest: true };
  return { word: 'not tested yet', needsTest: true };
}

export interface CountryGroup {
  /** "Works", "Blocked", "Not known", ... (what the address counts as there). */
  label: string;
  tone: Tone;
  countries: Array<{ code: string; title: string }>;
}

/**
 * Every checked country in one short line: the countries grouped by what the
 * address counts as there, in the order the countries are listed ("Works: CN
 * RU IR · Not known: AE"). "Blocked for 3 h" groups with every other block;
 * each country's own words (how long, why, from where) are its title.
 */
export function countrySummary(lines: EdgeCountryLine[], now: number): CountryGroup[] {
  const groups: CountryGroup[] = [];
  for (const line of lines) {
    const w = countryLine(line, now);
    const label = w.label.startsWith('Blocked for ') ? 'Blocked' : w.label;
    const title = [
      `${countryName(w.country, 'en')}: ${w.label.toLowerCase()}.`,
      w.from,
      w.reason,
      w.checked,
    ]
      .filter(Boolean)
      .join(' ');
    let g = groups.find((x) => x.label === label);
    if (!g) {
      g = { label, tone: w.tone, countries: [] };
      groups.push(g);
    }
    g.countries.push({ code: w.country, title });
  }
  // Problems first, so a block is never last on a long line.
  const rank = (t: Tone) => (t === 'danger' ? 0 : t === 'warning' ? 1 : t === 'success' ? 2 : 3);
  return groups.sort((a, b) => rank(a.tone) - rank(b.tone));
}

/**
 * Where a location's addresses come from, once: "Gcore" when the account is
 * named after its provider, else "<account> (<provider>)".
 */
export function accountText(accountName: string, provider: string): string {
  const p = providerLabel(provider);
  return accountName.trim().toLowerCase() === p.toLowerCase() ? p : `${accountName} (${p})`;
}
