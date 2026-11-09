/**
 * The words of a country's SNIs (pure; unit-tested): which
 * SNIs members there get, from which name list, what they count as there,
 * and whether other countries use them too (`CountryViewSni.scope`, from the
 * marks the selection reads).
 *
 * Exports:
 *   countryShort        "Iran"; an unknown code stays the code
 *   sniCardTitle / SNI_CARD_INTRO / SNI_CARD_EMPTY   the country page's SNI card
 *   sniScopeBadge       the short badge of a scope (null: none shown)
 *   sniScopeLine        where else an SNI is used, in one sentence
 *   sniVerdictLine      what it counts as there, and why
 *   sniHandedLine       how many members there are handed it
 *   sniSummaryLine      the countries list's count (null: no SNI in use)
 */
import type { CountryViewSni } from '@shared/contracts/edges';
import { countryName } from '@client/lib/countries';
import { NAME_BASIS_WORDS, STATE_WORDS, percent } from './words';

export function countryShort(code: string): string {
  const name = countryName(code, 'en');
  return name && name !== code ? name : code;
}

/** "China", "China or Russia", "China, Russia or Turkey". */
function orList(items: readonly string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}`;
}

export function sniCardTitle(code: string): string {
  return `SNIs in ${countryShort(code)}`;
}

export const SNI_CARD_INTRO =
  'Each SNI a member here may get, across all nodes, with its SNI list, its state here, and whether other countries use it too.';

export const SNI_CARD_EMPTY = 'No transport in use here presents an SNI.';

export function sniScopeBadge(s: Pick<CountryViewSni, 'scope'>, code: string): string | null {
  if (s.scope === 'only_here') return `Only for ${countryShort(code)}`;
  if (s.scope === 'not_here') return 'Not used here';
  return null;
}

export function sniScopeLine(
  s: Pick<CountryViewSni, 'scope' | 'blockedElsewhere'>,
  code: string,
): string {
  switch (s.scope) {
    case 'shared':
      return 'Shared: used in every listed country and outside them.';
    case 'some':
      return `Shared, but not in ${orList(s.blockedElsewhere.map(countryShort))}: blocked there.`;
    case 'only_here':
      return `Only for ${countryShort(code)}: blocked in every other listed country.`;
    case 'not_here':
      return `Not used in ${countryShort(code)}: blocked here.`;
  }
}

export function sniVerdictLine(s: Pick<CountryViewSni, 'state' | 'basis'>): string {
  return `${STATE_WORDS[s.state].label} here. ${NAME_BASIS_WORDS[s.basis]}`;
}

export function sniHandedLine(s: Pick<CountryViewSni, 'handed' | 'transports'>): string | null {
  const parts: string[] = [];
  if (s.handed > 0) parts.push(`Handed to ${percent(s.handed)} of members here.`);
  if (s.transports > 1) parts.push(`On ${s.transports} transports.`);
  return parts.length > 0 ? parts.join(' ') : null;
}

export function sniSummaryLine(
  counts: { used: number; onlyHere: number },
  code: string,
): string | null {
  if (counts.used === 0) return null;
  const used = `${counts.used} ${counts.used === 1 ? 'SNI' : 'SNIs'} in use there`;
  return counts.onlyHere > 0
    ? `${used}, ${counts.onlyHere} only for ${countryShort(code)}.`
    : `${used}.`;
}
