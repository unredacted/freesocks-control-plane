/**
 * Keys by country in words (pure; unit-tested): how many keys are set to a
 * country, and what that number is not (docs/edges.md "Keys by country").
 *
 * The numbers are counts of keys of freedom modes: a key of a privacy mode
 * carries no country, and a member who never answered and was never guessed
 * is counted for no country. Every sentence here keeps to that.
 *
 * Exports:
 *   keysLine      one country's count, for its row and its page
 *   keysNotes     under the countries: the opt-out, keys with neither, what is not counted
 *   KEYS_SCOPE    the one-line reminder of what the count leaves out
 *   KEYS_UNLISTED / KEYS_NOT_COUNTED   why a page gives no number
 */
import type { CountryKeyCounts, CountryKeyTotals } from '@shared/contracts/edges';
import { relativeTime } from '../lib/time';

const num = (n: number) => n.toLocaleString('en-US');

/** What a count of keys by country leaves out, in one line. */
export const KEYS_SCOPE =
  'Only keys of freedom modes are counted. A key of a privacy mode carries no country, and a member who never answered and was never guessed is counted for no country.';

/** A country that is not on the list has no count of its own. */
export const KEYS_UNLISTED =
  'Keys are counted per country only for countries on the censored-country list.';

/** Before the first count has finished: no number, never zero. */
export const KEYS_NOT_COUNTED =
  'Keys by country are not counted yet. The first count runs a few minutes after an update.';

/**
 * One country's count: "212 keys are set to it: 180 by the member's own
 * answer, 32 by FCP's guess." `where` is how the page names the country
 * ("it" on the list, "this country" on its own page). Null until the first
 * count has finished.
 */
export function keysLine(
  keys: CountryKeyCounts,
  counted: boolean,
  where: 'it' | 'this country' = 'it',
): string | null {
  if (!counted) return null;
  const total = keys.answered + keys.guessed;
  if (total === 0) return `No key is set to ${where}.`;
  const head = `${num(total)} ${total === 1 ? 'key is' : 'keys are'} set to ${where}`;
  if (keys.guessed === 0) return `${head}, by the member's own answer.`;
  if (keys.answered === 0) return `${head}, by FCP's guess.`;
  return `${head}: ${num(keys.answered)} by the member's own answer, ${num(keys.guessed)} by FCP's guess.`;
}

/**
 * Under the countries: the keys no country owns, and what none of the numbers
 * count. Before the first count: that it has not run yet.
 */
export function keysNotes(totals: CountryKeyTotals, now: number): string[] {
  if (!totals.counted) return [KEYS_NOT_COUNTED, KEYS_SCOPE];
  const out: string[] = [];
  out.push(
    `${num(totals.optOut)} ${totals.optOut === 1 ? 'key has' : 'keys have'} the opt-out: the member chose not to give a country.`,
  );
  const when = totals.countedAt ? ` (last ${relativeTime(totals.countedAt, now)})` : '';
  out.push(
    `${num(totals.neither)} ${totals.neither === 1 ? 'key' : 'keys'} of freedom modes ${totals.neither === 1 ? 'has' : 'have'} no answer and no guess. That number is counted once a day${when}. The numbers per country move as members answer.`,
  );
  if (totals.otherGuessed > 0)
    out.push(
      `${num(totals.otherGuessed)} ${totals.otherGuessed === 1 ? 'key is' : 'keys are'} guessed in a country that is not on this list.`,
    );
  out.push(KEYS_SCOPE);
  return out;
}
