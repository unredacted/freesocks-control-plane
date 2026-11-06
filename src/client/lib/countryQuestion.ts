/**
 * The country question (docs/privacy.md "Where a member connects from",
 * docs/mirrors.md "Shaped for the member's answer"): when the member page asks
 * "Where are you connecting from?" at sign-up and for a mirror, what it starts
 * from, and what a key's mirrors are set up for. Pure, so the rules are
 * unit-tested apart from the components (CountryQuestion, MirrorHelp,
 * MirrorSuggestion, GetAccount).
 *
 * The answer is the same stored choice as the account card's: a listed country
 * or the opt-out `ZZ`. Automatic is not offered here: a mirror cannot see where
 * its reader is, so for a mirror Automatic would mean "no country".
 */

/** The opt-out: "Somewhere else, or I'd rather not say". */
export const ELSEWHERE = 'ZZ';

/** What the sealed connection-region view says, as far as the question needs it. */
export interface RegionViewLike {
  applies: boolean;
  choice: string | null;
  options: readonly string[];
  guess?: { country: string } | null;
}

/**
 * Whether to ask: the deployment asks (`publicConfig.countryQuestion`), this
 * build can seal (the answer never travels in plaintext, and the server
 * refuses it), and the key (or, before the first key, the mode picked) holds a
 * country with at least one listed option.
 */
export function asksCountry(o: {
  countryQuestion?: boolean;
  canSeal: boolean;
  view?: RegionViewLike | null;
}): boolean {
  return (
    o.countryQuestion === true &&
    o.canSeal &&
    !!o.view &&
    o.view.applies &&
    o.view.options.length > 0
  );
}

/**
 * The answer the picker starts on: the first candidate (the guess, then this
 * request's country) that is a listed option, else nothing (`''`, "Choose
 * one"). Never the opt-out: that would make the question meaningless for the
 * people it is for.
 */
export function prefillAnswer(
  options: readonly string[],
  ...candidates: (string | null | undefined)[]
): string {
  for (const c of candidates) {
    const code = c?.trim().toUpperCase();
    if (code && options.includes(code)) return code;
  }
  return '';
}

/** Whether a picked value is an answer the server takes. */
export function isAnswer(value: string, options: readonly string[]): boolean {
  return value === ELSEWHERE || options.includes(value);
}

/** What a key's mirrors are set up for, from its stored answer. */
export type MirrorCountry =
  { kind: 'country'; country: string } | { kind: 'none' } | { kind: 'unset' };

export function mirrorCountry(view: RegionViewLike | null | undefined): MirrorCountry {
  const choice = view?.choice ?? null;
  if (choice === ELSEWHERE) return { kind: 'none' };
  if (choice && view?.options.includes(choice)) return { kind: 'country', country: choice };
  return { kind: 'unset' };
}
