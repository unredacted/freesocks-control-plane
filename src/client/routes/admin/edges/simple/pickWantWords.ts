/**
 * The words of a pick's address count (docs/edges.md "Addresses per
 * location"): the line on the node's providers card, and what saving a count
 * adds and costs before it is saved (pure).
 */
import type { PickWantPreview } from '@shared/contracts/edges';
import { MAX_DESIRED_PUBLISHED } from '@shared/contracts/edgeLimits';
import { costWords, money } from '../lib/planWords';

/** The most addresses per transport one pick may ask for (as the server checks). */
export const MAX_PICK_WANT = 8;

/** "Addresses here: …" for one pick. */
export function wantLine(
  want: number | null,
  carries: readonly string[],
  nameOf: (key: string) => string = (k) => k,
): string {
  if (want === null) return 'Addresses here: at least one, of any transport.';
  const each = carries.length > 1 ? ' of each transport' : '';
  const named = carries.length > 0 ? ` (${carries.map(nameOf).join(', ')})` : '';
  return `Addresses here: ${want}${each}${named}.`;
}

/** What saving the count would do, in a few lines. */
export function wantPreviewLines(p: PickWantPreview): string[] {
  const out: string[] = [];
  if (p.tooLarge) {
    out.push(
      `The node would then want ${p.total} addresses in use, over the limit of ${MAX_DESIRED_PUBLISHED}. Lower the count.`,
    );
    return out;
  }
  if (p.adds === 0) out.push('No new address. The location has that many already.');
  else {
    const n = p.adds === 1 ? '1 more address' : `${p.adds} more addresses`;
    const each = p.each;
    const monthly =
      each && each.monthly !== null && each.currency && each.basis !== 'unset'
        ? `, about ${money(each.monthly * p.adds, each.currency)} a month more (${costWords(each)} each)`
        : each
          ? ` (${costWords(each)} each)`
          : '';
    out.push(`Adds ${n} in use here${monthly}.`);
    if (p.fits < p.adds)
      out.push(
        p.fits === 0
          ? "None of them fits under this account's monthly cap. Raise the cap, or upkeep adds none."
          : `Only ${p.fits} of ${p.adds} fit under this account's monthly cap.`,
      );
  }
  out.push('Lowering a count later retires nothing. Rebalance frees what is no longer needed.');
  return out;
}
