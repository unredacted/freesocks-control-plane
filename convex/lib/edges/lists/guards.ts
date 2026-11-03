/**
 * When a new version of a country list waits for a person (pure; unit-tested;
 * docs/edges.md "Country lists"). A list only feeds evidence, so an ordinary
 * update is used as it comes; one that looks like a broken or replaced source
 * is held until someone ticks it. Each measure (names, IPv4 addresses, IPv6
 * /64s) is judged on its own, so a change in one family alone still counts.
 */

export type HoldReason =
  | 'first_version'
  | 'emptied'
  | 'jump'
  | 'replaced'
  | 'too_broad'
  | 'invalid'
  | 'capped';

export interface ListMeasure {
  names: number;
  v4: number;
  v6: number;
}

export interface GuardInput {
  /** The active version's measure; null when the list has none yet. */
  previous: ListMeasure | null;
  next: ListMeasure;
  /** What the two versions share, in the same units. */
  common: ListMeasure;
  entries: number;
  invalid: number;
  tooBroad: number;
  capped: number;
  jumpFactor: number;
  minOverlap: number;
}

/** More invalid lines than this share holds a version: the source is likely not a list. */
export const MAX_INVALID_SHARE = 0.05;

const MEASURES = ['names', 'v4', 'v6'] as const;
const total = (m: ListMeasure) => m.names + m.v4 + m.v6;

export function holdReasons(i: GuardInput): HoldReason[] {
  const out = new Set<HoldReason>();
  if (!i.previous) out.add('first_version');
  else if (total(i.next) === 0 && total(i.previous) > 0) out.add('emptied');
  else
    for (const k of MEASURES) {
      const before = i.previous[k];
      const after = i.next[k];
      if (before === 0 && after === 0) continue;
      // A family that appears or disappears moved by more than any factor.
      if (before === 0 || after === 0) {
        out.add('jump');
        continue;
      }
      if (Math.max(after / before, before / after) > i.jumpFactor) out.add('jump');
      if (i.common[k] / Math.max(before, after) < i.minOverlap) out.add('replaced');
    }
  if (i.tooBroad > 0) out.add('too_broad');
  if (i.entries > 0 && i.invalid / i.entries > MAX_INVALID_SHARE) out.add('invalid');
  if (i.capped > 0) out.add('capped');
  return [...out];
}
