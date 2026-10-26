/**
 * Who receives a replacement (docs/edges.md § "Replacing a blocked address
 * without a spare", § "Address enumeration"): the pool index a new address
 * takes when a replace swaps out a published one, and what that means for the
 * members who held the blocked one. Assignment walks the pool by the origin's
 * pick (lib/edges/assignment.ts), so this one decision says which members move
 * to the new address.
 *
 *  - `inherit` (an origin on the legacy modulus walk): the replacement takes
 *    its target's index, so exactly the members who held the blocked address
 *    get the new one, together. That includes an account a censor holds and
 *    used to find the blocked address, so it receives the next one too; the
 *    re-block guard in the rotation machine stops automatic replacement from
 *    cycling on that.
 *  - `spread` (an origin on `hrw1`): who holds an address is decided by each
 *    member's own ranking, never by its index. The blocked address's holders
 *    scatter, each to their own next best address, and the replacement goes to
 *    the members it now outranks: about 3 in P+1 of the old holders (2 in P of
 *    everyone), a random slice. The index is kept only so the listener's
 *    template Host stays where it was.
 *
 * Pure.
 */
import type { EdgePickVersion } from './assignment';

export const REPLACEMENT_POLICIES = ['inherit', 'spread'] as const;
export type ReplacementPolicy = (typeof REPLACEMENT_POLICIES)[number];

/** The policy a replace on this origin applies: it follows the origin's pick. */
export function replacementPolicyOf(origin: { edgePick?: EdgePickVersion }): ReplacementPolicy {
  return origin.edgePick === 'hrw1' ? 'spread' : 'inherit';
}

export function replacementPlacement(input: {
  policy: ReplacementPolicy;
  /** The published address being replaced. */
  target: { poolIndex: number };
}): { poolIndex: number } {
  switch (input.policy) {
    case 'inherit':
    case 'spread':
      return { poolIndex: input.target.poolIndex };
  }
}
