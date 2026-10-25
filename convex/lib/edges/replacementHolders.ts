/**
 * Who receives a replacement (docs/edges.md § "Replacing a blocked address
 * without a spare"): the pool index a new address takes when a replace swaps
 * out a published one. Assignment hashes members over the pool order
 * (lib/edges/assignment.ts), so this one decision says which members move to
 * the new address.
 *
 * `inherit`, today's and the only policy: the replacement takes its target's
 * index, so exactly the members who held the blocked address get the new one.
 * That includes an account a censor holds and used to find the blocked address,
 * so it receives the next one too; the re-block guard in the rotation machine
 * stops automatic replacement from cycling on that. A policy that spreads or
 * screens those holders (trust pools, suspicion) belongs here, behind this
 * function, and nowhere else. Pure.
 */
export const REPLACEMENT_POLICIES = ['inherit'] as const;
export type ReplacementPolicy = (typeof REPLACEMENT_POLICIES)[number];

/** The policy every replace applies. */
export const REPLACEMENT_POLICY: ReplacementPolicy = 'inherit';

export function replacementPlacement(input: {
  policy: ReplacementPolicy;
  /** The published address being replaced. */
  target: { poolIndex: number };
}): { poolIndex: number } {
  switch (input.policy) {
    case 'inherit':
      return { poolIndex: input.target.poolIndex };
  }
}
