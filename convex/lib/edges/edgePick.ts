/**
 * Switching an origin's address pick (`relays.edgePick`, docs/edges.md
 * "Address enumeration"): the share of its members whose pair of addresses
 * changes, estimated over synthetic seats with the pool as it is now, so the
 * operator sees what the switch costs before making it. Pure.
 */
import { assignEndpoints, fnv1a32, type EdgePickVersion, type PublishedEdge } from './assignment';

/** Synthetic seats the estimate is computed over. */
export const EDGE_PICK_SAMPLE = 600;

/** A synthetic 64-hex seat, spread over the whole seed space. */
export function sampleSeat(i: number): string {
  let out = '';
  for (let k = 0; k < 8; k++)
    out += (fnv1a32(`edge-pick-sample:${i}:${k}`) >>> 0).toString(16).padStart(8, '0');
  return out;
}

export interface PickMoves {
  /** Seats sampled (0 when the pool has nothing assignable). */
  sampled: number;
  /** Of those, how many are handed at least one address they were not handed before. */
  moved: number;
}

/** How many sampled seats move when the origin's pick goes from `from` to `to`. */
export function pickMoves(
  published: readonly PublishedEdge[],
  from: EdgePickVersion | null,
  to: EdgePickVersion | null,
  opts: { preferDistinctProviders: boolean; includeBackup: boolean; now: number },
  sample = EDGE_PICK_SAMPLE,
): PickMoves {
  const base = {
    now: opts.now,
    preferDistinctProviders: opts.preferDistinctProviders,
    includeBackup: opts.includeBackup,
  };
  // The addresses a seat is handed, whatever their roles: a primary and a
  // backup that swap places hand out nothing new.
  const heldBy = (seat: string, pick: EdgePickVersion | null) => {
    const a = assignEndpoints(seat, published, { ...base, ...(pick ? { edgePick: pick } : {}) });
    return [a.primary?.edge.edgeId, a.backup?.edge.edgeId].filter((x): x is string => !!x);
  };
  let sampled = 0;
  let moved = 0;
  for (let i = 0; i < sample; i++) {
    const seat = sampleSeat(i);
    const before = new Set(heldBy(seat, from));
    if (before.size === 0) continue;
    sampled++;
    if (heldBy(seat, to).some((id) => !before.has(id))) moved++;
  }
  return { sampled, moved };
}
