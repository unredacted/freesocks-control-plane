/**
 * Edge addresses against watched allowlists, pure (docs/edges.md "Edge
 * addresses against allowlists"). One mark per (edge, list, family) says
 * whether the version it was checked against holds the edge's address, and
 * since when. Under a whitelist both the dialled address and the server name
 * must be listed; this is the address half.
 *
 *  - A mark is current only while its version is the list's active one AND its
 *    address is the edge's address now. Otherwise it is "checking": the next
 *    recheck looks again.
 *  - A new address starts the mark over: dates seen with the old address say
 *    nothing about the new one.
 *  - An address that was listed and no longer is has left the list. That asks
 *    for a look until a person says they saw it ("Seen it"); being listed
 *    again and leaving again asks again. One never listed asks nothing.
 */
import type { CountryListMarkState } from '../../../../src/shared/contracts/edgeCodes';

export const MARK_FAMILIES = ['v4', 'v6'] as const;
export type MarkFamily = (typeof MARK_FAMILIES)[number];

export interface MarkFields<V extends string = string> {
  address: string;
  versionId: V;
  listed: boolean;
  firstListedAt?: number;
  lastListedAt?: number;
  leftAt?: number;
  checkedAt: number;
  seenAt?: number;
}

/** A mark after one check against a version. Fields absent from the result are cleared. */
export function nextMark<V extends string>(
  prev: MarkFields<V> | null,
  c: { address: string; versionId: V; listed: boolean; now: number },
): MarkFields<V> {
  if (!prev || prev.address !== c.address)
    return {
      address: c.address,
      versionId: c.versionId,
      listed: c.listed,
      checkedAt: c.now,
      ...(c.listed ? { firstListedAt: c.now, lastListedAt: c.now } : {}),
    };
  const out: MarkFields<V> = {
    address: prev.address,
    versionId: c.versionId,
    listed: c.listed,
    checkedAt: c.now,
    ...(prev.firstListedAt !== undefined ? { firstListedAt: prev.firstListedAt } : {}),
    ...(prev.lastListedAt !== undefined ? { lastListedAt: prev.lastListedAt } : {}),
    ...(prev.leftAt !== undefined ? { leftAt: prev.leftAt } : {}),
    ...(prev.seenAt !== undefined ? { seenAt: prev.seenAt } : {}),
  };
  if (c.listed) {
    out.firstListedAt = prev.firstListedAt ?? c.now;
    out.lastListedAt = c.now;
    delete out.leftAt;
  } else if (prev.listed) out.leftAt = c.now;
  return out;
}

export type MarkState = CountryListMarkState;

export interface MarkNow {
  /** The edge's address of the mark's family now (absent: it has none). */
  address: string | undefined;
  /** The list's version in use now. */
  activeVersionId: string | undefined;
}

/** What a mark says about the edge's address now. */
export function markState(mark: MarkFields | null, now: MarkNow): MarkState {
  if (
    !mark ||
    now.address === undefined ||
    mark.address !== now.address ||
    now.activeVersionId === undefined ||
    mark.versionId !== now.activeVersionId
  )
    return 'checking';
  if (mark.listed) return 'listed';
  return mark.lastListedAt !== undefined ? 'left' : 'not_listed';
}

/** The attention rule: it left the list, and nobody said they saw it since it was last listed. */
export function leftNeedsLook(mark: MarkFields | null, now: MarkNow): boolean {
  if (!mark || markState(mark, now) !== 'left') return false;
  return !(
    mark.seenAt !== undefined &&
    mark.lastListedAt !== undefined &&
    mark.seenAt > mark.lastListedAt
  );
}

/** When the state began, as far as the mark knows. */
export function markSince(mark: MarkFields | null, state: MarkState): number | null {
  if (!mark) return null;
  if (state === 'listed') return mark.firstListedAt ?? null;
  if (state === 'left') return mark.leftAt ?? null;
  return null;
}
