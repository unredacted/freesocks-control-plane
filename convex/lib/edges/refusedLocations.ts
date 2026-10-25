/**
 * Locations whose provider refused, for good, to create one of a node's
 * addresses (`relays.refusedLocations`, docs/edges.md § "A location that
 * refused a create"). The same request would be refused the same way (a quota,
 * a setting the provider rejects), so automatic selection leaves the location
 * alone for this node for a while and takes the next one. Held per node: a
 * refusal of one node's request (its origin, its ports) says nothing about
 * another node's.
 *
 * Exports:
 *   REFUSED_LOCATION_HOLD_MS          how long automatic work keeps away
 *   refusedLocationsOf(relay, now)    the location ids held on this node
 *   withRefusedLocation(list, entry)  the list after a refusal (later end wins)
 *   withoutRefusedLocation(list, id)  the list once a create there succeeded
 */
import type { Doc, Id } from '../../_generated/dataModel';

type Relay = Doc<'relays'>;
type Entry = NonNullable<Relay['refusedLocations']>[number];

/** Six hours: long enough to stop a retry loop, short enough to notice a raised quota. */
export const REFUSED_LOCATION_HOLD_MS = 6 * 3_600_000;

/** The location ids automatic work keeps away from on this node now. */
export function refusedLocationsOf(
  relay: Pick<Relay, 'refusedLocations'>,
  now: number = Date.now(),
): Set<string> {
  return new Set(
    (relay.refusedLocations ?? []).filter((r) => r.until > now).map((r) => r.locationId as string),
  );
}

/** The list after a refusal in `entry.locationId`: ended entries pruned, the later end wins. */
export function withRefusedLocation(
  list: Relay['refusedLocations'],
  entry: Entry,
  now: number,
): Entry[] {
  const kept = (list ?? []).filter((r) => r.until > now && r.locationId !== entry.locationId);
  const prev = (list ?? []).find((r) => r.locationId === entry.locationId && r.until > now);
  return [...kept, { ...entry, until: Math.max(entry.until, prev?.until ?? 0) }];
}

/** The list once a create in `locationId` succeeded (ended entries pruned); null = nothing changes. */
export function withoutRefusedLocation(
  list: Relay['refusedLocations'],
  locationId: Id<'edgeLocations'>,
  now: number,
): Entry[] | null {
  if (!(list ?? []).some((r) => r.locationId === locationId)) return null;
  return (list ?? []).filter((r) => r.until > now && r.locationId !== locationId);
}
