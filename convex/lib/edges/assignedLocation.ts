/**
 * A location an operator ASSIGNED (docs/edges.md § "Replacing a blocked
 * address without a spare"): where FCP's own client check may confirm an L4
 * address by itself, with no person testing it first. An operator who puts a
 * location in a node's picks (its provider set, or the picks of a guided setup
 * run working on the node) or trusts it by hand (the Trust override, or a
 * confirmed endpoint there) chose it on purpose; FCP then proves every address
 * made there with real clients before it is put in use.
 *
 * Not assigned: a location switched off, one an operator untrusted by hand
 * (`autoQualifyHold`, until they trust it again), and one no operator chose
 * for this node. Automatic selection never uses a location nobody assigned.
 * `locationAssigned` is pure.
 */
import type { Doc, Id } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';
import { resolveEdgeConfig, type EdgeConfig } from '../edgeConfig';
import { isTerminalRunState } from './setupRuns';

export function locationAssigned(
  loc:
    | Pick<
        Doc<'edgeLocations'>,
        '_id' | 'enabled' | 'qualified' | 'qualification' | 'autoQualifyHold'
      >
    | null
    | undefined,
  picks: ReadonlySet<string>,
): boolean {
  if (!loc || !loc.enabled || loc.autoQualifyHold) return false;
  if (loc.qualified && loc.qualification?.by === 'admin') return true;
  return picks.has(loc._id as string);
}

/**
 * The locations an operator picked for this node: its provider set, and the
 * picks of a guided setup run still working on it (its picks join the set only
 * at go-live, after the addresses were made and checked).
 */
export async function assignedPicksOf(
  db: DatabaseReader,
  origin: Pick<Doc<'relays'>, '_id' | 'providerSet'> | null | undefined,
): Promise<Set<string>> {
  const out = new Set<string>();
  if (!origin) return out;
  for (const p of origin.providerSet ?? []) out.add(p.locationId as string);
  const runs = await db
    .query('edgeSetupRuns')
    .withIndex('by_relay', (q) => q.eq('relayId', origin._id))
    .collect();
  for (const r of runs) {
    if (isTerminalRunState(r.state)) continue;
    for (const p of r.picks ?? []) out.add(p.locationId as string);
  }
  return out;
}

/** Whether the edge's own location is assigned for the edge's node. */
export async function edgeLocationAssigned(
  db: DatabaseReader,
  edge: Pick<Doc<'edges'>, 'locationId' | 'relayId'>,
): Promise<boolean> {
  if (!edge.locationId) return false;
  const [loc, origin] = await Promise.all([
    db.get(edge.locationId as Id<'edgeLocations'>),
    db.get(edge.relayId),
  ]);
  return locationAssigned(loc, await assignedPicksOf(db, origin));
}

/**
 * Whether a confirmation FCP's own client check wrote still stands in for an
 * operator's at the publication gate: only while the switch is on and the
 * edge's location is still assigned for its node (it was written on exactly
 * those terms). Any other confirmation stands as it is. An address already in
 * use keeps serving either way (render reads `verificationCurrent` alone); this
 * guards the next publication, so a spare FCP confirmed is not put in use once
 * the owner turned the check off or took the location away.
 */
export async function clientConfirmationStands(
  db: DatabaseReader,
  edge: Pick<Doc<'edges'>, 'verification' | 'locationId' | 'relayId'>,
  cfg?: Pick<EdgeConfig, 'clientCheck'>,
): Promise<boolean> {
  if (edge.verification?.method !== 'client_check') return true;
  const c = cfg ?? (await resolveEdgeConfig(db));
  if (!c.clientCheck.enabled) return false;
  return edgeLocationAssigned(db, edge);
}

/**
 * Whether automatic upkeep may use a pick of a node's set: a trusted location,
 * or (L4, with FCP's own client check ready) any location the operator picked
 * that is on and not untrusted by hand, since the check proves what is made there.
 */
export function pickUsable(
  loc: Pick<Doc<'edgeLocations'>, 'enabled' | 'qualified' | 'autoQualifyHold'>,
  opts: { l4: boolean; clientCheckReady: boolean },
): boolean {
  if (loc.qualified) return true;
  return opts.l4 && opts.clientCheckReady && loc.enabled && !loc.autoQualifyHold;
}
