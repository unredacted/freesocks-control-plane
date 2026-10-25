/**
 * A location the owner has TICKED an address in (docs/edges.md § "Replacing a
 * blocked address without a spare"): trusted, by an operator, on the evidence
 * of an L4 endpoint they confirmed there with a real session, for the template
 * the location builds with now. Only there may FCP's own client check stand in
 * for the owner's tick; the first address in any other location still needs
 * a human.
 *
 * The record is the location's existing trust (`qualification`), so every
 * invalidation that already clears it applies: a manual untrust, a credential
 * or settings change, a template edit. A trust override without a ticked
 * endpoint does not count. `locationTicked` is pure.
 */
import type { Doc } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';
import { resolveEdgeConfig, type EdgeConfig } from '../edgeConfig';

export function locationTicked(
  loc: Pick<Doc<'edgeLocations'>, 'enabled' | 'qualified' | 'qualification'> | null | undefined,
): boolean {
  return (
    !!loc &&
    loc.enabled &&
    loc.qualified &&
    loc.qualification?.by === 'admin' &&
    !!loc.qualification.evidence
  );
}

/**
 * Whether a confirmation FCP's own client check wrote still stands in for the
 * operator's at the publication gate: only while the switch is on and the
 * edge's location is still ticked (it was written on exactly those terms). Any
 * other confirmation stands as it is. An address already in use keeps serving
 * either way (render reads `verificationCurrent` alone); this guards the next
 * publication, so a spare FCP confirmed is not put in use once the owner turned
 * the check off or stopped trusting its location.
 */
export async function clientConfirmationStands(
  db: DatabaseReader,
  edge: Pick<Doc<'edges'>, 'verification' | 'locationId'>,
  cfg?: Pick<EdgeConfig, 'clientCheck'>,
): Promise<boolean> {
  if (edge.verification?.method !== 'client_check') return true;
  const c = cfg ?? (await resolveEdgeConfig(db));
  if (!c.clientCheck.enabled) return false;
  return !!edge.locationId && locationTicked(await db.get(edge.locationId));
}
