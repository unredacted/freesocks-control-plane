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
 * endpoint does not count. Pure.
 */
import type { Doc } from '../../_generated/dataModel';

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
