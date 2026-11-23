/**
 * Tier-gated locations. A backend instance may name the tiers allowed on it
 * (`backendServers.allowedTierIds`; absent or empty = every tier), and a tier
 * says whether its members may move their key between locations
 * (`tiers.canSwitchLocation`; absent = paid tiers yes, the default-free tier no).
 *
 * The instance list is a HARD issuance filter (lib/remnawavePlacement.ts
 * `resolvePlacementTarget` and backendServers.pickCandidatesForIssue): unlike
 * the member's location preference, which drops away whenever honoring it
 * would block issuance, a tier that is not allowed somewhere is never placed
 * there. The public catalog (lib/locations.ts) carries the allowed tier SLUGS
 * per location so the SPA can mark members-only locations "Members"
 * instead of hiding them.
 */
import type { Doc, Id } from '../_generated/dataModel';

type AccessRow = Pick<Doc<'backendServers'>, 'allowedTierIds'>;

/** Whether `tierId` may be placed on this instance. No tier given = no filter. */
export function serverAllowsTier(
  server: AccessRow,
  tierId: Id<'tiers'> | string | null | undefined,
): boolean {
  if (!tierId) return true;
  const list = server.allowedTierIds;
  return !list || list.length === 0 || list.some((id) => id === tierId);
}

/** Whether this instance is open to every tier. */
export function serverOpenToAll(server: AccessRow): boolean {
  return !server.allowedTierIds || server.allowedTierIds.length === 0;
}

/** May a member on this tier move their key to another location? */
export function tierCanSwitchLocation(
  tier: Pick<Doc<'tiers'>, 'canSwitchLocation' | 'isDefaultFree'>,
): boolean {
  return tier.canSwitchLocation ?? !tier.isDefaultFree;
}

/**
 * The tier slugs a location (all instances at one code) is open to: null when
 * any instance there takes every tier, else the union of the instances' lists,
 * by slug, in the tiers' own order. Ids that no longer name a tier drop out.
 */
export function locationTierSlugs(
  instances: readonly AccessRow[],
  tiers: readonly Pick<Doc<'tiers'>, '_id' | 'slug' | 'priority'>[],
): string[] | null {
  if (instances.some(serverOpenToAll)) return null;
  const ids = new Set<string>(instances.flatMap((s) => (s.allowedTierIds ?? []) as string[]));
  return tiers
    .filter((t) => ids.has(t._id as string))
    .sort((a, b) => a.priority - b.priority)
    .map((t) => t.slug);
}

/** Whether a catalog location (its `tiers` projection) is open to a tier slug. */
export function locationOpenTo(entry: { tiers: string[] | null }, tierSlug: string): boolean {
  return entry.tiers === null || entry.tiers.includes(tierSlug);
}
