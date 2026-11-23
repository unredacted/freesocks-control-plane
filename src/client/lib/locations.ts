/**
 * Member-facing location helpers over `PublicConfig.locations`. A location may
 * be open to a subset of tiers (`tiers`, slugs; null = every tier): the SPA
 * lists such a location for everyone, and marks it "Members" for a member
 * whose tier is not on it (the server never issues there: convex/lib/locationAccess.ts).
 */
export interface PublicLocation {
  code: string;
  label: string;
  online: boolean;
  load?: 'quiet' | 'busy' | 'crowded' | 'unknown';
  tiers?: string[] | null;
}

/** Whether a member on `tierSlug` may use this location. Unknown tier = only
 *  the locations open to everyone. */
export function locationOpenTo(loc: PublicLocation, tierSlug: string | null | undefined): boolean {
  const tiers = loc.tiers ?? null;
  if (tiers === null) return true;
  return !!tierSlug && tiers.includes(tierSlug);
}

/** The place part of a label ("Kansas City" of "Kansas City, MO"), for short button text. */
export function shortPlace(label: string): string {
  return label.split(',')[0]!.trim() || label;
}
