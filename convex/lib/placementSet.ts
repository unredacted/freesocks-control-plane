/**
 * A key's whole group membership on a placement-capable backend (pure): the
 * group of its mode (`primary`, `subscriptions.backendPlacement`) and the
 * groups it also needs (`extras`, `subscriptions.backendExtraPlacements`): a
 * Hysteria key's REALITY backup group, so its subscription carries the node's
 * REALITY entry beside the Hysteria one (connectionModes.fallbackModeSlug).
 *
 * The two are always written and sent together: Remnawave REPLACES a key's
 * groups with what an update names, so a writer that knew only the primary
 * would silently drop the backup. A row without `backendExtraPlacements` (every
 * row from before this field) has none: `[]`, never "keep whatever the backend
 * has".
 */
export interface PlacementSet {
  primary: string | null;
  extras: string[];
}

export function placementSetOf(sub: {
  backendPlacement?: string | null;
  backendExtraPlacements?: readonly string[] | null;
}): PlacementSet {
  return {
    primary: sub.backendPlacement ?? null,
    extras: sub.backendPlacement ? [...(sub.backendExtraPlacements ?? [])] : [],
  };
}

/** The backend groups a set names, mode group first, each once. */
export function placementGroups(set: PlacementSet): string[] {
  return set.primary ? [...new Set([set.primary, ...set.extras])] : [];
}
