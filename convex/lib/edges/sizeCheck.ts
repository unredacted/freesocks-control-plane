/**
 * Whether a load balancer SIZE can front an FCP node at all, checked before
 * anything billable is created.
 *
 * Scaleway: only its multi-cloud sizes accept a backend server hosted outside
 * Scaleway; the standard ones (LB-S, LB-GP-M) take Scaleway resources only and
 * refuse the backend of an outside node once the load balancer is built and
 * billed ("Only certain Load Balancer types (L and XL) allow you to add
 * non-Scaleway resources as backend servers":
 * https://www.scaleway.com/en/docs/load-balancer/troubleshooting/configuration/,
 * read 2026-10-21). An FCP node is always treated as outside Scaleway.
 *
 * Which sizes are multi-cloud is the provider's own answer: its size list
 * (`listLbTypes`, `LbType.multicloud`: "Ability to handle backend servers
 * outside Scaleway"), as the location's last inventory pull recorded it. A
 * location never pulled, or a size its list does not name, falls back to the
 * sizes the documentation names (`SCALEWAY_MULTICLOUD_SIZES`); anything else is
 * refused, since an unproven size would be paid for and then refused.
 */
import type { EdgeProviderId } from '../edgeProviderIds';

/** The reason code: the effective size takes the provider's own servers only. */
export const SIZE_NOT_MULTICLOUD = 'size_not_multicloud';

/** What a refusal says (the words of the code, for a pick check's issue line). */
export const SIZE_NOT_MULTICLOUD_WORDS =
  'This size only accepts servers hosted at Scaleway. Pick a multi-cloud size (L or XL).';

/** The documented multi-cloud sizes, for a location whose size list is not known. */
export const SCALEWAY_MULTICLOUD_SIZES: readonly string[] = ['lb-gp-l', 'lb-gp-xl'];

/** The label suffix the Scaleway inventory has given a multi-cloud size from the start. */
const MULTICLOUD_LABEL = '(multi-cloud)';

/** Providers whose size decides whether an outside node can be a backend. */
export function sizeCheckApplies(provider: EdgeProviderId | string): boolean {
  return provider === 'scaleway';
}

export interface SizeFlavor {
  id: string;
  label?: string;
  /** The provider's own flag; absent on an inventory pulled before it was kept. */
  multicloud?: boolean;
}

/** The flavors of a stored inventory snapshot (`edgeLocations.inventorySnapshot`), or null. */
export function flavorsOfSnapshot(snapshot: string | null | undefined): SizeFlavor[] | null {
  if (!snapshot) return null;
  try {
    const parsed = JSON.parse(snapshot) as { flavors?: unknown };
    if (!Array.isArray(parsed.flavors)) return null;
    return parsed.flavors.filter(
      (f): f is SizeFlavor =>
        !!f && typeof f === 'object' && typeof (f as { id?: unknown }).id === 'string',
    );
  } catch {
    return null;
  }
}

/**
 * Whether a Scaleway size takes a server outside Scaleway: the size list's own
 * flag (or, on a list pulled before the flag was kept, its label), else the
 * documented multi-cloud sizes. Sizes compare without regard to case.
 */
export function scalewaySizeIsMulticloud(size: string, flavors: SizeFlavor[] | null): boolean {
  const want = size.trim().toLowerCase();
  const listed = flavors?.find((f) => f.id.trim().toLowerCase() === want);
  if (listed) {
    if (typeof listed.multicloud === 'boolean') return listed.multicloud;
    return (listed.label ?? '').trim().toLowerCase().endsWith(MULTICLOUD_LABEL);
  }
  return SCALEWAY_MULTICLOUD_SIZES.includes(want);
}

/**
 * Why the effective template (template, regional values, the pick's options)
 * cannot front an FCP node at this place, or null: a Scaleway size that is not
 * multi-cloud (`size_not_multicloud`). `inventorySnapshot` is the location's.
 */
export function sizeProblemOf(
  provider: EdgeProviderId | string,
  params: Record<string, unknown>,
  inventorySnapshot: string | null | undefined,
): string | null {
  if (!sizeCheckApplies(provider)) return null;
  const size = typeof params.type === 'string' ? params.type : '';
  if (!size) return null;
  return scalewaySizeIsMulticloud(size, flavorsOfSnapshot(inventorySnapshot))
    ? null
    : SIZE_NOT_MULTICLOUD;
}
