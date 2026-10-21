/**
 * Shared constants of an account's CATALOG (`convex/edgeProviderCatalog.ts`):
 * what its credentials reach at the provider, as the location pickers offer
 * it. Isolate-safe: imported by the catalog module and the provider actions.
 */

export const CATALOG_KINDS = ['zones', 'regions', 'projects', 'tlsConfigurations'] as const;
export type CatalogKind = (typeof CATALOG_KINDS)[number];

/** A picker refreshes a catalog older than this (fail-soft: the old one shows meanwhile). */
export const CATALOG_STALE_MS = 12 * 60 * 60 * 1000;
/** A refresh this soon after the last one answers from the stored rows. */
export const CATALOG_REFRESH_FLOOR_MS = 30 * 1000;
