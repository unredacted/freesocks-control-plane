/**
 * The DNS zones an account reaches, as the pickers offer them (pure; unit
 * tested): the zones its catalog lists (what the token reaches, as last
 * listed) plus the zones of its own locations (checked with the provider when
 * each was created), active first, then by name. Used by the location form, the
 * protect sheet and the origin-name zone of a backend setup.
 *
 * Exports: zoneChoices(catalog, locations), catalogStale(catalog, now), catalogAge(catalog)
 */
import type { EdgeCatalogView, EdgeLocationAdmin } from '@shared/contracts/edges';

export interface ZoneChoice {
  id: string;
  name: string;
  /** The provider's status of the zone when last listed (`active`, `pending`, `paused`), or null. */
  status: string | null;
  /** The account already has a location in this zone. */
  located: boolean;
}

function placementZone(
  l: Pick<EdgeLocationAdmin, 'placement'>,
): { id: string; name: string } | null {
  const id = l.placement.zoneId;
  const name = l.placement.zoneName;
  return typeof id === 'string' && typeof name === 'string' ? { id, name } : null;
}

export function zoneChoices(
  catalog: Pick<EdgeCatalogView, 'kinds'> | null | undefined,
  locations: readonly Pick<EdgeLocationAdmin, 'placement'>[] = [],
): ZoneChoice[] {
  const out = new Map<string, ZoneChoice>();
  for (const z of catalog?.kinds.zones?.items ?? [])
    out.set(z.id, { id: z.id, name: z.label, status: z.facts?.status ?? null, located: false });
  for (const l of locations) {
    const z = placementZone(l);
    if (!z) continue;
    const known = out.get(z.id);
    out.set(z.id, known ? { ...known, located: true } : { ...z, status: null, located: true });
  }
  return [...out.values()].sort(
    (a, b) =>
      Number((b.status ?? 'active') === 'active') - Number((a.status ?? 'active') === 'active') ||
      a.name.localeCompare(b.name),
  );
}

/** When the catalog was last listed (any kind), or null when never. */
export function catalogAge(
  catalog: Pick<EdgeCatalogView, 'kinds'> | null | undefined,
): number | null {
  const at = Object.values(catalog?.kinds ?? {})
    .map((k) => k?.refreshedAt ?? null)
    .filter((n): n is number => typeof n === 'number' && n > 0);
  return at.length > 0 ? Math.max(...at) : null;
}

/** Whether a picker should list the account again (never listed, or older than the server says). */
export function catalogStale(
  catalog: Pick<EdgeCatalogView, 'kinds' | 'staleAfterMs'> | null | undefined,
  now: number = Date.now(),
): boolean {
  if (!catalog) return false;
  const at = catalogAge(catalog);
  return at === null || now - at > catalog.staleAfterMs;
}
