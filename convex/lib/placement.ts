/**
 * The generic mode→placement seam: a DB-side resolver per placement-capable
 * backend (the HTTP providers in lib/backends/* stay pure — this layer owns
 * everything that needs the database). Domain code dispatches through
 * `resolverFor(backend)` instead of importing a backend's placement module,
 * so a new backend participates in connection modes by registering a resolver
 * here + flipping its `placement` capability — no changes to issuance,
 * lifecycle, or the admin routes.
 *
 * Invariant (pinned by placement.test.ts): a backend has a resolver in
 * PLACEMENT_RESOLVERS ⇔ CAPABILITIES[backend].placement is true. Backends
 * without a placement concept get TRIVIAL_RESOLVER via `resolverFor`.
 */
import type { DatabaseReader } from '../_generated/server';
import { BACKEND_IDS, type BackendId } from './backendIds';
import { CAPABILITIES } from './backends/capabilities';
import {
  publicProjection,
  resolveModeCatalog,
  type ModeCatalog,
  type ModeWithAvailability,
  type PublicConnectionMode,
} from './connectionModes';
import {
  applyRemnawaveConfigPatch,
  remnawaveEffectiveGate,
  resolveBoundModeCounts,
  resolveBoundModeIds,
  resolvePlacementTarget,
  summarizeRemnawaveConfig,
} from './remnawavePlacement';

export interface PlacementTarget {
  placement: string | null;
  serverId: string | null;
  /** Multi-panel deploy where no pool squad is attributable to a panel yet —
   *  the caller must fail loudly (503) instead of minting a dead key. */
  unattributedMultiPanel?: boolean;
}

export interface PlacementResolver {
  /** The (placement, server) pair a NEW key issues into. */
  resolveTarget(
    db: DatabaseReader,
    modeSlug: string | null,
    opts: { location?: string | null; onlyServerId?: string | null; rand?: () => number },
  ): Promise<PlacementTarget>;
  /** Mode slugs with a usable binding on this backend (raw, no cross-mode
   *  fallback — feeds per-backend availability). */
  boundModeSlugs(db: DatabaseReader): Promise<Set<string>>;
  /** Per-mode bound counts (sizes only, never the config) for admin feedback. */
  boundCounts(db: DatabaseReader): Promise<Record<string, number>>;
  /** The re-issue anti-downgrade gate: blocked iff the member's effective mode
   *  is unusable here while some other mode is usable. */
  effectiveGate(db: DatabaseReader, modeSlug: string | null): Promise<{ blocked: boolean }>;
  /** Validate one mode's admin patch against the stored config; returns the
   *  JSON string to persist, or null when the entry carries no ops. Throws on
   *  malformed input. */
  applyConfigPatch(existingConfigJson: string | null, entry: unknown): string | null;
  /** Public-safe summary of one stored config (never its contents). */
  summarize(configJson: string | null): { bound: boolean; count: number };
}

const remnawaveResolver: PlacementResolver = {
  resolveTarget: (db, modeSlug, opts) => resolvePlacementTarget(db, modeSlug, opts),
  boundModeSlugs: (db) => resolveBoundModeIds(db),
  boundCounts: (db) => resolveBoundModeCounts(db),
  effectiveGate: (db, modeSlug) => remnawaveEffectiveGate(db, modeSlug),
  applyConfigPatch: applyRemnawaveConfigPatch,
  summarize: summarizeRemnawaveConfig,
};

/** For backends with no placement concept: every applicable mode is trivially
 *  "bound", nothing resolves to a placement, and there is no config to write.
 *  (The effective-mode availability gate for these backends is composed from
 *  the catalog — enabled + applicable — by the callers, not here.) */
export const TRIVIAL_RESOLVER: PlacementResolver = {
  resolveTarget: async () => ({ placement: null, serverId: null }),
  boundModeSlugs: async (db) => new Set((await resolveModeCatalog(db)).modes.map((m) => m.id)),
  boundCounts: async () => ({}),
  effectiveGate: async () => ({ blocked: false }),
  applyConfigPatch: () => {
    throw new Error('this backend has no placement configuration');
  },
  summarize: () => ({ bound: false, count: 0 }),
};

export const PLACEMENT_RESOLVERS: Partial<Record<BackendId, PlacementResolver>> = {
  remnawave: remnawaveResolver,
};

export function resolverFor(backend: BackendId): PlacementResolver {
  return PLACEMENT_RESOLVERS[backend] ?? TRIVIAL_RESOLVER;
}

export function hasPlacementResolver(backend: BackendId): boolean {
  return PLACEMENT_RESOLVERS[backend] !== undefined;
}

// --- availability composition -------------------------------------------------

export interface CatalogWithAvailability extends ModeCatalog {
  modes: ModeWithAvailability[];
  /** Per-backend bound sets (placement-capable backends only). */
  boundByBackend: Map<BackendId, Set<string>>;
}

/**
 * The catalog with per-backend availability composed in:
 *   availableBackends(mode) = mode.backends where the mode is enabled AND
 *   (the backend has no placement concept OR the mode is bound there).
 * The single source for publicConfig, the internal mode list, and the admin
 * view — so "available" can never mean different things on different surfaces.
 */
export async function resolveCatalogWithAvailability(
  db: DatabaseReader,
): Promise<CatalogWithAvailability> {
  const catalog = await resolveModeCatalog(db);
  const boundByBackend = new Map<BackendId, Set<string>>();
  for (const b of BACKEND_IDS) {
    if (CAPABILITIES[b].placement) {
      boundByBackend.set(b, await resolverFor(b).boundModeSlugs(db));
    }
  }
  const modes: ModeWithAvailability[] = catalog.modes.map((m) => ({
    ...m,
    availableBackends: m.enabled
      ? m.backends.filter((b) => !CAPABILITIES[b].placement || boundByBackend.get(b)!.has(m.id))
      : [],
  }));
  return { families: catalog.families, modes, boundByBackend };
}

/** The public modes projection (what publicConfig ships). */
export async function resolvePublicModes(db: DatabaseReader): Promise<{
  modes: PublicConnectionMode[];
  catalog: CatalogWithAvailability;
}> {
  const catalog = await resolveCatalogWithAvailability(db);
  return { modes: publicProjection(catalog.modes), catalog };
}
