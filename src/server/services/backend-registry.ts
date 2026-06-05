/**
 * Routes operations to the correct backend provider based on the data row
 * being acted on. Tiers and subscriptions carry a `backend` discriminator
 * column added in migration 0004; this registry reads it and returns the
 * matching `ProxyBackendProvider`.
 *
 * For rows that pre-date the migration (or that aren't yet typed in our
 * Drizzle schema), backend resolution defaults to `'remnawave'` so existing
 * behavior is preserved without an explicit migration of every row.
 */
import type { BackendId, ProxyBackendProvider } from '../providers/backend';

/**
 * Minimal shape this registry needs from a tier or subscription row. Using
 * structural types avoids a circular import on the Drizzle schema and lets
 * unit tests pass plain objects.
 */
export interface HasBackend {
  backend?: BackendId | null;
}

export class BackendRegistry {
  constructor(private readonly providers: Map<BackendId, ProxyBackendProvider>) {}

  /** Look up a provider by id. Throws if the backend isn't registered. */
  get(id: BackendId): ProxyBackendProvider {
    const p = this.providers.get(id);
    if (!p) throw new Error(`Backend "${id}" is not registered`);
    return p;
  }

  /** True if the given backend has a provider wired up. Useful for app-settings gating. */
  has(id: BackendId): boolean {
    return this.providers.has(id);
  }

  /**
   * Pick a provider based on the `backend` column of any tier-or-subscription
   * row. Rows with no `backend` field (e.g. older code paths that don't yet
   * pass the column) get the Remnawave provider — preserves existing
   * behavior until Stage 2 wires the schema.
   */
  fromRow(row: HasBackend): ProxyBackendProvider {
    return this.get(row.backend ?? 'remnawave');
  }

  /** Explicit alias for clarity at the call site. Same behavior as `fromRow`. */
  fromTier(tier: HasBackend): ProxyBackendProvider {
    return this.fromRow(tier);
  }

  /** Explicit alias for clarity at the call site. Same behavior as `fromRow`. */
  fromSubscription(sub: HasBackend): ProxyBackendProvider {
    return this.fromRow(sub);
  }

  /** List every registered backend id. Used by admin UIs and feature gates. */
  registeredIds(): BackendId[] {
    return Array.from(this.providers.keys());
  }
}
