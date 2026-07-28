/**
 * The set of proxy-backend TYPE ids — the single source of truth, deliberately
 * zod-free so Convex code can VALUE-import it without dragging zod into the
 * backend bundle. Everything else derives from this tuple:
 *   - the zod enum in ./backends.ts (client contracts),
 *   - the Convex validator in convex/lib/backendIds.ts (schema + fn args),
 *   - the capability record in convex/lib/backends/capabilities.ts,
 *   - the provider registry in convex/lib/backends/registry.ts.
 * Adding a backend type starts HERE; the derived `Record<BackendId, ...>` maps
 * then fail to compile until every per-backend surface has an entry.
 */
export const BACKEND_IDS = ['remnawave', 'outline'] as const;
export type BackendId = (typeof BACKEND_IDS)[number];

export function isBackendId(v: unknown): v is BackendId {
  return typeof v === 'string' && (BACKEND_IDS as readonly string[]).includes(v);
}
