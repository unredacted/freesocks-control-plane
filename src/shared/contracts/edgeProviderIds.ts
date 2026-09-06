/**
 * The set of relay-edge PROVIDER ids (cloud load-balancer APIs FCP can drive),
 * the single source of truth, deliberately zod-free so Convex code can
 * VALUE-import it. Everything else derives from this tuple:
 *   - the zod enum in ./relays.ts (client contracts),
 *   - the Convex validator in convex/lib/edgeProviderIds.ts (schema + fn args),
 *   - the capability record in convex/lib/relays/providers/capabilities.ts,
 *   - the adapter registry in convex/lib/relays/providers/registry.ts.
 * Adding a provider starts HERE; the derived `Record<EdgeProviderId, ...>`
 * maps then fail to compile until every per-provider surface has an entry.
 */
export const EDGE_PROVIDER_IDS = ['gcore', 'upcloud', 'scaleway', 'ovh'] as const;
export type EdgeProviderId = (typeof EDGE_PROVIDER_IDS)[number];

export function isRelayProviderId(v: unknown): v is EdgeProviderId {
  return typeof v === 'string' && (EDGE_PROVIDER_IDS as readonly string[]).includes(v);
}
