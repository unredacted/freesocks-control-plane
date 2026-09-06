/**
 * The set of relay-edge PROVIDER ids (cloud load-balancer APIs FCP can drive),
 * the single source of truth, deliberately zod-free so Convex code can
 * VALUE-import it. Everything else derives from this tuple:
 *   - the zod enum in ./relays.ts (client contracts),
 *   - the Convex validator in convex/lib/relayProviderIds.ts (schema + fn args),
 *   - the capability record in convex/lib/relays/providers/capabilities.ts,
 *   - the adapter registry in convex/lib/relays/providers/registry.ts.
 * Adding a provider starts HERE; the derived `Record<RelayProviderId, ...>`
 * maps then fail to compile until every per-provider surface has an entry.
 */
export const RELAY_PROVIDER_IDS = ['gcore', 'upcloud', 'scaleway', 'ovh'] as const;
export type RelayProviderId = (typeof RELAY_PROVIDER_IDS)[number];

export function isRelayProviderId(v: unknown): v is RelayProviderId {
  return typeof v === 'string' && (RELAY_PROVIDER_IDS as readonly string[]).includes(v);
}
