/**
 * The relay-provider registry: one adapter per EDGE_PROVIDER_IDS entry (a
 * missing one is a compile error). The casts erase the per-adapter config and
 * template generics; soundness is the invariant that an account row's
 * `provider` always equals its `credentials.type` and `settings.type`, enforced
 * by the account mutations, so dispatch pairs the right config with the right
 * adapter.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { EdgeProvider, EdgeProviderConfig } from './types';
import { gcoreProvider } from './gcore';
import { upcloudProvider } from './upcloud';
import { scalewayProvider } from './scaleway';
import { ovhProvider } from './ovh';

export const EDGE_PROVIDERS: Record<EdgeProviderId, EdgeProvider> = {
  gcore: gcoreProvider as unknown as EdgeProvider,
  upcloud: upcloudProvider as unknown as EdgeProvider,
  scaleway: scalewayProvider as unknown as EdgeProvider,
  ovh: ovhProvider as unknown as EdgeProvider,
};

export function edgeProviderFor(id: EdgeProviderId): EdgeProvider {
  return EDGE_PROVIDERS[id];
}

/** Merge an account's credentials + settings into the adapter config shape. */
export function edgeProviderConfigFrom(
  credentials: Record<string, unknown> & { type: EdgeProviderId },
  settings: Record<string, unknown> & { type: EdgeProviderId },
): EdgeProviderConfig {
  if (credentials.type !== settings.type) {
    throw new Error('relay account: credentials/settings provider mismatch');
  }
  return { ...settings, ...credentials } as unknown as EdgeProviderConfig;
}

/** Default template params per provider (seeded on first use). */
export function defaultTemplateParams(id: EdgeProviderId): Record<string, unknown> {
  return EDGE_PROVIDERS[id].defaultTemplate as Record<string, unknown>;
}
