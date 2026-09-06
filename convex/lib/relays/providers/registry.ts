/**
 * The relay-provider registry: one adapter per RELAY_PROVIDER_IDS entry (a
 * missing one is a compile error). The casts erase the per-adapter config and
 * template generics; soundness is the invariant that an account row's
 * `provider` always equals its `credentials.type` and `settings.type`, enforced
 * by the account mutations, so dispatch pairs the right config with the right
 * adapter.
 */
import type { RelayProviderId } from '../../relayProviderIds';
import type { RelayProvider, RelayProviderConfig } from './types';
import { gcoreProvider } from './gcore';
import { upcloudProvider } from './upcloud';
import { scalewayProvider } from './scaleway';
import { ovhProvider } from './ovh';

export const RELAY_PROVIDERS: Record<RelayProviderId, RelayProvider> = {
  gcore: gcoreProvider as unknown as RelayProvider,
  upcloud: upcloudProvider as unknown as RelayProvider,
  scaleway: scalewayProvider as unknown as RelayProvider,
  ovh: ovhProvider as unknown as RelayProvider,
};

export function relayProviderFor(id: RelayProviderId): RelayProvider {
  return RELAY_PROVIDERS[id];
}

/** Merge an account's credentials + settings into the adapter config shape. */
export function relayConfigFrom(
  credentials: Record<string, unknown> & { type: RelayProviderId },
  settings: Record<string, unknown> & { type: RelayProviderId },
): RelayProviderConfig {
  if (credentials.type !== settings.type) {
    throw new Error('relay account: credentials/settings provider mismatch');
  }
  return { ...settings, ...credentials } as unknown as RelayProviderConfig;
}

/** Default template params per provider (seeded on first use). */
export function defaultTemplateParams(id: RelayProviderId): Record<string, unknown> {
  return RELAY_PROVIDERS[id].defaultTemplate as Record<string, unknown>;
}
