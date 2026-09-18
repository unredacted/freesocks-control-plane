'use node';
/**
 * The relay-provider registry: one adapter per EDGE_PROVIDER_IDS entry (a
 * missing one is a compile error). The casts erase the per-adapter config and
 * template generics; soundness is the invariant that an account row's
 * `provider` always equals its `credentials.type` and `settings.type`,
 * enforced by the account mutations, so dispatch pairs the right config with
 * the right adapter.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { EdgeProvider, EdgeProviderConfig } from './types';
import { gcoreProvider } from './gcore';
import { upcloudProvider } from './upcloud';
import { scalewayProvider } from './scaleway';
import { ovhProvider } from './ovh';
import { cloudflareProvider } from './cloudflare';
import { fastlyProvider } from './fastly';
import { FAKE_L4_SHADOW, FAKE_L7_SHADOW, fakeEdgeProvider, fakeEdgeProviderEnabled } from './fake';

export const EDGE_PROVIDERS: Record<EdgeProviderId, EdgeProvider> = {
  gcore: gcoreProvider as unknown as EdgeProvider,
  upcloud: upcloudProvider as unknown as EdgeProvider,
  scaleway: scalewayProvider as unknown as EdgeProvider,
  ovh: ovhProvider as unknown as EdgeProvider,
  cloudflare: cloudflareProvider as unknown as EdgeProvider,
  fastly: fastlyProvider as unknown as EdgeProvider,
};

/**
 * Test seam: swap one provider's adapter for a fake. The orchestration tests
 * (the rotation machine, the reconcile loop) are about the STATE MACHINE, not
 * about one vendor's wire format, which its own contract tests pin. Without
 * this they would have to re-encode a vendor's request shapes, and would then
 * fail whenever that vendor's adapter changed for reasons the machine does not
 * care about. Production code never calls this.
 */
const overrides = new Map<EdgeProviderId, EdgeProvider>();

export function __setEdgeProviderForTests(id: EdgeProviderId, provider: EdgeProvider | null): void {
  if (provider) overrides.set(id, provider);
  else overrides.delete(id);
}

export function edgeProviderFor(id: EdgeProviderId): EdgeProvider {
  const o = overrides.get(id);
  if (o) return o;
  // DEV ONLY (double env gate): the fake shadows one real adapter per layer so
  // the setup flow can be walked without cloud credentials (providers/fake.ts).
  if (fakeEdgeProviderEnabled()) {
    if (id === FAKE_L4_SHADOW) return fakeEdgeProvider(EDGE_PROVIDERS[id], 'l4') as EdgeProvider;
    if (id === FAKE_L7_SHADOW) return fakeEdgeProvider(EDGE_PROVIDERS[id], 'l7') as EdgeProvider;
  }
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
