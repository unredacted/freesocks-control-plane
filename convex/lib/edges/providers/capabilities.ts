/**
 * Declarative per-provider capability record (the backends/capabilities.ts
 * pattern). Generic code branches on these, never on provider ids. Kept from
 * drifting against the adapters by capabilities.test.ts.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';

export interface EdgeProviderCapabilities {
  /** Mutations return a task/operation the adapter polls (`pollStep` present). */
  asyncOps: boolean;
  /** Async deletes: `confirmDestroyed` present. */
  asyncDelete: boolean;
  /** Settings must carry a private network/subnet (VIP on a private network + floating IP). */
  needsPrivateNetwork: boolean;
  /** The public side can carry an IPv6 address. */
  ipv6: boolean;
  /** UDP listeners are supported (none of the adapters implement them yet). */
  udp: boolean;
  /** Client idle timeouts are template-configurable. */
  idleTimeoutConfigurable: boolean;
  /** Typical wall clock from create to active, for the poll budget. */
  typicalProvisionMs: number;
}

const MIN = 60_000;

export const EDGE_PROVIDER_CAPABILITIES: Record<EdgeProviderId, EdgeProviderCapabilities> = {
  gcore: {
    asyncOps: true,
    asyncDelete: true,
    needsPrivateNetwork: false,
    ipv6: true,
    udp: false,
    idleTimeoutConfigurable: true,
    typicalProvisionMs: 2 * MIN,
  },
  upcloud: {
    asyncOps: false,
    asyncDelete: false,
    needsPrivateNetwork: false,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: true,
    typicalProvisionMs: 5 * MIN,
  },
  scaleway: {
    asyncOps: false,
    asyncDelete: true,
    needsPrivateNetwork: false,
    ipv6: true,
    udp: false,
    idleTimeoutConfigurable: true,
    typicalProvisionMs: 3 * MIN,
  },
  ovh: {
    asyncOps: true,
    asyncDelete: true,
    needsPrivateNetwork: true,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: true,
    typicalProvisionMs: 10 * MIN,
  },
};

export function edgeCapabilitiesOf(id: EdgeProviderId): EdgeProviderCapabilities {
  return EDGE_PROVIDER_CAPABILITIES[id];
}
