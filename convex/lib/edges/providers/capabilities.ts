/**
 * Declarative per-provider capability record (the backends/capabilities.ts
 * pattern). Generic code branches on these, never on provider ids. Kept from
 * drifting against the adapters by capabilities.test.ts, which cross-checks
 * every flag that has an observable adapter counterpart.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';
import type { EdgeSpec } from './types';

export interface EdgeProviderCapabilities {
  /** Mutations return a task/operation the adapter polls (`pollStep` present). */
  asyncOps: boolean;
  /** Async deletes: `confirmDestroyed` present. */
  asyncDelete: boolean;
  /** Settings must carry a private network/subnet (the settings schema requires them). */
  needsPrivateNetwork: boolean;
  /** The public side can carry an IPv6 address (the template exposes a family choice). */
  ipv6: boolean;
  /** UDP listeners are supported. `unsupportedTransport` refuses a udp spec otherwise. */
  udp: boolean;
  /** Client idle timeouts are template-configurable (a client-timeout template field exists). */
  idleTimeoutConfigurable: boolean;
  /**
   * `describe()` can report member/backend health (`online`). A provider without
   * it never answers `online`, only `unknown`/`degraded`/`offline`, so a health
   * gate must not wait for `online` from it.
   */
  memberHealth: boolean;
  /** Typical wall clock from create to active (informational; bounds `discoverySettleMs`). */
  typicalProvisionMs: number;
  /**
   * Minimum wall clock since a step was first requested before a by-name
   * listing that shows nothing may be promoted to `confirmed_absent` (the
   * provider may still be registering the object). Listing adapters require
   * BOTH ≥2 quiet looks AND this floor.
   */
  discoverySettleMs: number;
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
    memberHealth: true,
    typicalProvisionMs: 2 * MIN,
    discoverySettleMs: 2 * MIN,
  },
  upcloud: {
    asyncOps: false,
    asyncDelete: false,
    needsPrivateNetwork: false,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: true,
    memberHealth: false,
    typicalProvisionMs: 5 * MIN,
    discoverySettleMs: 0,
  },
  scaleway: {
    asyncOps: false,
    asyncDelete: true,
    needsPrivateNetwork: false,
    ipv6: true,
    udp: false,
    idleTimeoutConfigurable: true,
    memberHealth: true,
    typicalProvisionMs: 3 * MIN,
    discoverySettleMs: 0,
  },
  ovh: {
    asyncOps: true,
    asyncDelete: true,
    needsPrivateNetwork: true,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: true,
    memberHealth: true,
    typicalProvisionMs: 10 * MIN,
    discoverySettleMs: 5 * MIN,
  },
};

export function edgeCapabilitiesOf(id: EdgeProviderId): EdgeProviderCapabilities {
  return EDGE_PROVIDER_CAPABILITIES[id];
}

/**
 * The transport a spec asks for that the provider cannot carry, or null. Every
 * adapter forwards TCP; a `udp` listener is refused before any provider call
 * unless the capability says otherwise.
 */
export function unsupportedTransport(id: EdgeProviderId, spec: EdgeSpec): 'udp' | null {
  const caps = EDGE_PROVIDER_CAPABILITIES[id];
  for (const l of spec.listeners) {
    if ((l.transport ?? 'tcp') === 'udp' && !caps.udp) return 'udp';
  }
  return null;
}

/**
 * Whether a by-name listing that shows nothing may be promoted to
 * `confirmed_absent`: at least two quiet looks AND the provider's settle floor
 * elapsed since the step was first requested. Without a `startedAt` (a ledger
 * predating the stamp) only the look count applies.
 */
export function discoveryMaySettle(
  id: EdgeProviderId,
  attempt: number,
  startedAt: number | undefined,
  now = Date.now(),
): boolean {
  if (attempt < 2) return false;
  if (startedAt === undefined) return true;
  return now - startedAt >= EDGE_PROVIDER_CAPABILITIES[id].discoverySettleMs;
}

/**
 * Whether an edge's described health satisfies a "provider health" gate
 * (verify, publish, standby selection). `online` always does. A provider whose
 * `describe()` cannot see member health (`memberHealth: false`) never answers
 * `online`, so for it anything but `offline` passes — otherwise the gate would
 * wait forever. With the gate off (`requireHealth` false) everything passes.
 * An unknown provider (adopted rows) keeps the strict rule.
 */
export function providerHealthSatisfies(
  id: EdgeProviderId | string | null | undefined,
  health: string | null | undefined,
  requireHealth: boolean,
): boolean {
  if (!requireHealth) return true;
  if (health === 'online') return true;
  const caps =
    id && id in EDGE_PROVIDER_CAPABILITIES
      ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId]
      : undefined;
  return !!caps && !caps.memberHealth && health !== 'offline';
}
