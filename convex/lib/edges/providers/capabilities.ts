/**
 * Declarative per-provider capability record (the backends/capabilities.ts
 * pattern). Generic code branches on these, never on provider ids. Kept from
 * drifting against the adapters by capabilities.test.ts, which cross-checks
 * every flag that has an observable adapter counterpart.
 */
import type { EdgeProviderId } from '../../edgeProviderIds';
import {
  protocolIsHttpTransport,
  type ListenerProto,
  type ListenerStreamTransport,
} from '../protocols';
import type { EdgeSpec } from './types';

export type EdgeLayer = 'l4' | 'l7';
export type EdgeAddressKind = 'ip' | 'hostname';
/**
 * How the provider reaches the origin port: `any` (an L4 forwarder dials
 * whatever the listener says), `fixed` (the port follows the origin scheme:
 * 443 for https, 80 for http), `default-or-override` (a default by the zone's
 * encryption mode, any other port through a destination-port override).
 */
export type OriginPortMode = 'any' | 'fixed' | 'default-or-override';

export interface EdgeProviderCapabilities {
  /** L4 = a TCP forwarder in front of the node; L7 = a CDN front terminating TLS + HTTP. */
  layer: EdgeLayer;
  /** What members connect to: an IP literal (L4) or a hostname (L7). */
  addressKind: EdgeAddressKind;
  /** HTTP-carried stream transports an L7 front can carry (empty for L4: it carries any TCP listener). */
  l7Transports: readonly ListenerStreamTransport[];
  /** Fastly-style: the hostnames' DNS lives in a referenced Cloudflare account. */
  needsDnsAccount: boolean;
  /** Cloudflare-style: can host DNS records for other providers' edges. */
  providesDns: boolean;
  originPortMode: OriginPortMode;
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

const L4 = {
  layer: 'l4',
  addressKind: 'ip',
  l7Transports: [] as readonly ListenerStreamTransport[],
  needsDnsAccount: false,
  providesDns: false,
  originPortMode: 'any',
} as const satisfies Partial<EdgeProviderCapabilities>;

export const EDGE_PROVIDER_CAPABILITIES: Record<EdgeProviderId, EdgeProviderCapabilities> = {
  gcore: {
    ...L4,
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
    ...L4,
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
    ...L4,
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
    ...L4,
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
  // A proxied DNS record in one zone; TLS terminates at the CDN. DNS existence is
  // not origin health, so `memberHealth` is false and publication waits for the
  // front qualification instead.
  cloudflare: {
    layer: 'l7',
    addressKind: 'hostname',
    // XHTTP packet-up is plain GET + POST requests; the stream modes would need
    // the zone's gRPC switch, which the packet-up proof never depends on.
    l7Transports: ['ws', 'httpupgrade', 'grpc', 'xhttp'],
    needsDnsAccount: false,
    providesDns: true,
    originPortMode: 'default-or-override',
    asyncOps: false,
    asyncDelete: false,
    needsPrivateNetwork: false,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: false,
    memberHealth: false,
    typicalProvisionMs: 1 * MIN,
    discoverySettleMs: 0,
  },
  // A service + domain + backend + WebSockets product + TLS subscription, with
  // the DNS records written into a Cloudflare account. Certificate issuance is
  // asynchronous (minutes). The WebSockets path honours only name/address/
  // use_ssl/override_host on the backend, hence the fixed origin port.
  fastly: {
    layer: 'l7',
    addressKind: 'hostname',
    l7Transports: ['ws'],
    needsDnsAccount: true,
    providesDns: false,
    originPortMode: 'fixed',
    asyncOps: true,
    asyncDelete: true,
    needsPrivateNetwork: false,
    ipv6: false,
    udp: false,
    idleTimeoutConfigurable: false,
    memberHealth: false,
    typicalProvisionMs: 10 * MIN,
    discoverySettleMs: 0,
  },
};

export function edgeCapabilitiesOf(id: EdgeProviderId): EdgeProviderCapabilities {
  return EDGE_PROVIDER_CAPABILITIES[id];
}

export function edgeLayerOf(id: EdgeProviderId | string | null | undefined): EdgeLayer {
  return id && id in EDGE_PROVIDER_CAPABILITIES
    ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId].layer
    : 'l4';
}

export function edgeAddressKindOf(id: EdgeProviderId | string | null | undefined): EdgeAddressKind {
  return id && id in EDGE_PROVIDER_CAPABILITIES
    ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId].addressKind
    : 'ip';
}

/**
 * Whether the DNS zone's encryption mode decides how THIS provider's front
 * dials the origin.
 *
 * It does only when the CDN in front of the edge IS the zone's proxy, i.e. a
 * provider that hosts the zone itself (`providesDns`): the mode is that proxy's
 * own origin-leg setting. A front whose records merely live in someone else's
 * zone as unproxied CNAMEs dials the origin by its own service configuration,
 * so the zone's mode says nothing about it and must never refuse it (an
 * `ssl: strict` zone would otherwise block every plaintext origin behind an
 * unrelated CDN).
 */
export function zoneModeGovernsOrigin(id: EdgeProviderId | string | null | undefined): boolean {
  const caps =
    id && id in EDGE_PROVIDER_CAPABILITIES
      ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId]
      : undefined;
  return !!caps && caps.layer === 'l7' && caps.providesDns;
}

/**
 * Whether the provider's edges can carry a slot speaking `protocol`. An L4
 * forwarder carries any TCP protocol (the chain constraint on TLS-terminating
 * origins is layers.ts's job); an L7 front carries only the HTTP transports it
 * declares.
 */
export function protocolCarriedBy(id: EdgeProviderId, proto: ListenerProto): boolean {
  const caps = EDGE_PROVIDER_CAPABILITIES[id];
  if (caps.layer === 'l4') return proto.streamTransport !== 'udp' || caps.udp;
  return protocolIsHttpTransport(proto) && caps.l7Transports.includes(proto.streamTransport);
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
 * elapsed since the step was first requested. `startedAt` is the step's first
 * request time, or (when a lost settle never stamped it) the claim time /
 * the edge's creation time the caller falls back to; with no reference time
 * at all the floor cannot be proven and the answer is NO.
 */
export function discoveryMaySettle(
  id: EdgeProviderId,
  attempt: number,
  startedAt: number | undefined,
  now = Date.now(),
): boolean {
  if (attempt < 2) return false;
  const floor = EDGE_PROVIDER_CAPABILITIES[id].discoverySettleMs;
  if (floor === 0) return true;
  if (startedAt === undefined) return false;
  return now - startedAt >= floor;
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
