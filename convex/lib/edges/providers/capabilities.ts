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
 * What an account of the provider is FOR. `edge`: it fronts member traffic.
 * `dns`: it holds the records FCP writes for L7 fronts (a front's certificate
 * challenge and traffic name, a front node's origin name) and fronts nothing
 * itself unless the account is set to DNS and fronting (`frontsTraffic`,
 * `frontsAllowed`).
 */
export type EdgeProviderRole = 'edge' | 'dns';
/**
 * How the provider reaches the origin port: `any` (an L4 forwarder dials
 * whatever the listener says), `fixed` (the port follows the origin scheme:
 * 443 for https, 80 for http), `default-or-override` (a default by the zone's
 * encryption mode, any other port through a destination-port override),
 * `web-or-high` (the front's origin setting names the port, which may be 80,
 * 443 or one of 1024-65535: CloudFront's `HTTPPort` / `HTTPSPort`).
 */
export type OriginPortMode = 'any' | 'fixed' | 'default-or-override' | 'web-or-high';

export interface EdgeProviderCapabilities {
  /** L4 = a TCP forwarder in front of the node; L7 = a CDN front terminating TLS + HTTP. */
  layer: EdgeLayer;
  role: EdgeProviderRole;
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
  /**
   * The account's edges can share ONE certificate (Fastly's `*.<zone>`
   * wildcard, `certificateScope`): the adapter reports it (`sharedCertificate`)
   * and the reconcile cron keeps its state on the account.
   */
  sharedCertificates: boolean;
  /**
   * The Host header the front always sends the origin, when the provider
   * decides it rather than a template option (`overrideHost`): `origin` = the
   * origin's own name. CloudFront: forwarding the member's Host would make the
   * front check the origin's certificate against the front name, which a
   * node's certificate never carries. Absent = the template decides.
   */
  originHostHeader?: 'origin';
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
  role: 'edge',
  addressKind: 'ip',
  l7Transports: [] as readonly ListenerStreamTransport[],
  needsDnsAccount: false,
  providesDns: false,
  originPortMode: 'any',
  sharedCertificates: false,
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
    // A DNS account first: fronting member traffic through it is the
    // account's own choice, DNS only unless set otherwise (`frontsAllowed`).
    role: 'dns',
    addressKind: 'hostname',
    // XHTTP packet-up is plain GET + POST requests; the stream modes would need
    // the zone's gRPC switch, which the packet-up proof never depends on.
    l7Transports: ['ws', 'httpupgrade', 'grpc', 'xhttp'],
    // gRPC is proxied only to an origin listening on 443 (`originPortCarriedBy`),
    // and only while the zone's gRPC switch is on: dashboard only, there is no
    // API to read or set it. With it off the CDN answers 403, which the front
    // proof reports as `grpc_disabled`.
    // Source: developers.cloudflare.com/network/grpc-connections/, 2026-10-16.
    needsDnsAccount: false,
    providesDns: true,
    originPortMode: 'default-or-override',
    sharedCertificates: false,
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
  // asynchronous (minutes). The origin port is fixed to the scheme's own (443
  // over TLS, 80 without) and sent explicitly: Fastly's WebSockets guide lists
  // only name/address/use_ssl/override_host, yet dials the backend's `port`,
  // which defaults to 80.
  fastly: {
    layer: 'l7',
    role: 'edge',
    addressKind: 'hostname',
    l7Transports: ['ws'],
    needsDnsAccount: true,
    providesDns: false,
    originPortMode: 'fixed',
    // One `*.<zone>` subscription for every front of the account (`certificateScope`).
    sharedCertificates: true,
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
  // A distribution in front of one origin name, serving the zone's shared ACM
  // wildcard (`*.<zone>`, requested in us-east-1), with the DNS records written
  // into a Cloudflare account. Changes propagate asynchronously (`InProgress`
  // to `Deployed`, minutes), and a delete is disable, wait, delete. WebSocket
  // only: CloudFront proxies an RFC 6455 upgrade over HTTP/1.1 (it needs
  // `Sec-WebSocket-Key`); an HTTP Upgrade transport sends none, and gRPC needs
  // HTTP/2 to the origin, neither proven. The WebSocket idle timeout is fixed
  // at 10 minutes of no bytes from the origin (the node's heartbeat keeps a
  // quiet tunnel open). IPv6 on the viewer side is a distribution switch.
  // Sources: docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/
  // distribution-working-with.websockets.html and cloudfront-limits.html, 2026-10-22.
  cloudfront: {
    layer: 'l7',
    role: 'edge',
    addressKind: 'hostname',
    l7Transports: ['ws'],
    needsDnsAccount: true,
    providesDns: false,
    originPortMode: 'web-or-high',
    // Host is never forwarded: CloudFront sends the origin's own name.
    originHostHeader: 'origin',
    // One ACM `*.<zone>` certificate for every front of the account in a zone.
    sharedCertificates: true,
    asyncOps: true,
    asyncDelete: true,
    needsPrivateNetwork: false,
    ipv6: true,
    udp: false,
    idleTimeoutConfigurable: false,
    memberHealth: false,
    typicalProvisionMs: 10 * MIN,
    discoverySettleMs: 0,
  },
};

export function edgeLayerOf(id: EdgeProviderId | string | null | undefined): EdgeLayer {
  return id && id in EDGE_PROVIDER_CAPABILITIES
    ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId].layer
    : 'l4';
}

export function edgeRoleOf(id: EdgeProviderId | string | null | undefined): EdgeProviderRole {
  return id && id in EDGE_PROVIDER_CAPABILITIES
    ? EDGE_PROVIDER_CAPABILITIES[id as EdgeProviderId].role
    : 'edge';
}

/** What `frontsAllowed` reads of an account row. */
export interface FrontingAccount {
  provider: EdgeProviderId | string;
  frontsTraffic?: boolean;
}

/**
 * Whether NEW edges may be placed on this account, and its spares go live. A
 * DNS provider's account fronts member traffic only when it is set to DNS and
 * fronting (`frontsTraffic`); an edge provider's account always does. No
 * account at all fronts nothing. Edges that already exist are never torn down
 * by it.
 */
export function frontsAllowed(account: FrontingAccount | null | undefined): boolean {
  if (!account) return false;
  return edgeRoleOf(account.provider) !== 'dns' || account.frontsTraffic === true;
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
 * declares, and, given the listener's origin port, only on a port it dials for
 * that transport (`l7OriginPorts`).
 */
export function protocolCarriedBy(
  id: EdgeProviderId,
  proto: ListenerProto,
  originPort?: number,
): boolean {
  const caps = EDGE_PROVIDER_CAPABILITIES[id];
  if (caps.layer === 'l4') return proto.streamTransport !== 'udp' || caps.udp;
  if (!protocolIsHttpTransport(proto) || !caps.l7Transports.includes(proto.streamTransport))
    return false;
  return originPortCarriedBy(id, proto, originPort);
}

/**
 * Whether an L7 front dials the listener's origin port for its transport: gRPC
 * is carried end to end over HTTP/2 on 443 only (a destination-port override
 * breaks the h2 path; edgeProviderOps `checkOriginPort` refuses the same at
 * provision time). Unknown port = no opinion.
 */
export function originPortCarriedBy(
  id: EdgeProviderId,
  proto: ListenerProto,
  originPort?: number,
): boolean {
  if (EDGE_PROVIDER_CAPABILITIES[id].layer !== 'l7' || originPort === undefined) return true;
  return proto.streamTransport !== 'grpc' || originPort === 443;
}

/**
 * Whether an L7 front can dial this origin port at all, whatever the
 * transport: a `web-or-high` front only 80, 443 and 1024-65535 (CloudFront
 * refuses the other privileged ports). Unknown port = no opinion.
 */
export function originPortDialable(id: EdgeProviderId, port?: number): boolean {
  if (port === undefined || EDGE_PROVIDER_CAPABILITIES[id].originPortMode !== 'web-or-high')
    return true;
  return port === 80 || port === 443 || (port >= 1024 && port <= 65535);
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
