/**
 * Layer compatibility: which edge LAYERS (an L4 TCP forwarder, an L7 CDN front)
 * can carry an origin LISTENER, decided on the COMPLETE client-to-origin chain,
 * never on the protocol name alone. Pure; used by publishability, selection,
 * adoption and the detector's replacement choice.
 *
 *  - A listener whose origin speaks plaintext HTTP behind the CDN (`scheme:http`)
 *    is L7-only: an L4 forwarder cannot add the TLS the CDN terminated.
 *  - An `https` origin is L7-frontable when the listener is an HTTP transport
 *    with an authenticated proof, and L4-frontable only when a member's TLS
 *    session to the node itself is sound: the certificate is publicly trusted
 *    (members do not pin) AND every active server name the renderer may emit is
 *    covered by a certificate name (RFC 6125 wildcard matching) AND the node
 *    accepts those names as Host.
 *  - A listener without `originTransport` keeps the L4-only rules.
 *  - A UDP listener needs a provider that declares `udp`; none does today.
 *  - A WebSocket node's HTTP transport is never L4-frontable, whatever its
 *    certificate covers (`websocketNode`, lib/edges/websocketNode.ts).
 *
 * `hostTargetFor` is the single source of the Host tuple written to the backend
 * and emitted by assignment, so a flip and a render never disagree.
 */
import type { ListenerLayerExclusion } from '../../../src/shared/contracts/edgeProtocolIds';
import {
  EDGE_PROVIDER_CAPABILITIES,
  protocolCarriedBy,
  type EdgeLayer,
} from './providers/capabilities';
import type { EdgeProviderId } from '../edgeProviderIds';
import { addressFamily } from './ip';
import {
  protocolIsHttpTransport,
  protocolL7Proof,
  protocolTransport,
  protocolUsesHostHeader,
  protocolUsesSni,
  type ListenerProto,
} from './protocols';

export interface OriginTransport {
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: readonly string[];
  acceptsHostHeader: 'any' | 'names';
}

/** The listener fields the layer decision reads. */
export interface ListenerLike extends ListenerProto {
  originTransport?: OriginTransport | null;
  tlsNames?: ReadonlyArray<{ name: string; status: 'active' | 'retired' }> | null;
}

/**
 * RFC 6125 §6.4.3 style match: exact (case-insensitive) or a single leftmost
 * `*` label matching exactly one label. No partial-label wildcards
 * (`f*.example`), no wildcard for the apex, no match across dots.
 */
export function matchesCertName(name: string, pattern: string): boolean {
  const n = name.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (!n || !p) return false;
  if (!p.includes('*')) return n === p;
  if (!p.startsWith('*.') || p.indexOf('*', 1) !== -1) return false;
  const suffix = p.slice(1); // ".example.org"
  if (!n.endsWith(suffix)) return false;
  const label = n.slice(0, -suffix.length);
  return label.length > 0 && !label.includes('.');
}

export function certCovers(name: string, certNames: readonly string[]): boolean {
  return certNames.some((c) => matchesCertName(name, c));
}

export type LayerExclusion = ListenerLayerExclusion;

export interface ListenerLayers {
  layers: EdgeLayer[];
  /** Why a layer is excluded (empty when both are allowed). */
  excluded: Partial<Record<EdgeLayer, LayerExclusion>>;
}

/**
 * The Host header an L7 front sends the origin: the fronted hostname, or the
 * literal `'origin'` when the front passes the origin's own address through
 * (Fastly's `overrideHost: 'origin'`, every CloudFront front). `undefined` = not decided yet (the
 * hostname is minted when the edge is planned).
 */
export type L7HostHeader = string | 'origin';

/** `*.<zone>`: a pattern that covers ANY single first-level label under a zone. */
export function isFirstLevelWildcard(pattern: string): boolean {
  const p = pattern.trim().toLowerCase().replace(/\.$/, '');
  return p.startsWith('*.') && p.indexOf('*', 1) === -1 && p.length > 2;
}

/**
 * Whether the node would accept the Host header an L7 front sends it.
 *
 * `acceptsHostHeader: 'any'` always does. With `'names'` the node answers only
 * for the names on its certificate, so a front that rewrites the Host to the
 * minted hostname needs that hostname covered; a front that passes the origin's
 * own address through (`'origin'`) is always accepted. When the Host is not
 * known yet (before the hostname is minted) the only safe answer for a front
 * that sends its own name is a certificate name that could cover ANY
 * first-level label of a zone.
 */
export function l7HostAccepted(ot: OriginTransport, l7Host?: L7HostHeader): boolean {
  if (ot.acceptsHostHeader === 'any') return true;
  if (l7Host === 'origin') return true;
  if (l7Host) return certCovers(l7Host, ot.certNames);
  return ot.certNames.some(isFirstLevelWildcard);
}

/**
 * How a provider's front can send the origin's own name as Host: `always`
 * (capability `originHostHeader: 'origin'`), when its template says so
 * (`option`: Fastly's `overrideHost: 'origin'`), or never (null: it sends the
 * front name).
 */
export function originHostSupport(provider: string | null | undefined): 'always' | 'option' | null {
  if (!provider || !(provider in EDGE_PROVIDER_CAPABILITIES)) return null;
  const h =
    EDGE_PROVIDER_CAPABILITIES[provider as keyof typeof EDGE_PROVIDER_CAPABILITIES]
      .originHostHeader;
  return h === 'origin' ? 'always' : h === 'option' ? 'option' : null;
}

/**
 * Whether a front needs to send the origin's own name for the node to answer:
 * the node answers only for its certificate names, and the front name is not
 * one of them (before the name is minted: no first-level wildcard could cover
 * it).
 */
export function originHostNeeded(ot: OriginTransport, hostname?: string | null): boolean {
  return !l7HostAccepted(ot, hostname ?? undefined);
}

/**
 * The template a NEW front is built with: for a node that needs its own name
 * as Host (`originHostNeeded`), a provider whose template can send it is set
 * to (`overrideHost: 'origin'`), whatever the template or the pick chose,
 * since the front name would be refused. Applied once, when the edge is
 * planned; its intent freezes the result like every other template value.
 */
export function withOriginHost(
  provider: string | null | undefined,
  params: Record<string, unknown>,
  ot: OriginTransport | null | undefined,
  hostname: string | null | undefined,
): Record<string, unknown> {
  if (!ot || originHostSupport(provider) !== 'option' || !originHostNeeded(ot, hostname))
    return params;
  return params.overrideHost === 'origin' ? params : { ...params, overrideHost: 'origin' };
}

/**
 * Whether the origin's own address works as the Host of a node that answers
 * only for its own names: a front that sends "the origin's name" sends the
 * address it dials, so it must be a DNS name the certificate covers (an IP
 * literal or another name would be refused; the Fastly and CloudFront
 * adapters refuse that shape when the edge is planned). Not known = yes.
 */
export function originNameServes(ot: OriginTransport, originAddress?: string | null): boolean {
  if (originAddress === undefined || originAddress === null) return true;
  const a = originAddress
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  return addressFamily(a) === null && certCovers(a, ot.certNames);
}

/**
 * Whether a front FCP would build at `provider` gets an answer from the node:
 * the front name is accepted, or the provider sends the origin's own name
 * (always, or set by `withOriginHost`) and that name is one the node serves.
 */
export function frontHostAccepted(
  provider: string | null | undefined,
  ot: OriginTransport,
  opts: { hostname?: string | null; originAddress?: string | null } = {},
): boolean {
  if (!originHostNeeded(ot, opts.hostname)) return true;
  return originHostSupport(provider) !== null && originNameServes(ot, opts.originAddress);
}

/**
 * Whether some L7 provider's front can send the origin's own name and carry
 * the listener, and that name is one the node serves: then a node that answers
 * only for its own names can still be fronted at L7.
 */
function originHostCarrierExists(
  proto: ListenerProto,
  ot: OriginTransport,
  originAddress?: string | null,
): boolean {
  return (
    originNameServes(ot, originAddress) &&
    (Object.keys(EDGE_PROVIDER_CAPABILITIES) as EdgeProviderId[]).some(
      (p) => originHostSupport(p) !== null && protocolCarriedBy(p, proto),
    )
  );
}

/** The Host an L7 front would send, from the minted hostname + the template's rule. */
export function l7HostHeaderFor(
  hostname: string | null | undefined,
  overrideHost?: unknown,
  provider?: string | null,
): L7HostHeader | undefined {
  if (overrideHost === 'origin') return 'origin';
  // A provider that always sends the origin's own name (capability `originHostHeader`).
  if (
    provider &&
    provider in EDGE_PROVIDER_CAPABILITIES &&
    EDGE_PROVIDER_CAPABILITIES[provider as keyof typeof EDGE_PROVIDER_CAPABILITIES]
      .originHostHeader === 'origin'
  )
    return 'origin';
  return hostname ?? undefined;
}

/**
 * Whether a zone's encryption mode can carry the listener's origin transport. A
 * plaintext origin needs the mode that dials the origin over HTTP; an HTTPS
 * origin needs one of the modes that dials it over HTTPS, and the strictest of
 * them validates the origin certificate, which a privately issued one fails.
 */
export function zoneModeCarriesOrigin(mode: string, ot: OriginTransport): boolean {
  const m = mode.trim().toLowerCase();
  if (ot.scheme === 'http') return m === 'flexible';
  if (m !== 'full' && m !== 'strict') return false;
  return m !== 'strict' || ot.certPublic;
}

export interface ListenerLayerOpts {
  /**
   * The Host a decided front sends the origin (see `l7HostAccepted`). Absent =
   * no front decided yet: L7 stays open while some provider's front would get
   * an answer (`frontHostAccepted` then judges each provider).
   */
  l7Host?: L7HostHeader;
  /**
   * The address fronts dial (the origin's): a node that answers only for its
   * own names takes a front that sends it that name only when this address is
   * one (`originNameServes`). Absent = not known here.
   */
  originAddress?: string | null;
  /** Some enabled provider declares `udp` (none does today). */
  udpProviderAvailable?: boolean;
  /** The listener's node is a WebSocket node (`websocketNodeOf`): no load balancer fronts its HTTP transports. */
  websocketNode?: boolean;
}

/** The layers that can front `listener`. */
export function listenerLayers(
  listener: ListenerLike,
  opts: ListenerLayerOpts = {},
): ListenerLayers {
  const excluded: ListenerLayers['excluded'] = {};
  if (protocolTransport(listener) === 'udp') {
    // No L7 front carries UDP; an L4 forwarder only when a provider declares it.
    excluded.l7 = 'protocol_not_http_transport';
    if (opts.udpProviderAvailable) return { layers: ['l4'], excluded };
    excluded.l4 = 'no_udp_provider';
    return { layers: [], excluded };
  }
  const ot = listener.originTransport ?? null;
  const http = protocolIsHttpTransport(listener);
  // A member's TLS behind a load balancer would reach the node's Caddy with the
  // origin name as its server name (lib/edges/websocketNode.ts).
  const websocket = !!opts.websocketNode && http;
  if (!ot) {
    // Raw TCP to the transport; nothing an L7 front could dial.
    excluded.l7 = 'protocol_not_http_transport';
    if (websocket) {
      excluded.l4 = 'l4_not_for_websocket';
      return { layers: [], excluded };
    }
    return { layers: ['l4'], excluded };
  }
  const layers: EdgeLayer[] = [];
  if (!http) excluded.l7 = 'protocol_not_http_transport';
  // Without an authenticated proof a front can never be qualified, and
  // publication requires a current proof: never L7-frontable.
  else if (protocolL7Proof(listener) === 'unsupported') excluded.l7 = 'l7_proof_unsupported';
  // A front that rewrites the Host to a name the node does not answer for is
  // not a front: the origin would reject every member connection. With no
  // front decided yet, one that sends the origin's own name will do: FCP
  // builds a new front that way wherever the node needs it (`withOriginHost`),
  // and a provider that cannot is not a candidate (`frontHostAccepted`).
  else if (
    opts.l7Host !== undefined
      ? !l7HostAccepted(ot, opts.l7Host)
      : originHostNeeded(ot) && !originHostCarrierExists(listener, ot, opts.originAddress)
  )
    excluded.l7 = 'host_header_rejected';
  else layers.push('l7');
  if (ot.scheme === 'http') excluded.l4 = 'origin_plaintext';
  else if (websocket) excluded.l4 = 'l4_not_for_websocket';
  else if (protocolUsesSni(listener)) {
    const active = (listener.tlsNames ?? [])
      .filter((s) => s.status === 'active')
      .map((s) => s.name);
    // Behind an L4 forwarder the renderer must SELECT one of the listener's own
    // names; with none left there is nothing to emit, and a coverage check over
    // an empty set is vacuously true rather than a pass.
    if (active.length === 0) excluded.l4 = 'no_server_names';
    else if (!ot.certPublic) excluded.l4 = 'cert_not_public';
    // Every name covered also means a `names` node accepts each as Host: the
    // Host an L4 member sends IS the selected name (hostTargetFor).
    else if (active.some((n) => !certCovers(n, ot.certNames))) excluded.l4 = 'cert_name_uncovered';
    else layers.push('l4');
  } else layers.push('l4');
  // Keep a stable order: l4 first.
  layers.sort();
  return { layers, excluded };
}

export function listenerAllowsLayer(
  listener: ListenerLike,
  layer: EdgeLayer,
  opts: ListenerLayerOpts = {},
): boolean {
  return listenerLayers(listener, opts).layers.includes(layer);
}

export interface HostTuple {
  address: string;
  port: number;
  /** null = the Host presents no server name (plain) → clear it on the backend. */
  sni: string | null;
  /** null = no HTTP Host header → clear it on the backend. */
  host: string | null;
}

/**
 * The complete Host tuple for one edge + listener + selected server name.
 * L7 → the hostname everywhere; L4 HTTP transport → SNI and Host = the selected
 * name; L4 reality/tls → SNI only; plain → neither.
 */
export function hostTargetFor(
  edge: {
    layer?: EdgeLayer | null;
    addresses: { v4?: string | null; hostname?: string | null };
    edgePort: number;
  },
  proto: ListenerProto,
  selectedSni: string | null,
): HostTuple | null {
  if ((edge.layer ?? 'l4') === 'l7') {
    const h = edge.addresses.hostname;
    if (!h) return null;
    return { address: h, port: edge.edgePort, sni: h, host: h };
  }
  const address = edge.addresses.v4;
  if (!address) return null;
  if (!protocolUsesSni(proto)) return { address, port: edge.edgePort, sni: null, host: null };
  if (!selectedSni) return null;
  return {
    address,
    port: edge.edgePort,
    sni: selectedSni,
    host: protocolUsesHostHeader(proto) ? selectedSni : null,
  };
}
