/**
 * Layer compatibility: which edge LAYERS (an L4 TCP forwarder, an L7 CDN front)
 * can carry a relay LISTENER, decided on the COMPLETE client-to-origin chain,
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
 *
 * `hostTargetFor` is the single source of the Host tuple written to the panel
 * and emitted by assignment, so a flip and a render never disagree.
 */
import type { ListenerLayerExclusion } from '../../../src/shared/contracts/edgeProtocolIds';
import type { EdgeLayer } from './providers/capabilities';
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
 * (Fastly's `overrideHost: 'origin'`). `undefined` = not decided yet (the
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
 * known yet (before the hostname is minted) the only safe answer is a
 * certificate name that could cover ANY first-level label of a zone.
 */
export function l7HostAccepted(ot: OriginTransport, l7Host?: L7HostHeader): boolean {
  if (ot.acceptsHostHeader === 'any') return true;
  if (l7Host === 'origin') return true;
  if (l7Host) return certCovers(l7Host, ot.certNames);
  return ot.certNames.some(isFirstLevelWildcard);
}

/** The Host an L7 front would send, from the minted hostname + the template's rule. */
export function l7HostHeaderFor(
  hostname: string | null | undefined,
  overrideHost?: unknown,
): L7HostHeader | undefined {
  if (overrideHost === 'origin') return 'origin';
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
  /** The Host the front would send the origin (see `l7HostAccepted`). */
  l7Host?: L7HostHeader;
  /** Some enabled provider declares `udp` (none does today). */
  udpProviderAvailable?: boolean;
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
  if (!ot) {
    // Raw TCP to the inbound; nothing an L7 front could dial.
    excluded.l7 = 'protocol_not_http_transport';
    return { layers: ['l4'], excluded };
  }
  const layers: EdgeLayer[] = [];
  if (!http) excluded.l7 = 'protocol_not_http_transport';
  // Without an authenticated proof a front can never be qualified, and
  // publication requires a current proof: never L7-frontable.
  else if (protocolL7Proof(listener) === 'unsupported') excluded.l7 = 'l7_proof_unsupported';
  // A front that rewrites the Host to a name the node does not answer for is
  // not a front: the origin would reject every member connection.
  else if (!l7HostAccepted(ot, opts.l7Host)) excluded.l7 = 'host_header_rejected';
  else layers.push('l7');
  if (ot.scheme === 'http') excluded.l4 = 'origin_plaintext';
  else if (protocolUsesSni(listener)) {
    const active = (listener.tlsNames ?? [])
      .filter((s) => s.status === 'active')
      .map((s) => s.name);
    // Behind an L4 forwarder the renderer must SELECT one of the listener's own
    // names; with none left there is nothing to emit, and a coverage check over
    // an empty set is vacuously true rather than a pass.
    if (active.length === 0) excluded.l4 = 'no_server_names';
    else if (!ot.certPublic) excluded.l4 = 'cert_not_public';
    else if (active.some((n) => !certCovers(n, ot.certNames))) excluded.l4 = 'cert_name_uncovered';
    else if (
      http &&
      protocolUsesHostHeader(listener) &&
      ot.acceptsHostHeader === 'names' &&
      active.some((n) => !certCovers(n, ot.certNames))
    )
      excluded.l4 = 'host_header_rejected';
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
  /** null = the Host presents no server name (plain) → clear it on the panel. */
  sni: string | null;
  /** null = no HTTP Host header → clear it on the panel. */
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
