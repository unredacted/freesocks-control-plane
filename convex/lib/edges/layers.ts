/**
 * Layer compatibility: which edge LAYERS (an L4 TCP forwarder, an L7 CDN front)
 * can carry a relay slot, decided on the COMPLETE client-to-origin chain, never
 * on the protocol name alone. Pure; used by publishability, selection, adoption
 * and the detector's replacement choice.
 *
 *  - A slot whose origin speaks plaintext HTTP behind the CDN (`scheme:http`)
 *    is L7-only: an L4 forwarder cannot add the TLS the CDN terminated.
 *  - An `https` origin is L7-frontable when the profile is an HTTP transport,
 *    and L4-frontable only when a member's TLS session to the node itself is
 *    sound: the certificate is publicly trusted (members do not pin) AND every
 *    active server name the renderer may emit is covered by a certificate name
 *    (RFC 6125 wildcard matching) AND the node accepts those names as Host.
 *  - Legacy slots (no originTransport) keep today's L4-only rules.
 *
 * `hostTargetFor` is the single source of the Host tuple written to the panel
 * and emitted by assignment, so a flip and a render never disagree.
 */
import type { EdgeLayer } from './providers/capabilities';
import { protocolIsHttpTransport, protocolUsesHostHeader, protocolUsesSni, type SlotProtocol } from './protocols';

export interface OriginTransport {
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: readonly string[];
  acceptsHostHeader: 'any' | 'names';
}

export interface SlotLike {
  originTransport?: OriginTransport | null;
}
export interface ProfileLike {
  protocol: SlotProtocol;
  serverNames: ReadonlyArray<{ sni: string; status: 'active' | 'retired' }>;
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

export type LayerExclusion =
  | 'origin_plaintext'
  | 'cert_not_public'
  | 'cert_name_uncovered'
  | 'host_header_rejected'
  | 'protocol_not_http_transport';

export interface SlotLayers {
  layers: EdgeLayer[];
  /** Why a layer is excluded (empty when both are allowed). */
  excluded: Partial<Record<EdgeLayer, LayerExclusion>>;
}

/** The layers that can front `slot` speaking `profile.protocol`. */
export function slotLayers(slot: SlotLike, profile: ProfileLike): SlotLayers {
  const ot = slot.originTransport ?? null;
  const http = protocolIsHttpTransport(profile.protocol);
  const excluded: SlotLayers['excluded'] = {};
  if (!ot) {
    // Legacy slot: raw TCP to the inbound; nothing an L7 front could dial.
    excluded.l7 = 'protocol_not_http_transport';
    return { layers: ['l4'], excluded };
  }
  const layers: EdgeLayer[] = [];
  if (http) layers.push('l7');
  else excluded.l7 = 'protocol_not_http_transport';
  if (ot.scheme === 'http') excluded.l4 = 'origin_plaintext';
  else if (protocolUsesSni(profile.protocol)) {
    const active = profile.serverNames.filter((s) => s.status === 'active').map((s) => s.sni);
    if (!ot.certPublic) excluded.l4 = 'cert_not_public';
    else if (active.some((n) => !certCovers(n, ot.certNames))) excluded.l4 = 'cert_name_uncovered';
    else if (http && protocolUsesHostHeader(profile.protocol) && ot.acceptsHostHeader === 'names' && active.some((n) => !certCovers(n, ot.certNames)))
      excluded.l4 = 'host_header_rejected';
    else layers.push('l4');
  } else layers.push('l4');
  // Keep a stable order: l4 first.
  layers.sort();
  return { layers, excluded };
}

export function slotAllowsLayer(slot: SlotLike, profile: ProfileLike, layer: EdgeLayer): boolean {
  return slotLayers(slot, profile).layers.includes(layer);
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
 * The complete Host tuple for one edge + slot protocol + selected server name.
 * L7 → the hostname everywhere; L4 HTTP transport → SNI and Host = the selected
 * name; L4 reality/tls → SNI only; plain → neither.
 */
export function hostTargetFor(
  edge: { layer?: EdgeLayer | null; addresses: { v4?: string | null; hostname?: string | null }; edgePort: number },
  protocol: SlotProtocol,
  selectedSni: string | null,
): HostTuple | null {
  if ((edge.layer ?? 'l4') === 'l7') {
    const h = edge.addresses.hostname;
    if (!h) return null;
    return { address: h, port: edge.edgePort, sni: h, host: h };
  }
  const address = edge.addresses.v4;
  if (!address) return null;
  if (!protocolUsesSni(protocol)) return { address, port: edge.edgePort, sni: null, host: null };
  if (!selectedSni) return null;
  return {
    address,
    port: edge.edgePort,
    sni: selectedSni,
    host: protocolUsesHostHeader(protocol) ? selectedSni : null,
  };
}
