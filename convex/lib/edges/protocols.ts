/**
 * Listener protocol helpers over the shared catalogue
 * (src/shared/contracts/edgeProtocolIds.ts): what a listener speaks decides
 * what the renderer must rewrite in a subscriber's connection, what the
 * listener must hold (names, a REALITY target), which edge LAYERS can front it
 * (lib/edges/layers.ts) and which authenticated proof an L7 front has.
 *
 * Every helper takes the listener's three fields. The single-word `legacy`
 * id survives only inside the renderer codecs and the preview fixtures.
 *
 * `CODECS` says, per combination, which subscription formats the renderer can
 * rewrite. A combination is not shippable without a codec for every format it
 * claims; `protocols.test.ts` pins the table against the catalogue.
 */
import {
  comboKey,
  listenerCombo,
  type ListenerCombo,
  type ListenerComboKey,
  type ListenerProto,
} from '../../../src/shared/contracts/edgeProtocolIds';

export {
  LISTENER_COMBOS,
  LISTENER_PROTOCOL_IDS,
  LISTENER_SECURITY_IDS,
  LISTENER_STREAM_TRANSPORT_IDS,
  comboKey,
  isValidListenerCombo,
  listenerCombo,
} from '../../../src/shared/contracts/edgeProtocolIds';
export type {
  ListenerCombo,
  ListenerComboKey,
  ListenerProto,
  ListenerProtocolId,
  ListenerSecurity,
  ListenerStreamTransport,
} from '../../../src/shared/contracts/edgeProtocolIds';

export type ListenerTransport = 'tcp' | 'udp';

/** The descriptor, or a throw: callers only ever hold validated listeners. */
export function protocolDescriptor(p: ListenerProto): ListenerCombo {
  const c = listenerCombo(p);
  if (!c) throw new Error(`invalid listener combination ${comboKey(p)}`);
  return c;
}

/** What an L4 edge listener must carry. */
export function protocolTransport(p: ListenerProto): ListenerTransport {
  return protocolDescriptor(p).transport;
}

/** The renderer selects and writes a server name for these listeners. */
export function protocolUsesSni(p: ListenerProto): boolean {
  return protocolDescriptor(p).usesSni;
}

/** Only REALITY impersonates a target. */
export function protocolNeedsTarget(p: ListenerProto): boolean {
  return protocolDescriptor(p).needsTarget;
}

/** True for the HTTP-carried streams (the only listeners an L7 front can carry). */
export function protocolIsHttpTransport(p: ListenerProto): boolean {
  return protocolDescriptor(p).isHttpTransport;
}

/** The renderer writes an HTTP Host header for these (ws, httpupgrade, xhttp). */
export function protocolUsesHostHeader(p: ListenerProto): boolean {
  return protocolDescriptor(p).usesHostHeader;
}

/** Which authenticated end-to-end proof an L7 front of this listener has. */
export function protocolL7Proof(p: ListenerProto): ListenerCombo['l7Proof'] {
  return protocolDescriptor(p).l7Proof;
}

export function protocolLabel(p: ListenerProto): string {
  return listenerCombo(p)?.label ?? comboKey(p);
}

/** Subscription formats the renderer knows (render/*.ts). */
export const RENDER_FORMATS = ['links', 'singbox', 'clash'] as const;
export type RenderFormat = (typeof RENDER_FORMATS)[number];

/**
 * Per format, the entry shapes a codec can rewrite for a combination:
 *   links   URI scheme(s) of the share link
 *   singbox `outbounds[].type`
 *   clash   `proxies[].type`
 * An empty list means the format has no codec for the combination; such an
 * entry in a body is left alone and reported as `entry_unsupported`.
 */
export interface CodecSupport {
  links: readonly string[];
  singbox: readonly string[];
  clash: readonly string[];
}

export const CODECS: Partial<Record<ListenerComboKey, CodecSupport>> = {
  'vless/raw/reality': { links: ['vless'], singbox: ['vless'], clash: ['vless'] },
  'vless/raw/tls': { links: ['vless'], singbox: ['vless'], clash: ['vless'] },
  'vless/ws/tls': { links: ['vless'], singbox: ['vless'], clash: ['vless'] },
  'vless/httpupgrade/tls': { links: ['vless'], singbox: ['vless'], clash: ['vless'] },
  'vless/grpc/tls': { links: ['vless'], singbox: ['vless'], clash: ['vless'] },
  // Xray and Mihomo speak XHTTP (`network: xhttp` + `xhttp-opts`); sing-box has
  // no transport for it, so a sing-box body of such a listener is unavailable.
  'vless/xhttp/tls': { links: ['vless'], singbox: [], clash: ['vless'] },
  'trojan/raw/tls': { links: ['trojan'], singbox: ['trojan'], clash: ['trojan'] },
  'trojan/ws/tls': { links: ['trojan'], singbox: ['trojan'], clash: ['trojan'] },
  'shadowsocks/raw/none': { links: ['ss'], singbox: ['shadowsocks'], clash: ['ss'] },
  'hysteria2/udp/tls': {
    links: ['hysteria2', 'hy2'],
    singbox: ['hysteria2'],
    clash: ['hysteria2'],
  },
  'tuic/udp/tls': { links: ['tuic'], singbox: ['tuic'], clash: ['tuic'] },
};

export function codecFor(p: ListenerProto, format: RenderFormat): readonly string[] {
  return CODECS[comboKey(p)]?.[format] ?? [];
}

export function formatSupported(p: ListenerProto, format: RenderFormat): boolean {
  return codecFor(p, format).length > 0;
}
