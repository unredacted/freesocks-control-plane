/**
 * The relay LISTENER catalogue: what an inbound behind a relay speaks, as
 * three orthogonal fields with a validity matrix, plus the flags the renderer,
 * the layer logic and the qualification derive from them. Deliberately
 * zod-free so Convex code can VALUE-import it (the edgeProviderIds.ts pattern);
 * `convex/lib/edgeProtocolIds.ts` derives the validators, `convex/lib/edges/
 * protocols.ts` the server-side codec table.
 *
 *   protocol        what carries the payload (vless, trojan, shadowsocks, hysteria2, tuic)
 *   streamTransport the client-to-node stream (raw TCP, WebSocket, HTTP Upgrade, gRPC, XHTTP, or UDP)
 *   security        the client-facing security layer (none, TLS, REALITY)
 *
 * Client-to-edge security is NOT edge-to-origin security: how a CDN front
 * dials the node is the listener's `originTransport` (lib/edges/layers.ts).
 */
export const LISTENER_PROTOCOL_IDS = [
  'vless',
  'trojan',
  'shadowsocks',
  'hysteria2',
  'tuic',
] as const;
export type ListenerProtocolId = (typeof LISTENER_PROTOCOL_IDS)[number];

export const LISTENER_STREAM_TRANSPORT_IDS = [
  'raw',
  'ws',
  'httpupgrade',
  'grpc',
  'xhttp',
  'udp',
] as const;
export type ListenerStreamTransport = (typeof LISTENER_STREAM_TRANSPORT_IDS)[number];

export const LISTENER_SECURITY_IDS = ['none', 'tls', 'reality'] as const;
export type ListenerSecurity = (typeof LISTENER_SECURITY_IDS)[number];

/** The three fields that identify what a listener speaks. */
export interface ListenerProto {
  protocol: ListenerProtocolId;
  streamTransport: ListenerStreamTransport;
  security: ListenerSecurity;
}

/** `protocol/streamTransport/security`, the stable key of a combination. */
export type ListenerComboKey =
  `${ListenerProtocolId}/${ListenerStreamTransport}/${ListenerSecurity}`;

export function comboKey(p: ListenerProto): ListenerComboKey {
  return `${p.protocol}/${p.streamTransport}/${p.security}`;
}

export interface ListenerCombo extends ListenerProto {
  key: ListenerComboKey;
  label: string;
  /** What an L4 edge listener must carry. Every provider adapter forwards TCP today. */
  transport: 'tcp' | 'udp';
  /** The renderer selects and writes a server name (REALITY SNIs or certificate names). */
  usesSni: boolean;
  /** REALITY impersonates a target (address:port the node dials for the handshake). */
  needsTarget: boolean;
  /** HTTP-carried stream: the only kind an L7 (CDN) front can carry. */
  isHttpTransport: boolean;
  /** The renderer writes an HTTP Host header (ws / httpupgrade / xhttp; gRPC follows the SNI). */
  usesHostHeader: boolean;
  /** Which authenticated end-to-end proof exists for an L7 front of this listener. */
  l7Proof: 'vless' | 'unsupported';
  /** Legacy single-word protocol id the renderer codecs and Host logic used (kept for fixtures). */
  legacy: 'reality' | 'tls' | 'plain' | 'ws' | 'httpupgrade' | 'grpc' | 'xhttp' | 'udp';
}

function combo(
  protocol: ListenerProtocolId,
  streamTransport: ListenerStreamTransport,
  security: ListenerSecurity,
  label: string,
): ListenerCombo {
  const isHttpTransport =
    streamTransport === 'ws' ||
    streamTransport === 'httpupgrade' ||
    streamTransport === 'grpc' ||
    streamTransport === 'xhttp';
  const transport: 'tcp' | 'udp' = streamTransport === 'udp' ? 'udp' : 'tcp';
  const legacy: ListenerCombo['legacy'] =
    transport === 'udp'
      ? 'udp'
      : security === 'reality'
        ? 'reality'
        : security === 'none'
          ? 'plain'
          : isHttpTransport
            ? (streamTransport as 'ws' | 'httpupgrade' | 'grpc' | 'xhttp')
            : 'tls';
  return {
    key: `${protocol}/${streamTransport}/${security}`,
    protocol,
    streamTransport,
    security,
    label,
    transport,
    usesSni: security !== 'none',
    needsTarget: security === 'reality',
    isHttpTransport,
    usesHostHeader:
      streamTransport === 'ws' || streamTransport === 'httpupgrade' || streamTransport === 'xhttp',
    l7Proof:
      protocol === 'vless' && isHttpTransport && security === 'tls' ? 'vless' : 'unsupported',
    legacy,
  };
}

/**
 * Every valid combination. Anything not listed is `invalid_combination`. The
 * server-side codec table (convex/lib/edges/protocols.ts) is pinned against
 * this list by a test: a combination without a codec for every subscription
 * format it claims never ships.
 */
export const LISTENER_COMBOS: readonly ListenerCombo[] = [
  combo('vless', 'raw', 'reality', 'VLESS + REALITY'),
  combo('vless', 'raw', 'tls', 'VLESS over TLS'),
  combo('vless', 'ws', 'tls', 'VLESS over WebSocket (TLS)'),
  combo('vless', 'httpupgrade', 'tls', 'VLESS over HTTP Upgrade (TLS)'),
  combo('vless', 'grpc', 'tls', 'VLESS over gRPC (TLS)'),
  // XHTTP (Xray 1.8.24+): plain HTTP requests carry the stream, so any CDN that
  // passes HTTP can front it; an L4 forwarder carries it like any TCP listener.
  // Only behind a real certificate: with REALITY there is no Caddy in front.
  combo('vless', 'xhttp', 'tls', 'VLESS over XHTTP (TLS)'),
  combo('trojan', 'raw', 'tls', 'Trojan over TLS'),
  combo('trojan', 'ws', 'tls', 'Trojan over WebSocket (TLS)'),
  combo('shadowsocks', 'raw', 'none', 'Shadowsocks'),
  combo('hysteria2', 'udp', 'tls', 'Hysteria 2'),
  combo('tuic', 'udp', 'tls', 'TUIC'),
];

const BY_KEY: ReadonlyMap<string, ListenerCombo> = new Map(LISTENER_COMBOS.map((c) => [c.key, c]));

export function listenerCombo(p: ListenerProto): ListenerCombo | null {
  return BY_KEY.get(comboKey(p)) ?? null;
}

export function isValidListenerCombo(p: ListenerProto): boolean {
  return BY_KEY.has(comboKey(p));
}

export function isListenerProtocolId(v: unknown): v is ListenerProtocolId {
  return typeof v === 'string' && (LISTENER_PROTOCOL_IDS as readonly string[]).includes(v);
}
export function isListenerStreamTransport(v: unknown): v is ListenerStreamTransport {
  return typeof v === 'string' && (LISTENER_STREAM_TRANSPORT_IDS as readonly string[]).includes(v);
}
export function isListenerSecurity(v: unknown): v is ListenerSecurity {
  return typeof v === 'string' && (LISTENER_SECURITY_IDS as readonly string[]).includes(v);
}

/** Why an edge layer cannot carry a listener; surfaced to the operator in words. */
export const LISTENER_LAYER_EXCLUSIONS = [
  'origin_plaintext',
  'cert_not_public',
  'cert_name_uncovered',
  'host_header_rejected',
  'no_server_names',
  'protocol_not_http_transport',
  'l7_proof_unsupported',
  'no_udp_provider',
] as const;
export type ListenerLayerExclusion = (typeof LISTENER_LAYER_EXCLUSIONS)[number];
