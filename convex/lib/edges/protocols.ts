/**
 * Slot protocols: what the inbound behind a relay slot speaks. The protocol
 * (carried by the slot's PROFILE) decides what the renderer must rewrite in a
 * subscriber's connection, what the profile must hold, and which edge LAYERS
 * can front the slot (lib/edges/layers.ts).
 *
 *  - `reality`: VLESS+REALITY. The profile carries the impersonated target and
 *    the approved server names; the renderer swaps address, port AND the SNI.
 *  - `tls`: any protocol the node terminates with a real certificate (VLESS/
 *    Trojan over TLS). The profile carries the certificate's names; the
 *    renderer swaps address, port and SNI (one of those names).
 *  - `plain`: no TLS name to present (Shadowsocks, plain VLESS…). No server
 *    names; the renderer swaps address and port only.
 *  - `ws` / `httpupgrade` / `grpc`: TLS + that HTTP transport. Behind an L4
 *    edge they behave like `tls` (the profile names are the certificate's).
 *    Behind an L7 edge (a CDN front) the edge HOSTNAME is the SNI and the HTTP
 *    Host header; the renderer swaps address, port, SNI and Host.
 *
 * `PROTOCOL_TRANSPORT` is what an L4 edge listener must carry; every provider
 * adapter forwards TCP today, so a UDP protocol is refused at selection until
 * an adapter declares `udp` in its capabilities.
 */
export const SLOT_PROTOCOLS = ['reality', 'tls', 'plain', 'ws', 'httpupgrade', 'grpc'] as const;
export type SlotProtocol = (typeof SLOT_PROTOCOLS)[number];

export type ListenerTransport = 'tcp' | 'udp';

export const PROTOCOL_TRANSPORT: Record<SlotProtocol, ListenerTransport> = {
  reality: 'tcp',
  tls: 'tcp',
  plain: 'tcp',
  ws: 'tcp',
  httpupgrade: 'tcp',
  grpc: 'tcp',
};

export const PROTOCOL_LABELS: Record<SlotProtocol, string> = {
  reality: 'REALITY',
  tls: 'TLS (real certificate)',
  plain: 'Plain (no TLS name)',
  ws: 'WebSocket over TLS',
  httpupgrade: 'HTTP Upgrade over TLS',
  grpc: 'gRPC over TLS',
};

/** The HTTP-carried transports an L7 (CDN) edge can front. */
export const HTTP_TRANSPORT_PROTOCOLS = [
  'ws',
  'httpupgrade',
  'grpc',
] as const satisfies readonly SlotProtocol[];

export function isSlotProtocol(v: unknown): v is SlotProtocol {
  return typeof v === 'string' && (SLOT_PROTOCOLS as readonly string[]).includes(v);
}

/** The renderer selects and writes a server name for these protocols. */
export function protocolUsesSni(p: SlotProtocol): boolean {
  return p !== 'plain';
}

/** Only REALITY impersonates a target (address:port the node dials for the handshake). */
export function protocolNeedsTarget(p: SlotProtocol): boolean {
  return p === 'reality';
}

/** True for the HTTP-carried transports (the only protocols an L7 edge can front). */
export function protocolIsHttpTransport(p: SlotProtocol): boolean {
  return (HTTP_TRANSPORT_PROTOCOLS as readonly string[]).includes(p);
}

/**
 * The renderer writes an HTTP Host header for these protocols (`ws`,
 * `httpupgrade`; gRPC carries the name in `:authority`, which follows the SNI).
 */
export function protocolUsesHostHeader(p: SlotProtocol): boolean {
  return p === 'ws' || p === 'httpupgrade';
}
