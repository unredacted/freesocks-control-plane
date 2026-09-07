/**
 * Slot protocols: what the inbound behind a relay slot speaks. Edges are
 * protocol-agnostic L4 forwarders; the protocol (carried by the slot's PROFILE)
 * decides what the renderer must rewrite in a subscriber's connection and what
 * the profile must hold.
 *
 *  - `reality`: VLESS+REALITY. The profile carries the impersonated target and
 *    the approved server names; the renderer swaps address, port AND the SNI.
 *  - `tls`: any protocol the node terminates with a real certificate (VLESS/
 *    Trojan over TLS). The profile carries the certificate's names; the
 *    renderer swaps address, port and SNI (one of those names).
 *  - `plain`: no TLS name to present (Shadowsocks, plain VLESS…). No server
 *    names; the renderer swaps address and port only.
 *
 * `PROTOCOL_TRANSPORT` is what the edge listener must carry; every provider
 * adapter forwards TCP today, so a UDP protocol is refused at selection until
 * an adapter declares `udp` in its capabilities.
 */
export const SLOT_PROTOCOLS = ['reality', 'tls', 'plain'] as const;
export type SlotProtocol = (typeof SLOT_PROTOCOLS)[number];

export type ListenerTransport = 'tcp' | 'udp';

export const PROTOCOL_TRANSPORT: Record<SlotProtocol, ListenerTransport> = {
  reality: 'tcp',
  tls: 'tcp',
  plain: 'tcp',
};

export const PROTOCOL_LABELS: Record<SlotProtocol, string> = {
  reality: 'REALITY',
  tls: 'TLS (real certificate)',
  plain: 'Plain (no TLS name)',
};

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
