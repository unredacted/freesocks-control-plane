/**
 * Slot protocols: what the inbound behind a relay slot speaks. Edges are
 * protocol-agnostic L4 forwarders; the protocol decides what the renderer must
 * rewrite in a subscriber's connection and which extra data a slot needs.
 *
 *  - `reality`: VLESS+REALITY. Needs a REALITY profile (target + approved
 *    server names); the renderer swaps address, port AND the SNI.
 *  - `tcp`: any TCP protocol the node terminates itself (VLESS/Trojan over real
 *    TLS, Shadowsocks…). No profile; the renderer swaps address and port only.
 *
 * `PROTOCOL_TRANSPORT` is what the edge listener must carry; every provider
 * adapter forwards TCP today, so a UDP protocol is refused at selection until
 * an adapter declares `udp` in its capabilities.
 */
export const SLOT_PROTOCOLS = ['reality', 'tcp'] as const;
export type SlotProtocol = (typeof SLOT_PROTOCOLS)[number];

export type ListenerTransport = 'tcp' | 'udp';

export const PROTOCOL_TRANSPORT: Record<SlotProtocol, ListenerTransport> = {
  reality: 'tcp',
  tcp: 'tcp',
};

export const PROTOCOL_LABELS: Record<SlotProtocol, string> = {
  reality: 'REALITY',
  tcp: 'TCP passthrough',
};

export function isSlotProtocol(v: unknown): v is SlotProtocol {
  return typeof v === 'string' && (SLOT_PROTOCOLS as readonly string[]).includes(v);
}

/** Only REALITY slots carry a profile (the SNI pool is the profile). */
export function protocolNeedsProfile(p: SlotProtocol): boolean {
  return p === 'reality';
}
