/**
 * WebSocket nodes and load balancers (docs/edges.md § "Layers").
 *
 * A WebSocket node is an enrolled node whose mode a CDN fronts (shape
 * `{transport: 'ws', fronting: 'edge-l7'}`): its Caddy terminates TLS for the
 * node's origin name, the one name its public certificate covers. A load
 * balancer in front of it would pass a member's TLS straight to that Caddy,
 * so the member would have to send the origin name as its server name: a
 * name in public certificate logs that resolves to the node, where one block
 * of it takes out every load-balancer address the node has. So a WebSocket
 * node's HTTP-transport listeners are never fronted at L4: not offered, not
 * accepted, never chosen by automatic work, never published. Its backup at
 * another provider is a second CDN. L4 edges such a node already has are left
 * as they are.
 *
 * Exports:
 *   websocketNodeOf(db, origin)          whether the origin's node is a WebSocket node
 *   l4BarredFor(listener, websocketNode) whether a load balancer may not front the listener
 *   L4_NOT_FOR_WEBSOCKET                 the refusal's words
 */
import type { Doc } from '../../_generated/dataModel';
import type { DatabaseReader } from '../../_generated/server';
import { isCdnFronted } from '../backend/profileTemplate';
import { currentNodeName } from '../backend/nodeAliases';
import { protocolIsHttpTransport, type ListenerProto } from './protocols';

/** The refusal's words (`edge.l4_not_for_websocket`), one sentence wherever it is thrown. */
export const L4_NOT_FOR_WEBSOCKET =
  "A load balancer cannot front a WebSocket node: members would send the node's own name. Use a CDN";

/** Whether the node behind an origin is a WebSocket node (false for anything not an enrolled node). */
export async function websocketNodeOf(
  db: DatabaseReader,
  origin: Doc<'relays'>['origin'],
): Promise<boolean> {
  if (origin.kind !== 'panel-node') return false;
  const sid = origin.backendServerId;
  const byName = (name: string) =>
    db
      .query('panelNodeIntents')
      .withIndex('by_server_name', (q) => q.eq('backendServerId', sid).eq('name', name))
      .unique();
  // A name the node had before a rename is the same node.
  let intent = await byName(origin.nodeName);
  if (!intent) {
    const current = await currentNodeName(db, sid, origin.nodeName);
    intent = current ? await byName(current) : null;
  }
  if (!intent) return false;
  const setup = await db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  const mode = setup?.modes.find((m) => m.slug === intent.mode);
  // Without the mode's entry, the machine says it: only a WebSocket node has an ingress.
  return mode ? isCdnFronted(mode.shape) : !!intent.settings.ingress;
}

/** A load balancer may not front this listener: an HTTP transport of a WebSocket node. */
export function l4BarredFor(listener: ListenerProto, websocketNode: boolean): boolean {
  return websocketNode && protocolIsHttpTransport(listener);
}
