/**
 * The network a transport is scoped to (docs/edges.md "Networks"): the network
 * of the server-name family bound to it. A listener carries a copy
 * (`relayListeners.networkId`), written by the bind, the unbind and
 * registration, so the pure rules that pick where its edges come from
 * (`carries`, rotation selection) read it off the row.
 */
import type { Doc, Id } from '../../_generated/dataModel';
import type { DatabaseReader, MutationCtx } from '../../_generated/server';

/** The network of the family bound to a backend transport, if any. */
export async function transportNetwork(
  db: DatabaseReader,
  backendServerId: Id<'backendServers'>,
  inboundUuid: string,
): Promise<Id<'edgeNetworks'> | undefined> {
  const binding = await db
    .query('sniInboundBindings')
    .withIndex('by_server_inbound', (q) =>
      q.eq('backendServerId', backendServerId).eq('inboundUuid', inboundUuid),
    )
    .unique();
  if (!binding) return undefined;
  return (await db.get(binding.familyId))?.networkId;
}

/** The network a listener of this origin should carry, from its panel binding. */
export async function listenerNetworkOf(
  db: DatabaseReader,
  origin: Pick<Doc<'relays'>, 'origin'>,
  panelBinding: { configProfileInboundUuid: string } | undefined,
): Promise<Id<'edgeNetworks'> | undefined> {
  if (!panelBinding || origin.origin.kind === 'manual') return undefined;
  return transportNetwork(db, origin.origin.backendServerId, panelBinding.configProfileInboundUuid);
}

/** The live listeners of a backend transport, on every origin of its backend. */
export async function listenersOfTransport(
  db: DatabaseReader,
  backendServerId: Id<'backendServers'>,
  inboundUuid: string,
): Promise<Doc<'relayListeners'>[]> {
  const out: Doc<'relayListeners'>[] = [];
  for (const relay of await db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', backendServerId))
    .collect())
    for (const l of await db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect())
      if (!l.retired && l.panelBinding?.configProfileInboundUuid === inboundUuid) out.push(l);
  return out;
}

/** Write a transport's network onto its listeners (a bind sets it, an unbind clears it). */
export async function syncTransportNetwork(
  ctx: MutationCtx,
  backendServerId: Id<'backendServers'>,
  inboundUuid: string,
  networkId: Id<'edgeNetworks'> | undefined,
): Promise<number> {
  let changed = 0;
  for (const l of await listenersOfTransport(ctx.db, backendServerId, inboundUuid)) {
    if (l.networkId === networkId) continue;
    await ctx.db.patch(l._id, { networkId, updatedAt: Date.now() });
    changed++;
  }
  return changed;
}
