/**
 * The role's half of a staged port change (backendPortChanges.ts), as helpers
 * over the database: which ports an enrolled node's firewall must let in, and
 * what the role's applied report confirms. Here rather than in the module that
 * stages changes so the node lifecycle (nodeIntents.ts) can call them without
 * importing the ledger's write path.
 */
import type { MutationCtx, QueryCtx } from '../../_generated/server';
import { internal } from '../../_generated/api';
import type { Doc, Id } from '../../_generated/dataModel';
import { writeAuditLog } from '../audit';
import { inboundPortProtocol } from '../edges/inboundMapping';

export type PortProtocol = 'tcp' | 'udp';

/** A port as a firewall lets it in: the number and the IP protocol (absent = tcp). */
export interface FirewallOpening {
  port: number;
  protocol: PortProtocol;
}

/** The stable key of an opening, `443/udp`. */
export const openingKey = (o: { port: number; protocol?: PortProtocol | null }): string =>
  `${o.port}/${o.protocol ?? 'tcp'}`;

/** Whether a change still holds its ports: waiting, or sent with its op still open. */
async function changeOpen(
  ctx: { db: QueryCtx['db'] },
  changeId: Id<'panelPortChanges'>,
): Promise<boolean> {
  const change = await ctx.db.get(changeId);
  if (!change) return false;
  if (change.state === 'waiting') return true;
  if (change.state !== 'applying' || !change.opId) return false;
  const op = await ctx.db.get(change.opId);
  return !!op?.open;
}

export async function requirementsOf(
  ctx: { db: QueryCtx['db'] },
  changeId: Id<'panelPortChanges'>,
) {
  return ctx.db
    .query('panelPortRequirements')
    .withIndex('by_change', (q) => q.eq('changeId', changeId))
    .collect();
}

/** Wake the change once nothing is waiting any more. */
export async function wakeIfReady(ctx: MutationCtx, changeId: Id<'panelPortChanges'>) {
  const change = await ctx.db.get(changeId);
  if (!change || change.state !== 'waiting') return;
  const waiting = (await requirementsOf(ctx, changeId)).filter((r) => r.state === 'waiting');
  if (waiting.length === 0)
    await ctx.scheduler.runAfter(0, internal.backendPortChanges.apply, { changeId });
}

/**
 * The role's applied report named the ports its node's firewall lets in: every
 * waiting requirement of THIS node whose (port, protocol) is listed is
 * confirmed. A report naming `443/tcp` never confirms `443/udp`, so a role that
 * only opens TCP keeps a UDP requirement waiting. Called from
 * `nodeIntents.applied` in the same transaction as the report.
 */
export async function confirmFromRole(
  ctx: MutationCtx,
  intent: Doc<'panelNodeIntents'>,
  ports: readonly FirewallOpening[],
): Promise<number> {
  const open = new Set(ports.map(openingKey));
  const rows = (
    await ctx.db
      .query('panelPortRequirements')
      .withIndex('by_server_node', (q) =>
        q.eq('backendServerId', intent.backendServerId).eq('nodeName', intent.name),
      )
      .collect()
  ).filter(
    (r) =>
      r.state === 'waiting' &&
      r.confirmedBy === 'role' &&
      r.intentId === intent._id &&
      open.has(openingKey(r)),
  );
  const now = Date.now();
  for (const r of rows) {
    await ctx.db.patch(r._id, { state: 'confirmed', confirmedAt: now, updatedAt: now });
    const change = await ctx.db.get(r.changeId);
    const server = await ctx.db.get(intent.backendServerId);
    if (change)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'servers.port_change.confirmed',
        targetType: 'panel_port_change',
        targetId: change._id,
        payload: {
          backendSlug: server?.slug ?? '',
          label: change.profileName,
          by: 'role',
          nodes: 1,
          port: r.port,
          protocol: r.protocol ?? 'tcp',
        },
      });
  }
  for (const changeId of new Set(rows.map((r) => r.changeId))) await wakeIfReady(ctx, changeId);
  return rows.length;
}

function isLoopback(listen: string | null | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

/**
 * Every port an enrolled node's firewall must let in: what its transports
 * listen on (loopback ones excepted) and its own proxy's public port, as
 * `serving`; a staged change's port it has not confirmed yet, as `pending`.
 * The node's API port (the backend's channel to it) is the role's own
 * business and is not listed.
 */
export async function firewallPortsFor(
  ctx: { db: QueryCtx['db'] },
  intent: Doc<'panelNodeIntents'>,
): Promise<{ port: number; protocol: PortProtocol; reason: 'serving' | 'pending' }[]> {
  const sid = intent.backendServerId;
  const serving = new Map<string, FirewallOpening>();
  const add = (into: Map<string, FirewallOpening>, o: FirewallOpening) =>
    into.set(openingKey(o), o);
  const node = intent.nodeUuid
    ? await ctx.db
        .query('panelNodes')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', sid).eq('nodeUuid', intent.nodeUuid!),
        )
        .unique()
    : null;
  const profiles = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  let inboundUuids: string[] = node?.activeInboundUuids ?? [];
  if (!node) {
    // Not on the backend yet: the mode's transport is what it will serve.
    const setup = await ctx.db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .unique();
    const uuid = setup?.modes?.find((m) => m.slug === intent.mode)?.transport?.uuid;
    inboundUuids = uuid ? [uuid] : [];
  }
  for (const p of profiles)
    for (const i of p.inbounds)
      if (inboundUuids.includes(i.inboundUuid) && i.port !== null && !isLoopback(i.listen))
        add(serving, { port: i.port, protocol: inboundPortProtocol(i) });
  // The node's own proxy (a WebSocket node's Caddy) is TCP.
  if (intent.settings.ingress)
    add(serving, { port: intent.settings.ingress.externalPort, protocol: 'tcp' });
  // A port stays listed from the moment a change asks for it until that change
  // is over, CONFIRMED included: a role run between the confirmation and the
  // send (a busy profile, the switch off) must not close it again.
  const pending = new Map<string, FirewallOpening>();
  for (const r of await ctx.db
    .query('panelPortRequirements')
    .withIndex('by_server_node', (q) => q.eq('backendServerId', sid).eq('nodeName', intent.name))
    .collect()) {
    if (r.state === 'cancelled' || r.intentId !== intent._id || serving.has(openingKey(r)))
      continue;
    if (await changeOpen(ctx, r.changeId))
      add(pending, { port: r.port, protocol: r.protocol ?? 'tcp' });
  }
  const sorted = (m: Map<string, FirewallOpening>) =>
    [...m.values()].sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
  return [
    ...sorted(serving).map((o) => ({ ...o, reason: 'serving' as const })),
    ...sorted(pending).map((o) => ({ ...o, reason: 'pending' as const })),
  ];
}
