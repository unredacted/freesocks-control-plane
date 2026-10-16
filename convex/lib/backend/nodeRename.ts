/**
 * A node rename (backendNodeRenames.ts): the remark forms FCP writes with a
 * node's name, and the one transaction that moves every FCP row keyed by the
 * name. Remarks are pure (unit-tested); the bridge runs inside the ledger's
 * `applyLook`, in the same transaction that SEES the backend row carry the new
 * name, so FCP's rows and the backend's row never disagree for longer than a
 * look takes. The Host remarks and the subscriptions' pins follow afterwards,
 * and every lookup a lagging name could reach resolves it through
 * `panelNodeAliases` (lib/backend/nodeAliases.ts).
 */
import type { MutationCtx } from '../../_generated/server';
import type { Doc, Id } from '../../_generated/dataModel';
import { internal } from '../../_generated/api';
import { ADDRESS_SEP, HOST_REMARK_MAX, addressRemark } from './hostRemark';
import { relayRemarkRegex, templateHostRemark } from '../edges/hosts';

/** The node name an origin row carries (origins keep a lower-case DNS-label form). */
export const originNameOf = (name: string): string => name.trim().toLowerCase();

/**
 * The remark a Host FCP wrote for node `from` carries once the node is `to`,
 * or null when the remark is not one of FCP's forms for `from`:
 *  - a direct node's address, `<from> | <server name or tag>`: rebuilt from the
 *    Host's own server name, so a shorter or longer name picks the full or the
 *    tagged form exactly as a fresh address would;
 *  - an origin listener's Host, `<from>-relay[-<key>]` (origin names are lower case).
 */
export function renamedRemark(
  remark: string,
  sni: string | null | undefined,
  from: string,
  to: string,
): string | null {
  if (remark.startsWith(`${from}${ADDRESS_SEP}`)) {
    if (sni) return addressRemark(to, sni);
    const rest = remark.slice(from.length);
    const next = `${to}${rest}`;
    return next.length <= HOST_REMARK_MAX ? next : null;
  }
  const f = originNameOf(from);
  if (relayRemarkRegex(f).test(remark)) return `${originNameOf(to)}${remark.slice(f.length)}`;
  return null;
}

/** An origin listener's remark under the new name (the template form only). */
export function renamedListenerRemark(remark: string, from: string, to: string): string | null {
  const f = originNameOf(from);
  if (!relayRemarkRegex(f).test(remark)) return null;
  return `${originNameOf(to)}${remark.slice(f.length)}`;
}

/** The longest remark a listener of this origin would carry under `to` (the backend caps remarks). */
export function longestListenerRemark(keys: readonly string[], to: string): number {
  return Math.max(0, ...keys.map((k) => templateHostRemark(originNameOf(to), k).length));
}

/**
 * Move every FCP row keyed by the node's name, in the transaction that sees
 * the backend row renamed. Idempotent: a row already carrying the new name is
 * left as it is. The rename moves on to its Host remarks.
 */
export async function bridgeNodeRename(
  ctx: MutationCtx,
  renameId: Id<'panelNodeRenames'>,
  opId: Id<'panelOps'>,
): Promise<void> {
  const r = await ctx.db.get(renameId);
  if (!r || r.state !== 'running' || r.step !== 'backend' || r.opId !== opId) return;
  const sid = r.backendServerId;
  const { from, to } = r;
  const now = Date.now();

  // The enrolled node: its name, with every former one kept (the first is the
  // name its origin DNS record's marker carries).
  if (r.intentId) {
    const intent = await ctx.db.get(r.intentId);
    if (intent && intent.name === from)
      await ctx.db.patch(intent._id, {
        name: to,
        formerNames: [...(intent.formerNames ?? []), from],
        updatedAt: now,
      });
  }

  // Origins standing in front of the node, their listeners' remarks and
  // delivery bindings. A remark changes here only on FCP's own template form;
  // the old one stays matchable until the backend's Host carries the new one.
  const fromOrigin = originNameOf(from);
  const toOrigin = originNameOf(to);
  for (const relayId of r.relayIds) {
    const relay = await ctx.db.get(relayId);
    if (!relay) continue;
    if (relay.origin.kind === 'panel-node' && relay.origin.nodeName === fromOrigin)
      await ctx.db.patch(relayId, {
        origin: { ...relay.origin, nodeName: toOrigin },
        nodeName: toOrigin,
        updatedAt: now,
      });
    for (const l of await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect()) {
      const patch: Partial<Doc<'relayListeners'>> = {};
      if (l.matchRule.kind === 'remark') {
        const next = renamedListenerRemark(l.matchRule.remark, from, to);
        if (next) {
          patch.matchRule = { kind: 'remark', remark: next };
          patch.formerRemarks = [...new Set([...(l.formerRemarks ?? []), l.matchRule.remark])];
        }
      }
      const intended = l.host?.intended;
      const nextIntended = intended ? renamedListenerRemark(intended.remark, from, to) : null;
      if (l.host && intended && nextIntended)
        patch.host = { ...l.host, intended: { ...intended, remark: nextIntended } };
      if (Object.keys(patch).length > 0) await ctx.db.patch(l._id, { ...patch, updatedAt: now });
    }
  }
  for (const name of new Set([from, fromOrigin])) {
    const binding = await ctx.db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) => q.eq('backendServerId', sid).eq('nodeName', name))
      .unique();
    if (binding)
      await ctx.db.patch(binding._id, {
        nodeName: name === from ? to : toOrigin,
        // Part of every render's cache token: nothing rendered under the old
        // name is served under the new one.
        policyVersion: binding.policyVersion + 1,
        updatedAt: now,
      });
    for (const run of await ctx.db
      .query('edgeSetupRuns')
      .withIndex('by_origin', (q) => q.eq('backendServerId', sid).eq('nodeName', name))
      .collect())
      await ctx.db.patch(run._id, { nodeName: name === from ? to : toOrigin, updatedAt: now });
  }

  // Holds on unmanaged nodes, staged port requirements.
  for (const h of await ctx.db
    .query('panelMaintenanceHolds')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect())
    if (h.heldNodeNames.includes(from))
      await ctx.db.patch(h._id, {
        heldNodeNames: h.heldNodeNames.map((n) => (n === from ? to : n)),
        updatedAt: now,
      });
  for (const req of await ctx.db
    .query('panelPortRequirements')
    .withIndex('by_server_node', (q) => q.eq('backendServerId', sid).eq('nodeName', from))
    .collect())
    await ctx.db.patch(req._id, { nodeName: to, updatedAt: now });

  // The node role's token keeps acting for the node under either name.
  for (const t of await ctx.db.query('apiTokens').collect()) {
    const reg = t.edgeRegistration;
    if (!reg?.nodeNames?.includes(from) || reg.nodeNames.includes(to)) continue;
    await ctx.db.patch(t._id, { edgeRegistration: { ...reg, nodeNames: [...reg.nodeNames, to] } });
  }

  // Ownership: the new name is one more identity of the same node.
  for (const o of await ctx.db
    .query('panelOwnership')
    .withIndex('by_server_kind_identity', (q) => q.eq('backendServerId', sid).eq('kind', 'node'))
    .collect())
    if ((o.panelUuid === r.nodeUuid || o.lookup.includes(from)) && !o.lookup.includes(to))
      await ctx.db.patch(o._id, { lookup: [...o.lookup, to], updatedAt: now });

  // The read caches show it at once (the next look rewrites them anyway).
  const cached = await ctx.db
    .query('panelNodes')
    .withIndex('by_server_uuid', (q) => q.eq('backendServerId', sid).eq('nodeUuid', r.nodeUuid))
    .unique();
  if (cached && cached.name !== to) await ctx.db.patch(cached._id, { name: to });
  for (const inv of await ctx.db
    .query('backendNodeInventory')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect())
    if (inv.nodeUuid === r.nodeUuid && inv.name !== to) await ctx.db.patch(inv._id, { name: to });

  await ctx.db.insert('panelNodeAliases', {
    backendServerId: sid,
    formerName: from,
    name: to,
    nodeUuid: r.nodeUuid,
    renameId,
    at: now,
  });
  if (fromOrigin !== from)
    await ctx.db.insert('panelNodeAliases', {
      backendServerId: sid,
      formerName: fromOrigin,
      name: toOrigin,
      nodeUuid: r.nodeUuid,
      renameId,
      at: now,
    });

  // Every render carries the gate version it was made under.
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  if (setup) await ctx.db.patch(setup._id, { gateVersion: setup.gateVersion + 1, updatedAt: now });

  await ctx.db.patch(renameId, { step: 'hosts', opId: undefined, updatedAt: now });
  await ctx.scheduler.runAfter(0, internal.backendNodeRenames.resume, { renameId });
}
