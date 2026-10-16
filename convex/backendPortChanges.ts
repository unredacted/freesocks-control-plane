/**
 * Port changes and the firewall acknowledgement (docs/servers.md "Firewall
 * acknowledgement"). Moving a transport to another port makes every node that
 * serves it listen there at once (the backend re-applies the profile in
 * seconds, measured), and a node whose firewall drops the port then serves
 * nobody. So a port change is STAGED, not sent:
 *
 *  1. `stage` records the previewed edit and one requirement per node that will
 *     listen on the port. An enrolled node the role runs is confirmed by the
 *     role's applied report (`confirmFromRole`); any other node (unmanaged, or
 *     adopted, whose machine no role runs) by an admin (`acknowledge`).
 *     Nothing is claimed and nothing is sent; members keep the old port.
 *  2. When the last requirement is confirmed, `apply` admits the edit through
 *     the ledger (`claimProfilePatch`, owned by this change): the maintenance
 *     transition closes the nodes, then the one attempt is sent and looked at.
 *     A node that started serving the transport meanwhile gets a requirement
 *     of its own first: the edit waits for it.
 *  3. The change's outcome is its op's. A busy profile (another change still
 *     running) leaves it waiting; `sweep` (backend-reconcile) tries again.
 *
 * The only writer of `panelPortChanges` and `panelPortRequirements`.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { PatchRefused, checkPatchOps, type PatchOp } from './lib/backend/patchOps';
import { assertWritable, mapOp } from './backendLedger';
import { claimProfilePatch, portChangeImpact } from './backendWrites';
import { patchOp } from './lib/backend/patchOpArgs';
import { firewallPortsFor, requirementsOf, wakeIfReady } from './lib/backend/portRequirements';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Change = Doc<'panelPortChanges'>;
type Requirement = Doc<'panelPortRequirements'>;

/** Refusals of the claim that clear by themselves: the change keeps waiting and is tried again. */
const WAIT_CODES = new Set([
  'servers.op_running',
  'servers.op_uncertain',
  'servers.manage_disabled',
]);

function codeOf(err: unknown): string | null {
  return err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
    ? (err.data as { code: string }).code
    : null;
}

async function audit(
  ctx: MutationCtx,
  change: Change,
  action: string,
  payload: Record<string, unknown>,
  actorAdminId?: Id<'adminUsers'>,
) {
  const server = await ctx.db.get(change.backendServerId);
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId,
    action,
    targetType: 'panel_port_change',
    targetId: change._id,
    payload: { backendSlug: server?.slug ?? '', label: change.profileName, ...payload },
  });
}

// --- stage ------------------------------------------------------------------------------------------

/**
 * Stage a previewed port change. Refused when the transport cannot move here
 * (loopback, fronted by an origin, a port a node already uses), when another
 * port change of this profile is still open, and when nodes FCP does not
 * manage run the transport but no treatment was chosen for them (the same rule
 * as every shared change: `hold` or `acknowledge`).
 */
export const stage = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    profileUuid: v.string(),
    ops: v.array(patchOp),
    baseToken: v.string(),
    expectedToken: v.string(),
    inboundUuids: v.record(v.string(), v.string()),
    unmanaged: v.optional(v.union(v.literal('hold'), v.literal('acknowledge'))),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    await assertWritable(ctx, sid);
    let ops: PatchOp[];
    try {
      ops = checkPatchOps(a.ops as PatchOp[]);
    } catch (e) {
      if (e instanceof PatchRefused) return refuse(e.code, e.message);
      throw e;
    }
    const op = ops[0];
    if (ops.length !== 1 || op?.op !== 'setInboundPort')
      return refuse('validation', 'Only a port change is staged');
    if (a.baseToken === a.expectedToken) refuse('validation', 'Nothing to change');
    const profile = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server_uuid', (q) =>
        q.eq('backendServerId', sid).eq('profileUuid', a.profileUuid),
      )
      .unique();
    if (!profile)
      return refuse('not_found', 'That profile is not on this backend. Refresh and retry');
    const inboundUuid = a.inboundUuids[op.inboundTag];
    if (!inboundUuid)
      return refuse('servers.unknown_inbound', `No inbound is tagged ${op.inboundTag}`);
    let open = false;
    for (const c of await ctx.db
      .query('panelPortChanges')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect())
      if (c.profileUuid === a.profileUuid && (await isOpen(ctx, c))) open = true;
    if (open)
      refuse(
        'servers.port_change_waiting',
        'A port change of this profile is still waiting. Finish or cancel it first',
      );
    const impact = await portChangeImpact(ctx, sid, a.profileUuid, inboundUuid, op.port);
    const intents = await ctx.db
      .query('panelNodeIntents')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const unmanaged = impact.nodes.filter((n) => !intents.some((i) => i.name === n.name));
    if (unmanaged.length > 0 && !a.unmanaged)
      refuse(
        'servers.unmanaged_nodes_affected',
        `Nodes FCP does not manage run this too: ${unmanaged.map((n) => n.name).join(', ')}. Hold them closed or acknowledge`,
      );
    const now = Date.now();
    const changeId = await ctx.db.insert('panelPortChanges', {
      backendServerId: sid,
      profileUuid: a.profileUuid,
      profileName: profile.name,
      inboundTag: op.inboundTag,
      inboundUuid,
      fromPort: impact.fromPort ?? undefined,
      toPort: op.port,
      ops: JSON.stringify(ops),
      baseToken: a.baseToken,
      expectedToken: a.expectedToken,
      inboundUuids: a.inboundUuids,
      unmanaged: a.unmanaged,
      state: 'waiting',
      actorAdminId: a.actorAdminId,
      createdAt: now,
      updatedAt: now,
    });
    for (const n of impact.nodes)
      await ctx.db.insert('panelPortRequirements', {
        backendServerId: sid,
        changeId,
        nodeName: n.name,
        intentId: n.intentId,
        port: op.port,
        confirmedBy: n.confirmedBy,
        state: 'waiting',
        createdAt: now,
        updatedAt: now,
      });
    const change = (await ctx.db.get(changeId))!;
    await audit(
      ctx,
      change,
      'servers.port_change.staged',
      { port: op.port, nodes: impact.nodes.length },
      a.actorAdminId,
    );
    // No node listens there yet: nothing to wait for.
    if (impact.nodes.length === 0)
      await ctx.scheduler.runAfter(0, internal.backendPortChanges.apply, { changeId });
    return { changeId };
  },
});

/** A change still holds the profile's port-change slot: waiting, or claimed with its op open. */
async function isOpen(ctx: { db: QueryCtx['db'] }, c: Change): Promise<boolean> {
  if (c.state === 'waiting') return true;
  if (c.state !== 'applying' || !c.opId) return false;
  const op = await ctx.db.get(c.opId);
  return !!op?.open;
}

// --- confirmations --------------------------------------------------------------------------------

/**
 * An admin confirms, by name, that the firewall of nodes no role reports for
 * (unmanaged or adopted) lets the port in. A node the role confirms is not an
 * admin's to tick: the role's report is the evidence.
 */
export const acknowledge = internalMutation({
  args: {
    changeId: v.id('panelPortChanges'),
    nodeNames: v.array(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { changeId, nodeNames, actorAdminId }) => {
    const change = await ctx.db.get(changeId);
    if (!change) return refuse('not_found', 'No such port change');
    if (change.state !== 'waiting')
      refuse('servers.port_change_not_waiting', 'This port change is not waiting any more');
    const rows = await requirementsOf(ctx, changeId);
    const now = Date.now();
    let confirmed = 0;
    for (const name of new Set(nodeNames)) {
      const r = rows.find((x) => x.nodeName === name && x.state !== 'cancelled');
      if (!r) return refuse('not_found', `${name} does not wait for this port change`);
      if (r.confirmedBy === 'role')
        refuse(
          'servers.firewall_role_confirms',
          `The node role confirms ${name} itself, when it has opened the port`,
        );
      if (r.state === 'confirmed') continue;
      await ctx.db.patch(r._id, {
        state: 'confirmed',
        confirmedAt: now,
        byAdminId: actorAdminId,
        updatedAt: now,
      });
      confirmed++;
    }
    if (confirmed > 0)
      await audit(
        ctx,
        change,
        'servers.port_change.confirmed',
        { by: 'operator', nodes: confirmed, port: change.toPort },
        actorAdminId,
      );
    await wakeIfReady(ctx, changeId);
    return { confirmed };
  },
});

/** Withdraw a change that is still waiting. Nothing was sent; nodes that opened the port keep it open. */
export const cancel = internalMutation({
  args: { changeId: v.id('panelPortChanges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { changeId, actorAdminId }) => {
    const change = await ctx.db.get(changeId);
    if (!change) return refuse('not_found', 'No such port change');
    if (change.state === 'cancelled') return { ok: true as const };
    if (change.state !== 'waiting')
      refuse('servers.port_change_not_waiting', 'This port change is not waiting any more');
    const now = Date.now();
    await ctx.db.patch(changeId, { state: 'cancelled', updatedAt: now });
    for (const r of await requirementsOf(ctx, changeId))
      if (r.state === 'waiting') await ctx.db.patch(r._id, { state: 'cancelled', updatedAt: now });
    await audit(ctx, change, 'servers.port_change.cancelled', {}, actorAdminId);
    return { ok: true as const };
  },
});

// --- apply ------------------------------------------------------------------------------------------

/**
 * Admit a fully confirmed change through the ledger, in ONE transaction with
 * its own state. A node that serves the transport now but has no requirement
 * yet (it was assigned meanwhile) gets one, and the change keeps waiting.
 */
export const admit = internalMutation({
  args: { changeId: v.id('panelPortChanges') },
  handler: async (
    ctx,
    { changeId },
  ): Promise<{ opId: Id<'panelOps'> | null; code: string | null }> => {
    const change = await ctx.db.get(changeId);
    if (!change || change.state !== 'waiting') return { opId: null, code: null };
    const now = Date.now();
    const rows = await requirementsOf(ctx, changeId);
    let impact: Awaited<ReturnType<typeof portChangeImpact>>;
    try {
      impact = await portChangeImpact(
        ctx,
        change.backendServerId,
        change.profileUuid,
        change.inboundUuid,
        change.toPort,
      );
    } catch (err) {
      const code = codeOf(err);
      if (!code) throw err;
      await ctx.db.patch(changeId, { state: 'refused', code, updatedAt: now });
      await audit(ctx, change, 'servers.port_change.admitted', { outcome: 'refused', code });
      return { opId: null, code };
    }
    let added = 0;
    for (const n of impact.nodes) {
      if (rows.some((r) => r.nodeName === n.name && r.state !== 'cancelled')) continue;
      await ctx.db.insert('panelPortRequirements', {
        backendServerId: change.backendServerId,
        changeId,
        nodeName: n.name,
        intentId: n.intentId,
        port: change.toPort,
        confirmedBy: n.confirmedBy,
        state: 'waiting',
        createdAt: now,
        updatedAt: now,
      });
      added++;
    }
    if (added > 0 || rows.some((r) => r.state === 'waiting')) {
      await ctx.db.patch(changeId, { code: 'servers.firewall_unconfirmed', updatedAt: now });
      return { opId: null, code: 'servers.firewall_unconfirmed' };
    }
    try {
      const { opId } = await claimProfilePatch(ctx, {
        backendServerId: change.backendServerId,
        profileUuid: change.profileUuid,
        ops: JSON.parse(change.ops) as PatchOp[],
        baseToken: change.baseToken,
        expectedToken: change.expectedToken,
        inboundUuids: change.inboundUuids,
        unmanaged: change.unmanaged,
        portChangeId: changeId,
        actorAdminId: change.actorAdminId,
      });
      await ctx.db.patch(changeId, { state: 'applying', opId, code: undefined, updatedAt: now });
      await audit(ctx, change, 'servers.port_change.admitted', { outcome: 'claimed' });
      return { opId, code: null };
    } catch (err) {
      const code = codeOf(err);
      if (!code) throw err;
      // A claim that fails throws before anything of it is written; the change
      // records why and either waits (it clears by itself) or stops.
      if (WAIT_CODES.has(code)) {
        await ctx.db.patch(changeId, { code, updatedAt: now });
        return { opId: null, code };
      }
      await ctx.db.patch(changeId, { state: 'refused', code, updatedAt: now });
      await audit(ctx, change, 'servers.port_change.admitted', { outcome: 'refused', code });
      return { opId: null, code };
    }
  },
});

/** Admit and send. Safe to call again: a second call finds the change no longer waiting. */
export const apply = internalAction({
  args: { changeId: v.id('panelPortChanges') },
  handler: async (ctx, { changeId }): Promise<{ opId: Id<'panelOps'> | null; open: boolean }> => {
    const { opId } = await ctx.runMutation(internal.backendPortChanges.admit, { changeId });
    if (!opId) return { opId: null, open: false };
    const { open } = await ctx.runAction(internal.backendWrites.run, { opId });
    return { opId, open };
  },
});

/** Changes whose every requirement is confirmed but that still wait (a busy profile, a lost wake). */
export const ready = internalQuery({
  args: {},
  handler: async (ctx) => {
    const waiting = await ctx.db
      .query('panelPortChanges')
      .withIndex('by_state', (q) => q.eq('state', 'waiting'))
      .take(50);
    const out: Id<'panelPortChanges'>[] = [];
    for (const c of waiting)
      if ((await requirementsOf(ctx, c._id)).every((r) => r.state !== 'waiting')) out.push(c._id);
    return out;
  },
});

/** On `backend-reconcile`: try again what waits only on a busy profile. */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<number> => {
    const ids = await ctx.runQuery(internal.backendPortChanges.ready, {});
    for (const changeId of ids)
      await ctx.runAction(internal.backendPortChanges.apply, { changeId });
    return ids.length;
  },
});

// --- views ------------------------------------------------------------------------------------------

async function viewOf(ctx: { db: QueryCtx['db'] }, c: Change) {
  const op = c.opId ? await ctx.db.get(c.opId) : null;
  const rows: Requirement[] = await requirementsOf(ctx, c._id);
  // A claimed change is what its op is: still open, refused before any change, or done.
  const state =
    c.state !== 'applying'
      ? c.state
      : !op || op.open
        ? 'applying'
        : op.request === 'rejected_pre_mutation'
          ? 'refused'
          : 'applied';
  return {
    id: c._id as string,
    profileUuid: c.profileUuid,
    profileName: c.profileName,
    transportTag: c.inboundTag,
    fromPort: c.fromPort ?? null,
    toPort: c.toPort,
    state,
    code: state === 'refused' && op ? (op.errorCode ?? c.code ?? null) : (c.code ?? null),
    op: op ? mapOp(op) : null,
    nodes: rows.map((r) => ({
      name: r.nodeName,
      confirmedBy: r.confirmedBy,
      state: r.state,
      confirmedAt: r.confirmedAt ? new Date(r.confirmedAt).toISOString() : null,
    })),
    createdAt: new Date(c.createdAt).toISOString(),
    updatedAt: new Date(c.updatedAt).toISOString(),
  };
}

export type PortChangeRow = Awaited<ReturnType<typeof viewOf>>;

/** The open changes of an instance and the last few settled ones, newest first. */
export const listForServer = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const rows = await ctx.db
      .query('panelPortChanges')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .order('desc')
      .take(20);
    return Promise.all(rows.map((c) => viewOf(ctx, c)));
  },
});

export const view = internalQuery({
  args: { changeId: v.id('panelPortChanges') },
  handler: async (ctx, { changeId }) => {
    const c = await ctx.db.get(changeId);
    if (!c) return refuse('not_found', 'No such port change');
    return viewOf(ctx, c);
  },
});

/** The change must belong to the backend the path names. */
export const onServer = internalQuery({
  args: { backendServerId: v.id('backendServers'), changeId: v.string() },
  handler: async (ctx, { backendServerId, changeId }) => {
    const id = ctx.db.normalizeId('panelPortChanges', changeId);
    const c = id ? await ctx.db.get(id) : null;
    return c && c.backendServerId === backendServerId ? c._id : null;
  },
});

export const firewallForIntent = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    return intent ? firewallPortsFor(ctx, intent) : [];
  },
});
