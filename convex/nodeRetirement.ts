/**
 * Retiring a node (docs/servers.md "Retirement"). The role's
 * DELETE only records the request; whenever the node was ever live or
 * anything of it is still out there (an origin, Hosts, DNS, credentials, a
 * mirror) the node keeps serving until an admin decides: the disposition
 * `keep-dark` (its members get the edge-required unavailable behaviour; moving
 * them to another node is not offered), or rejecting the request. Never
 * `restore-direct`.
 *
 * An admin's own request is that decision (its confirm says members lose the
 * node at once): it starts draining keep-dark without a second question.
 *
 * The ladder, each step resumable by the sweep (`backend-bootstrap-sweep`,
 * every 5 minutes); `step` records where `draining` stopped last:
 *   requested / needs_admin -> draining      publication withdrawn, the origin
 *                                            deleted keep-dark (`origin`),
 *                                            credentials released
 *                                            (`credentials`), the direct Host
 *                                            deleted (`addresses`), DNS withdrawn
 *                                            (`dns`), mirrors refreshed
 *   draining -> panel_removed                the node row removed with
 *                                            removeOnly (the process may run)
 *   panel_removed -> ready_to_wipe           answered to the role
 *   ready_to_wipe -> retired                 the role's own ack, or an admin's
 *                                            confirmation for an ADOPTED node,
 *                                            whose machine the role never runs
 *                                            (nodeIntents.markWiped)
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { addressTransportsOf, addressesOf, closeForRetirement } from './nodeIntents';
import { runningRenameOf } from './lib/backend/nodeAliases';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Retirement = Doc<'panelRetirements'>;

/** Where `draining` stopped (`panelRetirements.step`). */
const STEP = v.union(
  v.literal('origin'),
  v.literal('credentials'),
  v.literal('addresses'),
  v.literal('dns'),
  v.literal('panel_row'),
);
type Step = 'origin' | 'credentials' | 'addresses' | 'dns' | 'panel_row';

async function event(
  ctx: { db: import('./_generated/server').MutationCtx['db'] },
  r: Retirement,
  patch: Partial<Retirement>,
  code: string,
) {
  const now = Date.now();
  await ctx.db.patch(r._id, {
    ...patch,
    events: [...r.events, { at: now, code }],
    updatedAt: now,
  });
}

/** The admin's decision on a retirement that needs one. */
export const decide = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    disposition: v.literal('keep-dark'),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    // A rename assumes the node, its origin and its addresses stay put until it is done.
    if (
      await runningRenameOf(ctx.db, intent.backendServerId, {
        nodeUuid: intent.nodeUuid,
        name: intent.name,
      })
    )
      refuse(
        'servers.node_rename_running',
        'This node is being renamed. Retire it once that is done',
      );
    let r = intent.retirementId ? await ctx.db.get(intent.retirementId) : null;
    if (!r) {
      const now = Date.now();
      const id = await ctx.db.insert('panelRetirements', {
        backendServerId: intent.backendServerId,
        intentId: intent._id,
        stage: 'requested',
        requestedBy: 'admin',
        events: [{ at: now, code: 'requested' }],
        createdAt: now,
        updatedAt: now,
      });
      r = (await ctx.db.get(id))!;
    }
    if (r.stage !== 'requested' && r.stage !== 'needs_admin')
      refuse('servers.retirement_stage', `The retirement is already ${r.stage}`);
    // A role's request left the node serving until now: members lose it here
    // (and its mirrors are rewritten, once). One closed before has had both.
    if (intent.state !== 'retiring' && intent.state !== 'retired')
      await closeForRetirement(ctx, intent, r._id);
    await event(ctx, r, { disposition: a.disposition, stage: 'draining' }, 'decided');
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.retire_decided',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name, disposition: a.disposition },
    });
    await ctx.scheduler.runAfter(0, internal.nodeRetirement.advance, { retirementId: r._id });
    return { stage: 'draining' as const };
  },
});

/**
 * The admin turns down a retirement the node role asked for. The request
 * changed nothing (the node kept serving while it waited), so nothing is put
 * back: the request is closed as `rejected` and the node is free of it; the
 * role may ask again. A request an earlier release recorded had already closed
 * the node, and is only decided.
 */
export const reject = internalMutation({
  args: { intentId: v.id('panelNodeIntents'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const r = intent.retirementId ? await ctx.db.get(intent.retirementId) : null;
    if (
      !r ||
      r.stage !== 'needs_admin' ||
      intent.state === 'retiring' ||
      intent.state === 'retired'
    )
      refuse(
        'servers.retirement_stage',
        'Only a retirement the node role asked for, still waiting for your decision, can be rejected',
      );
    await event(ctx, r!, { stage: 'rejected' }, 'rejected');
    await ctx.db.patch(intent._id, { retirementId: undefined, updatedAt: Date.now() });
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.retire_rejected',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name },
    });
    return { stage: 'rejected' as const };
  },
});

/**
 * A request that needs no further decision starts draining at once (keep-dark):
 * an admin's own request, whose confirm is the decision whatever the node
 * exposed, or a role's request for a node never live with nothing outstanding.
 * A role's request for anything else waits at `needs_admin` instead.
 */
export const startIfPlain = internalMutation({
  args: { retirementId: v.id('panelRetirements') },
  handler: async (ctx, { retirementId }) => {
    const r = await ctx.db.get(retirementId);
    if (!r || r.stage !== 'requested') return false;
    await event(ctx, r, { disposition: 'keep-dark', stage: 'draining' }, 'plain');
    await ctx.scheduler.runAfter(0, internal.nodeRetirement.advance, { retirementId });
    return true;
  },
});

export const context = internalQuery({
  args: { retirementId: v.id('panelRetirements') },
  handler: async (ctx, { retirementId }) => {
    const r = await ctx.db.get(retirementId);
    if (!r) return null;
    const intent = await ctx.db.get(r.intentId);
    if (!intent) return null;
    const server = await ctx.db.get(intent.backendServerId);
    if (!server) return null;
    const relay = (
      await ctx.db
        .query('relays')
        .withIndex('by_backend_server', (q) => q.eq('backendServerId', intent.backendServerId))
        .collect()
    ).find((x) => x.origin.kind === 'panel-node' && x.origin.nodeName === intent.name);
    const hosts = await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
      .collect();
    // By name while its uuid was never recorded (a create that landed late).
    const node = intent.nodeUuid
      ? await ctx.db
          .query('panelNodes')
          .withIndex('by_server_uuid', (q) =>
            q.eq('backendServerId', intent.backendServerId).eq('nodeUuid', intent.nodeUuid!),
          )
          .unique()
      : ((
          await ctx.db
            .query('panelNodes')
            .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
            .collect()
        ).find((n) => n.name === intent.name) ?? null);
    // Backend writes for the node still open that this retirement did not
    // make: an attempt sent them before the retirement, and what they make is
    // the node's (a Host, the row itself).
    const openOps = (
      await ctx.db
        .query('panelOps')
        .withIndex('by_open', (q) =>
          q.eq('open', true).eq('backendServerId', intent.backendServerId),
        )
        .collect()
    ).filter(
      (o) =>
        o.actorRun !== `retirement:${r._id}` &&
        (o.actorRun === `node:${intent._id}` ||
          (o.kind === 'node' &&
            (o.identity === intent.name ||
              (!!intent.nodeUuid && o.objectUuid === intent.nodeUuid)))),
    ).length;
    return {
      r,
      intent,
      server: { _id: server._id, slug: server.slug },
      relay: relay ? { _id: relay._id, deleting: !!relay.deleting } : null,
      // A direct node's own addresses (one per family name): recorded, or
      // under FCP's remark on its own transport.
      addresses: addressesOf(
        intent,
        hosts,
        (await addressTransportsOf(ctx, intent.backendServerId))(intent),
      ),
      node,
      openOps,
    };
  },
});

export const mark = internalMutation({
  args: {
    retirementId: v.id('panelRetirements'),
    stage: v.optional(
      v.union(v.literal('draining'), v.literal('panel_removed'), v.literal('ready_to_wipe')),
    ),
    code: v.optional(v.union(v.string(), v.null())),
    step: v.optional(STEP),
    tombstone: v.optional(v.boolean()),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.retirementId);
    if (!r) return null;
    const patch = {
      ...(a.stage ? { stage: a.stage } : {}),
      code: a.code ?? undefined,
      ...(a.step ? { step: a.step } : {}),
    };
    const code = a.code ?? a.stage ?? 'step';
    // The sweep stops on the same thing every 5 minutes while it waits: one
    // event for the wait (its `at` is when the wait began), not one per pass.
    const last = r.events[r.events.length - 1];
    if (!a.stage && !a.tombstone && last?.code === code && r.step === (a.step ?? r.step))
      await ctx.db.patch(r._id, { ...patch, updatedAt: Date.now() });
    else await event(ctx, r, patch, code);
    if (a.tombstone) {
      const intent = await ctx.db.get(r.intentId);
      if (intent) {
        // By any identity the node ever had: a renamed node keeps one row.
        const existing = (
          await ctx.db
            .query('panelOwnership')
            .withIndex('by_server_kind_identity', (q) =>
              q.eq('backendServerId', intent.backendServerId).eq('kind', 'node'),
            )
            .collect()
        ).find(
          (o) =>
            o.identity === intent.name ||
            o.lookup.includes(intent.name) ||
            (!!intent.nodeUuid && o.panelUuid === intent.nodeUuid),
        );
        const now = Date.now();
        if (existing)
          await ctx.db.patch(existing._id, {
            state: 'tombstoned',
            panelUuid: intent.nodeUuid,
            updatedAt: now,
          });
        else
          await ctx.db.insert('panelOwnership', {
            backendServerId: intent.backendServerId,
            kind: 'node',
            identity: intent.name,
            lookup: [intent.name, ...(intent.nodeUuid ? [intent.nodeUuid] : [])],
            panelUuid: intent.nodeUuid,
            state: 'tombstoned',
            since: now,
            updatedAt: now,
          });
        await ctx.db.patch(intent._id, {
          delivery: {
            ...intent.delivery,
            exposure: {
              ...intent.delivery.exposure,
              hosts: [],
              relayId: undefined,
              dns: 0,
              testCredentials: 0,
            },
          },
          updatedAt: now,
        });
      }
    }
    return null;
  },
});

/**
 * One pass of the ladder from `draining`; stops at the first thing not yet
 * settled and records why; the sweep calls it again. Every external step is
 * idempotent: an origin already gone, a Host already deleted, a record already
 * withdrawn each count as done.
 */
export const advance = internalAction({
  args: { retirementId: v.id('panelRetirements') },
  handler: async (ctx, { retirementId }): Promise<null> => {
    const c = await ctx.runQuery(internal.nodeRetirement.context, { retirementId });
    if (!c || c.r.stage !== 'draining') return null;
    const sid = c.intent.backendServerId;
    let step: Step = 'origin';
    const stop = (code: string) =>
      ctx.runMutation(internal.nodeRetirement.mark, { retirementId, code, step });
    try {
      // 1. The origin and its edges (publication withdrawn by the delete; edges destroyed by reconcile).
      if (c.relay) {
        if (!c.relay.deleting) {
          await ctx.runMutation(internal.relays.requestDelete, {
            id: c.relay._id,
            disposition: 'keep-dark',
            force: true,
          });
          await ctx.runMutation(internal.edgeTestCredentials.releaseForRelay, {
            relayId: c.relay._id,
          });
        }
        // Requested or already under way: the row is `deleting` until edge
        // reconcile has destroyed the edges and finalized it. Nothing below
        // runs while anything of the node is still out there; next pass.
        await stop('servers.relay_draining');
        return null;
      }
      // 2. The node's own test credentials.
      step = 'credentials';
      const released = await ctx.runMutation(internal.edgeTestCredentials.releaseForIntent, {
        nodeIntentId: c.intent._id,
      });
      if (released.outstanding > 0) {
        // The sweep removes them; the ladder waits so nothing of the node outlives it.
        await stop('servers.credentials_pending');
        return null;
      }
      // 3. The node's own addresses. A write an attempt of the node sent
      //    before the retirement settles first: what it made is removed here
      //    and at the backend row.
      step = 'addresses';
      if (c.openOps > 0) {
        await stop('servers.op_running');
        return null;
      }
      for (const h of c.addresses) {
        const { opId } = await ctx.runMutation(internal.backendWrites.requestAddressDelete, {
          backendServerId: sid,
          hostUuid: h.hostUuid,
          actorRun: `retirement:${retirementId}`,
        });
        const r = await ctx.runAction(internal.backendWrites.run, { opId });
        if (r.open) {
          await stop('servers.op_running');
          return null;
        }
      }
      // 4. Origin DNS.
      step = 'dns';
      const dns = await ctx.runAction(internal.nodeIntentOps.withdrawOriginDns, {
        intentId: c.intent._id,
      });
      if (dns.unresolved > 0) {
        await stop('servers.obligation_unresolved');
        return null;
      }
      // 5. The backend row: removed with removeOnly (the role stops the process after).
      step = 'panel_row';
      await ctx.runAction(internal.backendObserve.refresh, { backendServerId: sid });
      const fresh = await ctx.runQuery(internal.nodeRetirement.context, { retirementId });
      if (fresh?.node) {
        const { opId } = await ctx.runMutation(internal.backendWrites.requestNodeDelete, {
          backendServerId: sid,
          nodeUuid: fresh.node.nodeUuid,
          removeOnly: true,
          actorRun: `retirement:${retirementId}`,
        });
        const r = await ctx.runAction(internal.backendWrites.run, { opId });
        if (r.open) {
          await stop('servers.op_running');
          return null;
        }
      }
      await ctx.runMutation(internal.nodeRetirement.mark, {
        retirementId,
        stage: 'panel_removed',
        code: null,
        tombstone: true,
      });
      await ctx.runMutation(internal.nodeRetirement.mark, {
        retirementId,
        stage: 'ready_to_wipe',
        code: null,
      });
      return null;
    } catch (err) {
      const code =
        err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
          ? (err.data as { code: string }).code
          : 'servers.retirement_failed';
      await stop(code);
      return null;
    }
  },
});

/** Retirements the sweep should push along. */
export const pending = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await ctx.db.query('panelRetirements').collect())
      .filter((r) => r.stage === 'draining' || r.stage === 'requested')
      .map((r) => ({ id: r._id, stage: r.stage })),
});

export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<number> => {
    const rows = await ctx.runQuery(internal.nodeRetirement.pending, {});
    let n = 0;
    for (const r of rows) {
      if (r.stage === 'requested')
        await ctx.runMutation(internal.nodeRetirement.startIfPlain, { retirementId: r.id });
      else await ctx.runAction(internal.nodeRetirement.advance, { retirementId: r.id });
      n++;
    }
    return n;
  },
});

export type { Id };
