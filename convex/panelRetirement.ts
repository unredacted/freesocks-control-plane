/**
 * Retiring a node (docs/servers.md "Retirement and migration"). The role's
 * DELETE only records the request; whenever the node was ever live or
 * anything of it is still out there (a relay, Hosts, DNS, credentials, a
 * mirror) an admin decides the disposition: `keep-dark` (its members get the
 * edge-required unavailable behaviour) or `migrate` (an explicitly named
 * target). Never `restore-direct`.
 *
 * The ladder, each step resumable by the sweep:
 *   requested / needs_admin -> draining      publication withdrawn, the relay
 *                                            deleted keep-dark, credentials
 *                                            released, the direct Host deleted,
 *                                            DNS withdrawn, mirrors refreshed
 *   draining -> panel_removed                the node row removed with
 *                                            removeOnly (the process may run)
 *   panel_removed -> ready_to_wipe           answered to the role
 *   ready_to_wipe -> wiped -> retired        the role's own ack (panelIntents.markWiped)
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { bumpGateVersion } from './panelSetup';
import { scheduleMirrorRefresh } from './relays';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

type Retirement = Doc<'panelRetirements'>;

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
    disposition: v.union(v.literal('keep-dark'), v.literal('migrate')),
    targetIntentId: v.optional(v.id('panelNodeIntents')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
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
      await ctx.db.patch(intent._id, {
        retirementId: id,
        state: 'retiring',
        delivery: { ...intent.delivery, disposition: 'retiring', acceptingAssignments: false },
        updatedAt: now,
      });
      await bumpGateVersion(ctx, intent.backendServerId);
      r = (await ctx.db.get(id))!;
    }
    if (r.stage !== 'requested' && r.stage !== 'needs_admin')
      refuse('servers.retirement_stage', `The retirement is already ${r.stage}`);
    if (a.disposition === 'migrate') {
      if (!a.targetIntentId) refuse('validation', 'A migration needs a target node');
      const target = await ctx.db.get(a.targetIntentId!);
      if (!target || target.delivery.disposition !== 'live')
        refuse('servers.migration_target', 'The target node must be live');
      refuse(
        'servers.migration_not_built',
        'Migration is not available in this version; choose keep-dark',
      );
    }
    await event(ctx, r, { disposition: a.disposition, stage: 'draining' }, 'decided');
    await scheduleMirrorRefresh(ctx);
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.retire_decided',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name, disposition: a.disposition },
    });
    await ctx.scheduler.runAfter(0, internal.panelRetirement.advance, { retirementId: r._id });
    return { stage: 'draining' as const };
  },
});

/** A request that needs no decision (never live, nothing outstanding) starts draining at once. */
export const startIfPlain = internalMutation({
  args: { retirementId: v.id('panelRetirements') },
  handler: async (ctx, { retirementId }) => {
    const r = await ctx.db.get(retirementId);
    if (!r || r.stage !== 'requested') return false;
    await event(ctx, r, { disposition: 'keep-dark', stage: 'draining' }, 'plain');
    await ctx.scheduler.runAfter(0, internal.panelRetirement.advance, { retirementId });
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
    const node = intent.nodeUuid
      ? await ctx.db
          .query('panelNodes')
          .withIndex('by_server_uuid', (q) =>
            q.eq('backendServerId', intent.backendServerId).eq('nodeUuid', intent.nodeUuid!),
          )
          .unique()
      : null;
    return {
      r,
      intent,
      server: { _id: server._id, slug: server.slug },
      relay: relay ? { _id: relay._id, deleting: !!relay.deleting } : null,
      directHost: hosts.find((h) => h.remark === `${intent.name}-reality`) ?? null,
      node,
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
    tombstone: v.optional(v.boolean()),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.retirementId);
    if (!r) return null;
    await event(
      ctx,
      r,
      { ...(a.stage ? { stage: a.stage } : {}), code: a.code ?? undefined },
      a.code ?? a.stage ?? 'step',
    );
    if (a.tombstone) {
      const intent = await ctx.db.get(r.intentId);
      if (intent) {
        const existing = (
          await ctx.db
            .query('panelOwnership')
            .withIndex('by_server_kind_identity', (q) =>
              q
                .eq('backendServerId', intent.backendServerId)
                .eq('kind', 'node')
                .eq('identity', intent.name),
            )
            .collect()
        )[0];
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
 * idempotent: a relay already gone, a Host already deleted, a record already
 * withdrawn each count as done.
 */
export const advance = internalAction({
  args: { retirementId: v.id('panelRetirements') },
  handler: async (ctx, { retirementId }): Promise<null> => {
    const c = await ctx.runQuery(internal.panelRetirement.context, { retirementId });
    if (!c || c.r.stage !== 'draining') return null;
    const sid = c.intent.backendServerId;
    const stop = (code: string) =>
      ctx.runMutation(internal.panelRetirement.mark, { retirementId, code });
    try {
      // 1. The relay and its edges (publication withdrawn by the delete; edges destroyed by reconcile).
      if (c.relay && !c.relay.deleting) {
        await ctx.runMutation(internal.relays.requestDelete, {
          id: c.relay._id,
          disposition: 'keep-dark',
          force: true,
        });
        await ctx.runMutation(internal.edgeTestCredentials.releaseForRelay, {
          relayId: c.relay._id,
        });
      }
      if (c.relay?.deleting) {
        await stop('servers.relay_draining');
        return null;
      }
      // 2. The node's own test credentials.
      const released = await ctx.runMutation(internal.edgeTestCredentials.releaseForIntent, {
        nodeIntentId: c.intent._id,
      });
      if (released.outstanding > 0) {
        // The sweep removes them; the ladder waits so nothing of the node outlives it.
        await stop('servers.credentials_pending');
        return null;
      }
      // 3. The direct Host.
      if (c.directHost) {
        const { opId } = await ctx.runMutation(internal.panelWrites.requestHostDelete, {
          backendServerId: sid,
          hostUuid: c.directHost.hostUuid,
        });
        const r = await ctx.runAction(internal.panelWrites.run, { opId });
        if (r.open) {
          await stop('servers.op_running');
          return null;
        }
      }
      // 4. Origin DNS.
      const dns = await ctx.runAction(internal.panelIntentOps.withdrawOriginDns, {
        intentId: c.intent._id,
      });
      if (dns.unresolved > 0) {
        await stop('servers.obligation_unresolved');
        return null;
      }
      // 5. The panel row: removed with removeOnly (the role stops the process after).
      await ctx.runAction(internal.panelObserve.refresh, { backendServerId: sid });
      const fresh = await ctx.runQuery(internal.panelRetirement.context, { retirementId });
      if (fresh?.node) {
        const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeDelete, {
          backendServerId: sid,
          nodeUuid: fresh.node.nodeUuid,
          removeOnly: true,
        });
        const r = await ctx.runAction(internal.panelWrites.run, { opId });
        if (r.open) {
          await stop('servers.op_running');
          return null;
        }
      }
      await ctx.runMutation(internal.panelRetirement.mark, {
        retirementId,
        stage: 'panel_removed',
        code: null,
        tombstone: true,
      });
      await ctx.runMutation(internal.panelRetirement.mark, {
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
    const rows = await ctx.runQuery(internal.panelRetirement.pending, {});
    let n = 0;
    for (const r of rows) {
      if (r.stage === 'requested')
        await ctx.runMutation(internal.panelRetirement.startIfPlain, { retirementId: r.id });
      else await ctx.runAction(internal.panelRetirement.advance, { retirementId: r.id });
      n++;
    }
    return n;
  },
});

export type { Id };
