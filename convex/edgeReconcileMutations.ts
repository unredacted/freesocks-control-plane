/**
 * Isolate mutations the reconcile cron needs beyond the row-level ones in
 * relayEdges / relayOrigins: destroy bookkeeping (audited) and the
 * publish-a-standby decision (direct publish, or a `publish` rotation when the
 * free slot is pool index 0 on a Host-managed origin).
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveRelayConfig } from './lib/relayConfig';
import { checkPublishable } from './relays';
import { nextFreePoolIndex, withEdgeAt } from './lib/relays/pool';
import { isTerminalPhase } from './lib/relays/rotation';

export const markDestroyed = internalMutation({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.status === 'destroyed') return null;
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      status: 'destroyed',
      publication: 'unpublished',
      poolIndex: undefined,
      currentOp: undefined,
      resources: edge.resources.map((r) => ({ ...r, deleteState: 'confirmed_gone' as const })),
      destroyedAt: now,
      statusChangedAt: now,
      updatedAt: now,
    });
    const origin = await ctx.db.get(edge.relayId);
    if (origin) {
      const inPool = origin.publishedEdgeIds.includes(edgeId);
      const inStandby = origin.standbyEdgeIds.includes(edgeId);
      if (inPool || inStandby) {
        await ctx.db.patch(origin._id, {
          publishedEdgeIds: origin.publishedEdgeIds.map((e) => (e === edgeId ? null : e)),
          standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
          publicationEpoch: origin.publicationEpoch + 1,
          updatedAt: now,
        });
      }
    }
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.edge.destroyed',
      targetType: 'relay_edge',
      targetId: edgeId,
      payload: { relaySlug: origin?.slug ?? '', provider: edge.provider ?? null, edgeId },
    });
    return null;
  },
});

export const destroyExhausted = internalMutation({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.status !== 'destroying') return null;
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      status: 'needs_operator',
      statusChangedAt: now,
      failure: { step: 'destroy', code: 'destroy_attempts_exhausted' },
      updatedAt: now,
    });
    const origin = await ctx.db.get(edge.relayId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.edge.destroy_failed',
      targetType: 'relay_edge',
      targetId: edgeId,
      payload: {
        relaySlug: origin?.slug ?? '',
        provider: edge.provider ?? null,
        edgeId,
        attempts: edge.destroyAttempts,
      },
    });
    return null;
  },
});

/** Operator: put a parked edge back on the destroy path (resets the attempt counter). */
export const retryDestroy = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return { ok: false as const };
    if (!['needs_operator', 'failed', 'cancelled', 'draining', 'active'].includes(edge.status)) {
      return { ok: false as const };
    }
    if (edge.publication === 'published') return { ok: false as const, code: 'published' as const };
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      status: 'destroying',
      destroyAttempts: 0,
      currentOp: undefined,
      failure: undefined,
      statusChangedAt: now,
      updatedAt: now,
    });
    return { ok: true as const };
  },
});

/**
 * Pool upkeep: publish the first publishable standby. When the free index is 0
 * on a Host-managed origin the Host must flip, so a `publish` rotation is
 * started instead of a direct publish.
 */
export const publishStandby = internalMutation({
  args: { relayId: v.id('relays'), candidates: v.array(v.id('edges')) },
  handler: async (
    ctx,
    { relayId, candidates },
  ): Promise<{ published: boolean; rotationId: Id<'edgeRotations'> | null }> => {
    const origin = await ctx.db.get(relayId);
    if (!origin || origin.quarantine || origin.deleting)
      return { published: false, rotationId: null };
    if (origin.activeRotationId) {
      const active = await ctx.db.get(origin.activeRotationId);
      if (active && !isTerminalPhase(active.phase)) return { published: false, rotationId: null };
    }
    const cfg = await resolveRelayConfig(ctx.db);
    const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
    if (idx === null) return { published: false, rotationId: null };
    for (const edgeId of candidates) {
      const edge = await ctx.db.get(edgeId);
      if (!edge || edge.relayId !== relayId) continue;
      const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
      if (!check.ok) continue;
      if (idx === 0 && origin.hostManaged) {
        // Needs the template-Host flip: hand it to the rotation machine.
        const now = Date.now();
        const rotationId = await ctx.db.insert('edgeRotations', {
          relayId,
          kind: 'publish',
          trigger: 'reconcile',
          burn: false,
          force: false,
          toEdgeId: edgeId,
          phase: 'select',
          stepVersion: 1,
          cancelRequested: false,
          hostPlan: [],
          flipAttempts: 0,
          rollbackAttempts: 0,
          pollAttempts: 0,
          events: [{ at: now, level: 'info', code: 'started', detail: 'publish (reconcile)' }],
          startedAt: now,
          updatedAt: now,
        });
        await ctx.db.patch(relayId, { activeRotationId: rotationId, updatedAt: now });
        await ctx.scheduler.runAfter(0, internal.edgeRotations.step, { rotationId });
        await ctx.db.patch(rotationId, { nextStepAt: now });
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'admin.relay.provision',
          targetType: 'relay',
          targetId: relayId,
          payload: { slug: origin.slug, trigger: 'reconcile' },
        });
        return { published: false, rotationId };
      }
      const now = Date.now();
      const epoch = origin.publicationEpoch + 1;
      await ctx.db.patch(edgeId, {
        publication: 'published',
        poolIndex: idx,
        publishedAt: now,
        updatedAt: now,
      });
      await ctx.db.patch(relayId, {
        publishedEdgeIds: withEdgeAt(origin.publishedEdgeIds, idx, edgeId),
        standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
        publicationEpoch: epoch,
        updatedAt: now,
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.edge.published',
        targetType: 'relay_edge',
        targetId: edgeId,
        payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
      });
      return { published: true, rotationId: null };
    }
    return { published: false, rotationId: null };
  },
});

// The cron reads config through a query so the action has one resolved snapshot.
export const configSnapshot = internalQuery({
  args: {},
  handler: (ctx) => resolveRelayConfig(ctx.db),
});

/** The Node version the "use node" actions run on, for the admin dashboard. */
export const recordRuntime = internalMutation({
  args: { nodeVersion: v.string() },
  handler: async (ctx, { nodeVersion }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', 'relay:runtime'))
      .unique();
    const value = JSON.stringify({ nodeVersion: nodeVersion.slice(0, 32), at: now });
    if (row) await ctx.db.patch(row._id, { value, updatedAt: now });
    else await ctx.db.insert('appState', { key: 'relay:runtime', value, updatedAt: now });
    return null;
  },
});
