/**
 * Isolate mutations the reconcile cron needs beyond the row-level ones in
 * edges / relays: destroy bookkeeping (audited) and the
 * publish-a-standby decision (direct publish, or a `publish` rotation when the
 * free slot is pool index 0 on a Host-managed origin).
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import {
  assertNoRotationOrQuarantine,
  checkPublishable,
  dropEdgeFromPool,
  scheduleMirrorRefresh,
} from './relays';
import { destroyedPatch } from './edges';
import { nextFreePoolIndex, withEdgeAt } from './lib/edges/pool';
import { startRotation } from './edgeRotations';

export const markDestroyed = internalMutation({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.status === 'destroyed') return null;
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      ...destroyedPatch(now),
      resources: edge.resources.map((r) => ({ ...r, deleteState: 'confirmed_gone' as const })),
    });
    const origin = await ctx.db.get(edge.relayId);
    if (origin) await dropEdgeFromPool(ctx, origin, edge, { reason: 'destroyed' });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.destroyed',
      targetType: 'edge',
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
      action: 'edge.destroy_failed',
      targetType: 'edge',
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

/**
 * Operator: put a parked edge back on the destroy path (resets the attempt
 * counter). Refusals are ConvexErrors so the HTTP layer answers an error, never
 * a 200 with `ok:false`.
 */
export const retryDestroy = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if (!['needs_operator', 'failed', 'cancelled', 'draining', 'active'].includes(edge.status)) {
      throw new ConvexError({
        code: 'edge.not_destroyable',
        message: `An edge in status ${edge.status} cannot be sent to the destroy path`,
      });
    }
    if (edge.publication === 'published')
      throw new ConvexError({ code: 'edge.published', message: 'Unpublish the edge first' });
    const origin = await ctx.db.get(edge.relayId);
    if (origin) await assertNoRotationOrQuarantine(ctx.db, origin);
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      status: 'destroying',
      destroyAttempts: 0,
      destroyConfirm: undefined,
      currentOp: undefined,
      failure: undefined,
      statusChangedAt: now,
      updatedAt: now,
    });
    if (origin) {
      await ctx.db.patch(origin._id, {
        standbyEdgeIds: origin.standbyEdgeIds.filter((x) => x !== edgeId),
        updatedAt: now,
      });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.retry_destroy',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin?.slug ?? '', edgeId, provider: edge.provider ?? null },
    });
    return { ok: true as const };
  },
});

/**
 * Pool upkeep: publish the first publishable standby. When the free index is 0
 * on a Host-managed origin the Host must flip, so a `publish` rotation is
 * started — through `startRotation`, so every start guard (quarantine, one run
 * per origin, the global concurrency cap, publishability) applies and the run
 * is audited like an operator's. Gated by `edge.enabled` in the cron.
 */
export const publishStandby = internalMutation({
  args: { relayId: v.id('relays'), candidates: v.array(v.id('edges')) },
  handler: async (
    ctx,
    { relayId, candidates },
  ): Promise<{ published: boolean; rotationId: Id<'edgeRotations'> | null }> => {
    const origin = await ctx.db.get(relayId);
    if (!origin || origin.deleting) return { published: false, rotationId: null };
    try {
      await assertNoRotationOrQuarantine(ctx.db, origin);
    } catch {
      return { published: false, rotationId: null };
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
    if (idx === null) return { published: false, rotationId: null };
    for (const edgeId of candidates) {
      const edge = await ctx.db.get(edgeId);
      if (!edge || edge.relayId !== relayId) continue;
      const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
      if (!check.ok) continue;
      if (idx === 0 && origin.hostManaged) {
        // Needs the template-Host flip: hand it to the rotation machine.
        try {
          const { rotationId } = await startRotation(ctx, {
            relayId,
            kind: 'publish',
            trigger: 'reconcile',
            toEdgeId: edgeId,
          });
          return { published: false, rotationId };
        } catch (err) {
          // Concurrency cap / a guard the pre-check missed: try again next tick.
          if (err instanceof ConvexError) return { published: false, rotationId: null };
          throw err;
        }
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
        action: 'edge.published',
        targetType: 'edge',
        targetId: edgeId,
        payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
      });
      await scheduleMirrorRefresh(ctx);
      return { published: true, rotationId: null };
    }
    return { published: false, rotationId: null };
  },
});

// The cron reads config through a query so the action has one resolved snapshot.
export const configSnapshot = internalQuery({
  args: {},
  handler: (ctx) => resolveEdgeConfig(ctx.db),
});

/** The Node version the "use node" actions run on, for the admin dashboard. */
export const recordRuntime = internalMutation({
  args: { nodeVersion: v.string() },
  handler: async (ctx, { nodeVersion }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', 'edge:runtime'))
      .unique();
    const value = JSON.stringify({ nodeVersion: nodeVersion.slice(0, 32), at: now });
    if (row) await ctx.db.patch(row._id, { value, updatedAt: now });
    else await ctx.db.insert('appState', { key: 'edge:runtime', value, updatedAt: now });
    return null;
  },
});
