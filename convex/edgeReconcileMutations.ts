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
  refreshTemplateEdges,
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
 * Persist one step of a SHARED-resource teardown (an adopted domain on a
 * service FCP does not own). The known columns live on `edges.sharedTeardown`
 * so reconcile and the lock key can read them without parsing; the driver's own
 * extra fields ride along as JSON in `edges.sharedTeardownState`.
 *
 * Terminal phases act here, in the same transaction as the state write:
 *  - `done`: the workflow removed FCP's DOMAIN from the shared resource, so
 *    that child is `confirmed_gone`. Nothing else is: the DNS records live in
 *    another account's zone and no version workflow touches them, so they stay
 *    `present` and the ordinary destroy walk deletes and confirms them through
 *    the DNS client. Marking them gone here would leave the zone holding a
 *    CNAME (and an ACME challenge record) for a hostname FCP no longer serves;
 *  - `needs_operator`: the workflow cannot converge on its own (a lost clone, a
 *    version drift); the edge parks with the driver's code.
 */
export const recordSharedTeardown = internalMutation({
  args: {
    edgeId: v.id('edges'),
    state: v.object({
      phase: v.string(),
      serviceId: v.string(),
      fromVersion: v.optional(v.number()),
      workVersion: v.optional(v.number()),
      code: v.optional(v.string()),
      extra: v.optional(v.string()),
    }),
    /**
     * Ledger kinds a `done` phase resolves: the ones the workflow itself
     * removed. Only the domain by default; everything else is deleted by the
     * ordinary destroy walk, which can actually confirm it.
     */
    ownedKinds: v.optional(v.array(v.string())),
    countAttempt: v.optional(v.boolean()),
  },
  handler: async (ctx, { edgeId, state, ownedKinds, countAttempt }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return null;
    const now = Date.now();
    const prior = edge.sharedTeardown;
    const attempts =
      (prior?.serviceId === state.serviceId ? prior.attempts : 0) + (countAttempt ? 1 : 0);
    const kinds = ownedKinds ?? ['domain'];
    const done = state.phase === 'done';
    await ctx.db.patch(edgeId, {
      sharedTeardown: {
        phase: state.phase,
        serviceId: state.serviceId,
        // The version the workflow started from is the one it cloned; keep the
        // first observation so a re-entry never re-anchors on a newer version.
        fromVersion: prior?.fromVersion ?? state.fromVersion ?? state.workVersion ?? 0,
        ...(state.workVersion !== undefined ? { workVersion: state.workVersion } : {}),
        attempts,
      },
      ...(state.extra ? { sharedTeardownState: state.extra } : {}),
      ...(done
        ? {
            resources: edge.resources.map((r) =>
              kinds.includes(r.kind) ? { ...r, deleteState: 'confirmed_gone' as const } : r,
            ),
          }
        : {}),
      ...(state.phase === 'needs_operator'
        ? {
            status: 'needs_operator' as const,
            statusChangedAt: now,
            failure: {
              step: 'shared_teardown',
              code: (state.code ?? 'needs_operator').slice(0, 64),
            },
          }
        : {}),
      updatedAt: now,
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
      // A shared-resource teardown parked in a terminal phase must restart from
      // its first phase (the driver re-plans from the ledger); leaving the
      // terminal state would make the driver fall through to a destroy walk
      // that can only answer `unresolved` for a shared domain.
      sharedTeardown: undefined,
      sharedTeardownState: undefined,
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
  ): Promise<{
    published: boolean;
    rotationId: Id<'edgeRotations'> | null;
    /** A spare exists that only the operator's endpoint confirmation keeps out of the pool. */
    awaitingVerification: boolean;
  }> => {
    const none = { published: false, rotationId: null, awaitingVerification: false };
    const origin = await ctx.db.get(relayId);
    if (!origin || origin.deleting) return none;
    try {
      await assertNoRotationOrQuarantine(ctx.db, origin);
    } catch {
      return none;
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
    if (idx === null) return none;
    let awaitingVerification = false;
    for (const edgeId of candidates) {
      const edge = await ctx.db.get(edgeId);
      if (!edge || edge.relayId !== relayId) continue;
      const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
      if (!check.ok) {
        if (check.code === 'unverified_endpoint') awaitingVerification = true;
        continue;
      }
      const listener = await ctx.db.get(edge.listenerId);
      const becomesTemplate =
        origin.hostMode === 'fcp' &&
        (!listener?.templateEdgeId || listener.templateEdgeId === edge._id);
      if (becomesTemplate) {
        // Needs the panel-Host flip: hand it to the rotation machine.
        try {
          const { rotationId } = await startRotation(ctx, {
            relayId,
            kind: 'publish',
            trigger: 'reconcile',
            toEdgeId: edgeId,
          });
          return { published: false, rotationId, awaitingVerification };
        } catch (err) {
          // Concurrency cap / a guard the pre-check missed: try again next tick.
          if (err instanceof ConvexError)
            return { published: false, rotationId: null, awaitingVerification };
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
      await refreshTemplateEdges(ctx, origin);
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.published',
        targetType: 'edge',
        targetId: edgeId,
        payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
      });
      await scheduleMirrorRefresh(ctx);
      return { published: true, rotationId: null, awaitingVerification };
    }
    return { published: false, rotationId: null, awaitingVerification };
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
