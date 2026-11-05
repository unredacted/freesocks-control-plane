/**
 * Isolate mutations the reconcile cron needs beyond the row-level ones in
 * edges / origins: destroy bookkeeping (audited) and the
 * publish-a-standby decision (direct publish, or a `publish` rotation when the
 * free slot is pool index 0 on a Host-managed origin).
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { originPolicy, resolveEdgeConfig } from './lib/edgeConfig';
import { blockedCountries } from './edgeCountry';
import {
  assertNoRotationOrQuarantine,
  checkPublishable,
  dropEdgeFromPool,
  poolAdmitOf,
  refreshTemplateEdges,
  scheduleMirrorRefresh,
  unpublishFromPool,
} from './relays';
import { destroyedPatch } from './edges';
import { allocatePoolIndex, withEdgeAt, type PoolAdmit } from './lib/edges/pool';
import { isCooling } from './lib/edges/setState';
import { publicationApproval, startRotation } from './edgeRotations';
import { recordCandidateEdge } from './nodeActivation';
import { laneForPublish } from './edgeLanes';
import { audienceForPublish } from './edgeAudiences';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import { onlyCodesOf } from './lib/edges/audience';
import { pickWant } from './lib/edges/providerSet';

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
 *
 * `publish: false` (`edge.autoPublishStandby` off: spares go in use by hand)
 * only judges: `ready` names a spare that would go in use now. Either way the
 * cron buys no new address while a spare is ready or awaits its test.
 */
export const publishStandby = internalMutation({
  args: {
    relayId: v.id('relays'),
    candidates: v.array(v.id('edges')),
    publish: v.optional(v.boolean()),
  },
  handler: async (
    ctx,
    { relayId, candidates, publish },
  ): Promise<{
    published: boolean;
    rotationId: Id<'edgeRotations'> | null;
    /** A spare exists that only the operator's endpoint confirmation keeps out of the pool. */
    awaitingVerification: boolean;
    /** Judging only: a spare would go in use now, were spares put in use automatically. */
    ready: boolean;
  }> => {
    const none = { published: false, rotationId: null, awaitingVerification: false, ready: false };
    const origin = await ctx.db.get(relayId);
    if (!origin || origin.deleting) return none;
    try {
      await assertNoRotationOrQuarantine(ctx.db, origin);
    } catch {
      return none;
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    let awaitingVerification = false;
    // Automatic work stays inside the node's provider set and out of a pick
    // that cools (D6); a spare that fills a gap goes first.
    const inSet = new Set((origin.providerSet ?? []).map((p) => p.locationId as string));
    const ranked: Array<{ edge: Doc<'edges'>; admit: PoolAdmit }> = [];
    for (const edgeId of candidates) {
      const edge = await ctx.db.get(edgeId);
      if (!edge || edge.relayId !== relayId) continue;
      if (isCooling(origin, edge.locationId)) continue;
      if (origin.providerSet && edge.locationId && !inSet.has(edge.locationId as string)) continue;
      ranked.push({ edge, admit: await poolAdmitOf(ctx.db, origin, edge) });
    }
    // Per-country checks: among equals, a spare blocked in fewer checked
    // countries goes first (a stable sort keeps the given order otherwise).
    const now = Date.now();
    const blocked = (e: Doc<'edges'>) => (cfg.country.enabled ? blockedCountries(e, now) : 0);
    ranked.sort(
      (a, b) =>
        Number(b.admit.lowersDeficit) - Number(a.admit.lowersDeficit) ||
        blocked(a.edge) - blocked(b.edge),
    );
    for (const { edge, admit } of ranked) {
      const edgeId = edge._id;
      // Reserved allocation: an edge that adds nothing may not take a slot
      // held for what the origin still lacks.
      const alloc = allocatePoolIndex(origin.publishedEdgeIds, origin.desiredPublished, admit);
      if ('refused' in alloc) continue;
      const idx = alloc.index;
      const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
      if (!check.ok) {
        if (check.code === 'unverified_endpoint') awaitingVerification = true;
        continue;
      }
      // The node's approval (docs/servers.md "Node lifecycle"), as every other
      // publication: a spare outside what an enrolled node was approved for
      // stays a spare; one of the node's running activation is its candidate.
      const approval = await publicationApproval(ctx, origin, edge);
      if (approval.kind === 'refused') continue;
      // Its audience at its first publication: a spare an only location cannot
      // hand to its countries stays a spare (docs/edges.md "Addresses only for
      // some countries").
      const audience = await audienceForPublish(ctx.db, edge);
      if ('refused' in audience) continue;
      const listener = await ctx.db.get(edge.listenerId);
      // A contained address is never a transport's first one: the backend's
      // Host (and every raw body) would carry it to everyone.
      if (audience.contained && !listener?.templateEdgeId) continue;
      if (publish === false)
        return { published: false, rotationId: null, awaitingVerification, ready: true };
      const becomesTemplate =
        !audience.contained &&
        origin.hostMode === 'fcp' &&
        (!listener?.templateEdgeId || listener.templateEdgeId === edge._id);
      if (becomesTemplate) {
        // Needs the backend-Host flip: hand it to the rotation machine.
        try {
          const { rotationId } = await startRotation(ctx, {
            relayId,
            kind: 'publish',
            trigger: 'reconcile',
            toEdgeId: edgeId,
          });
          return { published: false, rotationId, awaitingVerification, ready: false };
        } catch (err) {
          // Concurrency cap / a guard the pre-check missed: try again next tick.
          if (err instanceof ConvexError)
            return { published: false, rotationId: null, awaitingVerification, ready: false };
          throw err;
        }
      }
      if (approval.kind === 'candidate') await recordCandidateEdge(ctx, approval.run, edgeId);
      const epoch = origin.publicationEpoch + 1;
      await ctx.db.patch(edgeId, {
        publication: 'published',
        poolIndex: idx,
        ...(await laneForPublish(ctx.db, origin, edge, null, {
          contained: audience.contained,
        })),
        ...audience.patch,
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
      return { published: true, rotationId: null, awaitingVerification, ready: false };
    }
    return { published: false, rotationId: null, awaitingVerification, ready: false };
  },
});

const sameCodes = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((c) => b.includes(c));

/**
 * Step 5O (docs/edges.md "Addresses only for some countries"): renew ONE
 * address that an edit of an only location's countries left out of date
 * (contained to other countries than the location's current ones). Until then
 * it keeps serving the members it was handed to, and it holds its place in the
 * pool and in the location's count, so the pool never grows for its renewal:
 * - the location holds more current addresses of its transport than the count
 *   asks for (at least one): it leaves, drained like a replaced one;
 * - else a tested spare there takes ITS slot, contained to the current
 *   countries, and it drains: one swap, the pool keeps its size;
 * - else the reconcile makes one spare there (`needs_spare`); a spare already
 *   there that awaits its test is waited for.
 * `publish: false` (spares go in use by hand) never swaps. Like every pool
 * write outside a rotation it does nothing while a rotation, quarantine,
 * restore, server change or guided setup holds the node.
 */
export const renewOutOfDate = internalMutation({
  args: { relayId: v.id('relays'), publish: v.optional(v.boolean()) },
  handler: async (
    ctx,
    { relayId, publish },
  ): Promise<
    | { kind: 'none' | 'waiting' }
    | { kind: 'retired'; edgeId: Id<'edges'> }
    | { kind: 'renewed'; edgeId: Id<'edges'>; by: Id<'edges'> }
    | { kind: 'needs_spare'; listenerId: Id<'relayListeners'>; locationId: Id<'edgeLocations'> }
  > => {
    const origin = await ctx.db.get(relayId);
    if (!origin?.providerSet || origin.deleting || origin.setupOwned) return { kind: 'none' };
    try {
      await assertNoRotationOrQuarantine(ctx.db, origin);
    } catch {
      return { kind: 'none' };
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    const published: Doc<'edges'>[] = [];
    for (const id of origin.publishedEdgeIds) {
      if (!id) continue;
      const e = await ctx.db.get(id);
      if (e && e.publication === 'published' && e.status === 'active') published.push(e);
    }
    // Spares as upkeep finds them: the node's live, unpublished edges.
    const spares = (await liveEdgesOfRelay(ctx.db, relayId)).filter(
      (e) => e.status === 'active' && e.publication === 'unpublished',
    );
    let waiting = false;
    for (const pick of origin.providerSet) {
      // Automatic work stays out of a pick that cools.
      if (isCooling(origin, pick.locationId)) continue;
      const location = await ctx.db.get(pick.locationId);
      const codes = onlyCodesOf(location?.forCountries);
      if (!location || !codes) continue;
      const here = published.filter((e) => e.locationId === pick.locationId);
      for (const listenerId of new Set(here.map((e) => e.listenerId))) {
        const mine = here.filter((e) => e.listenerId === listenerId);
        const old = mine
          .filter((e) => e.audience?.length && !sameCodes(e.audience, codes))
          .sort((a, b) => (a.publishedAt ?? 0) - (b.publishedAt ?? 0))[0];
        if (!old || old.poolIndex === undefined) continue;
        const audit = (how: 'retired' | 'renewed') =>
          writeAuditLog(ctx, {
            actorType: 'system',
            action: 'edge.audience_retired',
            targetType: 'edge',
            targetId: old._id,
            payload: {
              relaySlug: origin.slug,
              placeKey: location.placeKey,
              was: (old.audience ?? []).join(' '),
              now: codes.join(' '),
              how,
            },
          });
        const drainMs = originPolicy(origin, cfg).drainMs;
        const current = mine.filter((e) => sameCodes(e.audience ?? [], codes)).length;
        if (current >= Math.max(1, pickWant(pick.want) ?? 1)) {
          await unpublishFromPool(ctx, origin, old, { drainMs });
          await audit('retired');
          return { kind: 'retired', edgeId: old._id };
        }
        let spareThere = false;
        for (const s of spares) {
          if (s.listenerId !== listenerId || s.locationId !== pick.locationId) continue;
          // A spare the location cannot hand to its countries never serves there.
          const audience = await audienceForPublish(ctx.db, s);
          if ('refused' in audience || !audience.contained) continue;
          spareThere = true;
          // Awaiting its test (or its provider unhealthy): wait, buy nothing more.
          if (!(await checkPublishable(ctx, s, cfg.requireProviderHealth)).ok) continue;
          const approval = await publicationApproval(ctx, origin, s);
          if (approval.kind === 'refused') continue;
          if (publish === false) continue;
          if (approval.kind === 'candidate') await recordCandidateEdge(ctx, approval.run, s._id);
          const idx = old.poolIndex;
          await unpublishFromPool(ctx, origin, old, { drainMs });
          const after = (await ctx.db.get(relayId))!;
          const now = Date.now();
          await ctx.db.patch(s._id, {
            publication: 'published',
            poolIndex: idx,
            ...(await laneForPublish(ctx.db, after, s, null, { contained: true })),
            ...audience.patch,
            publishedAt: now,
            updatedAt: now,
          });
          const epoch = after.publicationEpoch + 1;
          await ctx.db.patch(relayId, {
            publishedEdgeIds: withEdgeAt(after.publishedEdgeIds, idx, s._id),
            standbyEdgeIds: after.standbyEdgeIds.filter((e) => e !== s._id),
            publicationEpoch: epoch,
            updatedAt: now,
          });
          await refreshTemplateEdges(ctx, after);
          await writeAuditLog(ctx, {
            actorType: 'system',
            action: 'edge.published',
            targetType: 'edge',
            targetId: s._id,
            payload: { relaySlug: origin.slug, edgeId: s._id, poolIndex: idx, epoch },
          });
          await audit('renewed');
          return { kind: 'renewed', edgeId: old._id, by: s._id };
        }
        if (spareThere) {
          waiting = true;
          continue;
        }
        return { kind: 'needs_spare', listenerId, locationId: pick.locationId };
      }
    }
    return { kind: waiting ? 'waiting' : 'none' };
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
