/**
 * Admin-facing relay reads/writes that span the relay modules: the summary the
 * CMS renders, the config namespace (with write-only probe secrets), the IaC
 * by-slug view, the published-endpoint view, live LB snapshots, operator
 * resolutions for parked edges, and the per-family render preview. Route
 * plumbing is in httpEdges.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import {
  EDGE_DEFAULTS,
  RENDER_CLIENT_FAMILIES,
  edgeConfigWrites,
  edgeSecretStatus,
  edgeSecretWrites,
  resolveEdgeConfig,
  resolveEdgeSecrets,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { assignEndpoints } from './lib/edges/assignment';
import { CLIENT_FAMILY_FORMATS } from './lib/edges/clientFamilies';
import { previewBody } from './lib/edges/preview';
import { applyEdgeRender } from './lib/edges/renderPipeline';
import { effectiveRule } from './lib/edges/render';
import { publishedCount } from './lib/edges/pool';
import { isTerminalPhase, progressPercent } from './lib/edges/rotation';
import {
  assertNoRotationOrQuarantine,
  dropEdgeFromPool,
  mapRelayAdmin,
  scheduleMirrorRefresh,
} from './relays';
import { mapSlotAdmin } from './relaySlots';
import { destroyedPatch, mapEdgeAdmin } from './edges';
import { publishedEdgesOf } from './edgeRender';
import { EDGE_CREDENTIAL_FIELDS } from './lib/edges/accountSettings';

const SAMPLE_RENDER_KEY = 'sample-subscriber-0000';

// --- summary ---------------------------------------------------------------------------------------

export const summary = internalQuery({
  args: {},
  handler: async (ctx) => {
    const origins = (await ctx.db.query('relays').collect()).sort((a, b) =>
      a.slug.localeCompare(b.slug),
    );
    const out = [];
    const counts = {
      relays: origins.length,
      published: 0,
      suspected: 0,
      rotating: 0,
      quarantined: 0,
      unreachableEdges: 0,
      needsOperator: 0,
    };
    for (const o of origins) {
      const edges = await ctx.db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', o._id))
        .collect();
      const pool = [];
      for (let i = 0; i < o.publishedEdgeIds.length; i++) {
        const id = o.publishedEdgeIds[i];
        if (!id) continue;
        const e = edges.find((x) => x._id === id);
        if (!e) continue;
        const unreachableIn = (e.reachability?.byCountry ?? [])
          .filter((c) => c.verdict === 'unreachable' && c.country !== 'XX')
          .map((c) => c.country);
        const mixedIn = (e.reachability?.byCountry ?? [])
          .filter((c) => c.verdict === 'mixed')
          .map((c) => c.country);
        if (unreachableIn.length > 0) counts.unreachableEdges++;
        pool.push({
          poolIndex: e.poolIndex ?? i,
          edgeId: e._id as string,
          provider: e.provider ?? null,
          managed: e.managed,
          addresses: { v4: e.addresses.v4 ?? null, v6: e.addresses.v6 ?? null },
          health: e.health,
          status: e.status,
          unreachableIn,
          mixedIn,
        });
      }
      counts.published += publishedCount(o.publishedEdgeIds);
      if (o.suspicion?.state === 'suspected') counts.suspected++;
      if (o.quarantine) counts.quarantined++;
      const needsOperator = edges.filter((e) => e.status === 'needs_operator').length;
      counts.needsOperator += needsOperator;
      let rotation: { id: string; kind: string; phase: string; percent: number } | null = null;
      if (o.activeRotationId) {
        const r = await ctx.db.get(o.activeRotationId);
        if (r && !isTerminalPhase(r.phase)) {
          counts.rotating++;
          const edge = r.toEdgeId ? edges.find((x) => x._id === r.toEdgeId) : null;
          rotation = {
            id: r._id as string,
            kind: r.kind,
            phase: r.phase,
            percent: progressPercent({
              phase: r.phase,
              stepStates: edge?.steps.map((s) => s.state),
              needsHostFlip: r.hostPlan.length > 0 || r.previousBinding?.poolIndex === 0,
            }),
          };
        }
      }
      out.push({
        relay: mapRelayAdmin(o),
        pool,
        standbys: edges.filter((e) => e.status === 'active' && e.publication === 'unpublished')
          .length,
        draining: edges.filter((e) => e.status === 'draining').length,
        needsOperator,
        rotation,
      });
    }
    return { counts, relays: out, generatedAt: new Date().toISOString() };
  },
});

/** The dashboard mini-card figures (cheap subset of `summary`). */
export const dashboardCounts = internalQuery({
  args: {},
  handler: async (ctx) => {
    const origins = await ctx.db.query('relays').collect();
    let published = 0;
    let suspected = 0;
    let quarantined = 0;
    let rotating = 0;
    for (const o of origins) {
      published += publishedCount(o.publishedEdgeIds);
      if (o.suspicion?.state === 'suspected') suspected++;
      if (o.quarantine) quarantined++;
      if (o.activeRotationId) {
        const r = await ctx.db.get(o.activeRotationId);
        if (r && !isTerminalPhase(r.phase)) rotating++;
      }
    }
    return { relays: origins.length, published, suspected, quarantined, rotating };
  },
});

// --- config ---------------------------------------------------------------------------------------

export const configView = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [config, secrets] = await Promise.all([
      resolveEdgeConfig(ctx.db),
      resolveEdgeSecrets(ctx.db),
    ]);
    return {
      config,
      secrets: edgeSecretStatus(secrets),
      families: [...RENDER_CLIENT_FAMILIES],
      defaults: EDGE_DEFAULTS,
    };
  },
});

/**
 * PATCH the `edge.*` namespace. `patch` is the nested config shape (any subset);
 * `patch.secrets` carries write-only probe credentials (blank = keep). Audited as
 * the list of changed keys only. A `render.*` change alters what every member
 * receives, so it bumps every enabled relay's publication epoch (the /sub cache
 * token) and refreshes the stored mirrors once.
 */
export const patchConfig = internalMutation({
  args: { patch: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { patch, actorAdminId }) => {
    const p = (patch && typeof patch === 'object' ? patch : {}) as Record<string, unknown>;
    const { secrets, ...rest } = p;
    const { writes, changedKeys } = edgeConfigWrites(rest);
    const secretWrites = edgeSecretWrites(secrets ?? {});
    for (const w of [...writes, ...secretWrites]) {
      await upsertSettingRow(ctx, w.key, w.value, actorAdminId);
    }
    const changed = [...changedKeys, ...secretWrites.map(() => 'probe.secret')];
    if (changedKeys.some((k) => k.startsWith('render.'))) {
      const now = Date.now();
      const relays = await ctx.db
        .query('relays')
        .withIndex('by_enabled', (q) => q.eq('enabled', true))
        .collect();
      for (const r of relays) {
        await ctx.db.patch(r._id, { publicationEpoch: r.publicationEpoch + 1, updatedAt: now });
      }
      await scheduleMirrorRefresh(ctx);
    }
    if (changed.length > 0) {
      const action = changed.every((k) => k.startsWith('render.'))
        ? 'admin.edge.render.change'
        : changed.every((k) => k.startsWith('probe.'))
          ? 'admin.edge.probe.change'
          : 'admin.edge.config.change';
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action,
        targetType: 'app_settings',
        payload: { changedKeys: changed },
      });
    }
    return { changedKeys: changed };
  },
});

// --- origins: IaC + endpoints -----------------------------------------------------------------------

async function publishedEndpoints(
  ctx: { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
) {
  // Role-usable endpoints ONLY: the node role bootstraps its template Host from
  // publishedEndpoints[0]'s address/port/SNI, so an index-0 edge that lost its
  // address, slot or profile must make it keep waiting, not configure a dud.
  // (Assignment and preview use the full, flagged pool elsewhere.)
  const { published } = await publishedEdgesOf(ctx, origin);
  const slots = await ctx.db
    .query('relaySlots')
    .withIndex('by_relay', (q) => q.eq('relayId', origin._id))
    .collect();
  return published.map((p) => ({
    poolIndex: p.poolIndex,
    edgeId: p.edgeId,
    provider: p.provider,
    slotKey: slots.find((s) => (s._id as string) === p.slotId)?.slotKey ?? '',
    slotRemark: p.slotRemark,
    protocol: p.protocol,
    port: p.edgePort,
    addresses: { v4: p.addresses.v4 ?? null, v6: p.addresses.v6 ?? null },
    activeServerNames: p.serverNames.filter((s) => s.status === 'active').map((s) => s.sni),
  }));
}

export const relayBySlugView = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const origin = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!origin) return null;
    const slots = await ctx.db
      .query('relaySlots')
      .withIndex('by_relay', (q) => q.eq('relayId', origin._id))
      .collect();
    const mapped = [];
    for (const s of slots)
      mapped.push(mapSlotAdmin(s, s.profileId ? await ctx.db.get(s.profileId) : null));
    return {
      relay: mapRelayAdmin(origin),
      slots: mapped.sort((a, b) => a.slotKey.localeCompare(b.slotKey)),
      publishedEndpoints: await publishedEndpoints(ctx, origin),
    };
  },
});

export const endpoints = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
    const assigned = assignEndpoints(SAMPLE_RENDER_KEY, published, {
      now: Date.now(),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      includeBackup: true,
    });
    return {
      relaySlug: origin.slug,
      epoch: origin.publicationEpoch,
      published: await publishedEndpoints(ctx, origin),
      sample: {
        primary: assigned.primary
          ? { edgeId: assigned.primary.edge.edgeId, sni: assigned.primary.sni }
          : null,
        backup: assigned.backup
          ? { edgeId: assigned.backup.edge.edgeId, sni: assigned.backup.sni }
          : null,
      },
    };
  },
});

// --- render preview ---------------------------------------------------------------------------------

export const renderPreview = internalQuery({
  args: { relayId: v.id('relays'), family: v.string(), sampleKey: v.optional(v.string()) },
  handler: async (ctx, { relayId, family, sampleKey }) => {
    if (!(RENDER_CLIENT_FAMILIES as readonly string[]).includes(family)) {
      throw new ConvexError({ code: 'validation', message: 'unknown client family' });
    }
    const fam = family as RenderClientFamily;
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published, templateRemarks } = await publishedEdgesOf(ctx, origin, {
      includeIneligible: true,
    });
    const format = CLIENT_FAMILY_FORMATS[fam];
    const input = previewBody(format, templateRemarks);
    const out = applyEdgeRender(
      {
        epoch: origin.publicationEpoch,
        templateRemarks,
        published,
        rule: effectiveRule(cfg.render, cfg.render.clients[fam]),
        preferDistinctProviders: cfg.render.preferDistinctProviders,
      },
      input,
      sampleKey && sampleKey.length > 0 ? sampleKey : SAMPLE_RENDER_KEY,
      { now: Date.now() },
    );
    return {
      family: fam,
      format,
      input,
      body: out.body,
      applied: out.applied,
      reason: out.reason ?? null,
      emitted: out.emitted,
    };
  },
});

// --- edges: detail, live, operator resolutions ---------------------------------------------------------

export const edgeDetail = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const e = await ctx.db.get(edgeId);
    if (!e) return null;
    const probes = await ctx.db
      .query('probeRuns')
      .withIndex('by_target_requested', (q) =>
        q.eq('targetKind', 'edge').eq('targetRef', edgeId as string),
      )
      .order('desc')
      .take(10);
    return {
      edge: mapEdgeAdmin(e),
      live: parseLive(e),
      probes: probes.map((r) => ({
        id: r._id as string,
        source: r.source,
        status: r.status,
        requestedAt: new Date(r.requestedAt).toISOString(),
        okVantages: r.results.filter((x) => x.ok).length,
        failVantages: r.results.filter((x) => !x.ok).length,
      })),
    };
  },
});

function parseLive(e: Doc<'edges'>) {
  if (!e.liveSnapshot || !e.liveAt) return null;
  try {
    const parsed = JSON.parse(e.liveSnapshot) as { summary?: unknown; raw?: unknown };
    return {
      summary: parsed.summary ?? { addresses: {}, members: [], listeners: [] },
      raw: parsed.raw ?? null,
      liveAt: new Date(e.liveAt).toISOString(),
    };
  } catch {
    return null;
  }
}

export const liveView = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const e = await ctx.db.get(edgeId);
    return { live: e ? parseLive(e) : null };
  },
});

export const recordLive = internalMutation({
  args: {
    edgeId: v.id('edges'),
    snapshot: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { edgeId, snapshot, actorAdminId }) => {
    const e = await ctx.db.get(edgeId);
    if (!e) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      liveSnapshot: snapshot.slice(0, 200_000),
      liveAt: now,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.live.pulled',
      targetType: 'edge',
      targetId: edgeId,
      payload: { edgeId, accountId: e.accountId ?? null },
    });
    return { ok: true as const };
  },
});

/**
 * Operator resolution for a parked edge (`needs_operator` / `ambiguous` steps):
 *  - `destroy`: the ledger is trusted; walk the destroy path again;
 *  - `forget`: the operator cleaned the provider by hand; mark destroyed with no calls;
 *  - `reactivate`: the resource turned out fine; back to an unpublished active edge.
 * Refused while the origin is quarantined or a rotation runs (the shared gate);
 * `forget` also heals the pool lists (an id that was still listed is removed and
 * the epoch bumped). Audited as `edge.destroy` / `edge.forget` / `edge.reactivate`.
 */
export const resolveOperator = internalMutation({
  args: {
    edgeId: v.id('edges'),
    action: v.union(v.literal('destroy'), v.literal('forget'), v.literal('reactivate')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { edgeId, action, actorAdminId }) => {
    const e = await ctx.db.get(edgeId);
    if (!e) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if (e.publication === 'published') {
      throw new ConvexError({ code: 'conflict', message: 'Unpublish the edge first' });
    }
    const now = Date.now();
    const origin = await ctx.db.get(e.relayId);
    if (origin) await assertNoRotationOrQuarantine(ctx.db, origin);
    if (action === 'destroy') {
      await ctx.db.patch(edgeId, {
        status: 'destroying',
        destroyAttempts: 0,
        destroyConfirm: undefined,
        currentOp: undefined,
        failure: undefined,
        steps: e.steps.map((s) => (s.state === 'ambiguous' ? { ...s, state: 'done' as const } : s)),
        statusChangedAt: now,
        updatedAt: now,
      });
      if (origin) await dropEdgeFromPool(ctx, origin, e, { reason: 'operator_destroy' });
    } else if (action === 'forget') {
      await ctx.db.patch(edgeId, {
        ...destroyedPatch(now),
        resources: e.resources.map((r) => ({ ...r, deleteState: 'confirmed_gone' as const })),
      });
      if (origin) await dropEdgeFromPool(ctx, origin, e, { reason: 'operator_forget' });
    } else {
      // Back to an unpublished, selectable standby: a row that came off the
      // drain path still carries `draining` + an expired drainUntil, which
      // would leave it active yet invisible to the standby picker.
      await ctx.db.patch(edgeId, {
        status: 'active',
        publication: 'unpublished',
        poolIndex: undefined,
        drainUntil: undefined,
        currentOp: undefined,
        failure: undefined,
        steps: e.steps.map((s) =>
          s.state === 'ambiguous' || s.state === 'needs_operator'
            ? { ...s, state: 'done' as const }
            : s,
        ),
        statusChangedAt: now,
        updatedAt: now,
      });
      if (origin && !origin.standbyEdgeIds.includes(edgeId)) {
        await ctx.db.patch(origin._id, {
          standbyEdgeIds: [...origin.standbyEdgeIds, edgeId],
          updatedAt: now,
        });
      }
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action:
        action === 'destroy'
          ? 'edge.destroy'
          : action === 'forget'
            ? 'edge.forget'
            : 'edge.reactivate',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin?.slug ?? '', edgeId, provider: e.provider ?? null },
    });
    return { ok: true as const };
  },
});

/**
 * DELETE an edge: refuses while published, quarantined or rotating; unmanaged
 * rows are forgotten, managed ones destroyed. Heals the pool lists on the way out.
 */
export const deleteEdge = internalMutation({
  args: { edgeId: v.id('edges'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { edgeId, actorAdminId }) => {
    const e = await ctx.db.get(edgeId);
    if (!e) return { ok: true as const };
    if (e.publication === 'published') {
      throw new ConvexError({ code: 'conflict', message: 'Unpublish the edge first' });
    }
    const now = Date.now();
    const origin = await ctx.db.get(e.relayId);
    if (origin) await assertNoRotationOrQuarantine(ctx.db, origin);
    if (!e.managed || e.status === 'destroyed') {
      await ctx.db.patch(edgeId, {
        ...destroyedPatch(now),
        destroyedAt: e.destroyedAt ?? now,
      });
    } else {
      await ctx.db.patch(edgeId, {
        status: 'destroying',
        publication: 'unpublished',
        poolIndex: undefined,
        destroyAttempts: 0,
        destroyConfirm: undefined,
        statusChangedAt: now,
        updatedAt: now,
      });
    }
    if (origin) await dropEdgeFromPool(ctx, origin, e, { reason: 'operator_delete' });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.delete',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin?.slug ?? '', edgeId, force: false },
    });
    return { ok: true as const };
  },
});

/** Every published edge of an origin gets a probe round (admin "Probe now"). */
export const publishedEdgeIdsOf = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<Id<'edges'>[]> => {
    const o = await ctx.db.get(relayId);
    return (o?.publishedEdgeIds ?? []).filter((x): x is Id<'edges'> => x !== null);
  },
});

/**
 * Nodes the panel currently lists (the healthcheck cron's inventory cache, or a
 * fresh pull via backendNodes.refreshNodeInventory), with whether a relay is
 * already registered for each: the "New relay" picker pre-fills from these.
 */
export const nodeCandidates = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const rows = await ctx.db
      .query('backendNodeInventory')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const relays = await ctx.db
      .query('relays')
      .withIndex('by_backend_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const bound = new Map(relays.map((r) => [r.nodeHostname, r.slug]));
    return {
      fetchedAt: rows.length
        ? new Date(Math.max(...rows.map((r) => r.lastStatsAt))).toISOString()
        : null,
      nodes: rows
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((r) => ({
          nodeUuid: r.nodeUuid,
          name: r.name,
          address: r.address ?? null,
          port: r.port ?? null,
          countryCode: r.countryCode ?? null,
          online: r.online,
          usersOnline: r.usersOnline,
          relaySlug: bound.get(r.name) ?? null,
        })),
    };
  },
});

export const credentialFields = internalQuery({
  args: {},
  handler: async () => EDGE_CREDENTIAL_FIELDS,
});
