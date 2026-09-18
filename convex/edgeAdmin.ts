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
  EDGE_CONFIG_BOUNDS,
  EDGE_DEFAULTS,
  EDGE_KEYS,
  RENDER_CLIENT_FAMILIES,
  flattenEdgeConfig,
  edgeConfigWrites,
  edgeSecretStatus,
  edgeSecretWrites,
  resolveEdgeConfig,
  resolveEdgeSecrets,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { assignEndpoints, edgeHostname, edgeLayer } from './lib/edges/assignment';
import { hostTargetFor } from './lib/edges/layers';
import { parseIntent } from './lib/edges/intent';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import { PREVIEW_DEFAULT_PROTO } from './lib/edges/preview';
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
import { activeNames, listenerRemark, listenersOf, mapListenerAdmin } from './relayListeners';
import { EDGE_PROVIDER_CAPABILITIES } from './lib/edges/providers/capabilities';
import { protocolLabel } from './lib/edges/protocols';
import { destroyedPatch, mapEdgeAdmin } from './edges';
import { deliveryStyleOf, publishedEdgesOf } from './edgeRender';
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
          addresses: {
            v4: e.addresses.v4 ?? null,
            v6: e.addresses.v6 ?? null,
            hostname: e.addresses.hostname ?? null,
          },
          layer: e.layer ?? 'l4',
          listenerId: e.listenerId as string,
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
              needsHostFlip: r.hostPlan.length > 0 || r.phase === 'host_flipping',
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
      // Flat paths: what the settings page diffs against and resets to.
      defaults: flattenEdgeConfig(EDGE_DEFAULTS),
      bounds: EDGE_CONFIG_BOUNDS,
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

/**
 * The one automation switch (`POST /api/v1/admin/edges/automation {on}`): in
 * ONE mutation set `edge.enabled`, `edge.autoRotate`, `edge.probe.enabled` and
 * `edge.autoProvisionToDesired` to `on`, and keep one verified spare per
 * listener (`edge.standbyPerListener = 1`) when turning on (left as-is when
 * turning off, so nobody's bill changes twice). Never `render.enabled` or
 * `l7.autoSelect`; no relay row is touched (a relay's own `autoRotate` keeps
 * its meaning under the global gate). Audited as the boolean only.
 */
export const setAutomation = internalMutation({
  args: { on: v.boolean(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { on, actorAdminId }) => {
    const flag = JSON.stringify(on);
    const writes: Array<{ key: string; value: string }> = [
      { key: EDGE_KEYS.enabled, value: flag },
      { key: EDGE_KEYS.autoRotate, value: flag },
      { key: EDGE_KEYS['probe.enabled'], value: flag },
      { key: EDGE_KEYS.autoProvisionToDesired, value: flag },
      ...(on ? [{ key: EDGE_KEYS.standbyPerListener, value: '1' }] : []),
    ];
    for (const w of writes) await upsertSettingRow(ctx, w.key, w.value, actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.automation.set',
      targetType: 'app_settings',
      payload: { on },
    });
    return { on, changedKeys: writes.map((w) => w.key) };
  },
});

// --- origins: IaC + endpoints -----------------------------------------------------------------------

async function publishedEndpoints(
  ctx: { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
) {
  // Role-usable endpoints ONLY: an edge that lost its address or listener must
  // make the role keep waiting, not configure a dud. (Assignment and preview
  // use the full, flagged pool elsewhere.)
  const { published } = await publishedEdgesOf(ctx, origin);
  const listeners = await listenersOf(ctx, origin._id);
  // An L7 front answers DNS long before it carries the transport: require a
  // current, passing end-to-end proof, re-derived from the live rows.
  const usable = [];
  for (const p of published) {
    if (edgeLayer(p) !== 'l7') {
      usable.push(p);
      continue;
    }
    const edge = await ctx.db.get(p.edgeId as Id<'edges'>);
    const listener = edge ? await ctx.db.get(edge.listenerId) : null;
    const intent = edge ? parseIntent(edge.provisionIntent) : null;
    if (!edge || !listener || !intent) continue;
    const verdict = qualificationVerdict(
      edge.frontQualification,
      qualificationBinding({ listener, intent, params: listener.transportParams ?? {} }),
      Date.now(),
    );
    if (verdict === 'ok') usable.push(p);
  }
  return usable.map((p) => {
    const actives = p.serverNames.filter((s) => s.status === 'active').map((s) => s.sni);
    // ONE source for the Host tuple, shared with the flip and with assignment.
    const target = hostTargetFor(p, p.proto, actives[0] ?? null);
    const layer = edgeLayer(p);
    const listener = listeners.find((l) => (l._id as string) === p.listenerId);
    return {
      poolIndex: p.poolIndex,
      edgeId: p.edgeId,
      provider: p.provider,
      listenerKey: p.listenerKey,
      templateHostRemark: listener ? listenerRemark(listener) : null,
      protocol: p.proto.protocol,
      streamTransport: p.proto.streamTransport,
      security: p.proto.security,
      layer,
      port: p.edgePort,
      addresses: {
        v4: p.addresses.v4 ?? null,
        v6: p.addresses.v6 ?? null,
        hostname: p.addresses.hostname ?? null,
      },
      hostname: edgeHostname(p),
      sni: target?.sni ?? null,
      hostHeader: target?.host ?? null,
      activeNames: layer === 'l7' && p.addresses.hostname ? [p.addresses.hostname] : actives,
    };
  });
}

/**
 * What a client must dial per listener (every origin kind): the listener's
 * template edge tuple. A manual origin lives off this alone.
 */
async function connectionPlan(
  ctx: { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
  endpoints: Awaited<ReturnType<typeof publishedEndpoints>>,
) {
  const listeners = (await listenersOf(ctx, origin._id)).filter((l) => !l.retired && l.deployed);
  const out: Array<{
    listenerKey: string;
    address: string;
    port: number;
    sni: string | null;
    host: string | null;
  }> = [];
  for (const l of listeners) {
    const ep = endpoints
      .filter((e) => e.listenerKey === l.listenerKey)
      .sort((a, b) => a.poolIndex - b.poolIndex)[0];
    if (!ep) continue;
    const address = ep.hostname ?? ep.addresses.v4;
    if (!address) continue;
    out.push({
      listenerKey: l.listenerKey,
      address,
      port: ep.port,
      sni: ep.sni,
      host: ep.hostHeader,
    });
  }
  return out;
}

/** The Hosts the OPERATOR must create/keep when hostMode is `operator`. */
function hostsPlan(
  origin: Doc<'relays'>,
  listeners: Doc<'relayListeners'>[],
  plan: Awaited<ReturnType<typeof connectionPlan>>,
) {
  if (origin.hostMode !== 'operator') return { mode: origin.hostMode, hosts: [] };
  const hosts = [];
  for (const p of plan) {
    const l = listeners.find((x) => x.listenerKey === p.listenerKey);
    const remark = l ? listenerRemark(l) : null;
    if (!l || !remark || !l.panelBinding) continue;
    hosts.push({
      listenerKey: p.listenerKey,
      remark,
      address: p.address,
      port: p.port,
      sni: p.sni,
      host: p.host,
      inbound: {
        configProfileUuid: l.panelBinding.configProfileUuid,
        configProfileInboundUuid: l.panelBinding.configProfileInboundUuid,
      },
    });
  }
  return { mode: origin.hostMode, hosts };
}

function udpProviderAvailable(): boolean {
  return Object.values(EDGE_PROVIDER_CAPABILITIES).some((c) => c.udp);
}

/**
 * The node role's view of a relay (`GET/PUT …/relays/by-slug/{slug}`): the
 * minimal projection. No detector state, no rotation limits, no pool-wide
 * provider names: a leaked register token learns none of them.
 */
export const relayBySlugView = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const origin = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (!origin) return null;
    const listeners = await listenersOf(ctx, origin._id);
    const endpoints = await publishedEndpoints(ctx, origin);
    const plan = await connectionPlan(ctx, origin, endpoints);
    const udp = udpProviderAvailable();
    return {
      relay: {
        id: origin._id as string,
        slug: origin.slug,
        hostMode: origin.hostMode,
        delivery: origin.delivery,
        enabled: origin.enabled,
        deleting: origin.deleting ?? false,
        publicationEpoch: origin.publicationEpoch,
        originAddress: origin.originAddress,
        lastRegisteredAt: origin.lastRegisteredAt
          ? new Date(origin.lastRegisteredAt).toISOString()
          : null,
      },
      listeners: listeners
        .map((l) => {
          const m = mapListenerAdmin(l, { udpProviderAvailable: udp });
          return {
            listenerKey: m.listenerKey,
            protocol: m.protocol,
            streamTransport: m.streamTransport,
            security: m.security,
            transport: m.transport,
            originPort: m.originPort,
            layers: m.layers,
            excluded: m.excluded,
            deployed: m.deployed,
            retired: m.retired,
            templateHostRemark: m.templateHostRemark,
          };
        })
        .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey)),
      publishedEndpoints: endpoints.map((e) => ({
        listenerKey: e.listenerKey,
        poolIndex: e.poolIndex,
        layer: e.layer,
        port: e.port,
        addresses: e.addresses,
        sni: e.sni,
        hostHeader: e.hostHeader,
      })),
      connectionPlan: plan,
      hostsPlan: hostsPlan(origin, listeners, plan),
    };
  },
});

/** The full admin view of a relay's listeners + endpoints (the CMS). */
export const relayListenersView = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return null;
    const listeners = await listenersOf(ctx, relayId);
    const udp = udpProviderAvailable();
    const endpoints = await publishedEndpoints(ctx, origin);
    const plan = await connectionPlan(ctx, origin, endpoints);
    return {
      listeners: listeners
        .map((l) => ({
          ...mapListenerAdmin(l, { udpProviderAvailable: udp }),
          label: protocolLabel(l),
        }))
        .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey)),
      publishedEndpoints: endpoints,
      connectionPlan: plan,
      hostsPlan: hostsPlan(origin, listeners, plan),
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
    // The sample must be assigned under the SAME family rule the renderer uses,
    // not under a default: with IPv6 emission off for a family, an edge that
    // only has a v6 address is not assignable, so a sample computed with v6
    // allowed would name an edge that family never renders.
    const assigned = assignEndpoints(SAMPLE_RENDER_KEY, published, {
      now: Date.now(),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      includeBackup: true,
      canEmitV6: RENDER_CLIENT_FAMILIES.every(
        (f) => effectiveRule(cfg.render, cfg.render.clients[f]).ipv6Mode !== 'off',
      ),
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
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    return renderPreviewFor(ctx, origin, family as RenderClientFamily, sampleKey);
  },
});

/** The per-family preview over the sample body (shared with the setup-status rendering step). */
export async function renderPreviewFor(
  ctx: { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
  fam: RenderClientFamily,
  sampleKey?: string,
) {
  {
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published, matchers } = await publishedEdgesOf(ctx, origin, {
      includeIneligible: true,
    });
    const format = CLIENT_FAMILY_FORMATS[fam];
    // The preview body must speak what the listeners speak: one template entry
    // per listener (by its remark, or a synthetic one for an address-matched
    // listener at the origin address:port), each in the listener's own shape.
    const listeners = await listenersOf(ctx, origin._id);
    const active = listeners.filter((l) => !l.retired && l.deployed && l.enabled);
    const first = active[0];
    const input = previewBody(
      format,
      active.map((l) => listenerRemark(l) ?? `${origin.slug}-${l.listenerKey}`),
      first
        ? {
            protocol: first.protocol,
            streamTransport: first.streamTransport,
            security: first.security,
          }
        : PREVIEW_DEFAULT_PROTO,
    );
    // Address-matched listeners are found by origin address:port; the fixture
    // carries the example origin, so give those matchers the fixture's address.
    const previewMatchers = matchers.map((m) =>
      m.rule.kind === 'remark' ? m : { ...m, originAddress: '192.0.2.10' },
    );
    const out = applyEdgeRender(
      {
        epoch: origin.publicationEpoch,
        matchers: previewMatchers,
        published,
        rule: effectiveRule(cfg.render, cfg.render.clients[fam]),
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        originAddress: '192.0.2.10',
        deliveryStyle: origin.backendServerId
          ? await deliveryStyleOf(ctx, origin.backendServerId)
          : 'subscription',
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
      delivery: out.delivery,
      listeners: out.listeners ?? [],
    };
  }
}

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
        // Restart a parked shared-resource teardown from its first phase.
        sharedTeardown: undefined,
        sharedTeardownState: undefined,
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
    const bound = new Map(relays.filter((r) => r.nodeName).map((r) => [r.nodeName!, r.slug]));
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
