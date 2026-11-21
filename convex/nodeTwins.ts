/**
 * A node serving its mode's ENCRYPTED TWIN (docs/servers.md "A node serving
 * the encrypted twin", docs/backends.md "VLESS Encryption"): the mode's own
 * WebSocket transport a second time, with VLESS Encryption inside the stream,
 * behind the same fronts. A CDN that terminates TLS then carries ciphertext
 * only. The twin has a lifecycle and evidence of its own, so nothing about it
 * ever closes the node's own transport, its address or its approval:
 *
 *   activating   An admin asked for it. The node reconcile turns the twin's
 *                transport on for the node (its active set = its own transport
 *                + the twin), and the node's front server is handed the twin's
 *                route (its path to its loopback port: the node role reads it
 *                with the node's other routes; on a node no role runs, an
 *                operator adds it). This run writes the twin's address,
 *                SWITCHED OFF, at the target of the listener's own address,
 *                names it to the renderer, and checks the twin's path through
 *                every published front with FCP's own test account, spoken
 *                with the twin's client string. That one session proves the
 *                route, the transport and the front together.
 *   serving      The address is on. The twin is handed out through the fronts
 *                that passed (`relayListeners.encryptedTwin.edges`) and no
 *                other: a front published later serves the plain entry alone
 *                until its own check passes. Each front is checked again
 *                before its check is an hour old. Bound to `evidence.revision`
 *                (lib/backend/nodeTwin.ts `twinRevision`): a new key, port,
 *                path or listener closes ONLY the twin (address off, no front
 *                counted) until every front is checked again.
 *   removing     No front counted, address off, then deleted, then the
 *                renderer forgets it and the transport is dropped from the node.
 *
 * Members never lose the plain entry while any of this runs: the renderer
 * hands the twin out first and the plain entry behind it, or the plain entry
 * alone, by app family (docs/backends.md "VLESS Encryption").
 */
import { ConvexError, v } from 'convex/values';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type ActionCtx,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import { writeAuditLog } from './lib/audit';
import { sha256Hex } from './lib/crypto';
import { EDGE_PLUMBING } from './lib/edgeConfig';
import { resolveServerConfig } from './lib/serverConfig';
import { modeOf, setupReady, type Setup } from './backendSetup';
import { modeSlug } from './nodeIntents';
import { observeInstance } from './backendObserve';
import { listenerKeyForTag } from './lib/edges/inboundMapping';
import { parseIntent } from './lib/edges/intent';
import { twinRemarksOf } from './lib/edges/listenerEncryption';
import { bumpEpochAndRefresh } from './lib/edges/relayGuards';
import { deliveryBindingFor } from './relays';
import {
  desiredTwinHost,
  dueEdges,
  keptChecks,
  nodeTwinProblem,
  twinHostDiff,
  twinRevision,
  twinRoute,
  type TwinEdgeCheck,
} from './lib/backend/nodeTwin';

type Intent = Doc<'panelNodeIntents'>;
type Twin = NonNullable<Intent['twin']>;

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

/** One run at a time per node; a run that died is taken over once this runs out. */
const LEASE_MS = 5 * 60_000;
/** Fronts checked in one run: each check is one bounded session through a front. */
const CHECKS_PER_RUN = 4;
/** How long a front's check counts before it is made again. */
export const TWIN_CHECK_TTL_MS = EDGE_PLUMBING.l7QualificationTtlMs;

const WORDS: Record<string, string> = {
  'servers.twin_absent': 'This mode has no encrypted twin on this backend',
  'servers.node_twin_present': 'The node already serves the encrypted twin',
  'servers.node_twin_absent': 'The node does not serve the encrypted twin',
  'servers.node_twin_no_front':
    'FCP runs no front for this node’s own transport yet. Put the node behind a front first',
  'servers.node_twin_not_rendered':
    'This node’s members are not served through its fronts yet. Take the node live behind them first',
};

// --- reads -----------------------------------------------------------------------------------------

async function readySetupOf(ctx: { db: QueryCtx['db'] }, sid: Id<'backendServers'>) {
  const row = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  return setupReady(row) ? row : null;
}

/**
 * The node's own listener (the one bound to its mode's transport), the
 * address FCP keeps for it as last observed, and the fronts published for it.
 */
async function frontOf(
  ctx: { db: QueryCtx['db'] },
  intent: Intent,
  setup: Setup,
  hosts: readonly Doc<'panelHosts'>[],
) {
  const mode = modeOf(setup, modeSlug(intent));
  const relay = await ctx.db
    .query('relays')
    .withIndex('by_node', (q) =>
      q.eq('backendServerId', intent.backendServerId).eq('nodeName', intent.name),
    )
    .first();
  const none = { relay, listener: null, listenerHost: null, edges: [] as string[] };
  if (!relay || !mode?.transport) return none;
  const listener =
    (
      await ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .collect()
    ).find(
      (l) => !l.retired && l.panelBinding?.configProfileInboundUuid === mode.transport!.uuid,
    ) ?? null;
  if (!listener) return none;
  const st = listener.host;
  const listenerHost =
    relay.hostMode === 'fcp' && st?.state === 'present' && st.uuid && !st.op
      ? (hosts.find((h) => h.hostUuid === st.uuid) ?? null)
      : null;
  const edges = (
    await ctx.db
      .query('edges')
      .withIndex('by_relay_publication', (q) =>
        q.eq('relayId', relay._id).eq('publication', 'published'),
      )
      .collect()
  )
    // A front the session can be run through: an L7 one, with its frozen name.
    .filter((e) => e.listenerId === listener._id && !!parseIntent(e.provisionIntent))
    .map((e) => e._id as string);
  return { relay, listener, listenerHost, edges };
}

/** Everything one run (and the sweep's "is anything due") reads. */
async function build(ctx: { db: QueryCtx['db'] }, intent: Intent) {
  if (!intent.twin) return null;
  // A retiring node's addresses, the twin's included, are the retirement's.
  if (intent.state === 'retiring' || intent.state === 'retired') return null;
  const s = await ctx.db.get(intent.backendServerId);
  const setup = await readySetupOf(ctx, intent.backendServerId);
  if (!s || !setup) return null;
  const mode = modeOf(setup, modeSlug(intent));
  const twin = mode?.twin;
  const node = intent.nodeUuid
    ? await ctx.db
        .query('panelNodes')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', intent.backendServerId).eq('nodeUuid', intent.nodeUuid!),
        )
        .unique()
    : null;
  const profile = setup.profileUuid
    ? await ctx.db
        .query('panelProfiles')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', intent.backendServerId).eq('profileUuid', setup.profileUuid!),
        )
        .unique()
    : null;
  const hosts = await ctx.db
    .query('panelHosts')
    .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
    .collect();
  const front = await frontOf(ctx, intent, setup, hosts);
  // Its members are served through its fronts: this origin holds the node's
  // delivery binding (a deferred or released one means raw bodies).
  const delivery = front.relay
    ? await deliveryBindingFor(ctx.db, intent.backendServerId, intent.name)
    : null;
  const rendered =
    !!front.relay &&
    !front.relay.bindingDeferred &&
    !!delivery &&
    delivery.relaySlug === front.relay.slug;
  // A rename in flight moves the node's name and every remark with it.
  const renaming = (
    await ctx.db
      .query('panelNodeRenames')
      .withIndex('by_state', (q) => q.eq('state', 'running'))
      .collect()
  ).some((r) => r.backendServerId === intent.backendServerId && r.intentId === intent._id);
  const twinKey = twin ? await listenerKeyForTag(twin.tag) : null;
  const binding =
    twin && twinKey && setup.profileUuid
      ? {
          key: twinKey,
          panelBinding: {
            inboundTag: twin.tag,
            configProfileUuid: setup.profileUuid,
            configProfileInboundUuid: twin.uuid,
          },
        }
      : null;
  // The twin's address is named like any address of the node's listener, with
  // the twin's key (lib/edges/listenerEncryption.ts): only a listener FCP
  // names itself has one.
  const twinRemark =
    front.listener && binding
      ? (twinRemarksOf({ ...front.listener, encryptedTwin: binding })[0] ?? null)
      : null;
  return {
    intent,
    server: { _id: s._id, backend: s.backend, config: s.config, slug: s.slug },
    rendered,
    renaming,
    twin: twin ?? null,
    binding,
    twinRemark,
    node,
    inbound: twin ? (profile?.inbounds.find((i) => i.inboundUuid === twin.uuid) ?? null) : null,
    hosts,
    relay: front.relay
      ? {
          _id: front.relay._id,
          // A front being replaced or a quarantine rewrites the listener's own
          // address: the twin waits for it.
          busy: !!(front.relay.activeRotationId || front.relay.quarantine),
          // The node is leaving its fronts (a restore to direct, a removal):
          // the twin's address would outlive the listener that explains it.
          leaving: !!(front.relay.restore || front.relay.deleting),
        }
      : null,
    listener: front.listener,
    listenerHost: front.listenerHost,
    edges: front.edges,
  };
}
type RunContext = NonNullable<Awaited<ReturnType<typeof build>>>;

function problemOf(c: RunContext): string | null {
  return nodeTwinProblem({
    twin: c.twin ?? undefined,
    inbound: c.inbound ?? undefined,
    activeInboundUuids: c.node?.activeInboundUuids ?? null,
    listenerReady: !!c.listener && !!c.listenerHost && c.listener.streamTransport === 'ws',
    rendered: c.rendered,
    twinRemark: c.twinRemark,
    listenerRemarkLength: c.listenerHost?.remark.length,
  });
}

/** What the checks are bound to, as a digest (the row keeps no path and no port for it). */
async function revisionOf(c: RunContext): Promise<string | null> {
  const auth = c.inbound?.vlessEncryption?.digest;
  if (!c.twin || !c.inbound || !auth || c.inbound.port === null || !c.inbound.path || !c.listener)
    return null;
  return sha256Hex(
    twinRevision({
      transportUuid: c.twin.uuid,
      authDigest: auth,
      port: c.inbound.port,
      path: c.inbound.path,
      listenerId: c.listener._id,
      listenerRevision: c.listener.revision,
    }),
  );
}

/** Whether the renderer knows the twin as this listener's (its key and its transport). */
function bound(c: RunContext): boolean {
  const have = c.listener?.encryptedTwin;
  const want = c.binding;
  return (
    !!have &&
    !!want &&
    have.key === want.key &&
    have.panelBinding.inboundTag === want.panelBinding.inboundTag &&
    have.panelBinding.configProfileUuid === want.panelBinding.configProfileUuid &&
    have.panelBinding.configProfileInboundUuid === want.panelBinding.configProfileInboundUuid
  );
}

/** The twin's own address: by the uuid recorded, or under its remark on its transport. */
function hostOf(c: RunContext): Doc<'panelHosts'> | null {
  const uuid = c.intent.twin?.hostUuid;
  const byUuid = uuid ? c.hosts.find((h) => h.hostUuid === uuid) : undefined;
  if (byUuid) return byUuid;
  if (!c.twin || !c.twinRemark) return null;
  return (
    c.hosts.find((h) => h.remark === c.twinRemark && h.configProfileInboundUuid === c.twin!.uuid) ??
    null
  );
}

/**
 * Whether a run has anything to do, from the rows as last observed (the sweep
 * asks this so a twin with nothing due costs no look at the backend).
 */
async function workDue(c: RunContext, now: number): Promise<boolean> {
  const t = c.intent.twin!;
  if (t.state !== 'serving' || t.code) return true;
  if (problemOf(c) || !bound(c) || c.relay?.busy || c.relay?.leaving) return true;
  if (t.evidence?.revision !== (await revisionOf(c))) return true;
  const host = hostOf(c);
  if (!host || host.isDisabled || !c.listenerHost || !c.twinRemark) return true;
  if (twinHostDiff(host, desiredTwinHost(c.listenerHost, c.twinRemark))) return true;
  const checks = c.listener?.encryptedTwin?.edges ?? [];
  if (checks.some((x) => !c.edges.includes(x.edgeId))) return true;
  return dueEdges(c.edges, checks, now, TWIN_CHECK_TTL_MS).length > 0;
}

async function audit(
  ctx: MutationCtx,
  intent: Intent,
  action: string,
  payload: Record<string, unknown>,
  actorAdminId?: Id<'adminUsers'>,
) {
  const s = await ctx.db.get(intent.backendServerId);
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'panel_node_intent',
    targetId: intent._id,
    payload: { backendSlug: s?.slug ?? '', name: intent.name, mode: modeSlug(intent), ...payload },
  });
}

/**
 * Where a node's twin stands, for its page: the stage, the route its front
 * server needs and who gives it that route (the node role, or an operator on a
 * node no role runs), and through how many of its published fronts the twin is
 * handed out. Never a key or a client string.
 */
export async function twinViewOf(ctx: { db: QueryCtx['db'] }, intent: Intent) {
  const t = intent.twin;
  if (!t) return null;
  const c = await build(ctx, intent);
  const checks = c?.listener?.encryptedTwin?.edges ?? [];
  return {
    state: t.state,
    code: t.code ?? null,
    route: c?.twin ? twinRoute(c.twin) : null,
    routeBy: intent.adopted ? ('operator' as const) : ('role' as const),
    // Whether the node role was handed the route on its last run (null: no
    // role runs this node, or its last run is from before this was recorded).
    routeServed:
      intent.adopted || !intent.servedRoutes || !c?.twin
        ? null
        : intent.servedRoutes.some((r) => r.path === c.twin!.path && r.port === c.twin!.port),
    fronts: {
      checked: c ? checks.filter((x) => c.edges.includes(x.edgeId)).length : 0,
      published: c?.edges.length ?? 0,
    },
    since: new Date(t.since).toISOString(),
  };
}

// --- admin -----------------------------------------------------------------------------------------

/** Ask a node to serve its mode's encrypted twin. Members get it only through fronts it was checked on. */
export const add = internalMutation({
  args: { intentId: v.id('panelNodeIntents'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    if (intent.state === 'retiring' || intent.state === 'retired')
      refuse('servers.node_retiring', 'This node is being retired');
    if (!(await resolveServerConfig(ctx.db)).manage.enabled)
      refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
    if (intent.twin) refuse('servers.node_twin_present', WORDS['servers.node_twin_present']!);
    const setup = await readySetupOf(ctx, intent.backendServerId);
    if (!setup) return refuse('servers.panel_not_set_up', 'The backend is not set up');
    const twin = modeOf(setup, modeSlug(intent))?.twin;
    if (!twin || twin.detaching) refuse('servers.twin_absent', WORDS['servers.twin_absent']!);
    // The twin is checked through the node's own fronts and rides their
    // listener: a node whose front another tool runs has neither here. Read
    // from what FCP runs today, never from how the node was adopted: a node
    // adopted while an earlier tool fronted it (`adopted.externallyFronted`)
    // keeps that flag after FCP's own edges took over its front.
    const hosts = await ctx.db
      .query('panelHosts')
      .withIndex('by_server', (q) => q.eq('backendServerId', intent.backendServerId))
      .collect();
    const front = await frontOf(ctx, intent, setup, hosts);
    if (!front.listener || !front.listenerHost)
      refuse('servers.node_twin_no_front', WORDS['servers.node_twin_no_front']!);
    const delivery = await deliveryBindingFor(ctx.db, intent.backendServerId, intent.name);
    if (front.relay!.bindingDeferred || delivery?.relaySlug !== front.relay!.slug)
      refuse('servers.node_twin_not_rendered', WORDS['servers.node_twin_not_rendered']!);
    const now = Date.now();
    await ctx.db.patch(intent._id, {
      twin: { state: 'activating', byAdminId: a.actorAdminId, since: now, updatedAt: now },
      updatedAt: now,
    });
    await audit(ctx, intent, 'admin.servers.node_twin.add', {}, a.actorAdminId);
    // The node reconcile turns the transport on, then asks this module's run.
    await ctx.scheduler.runAfter(0, internal.nodeIntents.reconcileNow, { intentId: intent._id });
    return { state: 'activating' as const };
  },
});

/** Stop serving the twin: no front counted, address off and removed, then the transport. */
export const remove = internalMutation({
  args: { intentId: v.id('panelNodeIntents'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const t = intent.twin;
    if (!t) return refuse('servers.node_twin_absent', WORDS['servers.node_twin_absent']!);
    const now = Date.now();
    await ctx.db.patch(intent._id, {
      twin: {
        ...t,
        state: 'removing',
        code: undefined,
        // A run holding the node now may end on what it read before: it runs
        // again when it releases, so the removal is never left waiting.
        rerun: t.lease && t.lease.expiresAt > now ? true : t.rerun,
        updatedAt: now,
      },
      updatedAt: now,
    });
    await audit(ctx, intent, 'admin.servers.node_twin.remove', {}, a.actorAdminId);
    await ctx.scheduler.runAfter(0, internal.nodeTwins.run, { intentId: intent._id });
    return { state: 'removing' as const };
  },
});

/**
 * After a node reconcile: the twin looks at what it left (its transport). A
 * serving twin with nothing due is left alone: most reconciles are not about it.
 */
export const kick = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    const t = intent?.twin;
    if (!intent || !t) return false;
    const now = Date.now();
    if (t.lease && t.lease.expiresAt > now) {
      // What this kick reports may be after the running run's look.
      if (!t.rerun) await ctx.db.patch(intent._id, { twin: { ...t, rerun: true } });
      return false;
    }
    if (t.state === 'serving') {
      const c = await build(ctx, intent);
      if (c && !(await workDue(c, now))) return false;
    }
    await ctx.scheduler.runAfter(0, internal.nodeTwins.run, { intentId });
    return true;
  },
});

/** Every twin with something due (a front's check an hour old, a moved address, a failed start). */
export const due = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }): Promise<Id<'panelNodeIntents'>[]> => {
    const out: Id<'panelNodeIntents'>[] = [];
    // One row per node: a small operator table.
    for (const intent of await ctx.db.query('panelNodeIntents').collect()) {
      const t = intent.twin;
      if (!t || (t.lease && t.lease.expiresAt > now)) continue;
      const c = await build(ctx, intent);
      if (c && (await workDue(c, now))) out.push(intent._id);
    }
    return out;
  },
});

/** The periodic look (the node sweep calls it): run each twin that has something due. */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<number> => {
    if (!(await ctx.runQuery(internal.serverAdmin.manageEnabled, {}))) return 0;
    const ids = await ctx.runQuery(internal.nodeTwins.due, { now: Date.now() });
    for (const intentId of ids)
      await ctx.scheduler.runAfter(0, internal.nodeTwins.run, { intentId });
    return ids.length;
  },
});

// --- the run ---------------------------------------------------------------------------------------

export const claim = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    const t = intent?.twin;
    const now = Date.now();
    if (!intent || !t) return null;
    if (t.lease && t.lease.expiresAt > now) return null;
    const attemptId = crypto.randomUUID();
    await ctx.db.patch(intent._id, {
      twin: { ...t, lease: { attemptId, expiresAt: now + LEASE_MS } },
    });
    return attemptId;
  },
});

const fence = { intentId: v.id('panelNodeIntents'), attemptId: v.string() };

/** The node's twin while `attemptId` still holds its lease, else null. */
async function held(ctx: MutationCtx, f: { intentId: Id<'panelNodeIntents'>; attemptId: string }) {
  const intent = await ctx.db.get(f.intentId);
  const t = intent?.twin;
  return intent && t && t.lease?.attemptId === f.attemptId ? { intent, t } : null;
}

/** A write still settling or a look that lags: tried again in seconds. */
const SETTLING = new Set(['servers.op_running', 'servers.observe_lag']);

const recordPatch = v.object({
  state: v.optional(v.union(v.literal('activating'), v.literal('serving'), v.literal('removing'))),
  code: v.optional(v.union(v.string(), v.null())),
  hostUuid: v.optional(v.union(v.string(), v.null())),
  evidence: v.optional(v.union(v.object({ revision: v.string(), at: v.number() }), v.null())),
  // The run stopped on something that clears by itself in seconds.
  retry: v.optional(v.boolean()),
  // The run has more to do than one run does (more fronts than it checks at once).
  again: v.optional(v.boolean()),
  drop: v.optional(v.boolean()),
  release: v.optional(v.boolean()),
});

/** What a run learned, recorded only while it still holds the node's lease. */
export const record = internalMutation({
  args: {
    ...fence,
    patch: recordPatch,
    audit: v.optional(
      v.object({
        action: v.string(),
        detail: v.optional(v.string()),
        fronts: v.optional(v.number()),
      }),
    ),
  },
  handler: async (ctx, a) => {
    const h = await held(ctx, a);
    if (!h) return { ok: false };
    const { intent, t } = h;
    const p = a.patch;
    // An admin's removal while the run worked wins over the run's own state.
    const state: Twin['state'] = t.state === 'removing' ? 'removing' : (p.state ?? t.state);
    if (p.drop) {
      await ctx.db.patch(intent._id, { twin: undefined, updatedAt: Date.now() });
    } else {
      const settling = p.retry && !!p.code && SETTLING.has(p.code);
      const retries = settling ? (t.retries ?? 0) + 1 : p.code === null ? undefined : t.retries;
      // Anything that does not clear in seconds waits for the sweep or a kick.
      if (settling)
        await ctx.scheduler.runAfter(
          Math.min(60_000, 5_000 * 2 ** Math.min((retries ?? 1) - 1, 4)),
          internal.nodeTwins.run,
          { intentId: intent._id },
        );
      const rerun = p.again ? true : t.rerun;
      await ctx.db.patch(intent._id, {
        twin: {
          ...t,
          state,
          retries,
          code: p.code === undefined ? t.code : (p.code ?? undefined),
          hostUuid: p.hostUuid === undefined ? t.hostUuid : (p.hostUuid ?? undefined),
          evidence: p.evidence === undefined ? t.evidence : (p.evidence ?? undefined),
          lease: p.release ? undefined : t.lease,
          rerun: p.release ? undefined : rerun,
          updatedAt: Date.now(),
        },
        updatedAt: Date.now(),
      });
      if (p.release && rerun)
        await ctx.scheduler.runAfter(0, internal.nodeTwins.run, { intentId: intent._id });
    }
    if (a.audit)
      await audit(ctx, intent, a.audit.action, {
        ...(a.audit.detail ? { code: a.audit.detail } : {}),
        ...(a.audit.fronts !== undefined ? { fronts: a.audit.fronts } : {}),
      });
    // The transport is on from the ask until the twin is gone: only then does
    // the node's own set change again.
    if (p.drop)
      await ctx.scheduler.runAfter(0, internal.nodeIntents.reconcileNow, { intentId: intent._id });
    return { ok: true };
  },
});

/**
 * Name the twin to the renderer as this listener's (its key and transport),
 * with no front counted. Its entry is then never passed through as it comes
 * from the backend: it is a template like the plain one.
 */
export const bindListener = internalMutation({
  args: {
    ...fence,
    listenerId: v.id('relayListeners'),
    key: v.string(),
    panelBinding: v.object({
      inboundTag: v.string(),
      configProfileUuid: v.string(),
      configProfileInboundUuid: v.string(),
    }),
  },
  handler: async (ctx, a) => {
    if (!(await held(ctx, a))) return { ok: false };
    const l = await ctx.db.get(a.listenerId);
    if (!l) return { ok: false };
    const had = (l.encryptedTwin?.edges ?? []).length > 0;
    await ctx.db.patch(l._id, {
      encryptedTwin: { key: a.key, panelBinding: a.panelBinding, edges: [] },
      updatedAt: Date.now(),
    });
    const relay = await ctx.db.get(l.relayId);
    if (had && relay) await bumpEpochAndRefresh(ctx, relay);
    return { ok: true };
  },
});

/**
 * The fronts the twin is handed out through. What members should receive
 * changes with the set, so the origin's epoch moves and mirrors are refreshed.
 */
export const setEdges = internalMutation({
  args: {
    ...fence,
    listenerId: v.id('relayListeners'),
    edges: v.array(v.object({ edgeId: v.string(), checkedAt: v.number() })),
  },
  handler: async (ctx, a) => {
    if (!(await held(ctx, a))) return { ok: false };
    const l = await ctx.db.get(a.listenerId);
    if (!l?.encryptedTwin) return { ok: false };
    const was = new Set((l.encryptedTwin.edges ?? []).map((e) => e.edgeId));
    const now = new Set(a.edges.map((e) => e.edgeId));
    const changed = was.size !== now.size || [...was].some((id) => !now.has(id));
    await ctx.db.patch(l._id, {
      encryptedTwin: { ...l.encryptedTwin, edges: a.edges },
      updatedAt: Date.now(),
    });
    const relay = await ctx.db.get(l.relayId);
    if (changed && relay) await bumpEpochAndRefresh(ctx, relay);
    return { ok: true };
  },
});

/** The renderer forgets the twin (its address is gone from the backend). */
export const unbindListener = internalMutation({
  args: { ...fence, listenerId: v.id('relayListeners') },
  handler: async (ctx, a) => {
    if (!(await held(ctx, a))) return { ok: false };
    const l = await ctx.db.get(a.listenerId);
    if (!l?.encryptedTwin) return { ok: true };
    const had = (l.encryptedTwin.edges ?? []).length > 0;
    await ctx.db.patch(l._id, { encryptedTwin: undefined, updatedAt: Date.now() });
    const relay = await ctx.db.get(l.relayId);
    if (had && relay) await bumpEpochAndRefresh(ctx, relay);
    return { ok: true };
  },
});

export const context = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    return intent ? build(ctx, intent) : null;
  },
});

async function loadContext(ctx: ActionCtx, intentId: Id<'panelNodeIntents'>) {
  return ctx.runQuery(internal.nodeTwins.context, { intentId });
}

class Stop extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function codeOf(err: unknown, fallback: string): string {
  if (err instanceof Stop) return err.code;
  return err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
    ? (err.data as { code: string }).code
    : fallback;
}

/** One backend write through the ledger, sent and looked at; never two at once. */
async function write(ctx: ActionCtx, make: () => Promise<{ opId: Id<'panelOps'> }>): Promise<void> {
  const { opId } = await make();
  const r = await ctx.runAction(internal.backendWrites.run, { opId });
  if (r.open) throw new Stop('servers.op_running');
}

async function step(ctx: ActionCtx, intentId: Id<'panelNodeIntents'>, attemptId: string) {
  const f = { intentId, attemptId };
  const rec = (
    patch: {
      state?: Twin['state'];
      code?: string | null;
      hostUuid?: string | null;
      evidence?: { revision: string; at: number } | null;
      again?: boolean;
      drop?: boolean;
    },
    auditAction?: { action: string; detail?: string; fronts?: number },
  ) =>
    ctx.runMutation(internal.nodeTwins.record, {
      ...f,
      patch,
      ...(auditAction ? { audit: auditAction } : {}),
    });
  let c = await loadContext(ctx, intentId);
  if (!c) return;
  const reload = async () => {
    await observeInstance(ctx, c!.server);
    c = await loadContext(ctx, intentId);
    if (!c) throw new Stop('not_found');
  };
  // A fresh look first: the node reconcile that turned the transport on may
  // have parked before it read the backend again.
  await reload();
  const twin = () => c!.intent.twin!;
  // The node's own actor: the retirement waits for every open write under it.
  const actorRun = `node:${intentId}`;
  const setDisabled = (hostUuid: string, isDisabled: boolean) =>
    write(ctx, () =>
      ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
        backendServerId: c!.server._id,
        hostUuid,
        isDisabled,
        actorRun,
      }),
    );
  /** Turn the address off and SEE it off: a refused write is never taken for one. */
  const switchOff = async (hostUuid: string) => {
    await setDisabled(hostUuid, true);
    await reload();
    const h = c!.hosts.find((x) => x.hostUuid === hostUuid);
    if (h && !h.isDisabled) throw new Stop('servers.node_twin_close_failed');
  };
  const setEdges = async (edges: TwinEdgeCheck[]) => {
    if (!c!.listener?.encryptedTwin) return;
    await ctx.runMutation(internal.nodeTwins.setEdges, {
      ...f,
      listenerId: c!.listener._id,
      edges,
    });
  };
  /** No front counted first (members stop being handed it), then the address off. */
  const close = async () => {
    if ((c!.listener?.encryptedTwin?.edges ?? []).length > 0) await setEdges([]);
    const host = hostOf(c!);
    if (host && !host.isDisabled) await switchOff(host.hostUuid);
  };

  if (twin().state === 'removing') {
    if (c.renaming) throw new Stop('servers.node_rename_running');
    await close();
    const host = hostOf(c);
    if (host) {
      await write(ctx, () =>
        ctx.runMutation(internal.backendWrites.requestAddressDelete, {
          backendServerId: c!.server._id,
          hostUuid: host.hostUuid,
          actorRun,
        }),
      );
      await reload();
      if (c.hosts.some((h) => h.hostUuid === host.hostUuid)) throw new Stop('servers.observe_lag');
    }
    if (c.listener?.encryptedTwin)
      await ctx.runMutation(internal.nodeTwins.unbindListener, {
        ...f,
        listenerId: c.listener._id,
      });
    await rec({ drop: true }, { action: 'servers.node.twin_removed' });
    return;
  }

  /**
   * A twin that can no longer be vouched for closes before the run stops:
   * no front counted and its address off, whatever state the row is in (a run
   * that died after switching the address on left it on).
   */
  const stopOn = async (code: string): Promise<never> => {
    await close();
    if (twin().state === 'serving')
      await rec(
        { state: 'activating', evidence: null, code },
        { action: 'servers.node.twin_closed', detail: code },
      );
    throw new Stop(code);
  };

  // A rename moves the node's name and the twin's remark with it: it waits.
  if (c.renaming) throw new Stop('servers.node_rename_running');
  // The node is leaving its fronts: the twin's address goes off first, so it
  // never outlives the listener that makes its entry a template.
  if (c.relay?.leaving) await stopOn('servers.node_twin_no_front');
  // The listener's own address is being rewritten (a front replaced, a
  // quarantine): nothing of the twin is written or checked meanwhile. What it
  // serves through stays as it was; a front that left is no longer published,
  // so no entry is made for it.
  if (c.relay?.busy) throw new Stop('servers.node_twin_front_busy');
  const problem = problemOf(c);
  if (problem) await stopOn(problem);
  const inbound = c.inbound!;
  const listener = c.listener!;
  const encryption = inbound.vlessEncryption!.encryption!;
  const path = inbound.path!;
  const revision = (await revisionOf(c))!;
  const want = desiredTwinHost(c.listenerHost!, c.twinRemark!);

  // The address: found by the uuid recorded for it, or (a create whose answer
  // was lost) under its remark on the twin's transport. Created switched off.
  let host = hostOf(c);
  if (host && host.hostUuid !== twin().hostUuid) await rec({ hostUuid: host.hostUuid });
  if (!host) {
    await write(ctx, () =>
      ctx.runMutation(internal.backendWrites.requestAddressCreate, {
        backendServerId: c!.server._id,
        remark: want.remark,
        address: want.address,
        port: want.port,
        ...(want.sni ? { sni: want.sni } : {}),
        ...(want.host ? { host: want.host } : {}),
        ...(want.alpn ? { alpn: want.alpn } : {}),
        ...(want.fingerprint ? { fingerprint: want.fingerprint } : {}),
        ...(want.securityLayer ? { securityLayer: want.securityLayer } : {}),
        isDisabled: true,
        inboundUuid: c!.twin!.uuid,
        relayTwin: true,
        // A twin taken away and asked for again is recreated on purpose: the
        // mark its removal left on the name does not stand in the way.
        restore: true,
        actorRun,
      }),
    );
    await reload();
    host = hostOf(c);
    if (!host) throw new Stop('servers.observe_lag');
    await rec({ hostUuid: host.hostUuid });
  } else {
    // It follows the listener's own address (a replaced front moved it). Both
    // are templates the renderer rewrites per front, so it is not closed for it.
    const diff = twinHostDiff(host, want);
    if (diff) {
      await write(ctx, () =>
        ctx.runMutation(internal.backendWrites.requestAddressUpdate, {
          backendServerId: c!.server._id,
          hostUuid: host!.hostUuid,
          ...diff,
          relayTwin: true,
          actorRun,
        }),
      );
      await reload();
      host = hostOf(c);
      if (!host || twinHostDiff(host, want)) throw new Stop('servers.observe_lag');
    }
  }

  // The renderer must know the entry as a twin BEFORE the address is ever on.
  if (!bound(c)) {
    await ctx.runMutation(internal.nodeTwins.bindListener, {
      ...f,
      listenerId: listener._id,
      ...c.binding!,
    });
    c = (await loadContext(ctx, intentId))!;
    if (!c || !bound(c)) throw new Stop('servers.observe_lag');
    host = hostOf(c);
    if (!host) throw new Stop('servers.observe_lag');
  }

  // Serving, but something its checks were made under moved: the twin alone closes.
  if (twin().state === 'serving' && twin().evidence?.revision !== revision) {
    await close();
    await rec(
      { state: 'activating', evidence: null, code: 'servers.node_twin_drifted' },
      { action: 'servers.node.twin_closed', detail: 'servers.node_twin_drifted' },
    );
    c = (await loadContext(ctx, intentId))!;
    if (!c) throw new Stop('not_found');
    host = hostOf(c);
    if (!host) throw new Stop('servers.observe_lag');
  }

  if (!c.node?.online) await stopOn('servers.node_offline');
  if (c.edges.length === 0) await stopOn('servers.node_twin_no_front');

  // The fronts: one session each, through the front, at the twin's path, with
  // the twin's client string. A check counts for an hour.
  const checks =
    twin().evidence?.revision === revision ? (c.listener?.encryptedTwin?.edges ?? []) : [];
  const now = Date.now();
  const allDue = dueEdges(c.edges, checks, now, TWIN_CHECK_TTL_MS);
  const rechecked = new Set<string>();
  const passed: TwinEdgeCheck[] = [];
  let failed = 0;
  let firstFailure: string | null = null;
  // More due than one run checks: start somewhere else each time, so fronts
  // that keep failing never hold the others back.
  const start = allDue.length > CHECKS_PER_RUN ? Math.floor(now / 1000) % allDue.length : 0;
  const turn = [...allDue.slice(start), ...allDue.slice(0, start)].slice(0, CHECKS_PER_RUN);
  for (const edgeId of turn) {
    const r = await ctx.runAction(internal.frontQualifyOps.runTwin, {
      edgeId: edgeId as Id<'edges'>,
      path,
      encryption,
    });
    rechecked.add(edgeId);
    if (r.ok) passed.push({ edgeId, checkedAt: Date.now() });
    else {
      failed++;
      firstFailure ??= r.detail ? `${r.code}:${r.detail}` : (r.code ?? 'failed');
    }
  }
  const next = [...keptChecks(c.edges, checks, rechecked), ...passed];
  const again = allDue.length > rechecked.size;

  if (next.length === 0) {
    // Never left on unproven: no front counted, the address off, seen off.
    await close();
    // Said once, not on every look while the route is still missing.
    const told = twin().code === 'servers.node_twin_check_failed';
    await rec(
      { state: 'activating', evidence: null, code: 'servers.node_twin_check_failed', again },
      told
        ? undefined
        : {
            action: 'servers.node.twin_check_failed',
            detail: (firstFailure ?? 'failed').slice(0, 120),
          },
    );
    return;
  }
  if (host.isDisabled) {
    await setDisabled(host.hostUuid, false);
    await reload();
    if (hostOf(c)?.isDisabled !== false) throw new Stop('servers.observe_lag');
  }
  await setEdges(next);
  const wasServing = twin().state === 'serving';
  // A front the twin was handed out through stopped carrying it (said when it
  // is lost, not on every look while it stays lost).
  const lost = checks.some(
    (x) => c!.edges.includes(x.edgeId) && !next.some((n) => n.edgeId === x.edgeId),
  );
  await rec(
    { state: 'serving', code: null, evidence: { revision, at: now }, again },
    wasServing
      ? failed > 0 && lost
        ? {
            action: 'servers.node.twin_front_failed',
            detail: (firstFailure ?? 'failed').slice(0, 120),
            fronts: next.length,
          }
        : undefined
      : { action: 'servers.node.twin_serving', fronts: next.length },
  );
}

/** Run a node's twin: one run at a time, under its lease. */
export const run = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<null> => {
    const c = await loadContext(ctx, intentId);
    if (!c) return null;
    if (!(await ctx.runQuery(internal.serverAdmin.manageEnabled, {}))) return null;
    const attemptId = await ctx.runMutation(internal.nodeTwins.claim, { intentId });
    if (!attemptId) return null;
    try {
      await step(ctx, intentId, attemptId);
    } catch (err) {
      const code = codeOf(err, 'servers.node_twin_failed');
      await ctx
        .runMutation(internal.nodeTwins.record, {
          intentId,
          attemptId,
          patch: { code, retry: true },
        })
        .catch(() => undefined);
    } finally {
      await ctx
        .runMutation(internal.nodeTwins.record, { intentId, attemptId, patch: { release: true } })
        .catch(() => undefined);
    }
    return null;
  },
});
