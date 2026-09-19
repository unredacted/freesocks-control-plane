/**
 * Node intents: the bootstrap contract v2 between the node role and FCP
 * (docs/servers.md "Node lifecycle"). The role enrolls a node ONCE (purpose,
 * name, label) and reports observations on every run; FCP owns the machine
 * settings (ingress, origin hostname, node port), the panel row, the direct
 * Host, the origin DNS record and the release to members. Every workflow
 * step is fenced by (generation, attempt) and resumed by the sweep; external
 * side effects are obligations persisted before the call.
 *
 * Stages: registered -> bootstrap_available -> machine_applied ->
 * machine_ready -> candidates_verified -> awaiting_approval -> activating ->
 * live. Nothing reaches a member before the delivery commit
 * (panelActivation.ts); until then the node's gate is closed.
 */
import { ConvexError, v, type Infer } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { runWithCronOutcome } from './cronHeartbeat';
import { writeAuditLog } from './lib/audit';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import {
  classifyChange,
  retainEvidence,
  stageAfterChange,
  type Evidence,
  type Revisions,
  type Stage,
} from './lib/panel/activation';
import { nodeGateOf, type NodeGate } from './lib/panel/deliveryGate';
import { CLAIM_LEASE_MS, claimAvailable, desiredHashOf, fenceHolds } from './lib/panel/fencing';
import type { IngressMapping } from './lib/panel/ingress';
import { LABEL_RE, originHostname, originLabel } from './lib/panel/originDns';
import { BOOTSTRAP_TAGS } from './lib/panel/profileTemplate';
import { resolveServerConfig } from './lib/serverConfig';
import { observeInstance } from './panelObserve';
import { bumpGateVersion } from './panelSetup';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

export const ROLE_CONTRACT_VERSION = 2;
const NODE_NAME = /^[A-Za-z0-9 ._-]{3,30}$/;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i;

export const purpose = v.union(v.literal('direct'), v.literal('front'), v.literal('relay'));
export type Purpose = 'direct' | 'front' | 'relay';

const observed = v.object({
  management: v.object({ address: v.string(), port: v.number() }),
  publicIps: v.object({ v4: v.optional(v.string()), v6: v.optional(v.string()) }),
  capabilities: v.object({ caddy: v.boolean(), ipv6: v.boolean() }),
});

const fence = { intentId: v.id('panelNodeIntents'), generation: v.number(), attemptId: v.string() };
type Fence = { intentId: Id<'panelNodeIntents'>; generation: number; attemptId: string };

type Intent = Doc<'panelNodeIntents'>;
type Setup = Doc<'panelSetups'>;

async function intentByName(
  ctx: { db: QueryCtx['db'] },
  sid: Id<'backendServers'>,
  name: string,
): Promise<Intent | null> {
  return ctx.db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) => q.eq('backendServerId', sid).eq('name', name))
    .unique();
}

async function readySetup(ctx: { db: QueryCtx['db'] }, sid: Id<'backendServers'>) {
  const row = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  return row && row.state === 'ready' && row.inbounds && row.profileUuid ? row : null;
}

/** The purpose's inbound on the setup row. */
export function inboundFor(setup: Setup, p: Purpose) {
  const ib = setup.inbounds!;
  return p === 'front' ? ib.cdn : p === 'direct' ? ib.reality : ib.relay;
}

/** The FCP-owned machine settings a fresh enrollment starts with. */
function defaultSettings(setup: Setup, p: Purpose): Intent['settings'] {
  const cdn = setup.inbounds!.cdn;
  return {
    ingress:
      p === 'front'
        ? {
            externalPort: 443,
            hostHeader: 'any',
            internal: [{ inboundTag: cdn.tag, listen: cdn.listen, port: cdn.port, path: cdn.path }],
          }
        : undefined,
    originHostnameSource: p === 'front' ? (setup.originDns ? 'managed' : 'explicit') : 'none',
    publishV6: false,
    nodePort: 2222,
  };
}

/** The origin hostname a front node presents, from its settings and the setup's zone. */
export function originHostnameOf(intent: Intent, setup: Setup | null): string | undefined {
  const s = intent.settings;
  if (s.originHostnameSource === 'managed' && setup?.originDns)
    return originHostname(intent.label, setup.originDns.zoneName);
  if (s.originHostnameSource === 'explicit') return s.explicitHostname;
  return undefined;
}

/** What edges dial (never published): the origin hostname for a front node, else the public v4. */
export function originAddressOf(intent: Intent, hostname: string | undefined): string {
  const s = intent.settings;
  if (s.originAddressOverride) return s.originAddressOverride;
  if (intent.purpose === 'front' && hostname) return hostname;
  return intent.observed.publicIps.v4 ?? intent.observed.management.address;
}

export function ingressOf(intent: Intent, hostname: string | undefined): IngressMapping | null {
  const i = intent.settings.ingress;
  if (!i || !hostname) return null;
  return {
    hostname,
    external: { port: i.externalPort, tls: 'caddy', hostHeader: i.hostHeader },
    internal: i.internal,
  };
}

function revisionsOf(intent: Intent): Revisions {
  return {
    machineRevision: intent.machineRevision,
    configRevision: intent.configRevision ?? '',
    authRevision: intent.authRevision,
    deliveryRevision: intent.deliveryRevision ?? '',
  };
}

// --- enrollment (the role) -------------------------------------------------------------------------

export const enroll = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    name: v.string(),
    label: v.optional(v.string()),
    purpose,
    contractVersion: v.number(),
    observed,
    tokenId: v.optional(v.id('apiTokens')),
  },
  handler: async (ctx, a) => {
    const sid = a.backendServerId;
    const cfg = await resolveServerConfig(ctx.db);
    if (!cfg.manage.enabled)
      refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
    if (a.contractVersion < ROLE_CONTRACT_VERSION)
      refuse(
        'servers.contract_version',
        `This panel expects role contract v${ROLE_CONTRACT_VERSION}`,
      );
    if (!NODE_NAME.test(a.name)) refuse('validation', 'A node name is 3 to 30 plain characters');
    const setup = await readySetup(ctx, sid);
    if (!setup) refuse('servers.panel_not_set_up', 'Set up this panel in Servers first');
    const o = a.observed;
    if (o.management.address.trim().length < 2)
      refuse('validation', 'A management address is required');
    if (!Number.isInteger(o.management.port) || o.management.port < 1 || o.management.port > 65535)
      refuse('validation', 'A management port is 1 to 65535');
    if (o.publicIps.v4 !== undefined && !IPV4.test(o.publicIps.v4))
      refuse('validation', 'publicIps.v4 is not an IPv4 address');
    const now = Date.now();
    let intent = await intentByName(ctx, sid, a.name);
    if (intent) {
      if (intent.state === 'retiring' || intent.state === 'retired')
        refuse('servers.node_retiring', 'This node is being retired. Enroll it under a new name');
      if (intent.purpose !== a.purpose)
        refuse(
          'servers.purpose_change_needs_admin',
          'A node keeps its purpose. An admin changes it from Servers',
        );
      const desiredHash = await desiredHashOf({ observed: o, settings: intent.settings });
      const changed = desiredHash !== intent.desiredHash;
      await ctx.db.patch(intent._id, {
        observed: { ...o, at: now },
        contractVersion: a.contractVersion,
        desiredHash,
        generation: changed ? intent.generation + 1 : intent.generation,
        tokenId: a.tokenId,
        updatedAt: now,
      });
      intent = (await ctx.db.get(intent._id))!;
    } else {
      // An existing panel node or Host of this name that no intent owns is an
      // adoption decision for an admin, never the token's.
      const nodes = await ctx.db
        .query('panelNodes')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect();
      if (nodes.some((n) => n.name === a.name))
        refuse(
          'servers.node_exists_unowned',
          'A node with this name exists on the panel. Adopt it from Servers first',
        );
      const tomb = (
        await ctx.db
          .query('panelOwnership')
          .withIndex('by_server_kind_identity', (q) =>
            q.eq('backendServerId', sid).eq('kind', 'node'),
          )
          .collect()
      ).some((r) => r.state === 'tombstoned' && r.lookup.includes(a.name));
      if (tomb)
        refuse(
          'servers.tombstoned',
          'This node was removed on purpose. An admin restores it from Servers',
        );
      const label = a.label ?? originLabel(a.name);
      if (!label || !LABEL_RE.test(label))
        return refuse(
          'servers.origin_label_invalid',
          'The label must be a DNS label (a-z, 0-9, hyphens)',
        );
      const hosts = await ctx.db
        .query('panelHosts')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect();
      if (a.purpose === 'direct' && hosts.some((h) => h.remark === `${a.name}-reality`))
        refuse(
          'servers.node_exists_unowned',
          'A Host with this node name exists on the panel. Adopt it from Servers first',
        );
      const settings = defaultSettings(setup!, a.purpose);
      const desiredHash = await desiredHashOf({ observed: o, settings });
      const id = await ctx.db.insert('panelNodeIntents', {
        backendServerId: sid,
        name: a.name,
        label,
        purpose: a.purpose,
        contractVersion: a.contractVersion,
        generation: 1,
        desiredHash,
        state: 'pending',
        observed: { ...o, at: now },
        settings,
        machineRevision: 1,
        activation: { stage: 'registered', evidence: [] },
        delivery: {
          disposition: 'staged',
          acceptingAssignments: false,
          exposure: { everLive: false, hosts: [], mirrors: 0, testCredentials: 0, dns: 0 },
        },
        origin: { dns: 'none' },
        tokenId: a.tokenId,
        registeredAt: now,
        updatedAt: now,
      });
      intent = (await ctx.db.get(id))!;
      const server = await ctx.db.get(sid);
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'servers.node.registered',
        targetType: 'panel_node_intent',
        targetId: id,
        payload: { backendSlug: server?.slug ?? '', name: a.name, purpose: a.purpose },
      });
    }
    await scheduleReconcile(ctx, intent);
    return { intentId: intent._id, generation: intent.generation };
  },
});

/** Take the lease and schedule the reconcile, unless an attempt already holds it. */
async function scheduleReconcile(ctx: MutationCtx, intent: Intent) {
  const now = Date.now();
  if (!claimAvailable(intent, now)) return false;
  const attemptId = crypto.randomUUID();
  await ctx.db.patch(intent._id, {
    claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS },
    updatedAt: now,
  });
  await ctx.scheduler.runAfter(0, internal.panelIntents.reconcile, {
    intentId: intent._id,
    generation: intent.generation,
    attemptId,
  });
  return true;
}

// --- machine settings (the admin) -------------------------------------------------------------------

const settingsPatch = v.object({
  ingress: v.optional(
    v.object({
      externalPort: v.number(),
      hostHeader: v.union(v.literal('any'), v.literal('hostname')),
      internal: v.array(
        v.object({
          inboundTag: v.string(),
          listen: v.string(),
          port: v.number(),
          path: v.string(),
        }),
      ),
    }),
  ),
  explicitHostname: v.optional(v.string()),
  originAddressOverride: v.optional(v.union(v.string(), v.null())),
  publishV6: v.optional(v.boolean()),
  nodePort: v.optional(v.number()),
  countryCode: v.optional(v.union(v.string(), v.null())),
});

/**
 * Change FCP-owned machine settings. A change that rewrites the running path
 * is applied in place and needs an explicit maintenance transition (the node
 * is closed until re-approved); a change that only adds a path is preparable.
 */
export const patchSettings = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    patch: settingsPatch,
    maintenance: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    if (intent.state === 'retiring' || intent.state === 'retired')
      refuse('servers.node_retiring', 'This node is being retired');
    const p = a.patch;
    const s = intent.settings;
    const next: Intent['settings'] = { ...s };
    let addsPath = false;
    let rewritesPath = false;
    if (p.ingress !== undefined) {
      if (!s.ingress) addsPath = true;
      else {
        const same = (x: typeof p.ingress, y: NonNullable<typeof s.ingress>) =>
          x.externalPort === y.externalPort &&
          x.hostHeader === y.hostHeader &&
          y.internal.every((r) =>
            x.internal.some(
              (q) => q.inboundTag === r.inboundTag && q.port === r.port && q.path === r.path,
            ),
          );
        if (!same(p.ingress, s.ingress)) rewritesPath = true;
        else if (p.ingress.internal.length > s.ingress.internal.length) addsPath = true;
      }
      next.ingress = p.ingress;
    }
    if (p.explicitHostname !== undefined) {
      if (!HOSTNAME_RE.test(p.explicitHostname)) refuse('validation', 'Not a hostname');
      if (s.explicitHostname !== p.explicitHostname) rewritesPath = true;
      next.explicitHostname = p.explicitHostname.toLowerCase();
      next.originHostnameSource = 'explicit';
    }
    if (p.originAddressOverride !== undefined) {
      if ((s.originAddressOverride ?? null) !== p.originAddressOverride) rewritesPath = true;
      next.originAddressOverride = p.originAddressOverride ?? undefined;
    }
    if (p.publishV6 !== undefined && p.publishV6 !== s.publishV6) {
      // Publishing v6 adds a record; withdrawing it rewrites what resolves.
      if (p.publishV6) addsPath = true;
      else rewritesPath = true;
      next.publishV6 = p.publishV6;
    }
    if (p.nodePort !== undefined && p.nodePort !== s.nodePort) {
      if (!Number.isInteger(p.nodePort) || p.nodePort < 1 || p.nodePort > 65535)
        refuse('validation', 'A port is 1 to 65535');
      rewritesPath = true;
      next.nodePort = p.nodePort;
    }
    if (p.countryCode !== undefined) {
      if (p.countryCode !== null && !/^[A-Za-z]{2}$/.test(p.countryCode))
        refuse('validation', 'A country is two letters');
      next.countryCode = p.countryCode?.toUpperCase() ?? undefined;
    }
    const kind = classifyChange({ addsPath, rewritesPath });
    if (kind === 'none' && p.countryCode === undefined) refuse('validation', 'Nothing to change');
    const now = Date.now();
    const patch: Partial<Intent> = { settings: next, updatedAt: now };
    if (kind !== 'none') {
      if (kind === 'in_place' && intent.delivery.disposition === 'live' && !a.maintenance)
        refuse(
          'servers.maintenance_required',
          'This change rewrites the running path. Start it as a maintenance transition',
        );
      const machineRevision = intent.machineRevision + 1;
      const revs = { ...revisionsOf(intent), machineRevision };
      const evidence = retainEvidence(intent.activation.evidence, revs);
      patch.machineRevision = machineRevision;
      patch.activation = {
        ...intent.activation,
        evidence,
        stage: stageAfterChange(intent.activation.stage, evidence),
        reviewHash: undefined,
      };
      if (kind === 'in_place' && intent.delivery.disposition === 'live') {
        patch.delivery = { ...intent.delivery, disposition: 'unavailable' };
        patch.maintenance = {
          id: crypto.randomUUID(),
          reason: 'settings',
          since: now,
          byAdminId: a.actorAdminId,
        };
        await bumpGateVersion(ctx, intent.backendServerId);
      }
      patch.desiredHash = await desiredHashOf({ observed: intent.observed, settings: next });
      patch.generation = intent.generation + 1;
      // A revision moved: no activation run of the old revisions may commit.
      for (const r of await ctx.db
        .query('panelActivationRuns')
        .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
        .collect())
        if (r.state === 'running' || r.state === 'blocked' || r.state === 'review')
          await ctx.db.patch(r._id, { state: 'superseded', updatedAt: now });
      patch.activation = { ...patch.activation!, currentRunId: undefined };
    }
    await ctx.db.patch(intent._id, patch);
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'servers.node.settings',
      targetType: 'panel_node_intent',
      targetId: intent._id,
      payload: { backendSlug: server?.slug ?? '', name: intent.name, change: kind },
    });
    const next2 = (await ctx.db.get(intent._id))!;
    if (kind !== 'none') await scheduleReconcile(ctx, next2);
    return { change: kind, machineRevision: next2.machineRevision };
  },
});

// --- the applied report (the role) ----------------------------------------------------------------

export const applied = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    appliedRevision: v.number(),
    certificateReady: v.optional(v.boolean()),
    nodeStarted: v.boolean(),
  },
  handler: async (ctx, a) => {
    const intent = await ctx.db.get(a.intentId);
    if (!intent) return refuse('not_found', 'No such node');
    if (intent.state === 'retiring' || intent.state === 'retired')
      refuse('servers.node_retiring', 'This node is being retired');
    if (a.appliedRevision < intent.machineRevision)
      refuse(
        'servers.revision_stale',
        `The machine configuration moved to revision ${intent.machineRevision}. Run the role again`,
      );
    if (a.appliedRevision > intent.machineRevision)
      refuse('servers.revision_unknown', 'That machine revision was never served for this node');
    const now = Date.now();
    // Idempotent: the same revision reported again changes nothing but the report.
    if (intent.appliedRevision === a.appliedRevision) {
      await ctx.db.patch(intent._id, {
        appliedReport: { certificateReady: a.certificateReady, nodeStarted: a.nodeStarted },
        appliedAt: now,
        updatedAt: now,
      });
      await scheduleReconcile(ctx, (await ctx.db.get(intent._id))!);
      return { stage: intent.activation.stage, repeated: true };
    }
    const evidence: Evidence[] = [
      ...intent.activation.evidence.filter((e) => e.kind !== 'machine_applied'),
      { kind: 'machine_applied', machineRevision: a.appliedRevision, at: now },
    ];
    const stage: Stage =
      intent.activation.stage === 'registered' || intent.activation.stage === 'bootstrap_available'
        ? 'machine_applied'
        : intent.activation.stage;
    await ctx.db.patch(intent._id, {
      appliedRevision: a.appliedRevision,
      appliedAt: now,
      appliedReport: { certificateReady: a.certificateReady, nodeStarted: a.nodeStarted },
      activation: { ...intent.activation, evidence, stage },
      updatedAt: now,
    });
    await scheduleReconcile(ctx, (await ctx.db.get(intent._id))!);
    return { stage, repeated: false };
  },
});

// --- what the run reads and records ----------------------------------------------------------------

export const loadForRun = internalQuery({
  args: fence,
  handler: async (ctx, f) => {
    const intent = await ctx.db.get(f.intentId);
    if (!intent || !fenceHolds(intent, f)) return null;
    return loadContext(ctx, intent);
  },
});

async function loadContext(ctx: QueryCtx, intent: Intent) {
  const sid = intent.backendServerId;
  const server = await ctx.db.get(sid);
  if (!server) return null;
  const setup = await readySetup(ctx, sid);
  if (!setup) return null;
  const node = intent.nodeUuid
    ? await ctx.db
        .query('panelNodes')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', sid).eq('nodeUuid', intent.nodeUuid!),
        )
        .unique()
    : ((
        await ctx.db
          .query('panelNodes')
          .withIndex('by_server', (q) => q.eq('backendServerId', sid))
          .collect()
      ).find((n) => n.name === intent.name) ?? null);
  const profile = await ctx.db
    .query('panelProfiles')
    .withIndex('by_server_uuid', (q) =>
      q.eq('backendServerId', sid).eq('profileUuid', setup.profileUuid!),
    )
    .unique();
  const hosts = await ctx.db
    .query('panelHosts')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .collect();
  const hostname = originHostnameOf(intent, setup);
  const ib = inboundFor(setup, intent.purpose);
  const inbound = profile?.inbounds.find((i) => i.inboundUuid === ib.uuid) ?? null;
  return {
    intent,
    server: { _id: server._id, backend: server.backend, config: server.config, slug: server.slug },
    setup,
    node,
    profile: profile
      ? { changeToken: profile.changeToken, foreignEditAt: profile.foreignEditAt }
      : null,
    inbound,
    directHost: hosts.find((h) => h.remark === `${intent.name}-reality`) ?? null,
    hostname,
    originAddress: originAddressOf(intent, hostname),
    ingress: ingressOf(intent, hostname),
  };
}
export type IntentContext = NonNullable<Awaited<ReturnType<typeof loadContext>>>;

const progressPatch = v.object({
  state: v.optional(v.union(v.literal('pending'), v.literal('ready'), v.literal('blocked'))),
  code: v.optional(v.union(v.string(), v.null())),
  nodeUuid: v.optional(v.string()),
  hostUuid: v.optional(v.string()),
  configRevision: v.optional(v.string()),
  authRevision: v.optional(v.union(v.string(), v.null())),
  deliveryRevision: v.optional(v.string()),
  stage: v.optional(v.string()),
  addEvidence: v.optional(
    v.array(
      v.object({
        kind: v.string(),
        machineRevision: v.number(),
        configRevision: v.optional(v.string()),
        authRevision: v.optional(v.string()),
        deliveryRevision: v.optional(v.string()),
        at: v.number(),
        detail: v.optional(v.string()),
      }),
    ),
  ),
  origin: v.optional(
    v.object({
      hostname: v.optional(v.string()),
      address: v.optional(v.string()),
      dns: v.union(
        v.literal('none'),
        v.literal('pending'),
        v.literal('created'),
        v.literal('resolves'),
        v.literal('conflict'),
      ),
    }),
  ),
  release: v.optional(v.boolean()),
});

type ProgressPatch = Infer<typeof progressPatch>;

/**
 * Record the revisions a run observed. A move under evidence already taken
 * (the profile token, the inbound, the REALITY material) or a direct node's
 * endpoint moving under its Host is OBSERVED DRIFT (docs/servers.md "Node
 * lifecycle"): the invalidated evidence goes, running activations are
 * superseded, and a live node closes under a maintenance transition until it
 * is re-verified and re-approved. FCP never claims the approved configuration
 * is still served.
 */
export const observeRevisions = internalMutation({
  args: {
    ...fence,
    configRevision: v.string(),
    authRevision: v.union(v.string(), v.null()),
    hostMoved: v.boolean(),
  },
  handler: async (ctx, { configRevision, authRevision, hostMoved, ...f }) => {
    const intent = await ctx.db.get(f.intentId);
    if (!intent || !fenceHolds(intent, f)) return { ok: false as const, drift: false };
    const now = Date.now();
    const revisionMoved =
      intent.configRevision !== undefined &&
      (intent.configRevision !== configRevision || (intent.authRevision ?? null) !== authRevision);
    const patch: Partial<Intent> = {
      configRevision,
      authRevision: authRevision ?? undefined,
      claim: { attemptId: f.attemptId, expiresAt: now + CLAIM_LEASE_MS },
      updatedAt: now,
    };
    const revs: Revisions = {
      machineRevision: intent.machineRevision,
      configRevision,
      authRevision: authRevision ?? undefined,
      deliveryRevision: intent.deliveryRevision ?? '',
    };
    const evidence = retainEvidence(intent.activation.evidence, revs).filter(
      (e) => !(hostMoved && e.kind === 'direct_confirmed'),
    );
    const d = intent.delivery.disposition;
    const drift =
      evidence.length < intent.activation.evidence.length ||
      ((revisionMoved || hostMoved) &&
        (!!intent.activation.currentRunId || d === 'live' || d === 'activating'));
    if (drift) {
      patch.activation = {
        ...intent.activation,
        evidence,
        stage: stageAfterChange(intent.activation.stage, evidence),
        reviewHash: undefined,
        currentRunId: undefined,
      };
      for (const r of await ctx.db
        .query('panelActivationRuns')
        .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
        .collect())
        if (r.state === 'running' || r.state === 'blocked' || r.state === 'review')
          await ctx.db.patch(r._id, { state: 'superseded', updatedAt: now });
      if (d === 'live') {
        patch.delivery = { ...intent.delivery, disposition: 'unavailable' };
        patch.maintenance = intent.maintenance ?? {
          id: crypto.randomUUID(),
          reason: 'drift',
          since: now,
        };
      } else if (d === 'activating') patch.delivery = { ...intent.delivery, disposition: 'staged' };
      await bumpGateVersion(ctx, intent.backendServerId);
      const server = await ctx.db.get(intent.backendServerId);
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'servers.node.drift',
        targetType: 'panel_node_intent',
        targetId: intent._id,
        payload: {
          backendSlug: server?.slug ?? '',
          name: intent.name,
          kind: revisionMoved ? 'revision' : 'endpoint',
          wasLive: d === 'live',
        },
      });
    }
    await ctx.db.patch(f.intentId, patch);
    return { ok: true as const, drift };
  },
});

/** Record progress of the fenced run; extends the lease, or releases it when the run is done. */
export const progress = internalMutation({
  args: { ...fence, patch: progressPatch },
  handler: async (ctx, { patch, ...f }) => {
    const intent = await ctx.db.get(f.intentId);
    if (!intent || !fenceHolds(intent, f)) return { ok: false as const };
    const now = Date.now();
    const next: Partial<Intent> = { updatedAt: now };
    if (patch.state !== undefined) next.state = patch.state;
    if (patch.code !== undefined) next.code = patch.code ?? undefined;
    if (patch.nodeUuid !== undefined) next.nodeUuid = patch.nodeUuid;
    if (patch.hostUuid !== undefined) next.hostUuid = patch.hostUuid;
    if (patch.configRevision !== undefined) next.configRevision = patch.configRevision;
    if (patch.authRevision !== undefined) next.authRevision = patch.authRevision ?? undefined;
    if (patch.deliveryRevision !== undefined) next.deliveryRevision = patch.deliveryRevision;
    if (patch.origin !== undefined) next.origin = patch.origin;
    let activation = intent.activation;
    if (patch.addEvidence) {
      const kinds = new Set(patch.addEvidence.map((e) => e.kind));
      activation = {
        ...activation,
        evidence: [...activation.evidence.filter((e) => !kinds.has(e.kind)), ...patch.addEvidence],
      };
    }
    if (patch.stage !== undefined) activation = { ...activation, stage: patch.stage as Stage };
    next.activation = activation;
    next.claim = patch.release
      ? undefined
      : { attemptId: f.attemptId, expiresAt: now + CLAIM_LEASE_MS };
    await ctx.db.patch(f.intentId, next);
    return { ok: true as const };
  },
});

// --- the run: reconcile the panel row, the direct Host and the origin name ----------------------

class Fenced extends Error {}

export const reconcile = internalAction({
  args: fence,
  handler: async (ctx, f): Promise<null> => {
    const load = async () => {
      const c = await ctx.runQuery(internal.panelIntents.loadForRun, f);
      if (!c) throw new Fenced();
      return c;
    };
    const record = (patch: ProgressPatch) =>
      ctx.runMutation(internal.panelIntents.progress, { ...f, patch });
    const stop = (state: 'pending' | 'blocked' | 'ready', code: string | null) =>
      record({ state, code, release: true });
    try {
      let c = await load();
      const sid = c.server._id;
      const writes = PROVIDERS[c.server.backend].panelWrites;
      if (!writes) return stop('blocked', 'servers.unsupported_backend').then(() => null);
      const setup = c.setup;
      const ib = inboundFor(setup, c.intent.purpose);
      // A run scheduled or resumed after the write-off switch was turned off
      // parks: the origin DNS writes below do not go through the ledger.
      if (!(await ctx.runQuery(internal.serverAdmin.manageEnabled, {}))) {
        await stop('pending', 'servers.manage_disabled');
        return null;
      }
      // The observation the row is compared against must be fresh.
      if (!(await observeInstance(ctx, c.server))) {
        await stop('pending', 'servers.observe_failed');
        return null;
      }
      c = await load();

      // 1. The node row: create through the ledger, or bring the fields in line.
      const want = {
        address: c.intent.observed.management.address,
        port: c.intent.settings.nodePort,
        countryCode: c.intent.settings.countryCode,
        configProfileUuid: setup.profileUuid!,
        activeInboundUuids: [ib.uuid],
      };
      if (!c.node) {
        const { opId } = await ctx.runMutation(internal.panelWrites.requestNodeCreate, {
          backendServerId: sid,
          name: c.intent.name,
          ...want,
        });
        const r = await ctx.runAction(internal.panelWrites.run, { opId });
        if (r.open) {
          await stop('pending', 'servers.op_running');
          return null;
        }
        await observeInstance(ctx, c.server);
        c = await load();
        if (!c.node) {
          await stop('pending', 'servers.observe_lag');
          return null;
        }
      } else {
        const diff: Record<string, unknown> = {};
        if (c.node.address !== want.address) diff.address = want.address;
        if (c.node.port !== want.port) diff.port = want.port;
        if (want.countryCode && c.node.countryCode !== want.countryCode)
          diff.countryCode = want.countryCode;
        if (
          c.node.configProfileUuid !== want.configProfileUuid ||
          c.node.activeInboundUuids.length !== 1 ||
          c.node.activeInboundUuids[0] !== ib.uuid
        ) {
          diff.configProfileUuid = want.configProfileUuid;
          diff.activeInboundUuids = want.activeInboundUuids;
        }
        if (Object.keys(diff).length > 0) {
          let opId: Id<'panelOps'>;
          try {
            ({ opId } = await ctx.runMutation(internal.panelWrites.requestNodeUpdate, {
              backendServerId: sid,
              nodeUuid: c.node.nodeUuid,
              ...diff,
            }));
          } catch (err) {
            await stop('blocked', codeOf(err));
            return null;
          }
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await stop('pending', 'servers.op_running');
            return null;
          }
          await observeInstance(ctx, c.server);
          c = await load();
        }
      }
      await record({ nodeUuid: c.node!.nodeUuid });

      // 2. Revisions the evidence is bound to. A move under evidence already
      //    taken, or a direct node's endpoint moving under its Host, is
      //    observed drift: evidence goes, a live node closes (observeRevisions).
      const configRevision = `${c.profile?.changeToken ?? ''}:${ib.uuid}`;
      const authRevision = c.inbound?.realityAuth?.digest ?? null;
      const reality = setup.inbounds!.reality;
      const hostWant = {
        address: c.originAddress,
        port: reality.port,
        sni: reality.serverNames[0] ?? null,
      };
      const hostMoved =
        c.intent.purpose === 'direct' &&
        !!c.directHost &&
        (c.directHost.address !== hostWant.address ||
          c.directHost.port !== hostWant.port ||
          (c.directHost.sni ?? null) !== hostWant.sni);
      const rev = await ctx.runMutation(internal.panelIntents.observeRevisions, {
        ...f,
        configRevision,
        authRevision,
        hostMoved,
      });
      if (!rev.ok) throw new Fenced();
      c = await load();

      // 3. A direct node's Host: created DISABLED; activation enables it. A
      //    moved endpoint is written to the existing Host: the gate closed
      //    above when that Host was committed, so members never hold a dead
      //    tuple as approved.
      if (c.intent.purpose === 'direct') {
        if (!c.directHost) {
          const { opId } = await ctx.runMutation(internal.panelWrites.requestHostCreate, {
            backendServerId: sid,
            remark: `${c.intent.name}-reality`,
            ...hostWant,
            fingerprint: 'chrome',
            securityLayer: 'DEFAULT',
            isDisabled: true,
            inboundUuid: reality.uuid,
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await stop('pending', 'servers.op_running');
            return null;
          }
          await observeInstance(ctx, c.server);
          c = await load();
        } else if (hostMoved) {
          const { opId } = await ctx.runMutation(internal.panelWrites.requestHostUpdate, {
            backendServerId: sid,
            hostUuid: c.directHost.hostUuid,
            ...hostWant,
          });
          const r = await ctx.runAction(internal.panelWrites.run, { opId });
          if (r.open) {
            await stop('pending', 'servers.op_running');
            return null;
          }
          await observeInstance(ctx, c.server);
          c = await load();
        }
        if (c.directHost) await record({ hostUuid: c.directHost.hostUuid });
      }

      // 4. A front node's origin name: obligations through the node runtime.
      if (c.intent.purpose === 'front') {
        if (!c.hostname) {
          await stop('blocked', 'servers.origin_hostname_missing');
          return null;
        }
        const dns = await ctx.runAction(internal.panelIntentOps.ensureOriginDns, f);
        if (dns.state === 'conflict') {
          await stop('blocked', 'servers.origin_name_taken');
          return null;
        }
        if (dns.state === 'unresolved') {
          await stop('pending', 'servers.obligation_unresolved');
          return null;
        }
      }

      // 5. Machine readiness, once the role has applied the current revision.
      c = await load();
      if (c.intent.appliedRevision === c.intent.machineRevision) {
        const ready = await verifyMachine(ctx, f, c);
        if (!ready.ok) {
          await stop('pending', ready.code);
          return null;
        }
      }
      await stop('ready', null);
      return null;
    } catch (err) {
      if (err instanceof Fenced) return null;
      await stop('blocked', codeOf(err));
      return null;
    }
  },
});

function codeOf(err: unknown): string {
  return err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
    ? (err.data as { code: string }).code
    : 'servers.reconcile_failed';
}

/**
 * `machine_ready`: the node row is what was asked and the node is online, the
 * profile token has not moved, and (front) the origin name resolves and the
 * external hop answers as declared. Evidence bound to the machine and config
 * revisions; an unchanged rerun keeps it.
 */
async function verifyMachine(
  ctx: ActionCtx,
  f: Fence,
  c: IntentContext,
): Promise<{ ok: true } | { ok: false; code: string }> {
  const record = (patch: ProgressPatch) =>
    ctx.runMutation(internal.panelIntents.progress, { ...f, patch });
  const configRevision = `${c.profile?.changeToken ?? ''}:${inboundFor(c.setup, c.intent.purpose).uuid}`;
  if (c.intent.configRevision !== configRevision)
    return { ok: false, code: 'servers.config_moved' };
  if (c.profile?.foreignEditAt) return { ok: false, code: 'servers.foreign_profile_edit' };
  if (!c.node || !c.node.online) return { ok: false, code: 'servers.node_offline' };
  const now = Date.now();
  const evidence: Evidence[] = [];
  if (c.intent.purpose === 'front') {
    const check = await ctx.runAction(internal.panelIntentOps.checkFrontIngress, {
      hostname: c.hostname!,
      port: c.ingress!.external.port,
      path: c.ingress!.internal[0]!.path,
      expected: {
        v4: c.intent.observed.publicIps.v4 ?? null,
        v6: c.intent.settings.publishV6 ? (c.intent.observed.publicIps.v6 ?? null) : null,
      },
    });
    if (!check.resolves) return { ok: false, code: 'servers.origin_not_resolving' };
    await record({ origin: { hostname: c.hostname, address: c.originAddress, dns: 'resolves' } });
    if (!check.tlsValid) return { ok: false, code: 'servers.origin_certificate' };
    if (!check.pathProxied) return { ok: false, code: 'servers.ingress_path' };
    if (!check.foreignHostAnswered) return { ok: false, code: 'servers.ingress_host_header' };
    evidence.push(
      { kind: 'dns_resolves', machineRevision: c.intent.machineRevision, at: now },
      { kind: 'ingress_verified', machineRevision: c.intent.machineRevision, at: now },
    );
  }
  evidence.push({
    kind: 'machine_ready',
    machineRevision: c.intent.machineRevision,
    configRevision,
    at: now,
  });
  const stageNow = c.intent.activation.stage;
  await record({
    addEvidence: evidence,
    stage:
      stageNow === 'registered' ||
      stageNow === 'bootstrap_available' ||
      stageNow === 'machine_applied'
        ? 'machine_ready'
        : stageNow,
  });
  return { ok: true };
}

// --- bootstrap (the role) --------------------------------------------------------------------------

export const bootstrapContext = internalQuery({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return null;
    return loadContext(ctx, intent);
  },
});

export const markBootstrapServed = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return null;
    if (intent.activation.stage === 'registered')
      await ctx.db.patch(intentId, {
        activation: { ...intent.activation, stage: 'bootstrap_available' },
        updatedAt: Date.now(),
      });
    return null;
  },
});

export interface BootstrapAnswer {
  machineRevision: number;
  secretKey: string;
  node: { port: number; name: string; purpose: Purpose };
  ingress: {
    hostname: string;
    externalPort: number;
    routes: { path: string; port: number }[];
  } | null;
  origin: { hostname: string | null; dns: Intent['origin']['dns'] };
}

/**
 * What the role needs to configure the machine, plus the panel's node secret
 * read from the panel right now and returned to the caller only: never
 * persisted by FCP, never audited, never logged.
 */
export const bootstrap = internalAction({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }): Promise<BootstrapAnswer> => {
    const c = (await ctx.runQuery(internal.panelIntents.bootstrapContext, {
      intentId,
    })) as IntentContext | null;
    if (!c) throw new ConvexError({ code: 'not_found', message: 'No such node' });
    if (c.intent.state === 'retiring' || c.intent.state === 'retired')
      throw new ConvexError({
        code: 'servers.node_retiring',
        message: 'This node is being retired',
      });
    const writes = PROVIDERS[c.server.backend].panelWrites;
    if (!writes)
      throw new ConvexError({ code: 'servers.unsupported_backend', message: 'Unsupported' });
    const secretKey = await writes.nodeSecret(c.server.config as BackendConfig);
    await ctx.runMutation(internal.panelIntents.markBootstrapServed, { intentId });
    const ingress = c.ingress;
    return {
      machineRevision: c.intent.machineRevision,
      secretKey,
      node: { port: c.intent.settings.nodePort, name: c.intent.name, purpose: c.intent.purpose },
      ingress: ingress
        ? {
            hostname: ingress.hostname,
            externalPort: ingress.external.port,
            routes: ingress.internal.map((i) => ({ path: i.path, port: i.port })),
          }
        : null,
      origin: { hostname: c.hostname ?? null, dns: c.intent.origin.dns },
    };
  },
});

// --- the delivery gate -------------------------------------------------------------------------------

/** The gate for one node of one panel (docs/servers.md "Node lifecycle"). */
export async function nodeGateFor(
  ctx: { db: QueryCtx['db'] },
  sid: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<NodeGate> {
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', sid))
    .unique();
  const gateVersion = setup?.gateVersion ?? 0;
  const intent = nodeName ? await intentByName(ctx, sid, nodeName) : null;
  const runs = intent
    ? await ctx.db
        .query('panelActivationRuns')
        .withIndex('by_intent', (q) => q.eq('intentId', intent._id))
        .collect()
    : [];
  return nodeGateOf(intent, runs, gateVersion, false);
}

/** The names of every enrolled node of a panel whose gate is closed (the pinner never picks one while another exists). */
export const blockedNodeNames = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) => {
    const intents = await ctx.db
      .query('panelNodeIntents')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    return intents
      .filter((i) => i.delivery.disposition !== 'live' || !!i.maintenance)
      .map((i) => i.name);
  },
});

export const nodeGate = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: (ctx, { backendServerId, nodeName }) => nodeGateFor(ctx, backendServerId, nodeName),
});

// --- retirement request (the role) ---------------------------------------------------------------------

/**
 * The role asks for a node to be retired. Only a request: the admin decides
 * whenever the node was ever live or anything of it is still out there
 * (Hosts, a relay, DNS, credentials); otherwise the ladder starts at once.
 */
export const requestRetirement = internalMutation({
  args: {
    intentId: v.id('panelNodeIntents'),
    requestedBy: v.union(v.literal('role'), v.literal('admin')),
  },
  handler: async (ctx, { intentId, requestedBy }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const existing = intent.retirementId ? await ctx.db.get(intent.retirementId) : null;
    if (existing) return { retirementId: existing._id, stage: existing.stage };
    const ex = intent.delivery.exposure;
    const outstanding =
      ex.everLive ||
      ex.hosts.length > 0 ||
      !!ex.relayId ||
      ex.mirrors > 0 ||
      ex.testCredentials > 0 ||
      ex.dns > 0 ||
      !!intent.hostUuid;
    const now = Date.now();
    const stage = outstanding && requestedBy === 'role' ? 'needs_admin' : 'requested';
    const id = await ctx.db.insert('panelRetirements', {
      backendServerId: intent.backendServerId,
      intentId,
      stage,
      requestedBy,
      events: [{ at: now, code: stage }],
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.patch(intentId, {
      retirementId: id,
      state: 'retiring',
      delivery: { ...intent.delivery, disposition: 'retiring', acceptingAssignments: false },
      updatedAt: now,
    });
    await bumpGateVersion(ctx, intent.backendServerId);
    if (stage === 'requested')
      await ctx.scheduler.runAfter(0, internal.panelRetirement.startIfPlain, { retirementId: id });
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: requestedBy === 'admin' ? 'admin' : 'system',
      action: 'servers.node.retire_requested',
      targetType: 'panel_node_intent',
      targetId: intentId,
      payload: { backendSlug: server?.slug ?? '', name: intent.name, stage },
    });
    return { retirementId: id, stage };
  },
});

/**
 * Finish a maintenance transition: the node is re-verified from the earliest
 * affected stage and approved again before it is served; nothing reopens here.
 */
export const finishMaintenance = internalMutation({
  args: { intentId: v.id('panelNodeIntents'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { intentId, actorAdminId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return refuse('not_found', 'No such node');
    if (!intent.maintenance) return { ok: true as const, stage: intent.activation.stage };
    const now = Date.now();
    await ctx.db.patch(intentId, {
      maintenance: undefined,
      delivery: { ...intent.delivery, disposition: intent.approved ? 'staged' : 'staged' },
      approved: undefined,
      updatedAt: now,
    });
    await bumpGateVersion(ctx, intent.backendServerId);
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'servers.node.maintenance_finished',
      targetType: 'panel_node_intent',
      targetId: intentId,
      payload: { backendSlug: server?.slug ?? '', name: intent.name },
    });
    await scheduleReconcile(ctx, (await ctx.db.get(intentId))!);
    return { ok: true as const, stage: intent.activation.stage };
  },
});

/** The role confirms the machine is cleaned up: `ready_to_wipe` -> `wiped` -> `retired`. */
export const markWiped = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent) return refuse('not_found', 'No such node');
    const r = intent.retirementId ? await ctx.db.get(intent.retirementId) : null;
    if (!r) refuse('servers.not_retiring', 'This node is not being retired');
    if (r!.stage === 'wiped' || r!.stage === 'retired') return { stage: r!.stage };
    if (r!.stage !== 'ready_to_wipe')
      refuse('servers.retirement_stage', `The node is not ready to wipe yet (${r!.stage})`);
    const now = Date.now();
    await ctx.db.patch(r!._id, {
      stage: 'retired',
      events: [...r!.events, { at: now, code: 'wiped' }, { at: now, code: 'retired' }],
      updatedAt: now,
    });
    await ctx.db.patch(intentId, { state: 'retired', updatedAt: now });
    const server = await ctx.db.get(intent.backendServerId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'servers.node.retired',
      targetType: 'panel_node_intent',
      targetId: intentId,
      payload: { backendSlug: server?.slug ?? '', name: intent.name },
    });
    return { stage: 'retired' as const };
  },
});

// --- views ---------------------------------------------------------------------------------------

export const byName = internalQuery({
  args: { backendServerId: v.id('backendServers'), name: v.string() },
  handler: (ctx, { backendServerId, name }) => intentByName(ctx, backendServerId, name),
});

export const listForServer = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: (ctx, { backendServerId }) =>
    ctx.db
      .query('panelNodeIntents')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .collect(),
});

/** The role-facing view: what the role may know (never a secret, never another node). */
export function roleView(intent: Intent, retirement: Doc<'panelRetirements'> | null) {
  return {
    name: intent.name,
    purpose: intent.purpose,
    registration: { state: intent.state, code: intent.code ?? null, generation: intent.generation },
    stage: intent.activation.stage,
    delivery: intent.delivery.disposition,
    machineRevision: intent.machineRevision,
    appliedRevision: intent.appliedRevision ?? null,
    node: { uuid: intent.nodeUuid ?? null, port: intent.settings.nodePort },
    origin: { hostname: intent.origin.hostname ?? null, dns: intent.origin.dns },
    retirement: retirement ? { stage: retirement.stage, code: retirement.code ?? null } : null,
    updatedAt: new Date(intent.updatedAt).toISOString(),
  };
}

export const roleViewByName = internalQuery({
  args: { backendServerId: v.id('backendServers'), name: v.string() },
  handler: async (ctx, { backendServerId, name }) => {
    const intent = await intentByName(ctx, backendServerId, name);
    if (!intent) return null;
    const retirement = intent.retirementId ? await ctx.db.get(intent.retirementId) : null;
    return roleView(intent, retirement);
  },
});

// --- the sweep ---------------------------------------------------------------------------------------

/** Intents whose lease expired while pending, and setups likewise: resumed from the cron. */
export const stale = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const intents = (
      await ctx.db
        .query('panelNodeIntents')
        .withIndex('by_state', (q) => q.eq('state', 'pending'))
        .take(100)
    ).filter((i) => claimAvailable(i, now));
    const setups = (await ctx.db.query('panelSetups').collect()).filter(
      (s) => s.state === 'pending' && claimAvailable(s, now),
    );
    return { intents: intents.map((i) => i._id), setups: setups.map((s) => s._id) };
  },
});

export const resume = internalMutation({
  args: { intentId: v.id('panelNodeIntents') },
  handler: async (ctx, { intentId }) => {
    const intent = await ctx.db.get(intentId);
    if (!intent || intent.state !== 'pending') return false;
    return scheduleReconcile(ctx, intent);
  },
});

export const resumeSetup = internalMutation({
  args: { setupId: v.id('panelSetups') },
  handler: async (ctx, { setupId }) => {
    const row = await ctx.db.get(setupId);
    const now = Date.now();
    if (!row || row.state !== 'pending' || !claimAvailable(row, now)) return false;
    const attemptId = crypto.randomUUID();
    await ctx.db.patch(setupId, {
      claim: { attemptId, expiresAt: now + CLAIM_LEASE_MS },
      updatedAt: now,
    });
    await ctx.scheduler.runAfter(0, internal.panelSetup.run, {
      setupId,
      generation: row.generation,
      attemptId,
    });
    return true;
  },
});

/** On `panel-reconcile`: resume what an interrupted attempt left pending. */
export const sweep = internalAction({
  args: {},
  handler: async (ctx): Promise<{ intents: number; setups: number }> =>
    runWithCronOutcome(ctx, 'panel-bootstrap-sweep', async () => {
      const { intents, setups } = await ctx.runQuery(internal.panelIntents.stale, {
        now: Date.now(),
      });
      let a = 0;
      let b = 0;
      for (const id of intents)
        if (await ctx.runMutation(internal.panelIntents.resume, { intentId: id })) a++;
      for (const id of setups)
        if (await ctx.runMutation(internal.panelIntents.resumeSetup, { setupId: id })) b++;
      await ctx.runAction(internal.panelRetirement.sweep, {});
      return { intents: a, setups: b };
    }),
});

export { BOOTSTRAP_TAGS };
