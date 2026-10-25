/**
 * RELAYS: an ORIGIN members reach only through edges. An origin's origin is a
 * backend node, a whole backend server or a hand-described address
 * (lib/edges/origin.ts); its LISTENERS (relayListeners.ts) say what the origin
 * speaks; its published POOL of edges is what members are handed. Owns the
 * origin CRUD (admin and guided setup), edge adoption,
 * the delivery binding that keeps subscriptions of the origin edge-required,
 * and the published-pool bookkeeping (publish / unpublish with pool-index
 * inheritance and the publication epoch the render cache keys on). Rotation
 * state lives in edgeRotations.ts; edge rows in edges.ts.
 */
import { verificationListenerOf } from './lib/edges/verificationContext';
import { ConvexError, v } from 'convex/values';
import { resolveModeCatalog } from './lib/connectionModes';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, DatabaseWriter, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { isTerminalPhase } from './lib/edges/rotation';
import { setupVetoNow } from './lib/edges/scoring';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import {
  MAX_DESIRED_PUBLISHED,
  drainWarnings,
  originOverrideNames,
  originPolicy,
  resolveEdgeConfig,
  type EdgeConfig,
} from './lib/edgeConfig';
import { capabilitiesOf } from './lib/backends/capabilities';
import {
  isPublicIpLiteral,
  addressFamily,
  publishAddressOf,
  hasPublishableAddress,
} from './lib/edges/ip';
import { sameAddress } from './lib/edges/hosts';
import { isValidHostname } from './lib/edges/hostname';
import { l7HostHeaderFor, listenerAllowsLayer, zoneModeCarriesOrigin } from './lib/edges/layers';
import { protocolIsHttpTransport, protocolTransport, protocolUsesSni } from './lib/edges/protocols';
import { websocketNodeOf } from './lib/edges/websocketNode';
import {
  EDGE_PROVIDER_CAPABILITIES,
  edgeAddressKindOf,
  edgeLayerOf,
  edgeRoleOf,
  frontsAllowed,
  protocolCarriedBy,
  providerHealthSatisfies,
  zoneModeGovernsOrigin,
} from './lib/edges/providers/capabilities';
import { buildProvisionIntent, IntentError, parseIntent } from './lib/edges/intent';
import {
  qualificationBinding,
  qualificationRefusal,
  qualificationVerdict,
} from './lib/edges/frontCheck/binding';
import {
  EDGE_LIVE_STATUSES,
  LIVE_EDGE_SCAN_LIMIT,
  allocatePoolIndex,
  coverageListeners,
  withEdgeAt,
  withoutEdge,
  publishedCount,
  type PoolAdmit,
  type PoolListener,
} from './lib/edges/pool';
import { ensurePoolCapacity } from './lib/edges/poolCapacity';
import { admissionOf, publishedRefOf, setStateOf } from './lib/edges/setState';
import { removableUnder } from './lib/edges/providerSet';
import { resolveTemplateFor } from './edgeTemplates';
import { accountOptionDefaultsOf, certificateValuesFor } from './lib/edges/choices';
import { defaultLocationOf } from './edgeLocations';
import { l7PlaceOf } from './lib/edges/l7Place';
import { assertAdmission } from './lib/edges/maintenance';
import { assertNoRestore, hasHideRows, startRestoreWorkflow } from './lib/edges/restore';
import {
  needsEndpointVerification,
  verificationBinding,
  verificationCurrent,
} from './lib/edges/verification';
import {
  deriveHostMode,
  describeOrigin,
  hostModeAllowed,
  originBackendServerId,
  originNodeName,
  type HostMode,
  type RelayOrigin,
} from './lib/edges/origin';
import {
  assertNoRotationOrQuarantine,
  assertNotQuarantined,
  assertNoRunningSetup,
  bumpEpochAndRefresh,
  liveEdgesOfRelay,
  scheduleMirrorRefresh,
  setupRunLiveOn,
} from './lib/edges/relayGuards';
import {
  activeNames,
  applyRegistration,
  listenerSpecValidator,
  listenersOf,
} from './relayListeners';
import type { ListenerSpecInput } from './lib/edges/registration';
import { currentNodeName, runningRenameOf } from './lib/backend/nodeAliases';

export {
  assertNoRotationOrQuarantine,
  assertNotQuarantined,
  liveEdgesOfRelay,
  scheduleMirrorRefresh,
} from './lib/edges/relayGuards';

type Db = DatabaseReader;

/** The same bounded read per provider account (the capacity / lock questions). */
export async function liveEdgesOfAccount(
  db: Db,
  accountId: Id<'edgeProviderAccounts'>,
): Promise<Doc<'edges'>[]> {
  const out: Doc<'edges'>[] = [];
  for (const status of EDGE_LIVE_STATUSES) {
    out.push(
      ...(await db
        .query('edges')
        .withIndex('by_account_status', (q) => q.eq('accountId', accountId).eq('status', status))
        .take(LIVE_EDGE_SCAN_LIMIT)),
    );
  }
  return out;
}

// --- origin uniqueness / locks -------------------------------------------------------------

/**
 * One origin per place: per (backend server, node) for a backend node, per
 * backend server for a whole-server origin. A manual origin is unique by slug.
 */
async function assertOriginUnbound(db: Db, origin: RelayOrigin, selfId: Id<'relays'> | null) {
  if (origin.kind === 'manual') return;
  const rows =
    origin.kind === 'panel-node'
      ? await db
          .query('relays')
          .withIndex('by_node', (q) =>
            q.eq('backendServerId', origin.backendServerId).eq('nodeName', origin.nodeName),
          )
          .collect()
      : await db
          .query('relays')
          .withIndex('by_backend_server', (q) => q.eq('backendServerId', origin.backendServerId))
          .collect();
  const other = rows.find(
    (r) => r._id !== selfId && (origin.kind === 'panel-node' || r.origin.kind === 'backend-server'),
  );
  if (other) {
    throw new ConvexError({
      code: origin.kind === 'panel-node' ? 'edge.node_already_bound' : 'edge.server_already_bound',
      message: `Relay ${other.slug} already covers this ${origin.kind === 'panel-node' ? 'node' : 'backend server'}`,
    });
  }
}

/**
 * `originAddress` is baked into every provisioned edge's listener members; FCP
 * has no member-update operation, so a change while edges exist would leave the
 * balancers dialing the old target while FCP reports the new one.
 */
async function assertAddressChangeAllowed(db: Db, origin: Doc<'relays'>, next?: string) {
  if (next === undefined || sameAddress(next, origin.originAddress)) return;
  const edges = await liveEdgesOfRelay(db, origin._id);
  if (edges.length > 0) {
    throw new ConvexError({
      code: 'edge.origin_address_locked',
      message: 'Drain or destroy every edge of this origin before changing originAddress',
    });
  }
}

/** A published edge's own address can never be registered as an origin (anti-leak). */
async function assertOriginIsNotAnEdge(db: Db, originAddress: string, selfId: Id<'relays'> | null) {
  const relays = await db.query('relays').collect(); // small operator table
  for (const r of relays) {
    for (const edgeId of r.publishedEdgeIds) {
      if (!edgeId) continue;
      const e = await db.get(edgeId);
      if (!e || (selfId && e.relayId === selfId)) continue;
      const addrs = [e.addresses.v4, e.addresses.v6, e.addresses.hostname].filter(
        (x): x is string => !!x,
      );
      if (addrs.some((a) => sameAddress(a, originAddress)))
        throw new ConvexError({
          code: 'edge.origin_is_edge',
          message: 'originAddress is a published edge address',
        });
    }
  }
}

// --- delivery bindings -------------------------------------------------------------------------

/**
 * Keep the subscriptions of this origin edge-required, independently of the
 * origin row. `policyVersion` bumps whenever the binding is (re)claimed so the
 * sub cache can key on it. Claiming a place changes what its members must
 * receive RIGHT NOW, so the mirrors are refreshed immediately: a mirror still
 * holding the origin's raw body must not wait for the six-hour cron (a
 * re-parent with unchanged listeners bumps no epoch, so nothing else would).
 */
export async function upsertDeliveryBinding(
  ctx: MutationCtx,
  relay: Pick<Doc<'relays'>, 'origin' | 'slug'>,
): Promise<void> {
  const db = ctx.db;
  const backendServerId = originBackendServerId(relay.origin);
  if (!backendServerId) return; // a manual origin serves nothing
  const nodeName = originNodeName(relay.origin);
  const existing = await db
    .query('edgeDeliveryBindings')
    .withIndex('by_server_node', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeName', nodeName),
    )
    .unique();
  const now = Date.now();
  if (existing) {
    await db.patch(existing._id, {
      relaySlug: relay.slug,
      state: 'active',
      policyVersion: existing.policyVersion + 1,
      updatedAt: now,
    });
  } else {
    await db.insert('edgeDeliveryBindings', {
      backendServerId,
      nodeName,
      policy: 'edge-required',
      policyVersion: 1,
      relaySlug: relay.slug,
      state: 'active',
      updatedAt: now,
    });
  }
  await scheduleMirrorRefresh(ctx);
}

export type DeleteDisposition = 'restore-direct' | 'keep-dark';

async function settleDeliveryBinding(
  db: DatabaseWriter,
  relay: Pick<Doc<'relays'>, 'origin' | 'slug'>,
  disposition: DeleteDisposition,
): Promise<void> {
  const backendServerId = originBackendServerId(relay.origin);
  if (!backendServerId) return;
  const nodeName = originNodeName(relay.origin);
  const existing = await db
    .query('edgeDeliveryBindings')
    .withIndex('by_server_node', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeName', nodeName),
    )
    .unique();
  if (!existing || existing.relaySlug !== relay.slug) return;
  if (disposition === 'restore-direct') {
    await db.patch(existing._id, {
      state: 'released',
      policyVersion: existing.policyVersion + 1,
      updatedAt: Date.now(),
    });
  }
  // keep-dark: the binding stays active with the departed slug; members on the
  // node stay unavailable until another origin claims it (or an operator releases).
}

/** The active binding covering (backend server, node) or the whole server; null = raw delivery. */
export async function deliveryBindingFor(
  db: Db,
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<Doc<'edgeDeliveryBindings'> | null> {
  if (nodeName) {
    // A name a renamed node had (a pin not drained yet) is that node's binding.
    for (const name of [nodeName, await currentNodeName(db, backendServerId, nodeName)]) {
      if (!name) continue;
      const byNode = await db
        .query('edgeDeliveryBindings')
        .withIndex('by_server_node', (q) =>
          q.eq('backendServerId', backendServerId).eq('nodeName', name),
        )
        .unique();
      if (byNode && byNode.state === 'active') return byNode;
      if (byNode) break;
    }
  }
  const byServer = await db
    .query('edgeDeliveryBindings')
    .withIndex('by_server_node', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeName', undefined),
    )
    .unique();
  return byServer && byServer.state === 'active' ? byServer : null;
}

/** Operator release of a `keep-dark` binding left behind by a deleted origin. */
export const releaseDeliveryBinding = internalMutation({
  args: { id: v.id('edgeDeliveryBindings'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const b = await ctx.db.get(id);
    if (!b) return { ok: true as const };
    const relay = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', b.relaySlug))
      .unique();
    if (relay && !relay.deleting)
      throw new ConvexError({ code: 'conflict', message: 'The binding’s origin still exists' });
    await ctx.db.patch(id, {
      state: 'released',
      policyVersion: b.policyVersion + 1,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.delivery.released',
      targetType: 'relay',
      payload: { relaySlug: b.relaySlug },
    });
    // The place serves direct again: replace the unavailable stubs now.
    await scheduleMirrorRefresh(ctx);
    return { ok: true as const };
  },
});

// --- pool drop shared with edges.ts ------------------------------------------------------------

/**
 * Remove an edge from the published pool / standby list WITHOUT a drain (the
 * provider no longer has it, or an operator forgot it) and bump the epoch so
 * renders stop emitting it. Shared by `dropFromPool` and the describe(gone)
 * transition in edges.ts so the drop happens in the SAME mutation as the status.
 */
export async function dropEdgeFromPool(
  ctx: MutationCtx,
  origin: Doc<'relays'>,
  edge: Doc<'edges'>,
  opts: { reason: string; rotationId?: Id<'edgeRotations'> } = { reason: 'drift' },
): Promise<{ dropped: boolean; epoch: number; inPool: boolean }> {
  const now = Date.now();
  const inPool = origin.publishedEdgeIds.includes(edge._id);
  const inStandby = origin.standbyEdgeIds.includes(edge._id);
  if (!inPool && !inStandby) return { dropped: false, epoch: origin.publicationEpoch, inPool };
  if (edge.publication !== 'unpublished') {
    await ctx.db.patch(edge._id, {
      publication: 'unpublished',
      poolIndex: undefined,
      updatedAt: now,
    });
  }
  const epoch = origin.publicationEpoch + 1;
  await ctx.db.patch(origin._id, {
    publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edge._id),
    standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edge._id),
    publicationEpoch: epoch,
    updatedAt: now,
  });
  // Every caller (describe-gone, operator forget/destroy/delete, the cron's
  // destroyed sweep) changes what each listener's template edge is.
  await refreshTemplateEdges(ctx, origin);
  if (inPool) {
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.unpublished',
      targetType: 'edge',
      targetId: edge._id,
      payload: {
        relaySlug: origin.slug,
        edgeId: edge._id,
        poolIndex: edge.poolIndex ?? null,
        epoch,
        rotationId: opts.rotationId,
      },
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.drift',
      targetType: 'relay',
      targetId: origin._id,
      payload: {
        relaySlug: origin.slug,
        edgeId: edge._id,
        mismatched: 1,
        total: publishedCount(origin.publishedEdgeIds),
      },
    });
    await scheduleMirrorRefresh(ctx);
  }
  return { dropped: true, epoch, inPool };
}

// --- admin projection ---------------------------------------------------------------------------

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
const NODE_NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * The admin view of one origin. `setupRunLive` (whether a guided setup run is
 * working on it now, null when the caller did not look) keeps the detector's
 * setup veto true between its passes (`setupVetoNow`): a run that failed or
 * was cancelled does not leave "Owned by a setup run" behind.
 */
export function mapRelayAdmin(
  r: Doc<'relays'>,
  cfg: EdgeConfig,
  setupRunLive: boolean | null = null,
) {
  const policy = originPolicy(r, cfg);
  const storedVeto = r.suspicion?.veto ?? null;
  const veto = setupVetoNow(storedVeto, {
    setupOwned: r.setupOwned === true,
    runLive: setupRunLive,
  });
  return {
    id: r._id as string,
    slug: r.slug,
    label: r.label ?? null,
    origin:
      r.origin.kind === 'panel-node'
        ? {
            kind: 'panel-node' as const,
            backendServerId: r.origin.backendServerId as string,
            nodeName: r.origin.nodeName,
            nodeUuid: r.origin.nodeUuid ?? null,
          }
        : r.origin.kind === 'backend-server'
          ? { kind: 'backend-server' as const, backendServerId: r.origin.backendServerId as string }
          : { kind: 'manual' as const },
    originAddress: r.originAddress,
    locationCode: r.locationCode ?? null,
    hostMode: r.hostMode,
    delivery: r.delivery,
    enabled: r.enabled,
    autoRotate: r.autoRotate,
    probeNode: r.probeNode ?? false,
    qualificationCredential: !!r.qualificationUserId,
    qualificationModeSlug: r.qualificationModeSlug ?? null,
    reachability: r.reachability
      ? {
          byCountry: r.reachability.byCountry.map((c) => ({
            ...c,
            lastAt: new Date(c.lastAt).toISOString(),
          })),
          updatedAt: new Date(r.reachability.updatedAt).toISOString(),
        }
      : null,
    providerPreference: r.providerPreference ?? null,
    desiredPublished: r.desiredPublished,
    // The five per-origin knobs: the EFFECTIVE value (the origin's override,
    // else the fleet's) and which of them this origin overrides.
    standbyPerRelay: policy.standbyPerRelay,
    standbyPerListener: policy.standbyPerListener,
    bindingDeferred: r.bindingDeferred ?? false,
    setupOwned: r.setupOwned ?? false,
    autoReplaceHolds: (r.autoReplaceHolds ?? []).map((h) => ({
      listenerId: h.listenerId as string,
      code: h.code,
      at: new Date(h.at).toISOString(),
    })),
    cooldownMinutes: Math.round(policy.cooldownMs / 60_000),
    maxRotationsPerDay: policy.maxRotationsPerDay,
    drainMinutes: Math.round(policy.drainMs / 60_000),
    overrides: originOverrideNames(r),
    publicationEpoch: r.publicationEpoch,
    publishedEdgeIds: r.publishedEdgeIds.map((e) => (e as string | null) ?? null),
    publishedCount: publishedCount(r.publishedEdgeIds),
    standbyEdgeIds: r.standbyEdgeIds.map((e) => e as string),
    activeRotationId: (r.activeRotationId as string | undefined) ?? null,
    cooldownUntil: r.cooldownUntil ? new Date(r.cooldownUntil).toISOString() : null,
    rotationsToday: r.rotationsDayKey === todayKey() ? r.rotationsToday : 0,
    lastRotatedAt: r.lastRotatedAt ? new Date(r.lastRotatedAt).toISOString() : null,
    lastRegisteredAt: r.lastRegisteredAt ? new Date(r.lastRegisteredAt).toISOString() : null,
    quarantine: r.quarantine
      ? {
          rotationId: r.quarantine.rotationId as string,
          since: new Date(r.quarantine.since).toISOString(),
          reason: r.quarantine.reason,
        }
      : null,
    deleting: r.deleting ?? false,
    restore: r.restore
      ? {
          purpose: r.restore.purpose,
          phase: r.restore.phase,
          startedAt: new Date(r.restore.startedAt).toISOString(),
          attempt: r.restore.attempt,
          lastError: r.restore.lastError ?? null,
        }
      : null,
    suspicion: r.suspicion
      ? {
          ...r.suspicion,
          veto,
          hint:
            r.suspicion.hint && veto !== storedVeto
              ? r.suspicion.hint.replace(
                  `; automatic rotation held (${storedVeto})`,
                  veto ? `; automatic rotation held (${veto})` : '',
                )
              : r.suspicion.hint,
          edgeEvidence: r.suspicion.edgeEvidence.map((e) => ({ ...e, edgeId: e.edgeId as string })),
          firstSeenAt: r.suspicion.firstSeenAt
            ? new Date(r.suspicion.firstSeenAt).toISOString()
            : null,
          lastEvalAt: new Date(r.suspicion.lastEvalAt).toISOString(),
        }
      : null,
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export function todayKey(now = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

// --- reads --------------------------------------------------------------------------------------

export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const rows = (await ctx.db.query('relays').collect()).sort((a, b) =>
      a.slug.localeCompare(b.slug),
    );
    const out = [];
    for (const r of rows) out.push(mapRelayAdmin(r, cfg, await setupRunLiveOn(ctx.db, r)));
    return out;
  },
});

export const get = internalQuery({
  args: { id: v.id('relays') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Every origin (small, operator-managed table) for the reconcile cron. */
export const listAll = internalQuery({
  args: {},
  handler: (ctx) => ctx.db.query('relays').collect(),
});

export const listEnabled = internalQuery({
  args: {},
  handler: (ctx) =>
    ctx.db
      .query('relays')
      .withIndex('by_enabled', (q) => q.eq('enabled', true))
      .collect(),
});

/**
 * The origin behind a subscription's resolved place: the backend node it was
 * pinned to, or the whole backend server. The attribution + render lookup.
 */
export async function relayForBackendNode(
  db: Db,
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<Doc<'relays'> | null> {
  if (nodeName) {
    // A name a renamed node had (a pin not drained yet) is that node's origin.
    for (const name of [nodeName, await currentNodeName(db, backendServerId, nodeName)]) {
      if (!name) continue;
      const byNode = await db
        .query('relays')
        .withIndex('by_node', (q) => q.eq('backendServerId', backendServerId).eq('nodeName', name))
        .unique();
      if (byNode) return byNode;
    }
  }
  const rows = await db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', backendServerId))
    .collect();
  return rows.find((r) => r.origin.kind === 'backend-server') ?? null;
}

// --- validation ---------------------------------------------------------------------------------

/** The origin as an admin form names it (by id). */
export const adminOriginValidator = v.union(
  v.object({
    kind: v.literal('panel-node'),
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    nodeUuid: v.optional(v.union(v.string(), v.null())),
  }),
  v.object({ kind: v.literal('backend-server'), backendServerId: v.id('backendServers') }),
  v.object({ kind: v.literal('manual') }),
);

type AdminOriginArg =
  | {
      kind: 'panel-node';
      backendServerId: Id<'backendServers'>;
      nodeName: string;
      nodeUuid?: string | null;
    }
  | { kind: 'backend-server'; backendServerId: Id<'backendServers'> }
  | { kind: 'manual' };

async function checkOrigin(db: Db, o: AdminOriginArg): Promise<RelayOrigin> {
  if (o.kind === 'manual') return { kind: 'manual' };
  const server = await db.get(o.backendServerId);
  if (!server) throw new ConvexError({ code: 'validation', message: 'unknown backend server' });
  if (o.kind === 'panel-node') {
    const nodeName = o.nodeName.trim().toLowerCase();
    if (!NODE_NAME_RE.test(nodeName))
      throw new ConvexError({
        code: 'validation',
        message: 'nodeName must be a lowercase host label',
      });
    if (!capabilitiesOf(server.backend).nodePinning)
      throw new ConvexError({
        code: 'validation',
        message: 'this backend has no nodes; register the whole server instead',
      });
    return {
      kind: 'panel-node',
      backendServerId: o.backendServerId,
      nodeName,
      nodeUuid: o.nodeUuid ?? undefined,
    };
  }
  return { kind: 'backend-server', backendServerId: o.backendServerId };
}

function checkOriginFields(a: {
  originAddress?: string;
  label?: string | null;
  desiredPublished?: number;
  standbyPerRelay?: number | null;
  standbyPerListener?: number | null;
  cooldownMinutes?: number | null;
  maxRotationsPerDay?: number | null;
  drainMinutes?: number | null;
  locationCode?: string | null;
}) {
  if (a.originAddress !== undefined) {
    const fam = addressFamily(a.originAddress);
    const isName = /^[a-z0-9.-]{1,253}$/i.test(a.originAddress);
    if (!fam && !isName)
      throw new ConvexError({
        code: 'validation',
        message: 'originAddress must be an IP or hostname',
      });
  }
  if (
    a.label !== undefined &&
    a.label !== null &&
    (a.label.trim().length === 0 || a.label.length > 64)
  )
    throw new ConvexError({ code: 'validation', message: 'label must be 1..64 characters' });
  if (
    a.desiredPublished !== undefined &&
    (!Number.isInteger(a.desiredPublished) ||
      a.desiredPublished < 1 ||
      a.desiredPublished > MAX_DESIRED_PUBLISHED)
  )
    throw new ConvexError({
      code: 'validation',
      message: `desiredPublished must be 1..${MAX_DESIRED_PUBLISHED}`,
    });
  if (a.standbyPerRelay != null && (a.standbyPerRelay < 0 || a.standbyPerRelay > 2))
    throw new ConvexError({ code: 'validation', message: 'standbyPerRelay must be 0..2' });
  if (
    a.standbyPerListener != null &&
    (!Number.isInteger(a.standbyPerListener) ||
      a.standbyPerListener < 0 ||
      a.standbyPerListener > 2)
  )
    throw new ConvexError({ code: 'validation', message: 'standbyPerListener must be 0..2' });
  if (a.cooldownMinutes != null && (a.cooldownMinutes < 10 || a.cooldownMinutes > 1440))
    throw new ConvexError({ code: 'validation', message: 'cooldownMinutes must be 10..1440' });
  if (a.maxRotationsPerDay != null && (a.maxRotationsPerDay < 1 || a.maxRotationsPerDay > 12))
    throw new ConvexError({ code: 'validation', message: 'maxRotationsPerDay must be 1..12' });
  if (a.drainMinutes != null && (a.drainMinutes < 1 || a.drainMinutes > 7 * 1440))
    throw new ConvexError({ code: 'validation', message: 'drainMinutes must be 1..10080' });
  if (
    a.locationCode !== undefined &&
    a.locationCode !== null &&
    !/^[A-Za-z0-9-]{1,16}$/.test(a.locationCode)
  )
    throw new ConvexError({ code: 'validation', message: 'invalid locationCode' });
}

const hostModeValidator = v.union(v.literal('fcp'), v.literal('operator'), v.literal('none'));

/** Operator-owned knobs (the admin form). */
const originWriteArgs = {
  label: v.optional(v.union(v.string(), v.null())),
  originAddress: v.optional(v.string()),
  locationCode: v.optional(v.union(v.string(), v.null())),
  enabled: v.optional(v.boolean()),
  autoRotate: v.optional(v.boolean()),
  hostMode: v.optional(hostModeValidator),
  probeNode: v.optional(v.boolean()),
  providerPreference: v.optional(v.union(edgeProviderIdValidator, v.null())),
  desiredPublished: v.optional(v.number()),
  // The per-origin overrides: a number sets one, null follows the fleet again.
  standbyPerRelay: v.optional(v.union(v.number(), v.null())),
  standbyPerListener: v.optional(v.union(v.number(), v.null())),
  cooldownMinutes: v.optional(v.union(v.number(), v.null())),
  maxRotationsPerDay: v.optional(v.union(v.number(), v.null())),
  drainMinutes: v.optional(v.union(v.number(), v.null())),
  // The connection mode whose placement the L7 qualification user is minted on
  // (null = the backend's default placement).
  qualificationModeSlug: v.optional(v.union(v.string(), v.null())),
  actorAdminId: v.optional(v.id('adminUsers')),
};

type OriginWrite = {
  label?: string | null;
  originAddress?: string;
  locationCode?: string | null;
  enabled?: boolean;
  autoRotate?: boolean;
  hostMode?: HostMode;
  probeNode?: boolean;
  providerPreference?: Doc<'relays'>['providerPreference'] | null;
  desiredPublished?: number;
  standbyPerRelay?: number | null;
  standbyPerListener?: number | null;
  cooldownMinutes?: number | null;
  maxRotationsPerDay?: number | null;
  drainMinutes?: number | null;
  qualificationModeSlug?: string | null;
};

function patchFrom(a: OriginWrite): Partial<Doc<'relays'>> {
  checkOriginFields(a);
  const p: Partial<Doc<'relays'>> = {};
  if (a.label !== undefined) p.label = a.label?.trim() || undefined;
  if (a.originAddress !== undefined) p.originAddress = a.originAddress.trim();
  if (a.locationCode !== undefined) p.locationCode = a.locationCode ?? undefined;
  if (a.enabled !== undefined) p.enabled = a.enabled;
  if (a.autoRotate !== undefined) p.autoRotate = a.autoRotate;
  if (a.hostMode !== undefined) p.hostMode = a.hostMode;
  if (a.probeNode !== undefined) p.probeNode = a.probeNode;
  if (a.providerPreference !== undefined) p.providerPreference = a.providerPreference ?? undefined;
  if (a.desiredPublished !== undefined) p.desiredPublished = a.desiredPublished;
  // An override: a number sets it, null clears it (the origin follows the fleet again).
  if (a.standbyPerRelay !== undefined) p.standbyPerRelay = a.standbyPerRelay ?? undefined;
  if (a.standbyPerListener !== undefined) p.standbyPerListener = a.standbyPerListener ?? undefined;
  if (a.cooldownMinutes !== undefined)
    p.cooldownMs = a.cooldownMinutes === null ? undefined : a.cooldownMinutes * 60_000;
  if (a.maxRotationsPerDay !== undefined) p.maxRotationsPerDay = a.maxRotationsPerDay ?? undefined;
  if (a.drainMinutes !== undefined)
    p.drainMs = a.drainMinutes === null ? undefined : a.drainMinutes * 60_000;
  if (a.qualificationModeSlug !== undefined)
    p.qualificationModeSlug = a.qualificationModeSlug?.trim() || undefined;
  return p;
}

/** Audit view of a write: field NAMES that changed, never their values. */
function changedFields(
  before: Doc<'relays'> | null,
  p: Partial<Doc<'relays'>>,
): { changed: string[]; autoRotate?: boolean; hostMode?: HostMode; enabled?: boolean } {
  const changed: string[] = [];
  for (const [k, val] of Object.entries(p)) {
    if (val === undefined) continue;
    const prev = before ? (before as unknown as Record<string, unknown>)[k] : undefined;
    if (before && JSON.stringify(prev) === JSON.stringify(val)) continue;
    changed.push(k);
  }
  const flips: { autoRotate?: boolean; hostMode?: HostMode; enabled?: boolean } = {};
  if (changed.includes('autoRotate') && typeof p.autoRotate === 'boolean')
    flips.autoRotate = p.autoRotate;
  if (changed.includes('enabled') && typeof p.enabled === 'boolean') flips.enabled = p.enabled;
  if (changed.includes('hostMode') && p.hostMode) flips.hostMode = p.hostMode;
  return { changed: changed.sort(), ...flips };
}

async function backendCapsOf(db: Db, origin: RelayOrigin) {
  const id = originBackendServerId(origin);
  if (!id) return null;
  const server = await db.get(id);
  return server ? capabilitiesOf(server.backend) : null;
}

/**
 * Insert-time options a guided setup passes (never a request body): defer the
 * delivery binding to go-live (`claimDeliveryBinding`) and mark the origin as
 * owned by the run (upkeep + the detector's automatic replacement skip it).
 */
export interface InsertRelayOptions {
  deferBinding?: boolean;
  setupOwned?: boolean;
}

async function insertRelay(
  ctx: MutationCtx,
  slug: string,
  origin: RelayOrigin,
  a: OriginWrite,
  opts: InsertRelayOptions = {},
): Promise<Id<'relays'>> {
  if (!SLUG_RE.test(slug)) throw new ConvexError({ code: 'validation', message: 'invalid slug' });
  if (!a.originAddress)
    throw new ConvexError({ code: 'validation', message: 'originAddress is required' });
  const cfg = await resolveEdgeConfig(ctx.db);
  const p = patchFrom(a);
  await assertOriginUnbound(ctx.db, origin, null);
  // A node being renamed gets no new origin keyed to either of its names.
  if (
    origin.kind === 'panel-node' &&
    (await runningRenameOf(ctx.db, origin.backendServerId, { name: origin.nodeName }))
  )
    throw new ConvexError({
      code: 'edge.panel_op_running',
      message: 'This node is being renamed; wait for it to finish',
    });
  await assertOriginIsNotAnEdge(ctx.db, p.originAddress!, null);
  const caps = await backendCapsOf(ctx.db, origin);
  const derived = deriveHostMode(origin, caps);
  const requested = p.hostMode;
  let hostMode: HostMode = derived;
  if (requested !== undefined) {
    if (!hostModeAllowed(origin, caps, requested))
      throw new ConvexError({
        code: 'edge.host_mode_unsupported',
        message: `hostMode ${requested} is not possible for a ${origin.kind} origin on this backend`,
      });
    hostMode = requested;
  }
  const now = Date.now();
  const id = await ctx.db.insert('relays', {
    slug,
    label: p.label,
    origin,
    backendServerId: originBackendServerId(origin),
    nodeName: originNodeName(origin),
    originAddress: p.originAddress!,
    locationCode: p.locationCode,
    hostMode,
    delivery: 'edge-required',
    enabled: p.enabled ?? true,
    autoRotate: p.autoRotate ?? false,
    probeNode: p.probeNode ?? false,
    providerPreference: p.providerPreference,
    desiredPublished: p.desiredPublished ?? cfg.desiredPublishedDefault,
    // OVERRIDES of the fleet knobs, persisted only when the caller set them, so
    // a later change of the fleet value applies to this origin (`originPolicy`).
    ...(p.standbyPerRelay !== undefined ? { standbyPerRelay: p.standbyPerRelay } : {}),
    ...(p.standbyPerListener !== undefined ? { standbyPerListener: p.standbyPerListener } : {}),
    ...(p.cooldownMs !== undefined ? { cooldownMs: p.cooldownMs } : {}),
    ...(p.maxRotationsPerDay !== undefined ? { maxRotationsPerDay: p.maxRotationsPerDay } : {}),
    ...(p.drainMs !== undefined ? { drainMs: p.drainMs } : {}),
    publicationEpoch: 0,
    publishedEdgeIds: [],
    standbyEdgeIds: [],
    rotationsToday: 0,
    ...(opts.deferBinding ? { bindingDeferred: true } : {}),
    ...(opts.setupOwned ? { setupOwned: true } : {}),
    updatedAt: now,
  });
  // From this moment the origin's subscriptions are edge-required, unless the
  // binding is deferred to go-live (the origin keeps serving its raw body; there
  // is NO shortcut that binds it when an edge publishes).
  if (!opts.deferBinding) await upsertDeliveryBinding(ctx, { origin, slug });
  return id;
}

/**
 * Claim the deferred delivery binding of an origin (the go-live step): upsert the
 * binding (policy version bump + mirror refresh, exactly as an insert does) and
 * clear `bindingDeferred`. Its one caller is the guided setup run's stage-8
 * `goLive` (edgeSetupRuns.ts), after the activation promotion.
 */
export async function claimDeliveryBinding(ctx: MutationCtx, relay: Doc<'relays'>): Promise<void> {
  await upsertDeliveryBinding(ctx, { origin: relay.origin, slug: relay.slug });
  if (relay.bindingDeferred)
    await ctx.db.patch(relay._id, { bindingDeferred: undefined, updatedAt: Date.now() });
}

/**
 * The hostMode handoff. `fcp` -> `operator`: keep the Host, FCP stops writing
 * (ownership becomes `adopted`). `operator` -> `fcp`: every listener with a
 * remark must already hold a validated Host (the explicit adopt-host operation
 * in relayListeners), otherwise the first rotation would create a duplicate.
 */
async function applyHostModeChange(
  ctx: MutationCtx,
  row: Doc<'relays'>,
  next: HostMode,
): Promise<void> {
  if (next === row.hostMode) return;
  const caps = await backendCapsOf(ctx.db, row.origin);
  if (!hostModeAllowed(row.origin, caps, next))
    throw new ConvexError({
      code: 'edge.host_mode_unsupported',
      message: `hostMode ${next} is not possible for a ${row.origin.kind} origin on this backend`,
    });
  if (row.activeRotationId) {
    const rot = await ctx.db.get(row.activeRotationId);
    if (rot && !isTerminalPhase(rot.phase))
      throw new ConvexError({
        code: 'edge.rotation_running',
        message: 'hostMode cannot change while a rotation is running',
      });
  }
  const listeners = (await listenersOf(ctx, row._id)).filter((l) => !l.retired);
  const now = Date.now();
  if (row.hostMode === 'fcp' && next === 'operator') {
    for (const l of listeners) {
      if (l.host?.state === 'present')
        await ctx.db.patch(l._id, { host: { ...l.host, ownership: 'adopted' }, updatedAt: now });
    }
    return;
  }
  if (next === 'fcp') {
    const missing = listeners.filter(
      (l) =>
        l.matchRule.kind === 'remark' && (!l.host || l.host.state !== 'present' || !l.host.uuid),
    );
    if (missing.length > 0)
      throw new ConvexError({
        code: 'edge.host_adopt_required',
        message: `adopt the panel Host of listener(s) ${missing.map((l) => l.listenerKey).join(', ')} first`,
      });
  }
}

// --- CRUD ---------------------------------------------------------------------------------------

export const create = internalMutation({
  args: {
    slug: v.string(),
    origin: adminOriginValidator,
    listeners: v.optional(v.array(listenerSpecValidator)),
    ...originWriteArgs,
    // Internal callers only (a guided setup); the HTTP handler strips both.
    deferBinding: v.optional(v.boolean()),
    setupOwned: v.optional(v.boolean()),
  },
  handler: async (
    ctx,
    { slug, origin: originArg, listeners, actorAdminId, deferBinding, setupOwned, ...a },
  ) => {
    await assertAdmission(ctx.db, 'registration');
    const dup = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (dup)
      throw new ConvexError({ code: 'conflict', message: 'An origin with this slug exists' });
    const origin = await checkOrigin(ctx.db, originArg);
    const id = await insertRelay(ctx, slug, origin, a, {
      deferBinding: deferBinding === true,
      setupOwned: setupOwned === true,
    });
    let poolRaised = false;
    if (listeners && listeners.length > 0) {
      const row = (await ctx.db.get(id))!;
      await applyRegistration(ctx, row, listeners as ListenerSpecInput[], 'admin', {
        prune: false,
        actorAdminId,
      });
      poolRaised = (await ensurePoolCapacity(ctx, (await ctx.db.get(id))!)).raised;
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.create',
      targetType: 'relay',
      targetId: id,
      payload: {
        slug,
        ...describeOrigin(origin),
        ...(deferBinding ? { bindingDeferred: true } : {}),
        ...(poolRaised ? { poolRaised: true } : {}),
      },
    });
    return { id, warnings: poolRaised ? ['edge.pool_raised'] : [] };
  },
});

export const update = internalMutation({
  args: { id: v.id('relays'), ...originWriteArgs },
  handler: async (ctx, { id, actorAdminId, ...a }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    // A restore workflow's raw-body checks assume the origin holds still.
    assertNoRestore(row);
    const p = patchFrom(a);
    await assertAddressChangeAllowed(ctx.db, row, p.originAddress);
    if (p.originAddress !== undefined) await assertOriginIsNotAnEdge(ctx.db, p.originAddress, id);
    if (p.hostMode !== undefined) await applyHostModeChange(ctx, row, p.hostMode);
    // Capacity follows coverage (lib/edges/poolCapacity.ts): a pool that cannot
    // give every deployed, enabled listener a slot is refused rather than
    // silently raised back on the next tick.
    if (p.desiredPublished !== undefined) {
      const coverage = coverageListeners(await poolListenersOf(ctx.db, id)).length;
      if (p.desiredPublished < coverage)
        throw new ConvexError({
          code: 'edge.pool_below_coverage',
          message: `desiredPublished cannot go below the ${coverage} deployed, enabled listener(s) of this relay; retire or disable a listener first`,
        });
      // With a provider set, nor below what is published plus what it still lacks.
      if (row.providerSet) {
        const state = await setStateOf(ctx.db, row);
        const floor = Math.min(MAX_DESIRED_PUBLISHED, state.published.length + state.deficit);
        if (p.desiredPublished < floor)
          throw new ConvexError({
            code: 'edge.pool_below_coverage',
            message: `desiredPublished cannot go below ${floor}: the published addresses plus what the provider set still needs`,
          });
      }
    }
    if (p.qualificationModeSlug) {
      const { modes } = await resolveModeCatalog(ctx.db);
      if (!modes.some((m) => m.id === p.qualificationModeSlug))
        throw new ConvexError({
          code: 'validation',
          message: 'qualificationModeSlug names no connection mode',
        });
    }
    // Publication-affecting edits bump the epoch (render cache + assignment).
    const affects =
      p.desiredPublished !== undefined || p.enabled !== undefined || p.hostMode !== undefined;
    await ctx.db.patch(id, {
      ...p,
      ...(affects ? { publicationEpoch: row.publicationEpoch + 1 } : {}),
      updatedAt: Date.now(),
    });
    if (affects) await scheduleMirrorRefresh(ctx);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.update',
      targetType: 'relay',
      targetId: id,
      payload: { slug: row.slug, ...changedFields(row, p) },
    });
    // An origin's own drain that a member's refresh cannot outlive (a warning).
    const warnings =
      typeof p.drainMs === 'number'
        ? drainWarnings(await resolveEdgeConfig(ctx.db), p.drainMs / 60_000)
        : [];
    return { ok: true as const, warnings };
  },
});

/**
 * Mark an origin for teardown; the edge-reconcile cron drains/destroys its edges
 * and removes the row. `disposition` says what happens to the delivery binding
 * of the origin: `restore-direct` releases it (raw delivery returns),
 * `keep-dark` keeps members on the node unavailable until another origin claims it.
 *
 * Re-sequenced for GUIDED origins (docs/edges.md § "Direct-Host hides and the
 * restore workflow"): a `restore-direct` delete of an origin that hid direct
 * Hosts, or that a setup run bound, does NOT tear down at once. It enters the
 * restore workflow with purpose `delete_relay` (hides settled, the raw FCP body
 * verified, the binding released WHILE the origin stays enabled and its edges
 * published, direct Hosts re-enabled, the direct body verified) and only its
 * last phase runs the deletion body below. `keep-dark` keeps the binding and
 * never restores a hidden Host (members stay dark by choice), so it tears down
 * at once as before. Refused while a restore is already running.
 */
export const requestDelete = internalMutation({
  args: {
    id: v.id('relays'),
    force: v.optional(v.boolean()),
    disposition: v.optional(v.union(v.literal('restore-direct'), v.literal('keep-dark'))),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, force, disposition, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const, deleted: true };
    if (!disposition && originBackendServerId(row.origin))
      throw new ConvexError({
        code: 'edge.delivery_disposition_required',
        message: 'say what happens to members of this origin: restore-direct or keep-dark',
      });
    assertNotQuarantined(row);
    assertNoRestore(row);
    if (row.activeRotationId) {
      const rot = await ctx.db.get(row.activeRotationId);
      if (rot && ['host_flipping', 'confirming', 'rolling_back'].includes(rot.phase)) {
        throw new ConvexError({
          code: 'edge.busy',
          message: 'A Host flip is in progress; retry when it converges',
        });
      }
      if (
        rot &&
        !['done', 'failed', 'rolled_back', 'quarantined', 'cancelled'].includes(rot.phase)
      ) {
        await ctx.db.patch(rot._id, { cancelRequested: true, updatedAt: Date.now() });
      }
    }
    if (disposition === 'restore-direct' && (await needsRestoreWorkflow(ctx.db, row))) {
      // The cohorts a completed guided setup left dark by consent (stamped on
      // the origin at go-live) are skipped by the workflow's raw-body checks.
      await startRestoreWorkflow(ctx, row, {
        purpose: 'delete_relay',
        force,
        ...(actorAdminId ? { actorAdminId } : {}),
      });
      await writeAuditLog(ctx, {
        actorType: actorAdminId ? 'admin' : 'system',
        actorId: actorAdminId ?? undefined,
        action: 'relay.delete',
        targetType: 'relay',
        targetId: id,
        payload: { slug: row.slug, force: force ?? false, disposition, restore: true },
      });
      return { ok: true as const, deleted: false, restore: true };
    }
    await applyDeleteBody(ctx, row, { force, disposition, actorAdminId });
    return { ok: true as const, deleted: false };
  },
});

/**
 * A guided origin's delete restores first: it hid direct Hosts (a hide row
 * exists), or a setup run bound it (`setupStage` recorded) and the binding is
 * active. An origin with neither tears down at once, as before.
 */
async function needsRestoreWorkflow(db: DatabaseReader, row: Doc<'relays'>): Promise<boolean> {
  if (await hasHideRows(db, row._id)) return true;
  const backendServerId = originBackendServerId(row.origin);
  if (!backendServerId || row.setupStage === undefined) return false;
  const binding = await deliveryBindingFor(db, backendServerId, originNodeName(row.origin));
  return !!binding && binding.relaySlug === row.slug;
}

/**
 * The deletion body: cancel-free by now (the guards ran), drains the managed
 * edges (destroys the observe-only ones), empties the pool, flags `deleting`,
 * settles the binding by disposition and refreshes the mirrors. Shared by the
 * immediate delete and the restore workflow's last phase.
 */
export async function applyDeleteBody(
  ctx: MutationCtx,
  row: Doc<'relays'>,
  opts: {
    force?: boolean;
    disposition?: DeleteDisposition;
    actorAdminId?: Id<'adminUsers'>;
    /** The restore workflow already audited `origin.delete`; skip the second entry. */
    audited?: boolean;
  },
): Promise<void> {
  const { force, disposition, actorAdminId } = opts;
  const id = row._id;
  const { drainMs } = originPolicy(row, await resolveEdgeConfig(ctx.db));
  {
    const now = Date.now();
    const edges = await liveEdgesOfRelay(ctx.db, id);
    for (const e of edges) {
      if (!e.managed) {
        await ctx.db.patch(e._id, {
          status: 'destroyed',
          publication: 'unpublished',
          destroyedAt: now,
          statusChangedAt: now,
          updatedAt: now,
        });
        continue;
      }
      if (['active', 'verifying'].includes(e.status)) {
        // An edge that was never published never served a member: no one is
        // connected through it, so there is nothing to drain.
        const served = e.publishedAt !== undefined;
        await ctx.db.patch(e._id, {
          status: 'draining',
          publication: 'draining',
          drainUntil: force || !served ? now : now + drainMs,
          statusChangedAt: now,
          updatedAt: now,
        });
      }
    }
    await ctx.db.patch(id, {
      deleting: true,
      enabled: false,
      publishedEdgeIds: [],
      standbyEdgeIds: [],
      publicationEpoch: row.publicationEpoch + 1,
      updatedAt: now,
    });
    if (!opts.audited)
      await writeAuditLog(ctx, {
        actorType: actorAdminId ? 'admin' : 'system',
        actorId: actorAdminId ?? undefined,
        action: 'relay.delete',
        targetType: 'relay',
        targetId: id,
        payload: { slug: row.slug, force: force ?? false, disposition: disposition ?? null },
      });
    if (disposition) await settleDeliveryBinding(ctx.db, row, disposition);
    await scheduleMirrorRefresh(ctx);
  }
}

/**
 * Remove the origin row once every managed edge is destroyed and no FCP-owned
 * backend Host remains (the Host cleanup runs in the reconcile cron and deletes
 * them read-back-confirmed first).
 */
export const finalizeDelete = internalMutation({
  args: { id: v.id('relays') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (!row?.deleting) return { removed: false, waitingOn: null };
    const edges = await ctx.db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', id))
      .collect();
    if (edges.some((e) => e.status !== 'destroyed'))
      return { removed: false, waitingOn: 'edges' as const };
    const listeners = await listenersOf(ctx, id);
    if (listeners.some((l) => l.host && l.host.ownership === 'fcp' && l.host.state !== 'absent'))
      return { removed: false, waitingOn: 'hosts' as const };
    for (const l of listeners) await ctx.db.delete(l._id);
    // Probe rollups are keyed by target id strings and never cascade.
    const dropRollups = async (kind: 'edge' | 'relay', ref: string) => {
      const rows = await ctx.db
        .query('probeReachability')
        .withIndex('by_target_country', (q) => q.eq('targetKind', kind).eq('targetRef', ref))
        .collect();
      for (const x of rows) await ctx.db.delete(x._id);
    };
    for (const e of edges) {
      await dropRollups('edge', e._id);
      await ctx.db.delete(e._id);
    }
    await dropRollups('relay', id);
    // The qualification credential is a backend user: deactivate it after the row
    // is gone (best effort; an orphan is a capped, expiring test account).
    const owedUsers = [
      ...(row.qualificationBackendUserId ? [row.qualificationBackendUserId] : []),
      ...(row.qualificationRemovalPending ?? []),
    ];
    const serverId = originBackendServerId(row.origin);
    if (owedUsers.length > 0 && serverId) {
      const server = await ctx.db.get(serverId);
      if (server)
        for (const backendUserId of new Set(owedUsers))
          await ctx.scheduler.runAfter(0, internal.relayQualification.removeBackendUser, {
            backend: server.backend,
            backendUserId,
            backendServerId: server._id,
          });
    }
    // An unsettled mint operation may have created a user only its username
    // names: re-find and remove it by name (best effort, like the ids above).
    const mint = row.qualificationMint;
    if (mint && mint.state !== 'stored')
      await ctx.scheduler.runAfter(0, internal.relayQualification.removeByUsername, {
        backendServerId: mint.backendServerId,
        username: mint.username,
      });
    await ctx.db.delete(id);
    return { removed: true, waitingOn: null };
  },
});

// --- adoption -------------------------------------------------------------------------------------

/**
 * The ledger `meta` of one imported child: whatever the adapter reported, plus
 * `shared:true` on the SERVICE-kind child of a resource that also serves other
 * hostnames.
 */
function metaFor(r: { kind: string; meta?: string }, sharedService: boolean): { meta?: string } {
  const isService = r.kind.includes('service');
  if (!r.meta && !(sharedService && isService)) return {};
  let parsed: Record<string, unknown> = {};
  if (r.meta) {
    try {
      const raw = JSON.parse(r.meta) as unknown;
      if (raw && typeof raw === 'object' && !Array.isArray(raw))
        parsed = raw as Record<string, unknown>;
    } catch {
      return { meta: r.meta.slice(0, 4_000) };
    }
  }
  if (sharedService && isService) parsed.shared = true;
  return { meta: JSON.stringify(parsed).slice(0, 4_000) };
}

/** A child the adapter read back as NOT fronted (`meta.proxied:false`) answers with the origin itself. */
function unproxiedChild(resources: ReadonlyArray<{ meta?: string }>): boolean {
  return resources.some((r) => {
    if (!r.meta) return false;
    try {
      const raw = JSON.parse(r.meta) as unknown;
      return !!raw && typeof raw === 'object' && (raw as Record<string, unknown>).proxied === false;
    } catch {
      return false;
    }
  });
}

interface AdoptInput {
  ipv4?: string;
  ipv6?: string | null;
  hostname?: string;
  port?: number;
  accountRow: Doc<'edgeProviderAccounts'> | null;
  /** Where the imported resource lives (its account's location); frozen on the edge. */
  locationRow?: Doc<'edgeLocations'> | null;
  resources: Array<{
    kind: string;
    resourceId: string;
    meta?: string;
    ownership?: 'created' | 'adopted';
  }>;
  inspection?: { hostnames: string[]; shared: boolean; content?: string };
  publish?: boolean;
  /**
   * The operator's statement that this L4 address ALREADY serves members (an
   * import of a live front): recorded as an `edges.verification` of method
   * `named_connection` against the configuration adopted here. Without it an
   * adopted L4 edge is a spare that needs its own test before publication.
   */
  verified?: boolean;
  actorAdminId?: Id<'adminUsers'>;
}

async function insertAdoptedEdge(
  ctx: MutationCtx,
  origin: Doc<'relays'>,
  listener: Doc<'relayListeners'>,
  a: AdoptInput,
): Promise<{ edgeId: Id<'edges'>; poolIndex: number | null; code: string | null }> {
  const port = a.port ?? 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new ConvexError({ code: 'validation', message: 'port out of range' });
  const accountRow = a.accountRow;
  if (
    accountRow &&
    listener.providerScope &&
    listener.providerScope.provider !== accountRow.provider
  )
    throw new ConvexError({
      code: 'validation',
      message: 'account provider does not match the listener’s provider scope',
    });
  const kind = accountRow ? edgeAddressKindOf(accountRow.provider) : a.hostname ? 'hostname' : 'ip';
  const layer = accountRow ? edgeLayerOf(accountRow.provider) : kind === 'hostname' ? 'l7' : 'l4';
  let hostname: string | undefined;
  if (kind === 'hostname') {
    const h = (a.hostname ?? '').trim().toLowerCase().replace(/\.$/, '');
    if (!h || !isValidHostname(h))
      throw new ConvexError({ code: 'validation', message: 'hostname must be a valid hostname' });
    if (sameAddress(h, origin.originAddress))
      throw new ConvexError({
        code: 'validation',
        message: 'the edge hostname is the origin itself (anti-leak)',
      });
    hostname = h;
    if (a.ipv4 || a.ipv6)
      throw new ConvexError({
        code: 'validation',
        message: 'an L7 edge is addressed by hostname only',
      });
  } else {
    if (a.hostname)
      throw new ConvexError({
        code: 'validation',
        message: 'an L4 edge is addressed by IP literal only',
      });
    if (!a.ipv4 || !isPublicIpLiteral(a.ipv4) || addressFamily(a.ipv4) !== 'v4')
      throw new ConvexError({ code: 'validation', message: 'ipv4 must be a public IPv4 literal' });
    if (a.ipv6 && (!isPublicIpLiteral(a.ipv6) || addressFamily(a.ipv6) !== 'v6'))
      throw new ConvexError({ code: 'validation', message: 'ipv6 must be a public IPv6 literal' });
    if (sameAddress(a.ipv4, origin.originAddress))
      throw new ConvexError({
        code: 'validation',
        message: 'the edge address is the origin itself (anti-leak)',
      });
  }
  assertNoRestore(origin);
  if (a.publish) await assertNoRotationOrQuarantine(ctx.db, origin);
  if (unproxiedChild(a.resources))
    throw new ConvexError({
      code: 'edge.record_not_proxied',
      message: 'the record is DNS only: nothing fronts this hostname',
    });
  const managed = !!accountRow && a.resources.length > 0;
  const now = Date.now();
  let provisionIntent: string | undefined;
  let sharedService = false;
  if (managed && layer === 'l7') {
    const insp = a.inspection;
    if (!insp)
      throw new ConvexError({
        code: 'validation',
        message: 'an L7 import needs the provider inspection',
      });
    if (!insp.content || !sameAddress(insp.content, origin.originAddress))
      throw new ConvexError({
        code: 'edge.not_owned',
        message: 'the resource does not dial this origin',
      });
    if (!insp.hostnames.some((h) => h.trim().toLowerCase().replace(/\.$/, '') === hostname))
      throw new ConvexError({
        code: 'edge.not_owned',
        message: 'the resource does not serve this hostname',
      });
    sharedService = insp.shared;
    const template = await resolveTemplateFor(
      ctx,
      accountRow!.provider,
      null,
      accountRow!.defaultTemplateId ?? null,
      accountRow!._id,
      a.locationRow ?? null,
    );
    // The front lives in the picked location's zone: its records are looked
    // for there, so a hostname outside it cannot be described or destroyed.
    const place = await l7PlaceOf(ctx.db, accountRow!, a.locationRow ?? null);
    const zone = place.zoneName?.toLowerCase();
    if (zone && hostname && hostname !== zone && !hostname.endsWith(`.${zone}`))
      throw new ConvexError({
        code: 'edge.hostname_not_in_zone',
        message: `The hostname is not in ${zone}: pick the location of its zone`,
      });
    try {
      provisionIntent = JSON.stringify(
        buildProvisionIntent({
          account: {
            id: accountRow!._id as string,
            provider: accountRow!.provider,
            settings: accountRow!.settings as Record<string, unknown>,
          },
          place,
          // An imported front serves the certificate it has; the account's
          // defaults are what a discovery or a destroy looks for.
          certificate: certificateValuesFor(
            accountRow!.provider,
            accountOptionDefaultsOf(accountRow!),
            null,
          ),
          specName: `adopted-${origin.slug}-${now.toString(36)}`,
          templateParams: template.params,
          templateHash: template.hash,
          listener,
          hostnameOverride: hostname,
        }),
      );
    } catch (err) {
      throw new ConvexError({
        code: `edge.${err instanceof IntentError ? err.code : 'intent_failed'}`,
        message: 'the import cannot be described',
      });
    }
  }
  const edgeId = await ctx.db.insert('edges', {
    relayId: origin._id,
    listenerId: listener._id,
    accountId: accountRow?._id,
    ...(accountRow && a.locationRow
      ? {
          locationId: a.locationRow._id,
          placeKey: a.locationRow.placeKey,
          placement: a.locationRow.placement,
        }
      : {}),
    provider: accountRow?.provider,
    managed,
    name: `adopted-${origin.slug}-${now.toString(36)}`,
    steps: [],
    resources: a.resources.map((r) => ({
      stepId: 'adopted',
      kind: r.kind,
      resourceId: r.resourceId,
      ownership: 'adopted' as const,
      deleteState: 'present' as const,
      ...metaFor(r, sharedService),
    })),
    listeners: [
      {
        edgePort: port,
        originAddress: origin.originAddress,
        originPort: listener.originPort,
        transport: protocolTransport(listener),
      },
    ],
    addresses: { v4: a.ipv4, v6: a.ipv6 ?? undefined, hostname },
    layer,
    ...(provisionIntent ? { provisionIntent } : {}),
    publication: 'unpublished',
    status: 'active',
    statusChangedAt: now,
    health: 'unknown',
    destroyAttempts: 0,
    updatedAt: now,
  });
  if (a.verified && layer !== 'l7') {
    const inserted = (await ctx.db.get(edgeId))!;
    const verifiable = await verificationListenerOf(ctx.db, listener);
    const binding = verificationBinding(inserted, verifiable);
    if (binding)
      await ctx.db.patch(edgeId, {
        verification: {
          rung: 'verified',
          by: 'admin',
          at: now,
          method: 'named_connection',
          ...binding,
          ...(verifiable.authRevision ? { authRevision: verifiable.authRevision } : {}),
        },
        updatedAt: now,
      });
  }
  let poolIndex: number | null = null;
  const softRefusal = layer === 'l7' && managed;
  let refusedCode: string | null = null;
  let allocated: number | null = null;
  if (a.publish) {
    const alloc = allocatePoolIndex(
      origin.publishedEdgeIds,
      origin.desiredPublished,
      await poolAdmitOf(ctx.db, origin, (await ctx.db.get(edgeId))!),
    );
    if ('refused' in alloc) {
      if (!softRefusal) throw poolRefusal(alloc.refused);
      refusedCode = alloc.refused;
    } else allocated = alloc.index;
    const cfg = await resolveEdgeConfig(ctx.db);
    const fresh = (await ctx.db.get(edgeId))!;
    const check = refusedCode
      ? { ok: false as const, code: refusedCode }
      : await checkPublishable(ctx, fresh, cfg.requireProviderHealth);
    if (!check.ok) {
      if (!softRefusal)
        throw new ConvexError({
          code: `edge.${check.code}`,
          message: `Edge cannot be published: ${check.code}`,
        });
      refusedCode = check.code ?? 'not_publishable';
    }
  }
  if (a.publish && !refusedCode && allocated !== null) {
    const idx = allocated;
    poolIndex = idx;
    await ctx.db.patch(edgeId, {
      publication: 'published',
      poolIndex: idx,
      publishedAt: now,
      updatedAt: now,
    });
    await ctx.db.patch(origin._id, {
      publishedEdgeIds: withEdgeAt(origin.publishedEdgeIds, idx, edgeId),
      publicationEpoch: origin.publicationEpoch + 1,
      updatedAt: now,
    });
    if (!listener.templateEdgeId)
      await ctx.db.patch(listener._id, { templateEdgeId: edgeId, updatedAt: now });
    await scheduleMirrorRefresh(ctx);
  }
  await writeAuditLog(ctx, {
    actorType: a.actorAdminId ? 'admin' : 'system',
    actorId: a.actorAdminId ?? undefined,
    action: 'edge.adopted',
    targetType: 'relay',
    targetId: origin._id,
    payload: {
      slug: origin.slug,
      edgeId,
      managed,
      publication: poolIndex !== null ? 'published' : 'unpublished',
      ...(refusedCode ? { refused: refusedCode } : {}),
      ...(sharedService ? { shared: true } : {}),
      ...(a.verified && layer !== 'l7' ? { verified: true } : {}),
    },
  });
  return { edgeId, poolIndex, code: refusedCode };
}

/**
 * Adopt an edge that exists outside FCP's ledger: observe-only (`managed:false`,
 * only the address + port known; never destroyed) or managed (account +
 * resource ids supplied). Optionally publish it right away at the next free
 * pool index.
 */
export const adoptEdge = internalMutation({
  args: {
    relayId: v.id('relays'),
    listenerId: v.id('relayListeners'),
    ipv4: v.optional(v.string()),
    ipv6: v.optional(v.union(v.string(), v.null())),
    hostname: v.optional(v.string()),
    port: v.optional(v.number()),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    /** The account's location the resource lives in (its default location when absent). */
    locationId: v.optional(v.union(v.id('edgeLocations'), v.null())),
    resources: v.optional(
      v.array(
        v.object({
          kind: v.string(),
          resourceId: v.string(),
          meta: v.optional(v.string()),
          ownership: v.optional(v.union(v.literal('created'), v.literal('adopted'))),
        }),
      ),
    ),
    inspection: v.optional(
      v.object({
        hostnames: v.array(v.string()),
        shared: v.boolean(),
        content: v.optional(v.string()),
      }),
    ),
    publish: v.optional(v.boolean()),
    verified: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const listener = await ctx.db.get(a.listenerId);
    await assertAdmission(ctx.db, 'adopt');
    if (!listener || listener.relayId !== a.relayId)
      throw new ConvexError({
        code: 'validation',
        message: 'listener does not belong to the origin',
      });
    // An import that publishes is a pool write: not while a setup run is working on the origin.
    if (a.publish) await assertNoRunningSetup(ctx.db, origin);
    let accountRow: Doc<'edgeProviderAccounts'> | null = null;
    let locationRow: Doc<'edgeLocations'> | null = null;
    if (a.accountId) {
      accountRow = await ctx.db.get(a.accountId);
      if (!accountRow) throw new ConvexError({ code: 'validation', message: 'unknown account' });
      // A managed import is destroyed by FCP one day: it must know the region.
      locationRow = a.locationId
        ? await ctx.db.get(a.locationId)
        : await defaultLocationOf(ctx.db, accountRow);
      if (!locationRow || locationRow.accountId !== accountRow._id)
        throw new ConvexError({ code: 'validation', message: 'unknown location for the account' });
    }
    return insertAdoptedEdge(ctx, origin, listener, {
      ipv4: a.ipv4,
      ipv6: a.ipv6,
      hostname: a.hostname,
      port: a.port,
      accountRow,
      locationRow,
      resources: a.resources ?? [],
      inspection: a.inspection,
      publish: a.publish,
      verified: a.verified,
      actorAdminId: a.actorAdminId,
    });
  },
});

// --- published pool -----------------------------------------------------------------------------

/** The listener projection the reserved-allocation rule reads. */
/**
 * What publishing `edge` on `relay` does to the coverage deficit (the pool
 * admission input, `allocatePoolIndex`): read from the origin's provider set
 * and what its pool publishes now.
 */
export async function poolAdmitOf(
  db: Db,
  relay: Doc<'relays'>,
  edge: Pick<Doc<'edges'>, 'listenerId' | 'locationId' | 'provider' | 'placeKey'>,
): Promise<PoolAdmit> {
  const state = await setStateOf(db, relay);
  const listener = await db.get(edge.listenerId);
  return admissionOf(state, publishedRefOf(edge, listener?.listenerKey ?? ''));
}

export async function poolListenersOf(db: Db, relayId: Id<'relays'>): Promise<PoolListener[]> {
  const rows = await db
    .query('relayListeners')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .collect();
  return rows.map((l) => ({
    id: l._id as string,
    templateEdgeId: (l.templateEdgeId as string | undefined) ?? null,
    deployed: l.deployed,
    enabled: l.enabled,
    retired: l.retired,
  }));
}

export function poolRefusal(
  code: 'pool_full' | 'pool_reserved',
): ConvexError<{ code: string; message: string }> {
  return new ConvexError({
    code: `edge.${code}`,
    message:
      code === 'pool_full'
        ? 'The published pool is full'
        : 'The free pool slots are held for what this origin still lacks (a listener, or a location of its provider set, with nothing published)',
  });
}

export interface PublishCheck {
  ok: boolean;
  code?: string;
}

function udpProviderAvailable(): boolean {
  return Object.values(EDGE_PROVIDER_CAPABILITIES).some((c) => c.udp);
}

/**
 * Publication preconditions: the edge is active + unpublished, has the address
 * of ITS layer's kind, its listener is deployed, enabled and not retired, with
 * ≥1 active name when it presents one behind an L4 edge, the edge's provider
 * matches the listener's scope and can carry the listener at the edge's layer,
 * and, for an L7 front, an authenticated end-to-end session has proven exactly
 * this configuration and has not expired. An edge of a DNS account (role `dns`)
 * goes live only while that account is set to DNS and fronting: a spare made
 * earlier must not start carrying members once it is DNS only (a published one
 * is left as it is). Nor does a load balancer in front of a WebSocket node's
 * transport (`l4_not_for_websocket`, lib/edges/websocketNode.ts).
 *
 * `skipVerification` takes ONLY the L4 endpoint-verification rule out (the
 * verification-binding view asks "what else blocks this edge once tested?");
 * no publish path passes it.
 */
export async function checkPublishable(
  ctx: { db: DatabaseReader },
  edge: Doc<'edges'>,
  requireHealth: boolean,
  opts: { skipVerification?: boolean } = {},
): Promise<PublishCheck> {
  if (edge.status !== 'active') return { ok: false, code: 'edge_not_active' };
  if (edge.publication === 'published') return { ok: false, code: 'already_published' };
  if (edgeRoleOf(edge.provider) === 'dns') {
    const account = edge.accountId ? await ctx.db.get(edge.accountId) : null;
    if (!frontsAllowed(account ?? { provider: edge.provider ?? '' }))
      return { ok: false, code: 'dns_account_not_fronting' };
  }
  if (!hasPublishableAddress(edge)) return { ok: false, code: 'no_address' };
  const listener = await ctx.db.get(edge.listenerId);
  if (!listener || listener.retired) return { ok: false, code: 'listener_retired' };
  if (!listener.deployed) return { ok: false, code: 'listener_not_deployed' };
  if (!listener.enabled) return { ok: false, code: 'listener_disabled' };
  const layer = edge.layer ?? edgeLayerOf(edge.provider);
  const intent = parseIntent(edge.provisionIntent);
  if (layer === 'l4' && protocolUsesSni(listener) && activeNames(listener).length === 0)
    return { ok: false, code: 'listener_no_active_name' };
  if (edge.provider && listener.providerScope && listener.providerScope.provider !== edge.provider)
    return { ok: false, code: 'provider_mismatch' };
  // A load balancer a WebSocket node already had stays as it is, but never goes
  // live (lib/edges/websocketNode.ts).
  if (
    layer === 'l4' &&
    protocolIsHttpTransport(listener) &&
    (await ctx.db.get(edge.relayId).then((r) => !!r && websocketNodeOf(ctx.db, r.origin)))
  )
    return { ok: false, code: 'l4_not_for_websocket' };
  if (protocolTransport(listener) === 'udp' && !udpProviderAvailable())
    return { ok: false, code: 'transport_not_carried' };
  const l7Host = l7HostHeaderFor(
    edge.addresses.hostname ?? intent?.hostname,
    (intent?.templateParams as { overrideHost?: unknown } | undefined)?.overrideHost,
    edge.provider,
  );
  if (edge.provider) {
    if (!protocolCarriedBy(edge.provider, listener, listener.originPort))
      return { ok: false, code: 'protocol_not_carried' };
    if (
      !listenerAllowsLayer(listener, edgeLayerOf(edge.provider), {
        l7Host,
        udpProviderAvailable: udpProviderAvailable(),
      })
    )
      return { ok: false, code: 'layer_mismatch' };
  }
  if (layer === 'l7') {
    if (
      intent?.zoneSslMode &&
      zoneModeGovernsOrigin(edge.provider) &&
      !zoneModeCarriesOrigin(intent.zoneSslMode, intent.originTransport)
    )
      return { ok: false, code: 'origin_tls_mismatch' };
    if (!intent) return { ok: false, code: 'front_unqualified' };
    const verdict = qualificationVerdict(
      edge.frontQualification,
      qualificationBinding({ listener, intent, params: listener.transportParams ?? {} }),
      Date.now(),
    );
    const refusal = qualificationRefusal(verdict);
    if (refusal) return { ok: false, code: refusal };
  }
  if (
    edge.accountId &&
    listener.providerScope?.accountId &&
    listener.providerScope.accountId !== edge.accountId
  )
    return { ok: false, code: 'account_mismatch' };
  // An L4 endpoint goes live only with a confirmation against the configuration
  // it holds now (lib/edges/verification.ts): the operator's own, or FCP's own
  // client check where it may stand in for one (a ticked location, the switch
  // on; edgeClientCheck.ts). A stale one (listener revision bump,
  // re-addressing) is none at all. The L7 proof above is the L7 form.
  if (
    !opts.skipVerification &&
    needsEndpointVerification(edge) &&
    !verificationCurrent(edge, await verificationListenerOf(ctx.db, listener))
  )
    return { ok: false, code: 'unverified_endpoint' };
  if (edge.managed && !providerHealthSatisfies(edge.provider, edge.health, requireHealth))
    return { ok: false, code: 'edge_unhealthy' };
  return { ok: true };
}

/** After a pool change: each listener's template edge = its lowest-index published edge. */
export async function refreshTemplateEdges(ctx: MutationCtx, origin: Doc<'relays'>): Promise<void> {
  const listeners = await listenersOf(ctx, origin._id);
  const relay = (await ctx.db.get(origin._id)) ?? origin;
  for (const l of listeners) {
    let pick: Id<'edges'> | undefined;
    for (const edgeId of relay.publishedEdgeIds) {
      if (!edgeId) continue;
      const e = await ctx.db.get(edgeId);
      if (e && e.listenerId === l._id && e.publication === 'published') {
        pick = e._id;
        break;
      }
    }
    if ((l.templateEdgeId ?? undefined) !== pick)
      await ctx.db.patch(l._id, { templateEdgeId: pick, updatedAt: Date.now() });
  }
}

export const publishEdge = internalMutation({
  args: {
    relayId: v.id('relays'),
    edgeId: v.id('edges'),
    poolIndex: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, edgeId, poolIndex, actorAdminId }) => {
    await assertAdmission(ctx.db, 'publish');
    const origin = await ctx.db.get(relayId);
    const edge = await ctx.db.get(edgeId);
    if (!origin || !edge || edge.relayId !== relayId)
      throw new ConvexError({ code: 'not_found', message: 'Origin/edge not found' });
    await assertNoRunningSetup(ctx.db, origin);
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const cfg = await resolveEdgeConfig(ctx.db);
    const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
    if (!check.ok)
      throw new ConvexError({
        code: `edge.${check.code}`,
        message: `Edge cannot be published: ${check.code}`,
      });
    // A named index that is occupied is refused as such, before any pool rule.
    if (poolIndex !== undefined) {
      const named = origin.publishedEdgeIds[poolIndex];
      if (named && named !== edgeId)
        throw new ConvexError({ code: 'edge.pool_index_taken', message: 'Pool index is occupied' });
    }
    // Reserved allocation applies whether or not an index was named: a free
    // slot held for an uncovered listener is not this edge's to take.
    const alloc = allocatePoolIndex(
      origin.publishedEdgeIds,
      origin.desiredPublished,
      await poolAdmitOf(ctx.db, origin, edge),
    );
    if ('refused' in alloc) throw poolRefusal(alloc.refused);
    let idx = poolIndex ?? alloc.index;
    if (idx < 0 || idx >= Math.max(origin.desiredPublished, origin.publishedEdgeIds.length))
      idx = alloc.index;
    const occupant = origin.publishedEdgeIds[idx];
    if (occupant && occupant !== edgeId)
      throw new ConvexError({ code: 'edge.pool_index_taken', message: 'Pool index is occupied' });
    // A listener's template Host follows its FIRST published edge. When FCP
    // owns the Hosts and this edge would become that template, the direct path
    // would leave the backend sending everyone to the previous address: the
    // rotation machine (kind `publish`) does the flip.
    const listener = await ctx.db.get(edge.listenerId);
    const becomesTemplate =
      origin.hostMode === 'fcp' &&
      (!listener?.templateEdgeId ||
        origin.publishedEdgeIds.findIndex((e) => e === listener.templateEdgeId) > idx);
    if (becomesTemplate) {
      throw new ConvexError({
        code: 'edge.needs_rotation',
        message:
          'Publishing the listener’s template edge needs the backend-Host flip; start a publish rotation',
      });
    }
    const now = Date.now();
    await ctx.db.patch(edgeId, {
      publication: 'published',
      poolIndex: idx,
      publishedAt: now,
      updatedAt: now,
    });
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(relayId, {
      publishedEdgeIds: withEdgeAt(origin.publishedEdgeIds, idx, edgeId),
      standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
      publicationEpoch: epoch,
      updatedAt: now,
    });
    await refreshTemplateEdges(ctx, origin);
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'edge.published',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
    });
    await scheduleMirrorRefresh(ctx);
    return { poolIndex: idx, epoch };
  },
});

export const unpublishEdge = internalMutation({
  args: {
    relayId: v.id('relays'),
    edgeId: v.id('edges'),
    drainMs: v.optional(v.number()),
    keepActive: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, edgeId, drainMs, keepActive, actorAdminId }) => {
    const origin = await ctx.db.get(relayId);
    const edge = await ctx.db.get(edgeId);
    if (!origin || !edge || edge.relayId !== relayId)
      throw new ConvexError({ code: 'not_found', message: 'Origin/edge not found' });
    await assertNoRunningSetup(ctx.db, origin);
    await assertNoRotationOrQuarantine(ctx.db, origin);
    if (edge.publication !== 'published')
      return { ok: true as const, epoch: origin.publicationEpoch };
    const { epoch } = await unpublishFromPool(ctx, origin, edge, {
      drainMs,
      keepActive,
      actorAdminId,
    });
    return { ok: true as const, epoch };
  },
});

/**
 * The body of `unpublishEdge` once its guards passed (the caller checked the
 * rotation / quarantine / restore guard and that the edge is published): out
 * of the pool (draining, or back to standby with `keepActive`), epoch bump,
 * template edges refreshed, audited, mirrors refreshed. Re-reads the origin,
 * so one mutation may call it for several edges. A re-protect cancel drops its
 * published candidates through it.
 */
export async function unpublishFromPool(
  ctx: MutationCtx,
  originRow: Doc<'relays'>,
  edge: Doc<'edges'>,
  opts: { drainMs?: number; keepActive?: boolean; actorAdminId?: Id<'adminUsers'> } = {},
): Promise<{ epoch: number }> {
  const origin = (await ctx.db.get(originRow._id)) ?? originRow;
  const edgeId = edge._id;
  const now = Date.now();
  const poolIndex = edge.poolIndex ?? null;
  if (opts.keepActive) {
    await ctx.db.patch(edgeId, {
      publication: 'unpublished',
      poolIndex: undefined,
      updatedAt: now,
    });
  } else {
    await ctx.db.patch(edgeId, {
      publication: 'draining',
      status: 'draining',
      drainUntil:
        now + (opts.drainMs ?? originPolicy(origin, await resolveEdgeConfig(ctx.db)).drainMs),
      poolIndex: undefined,
      statusChangedAt: now,
      updatedAt: now,
    });
  }
  const epoch = origin.publicationEpoch + 1;
  await ctx.db.patch(origin._id, {
    publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
    standbyEdgeIds: opts.keepActive
      ? [...origin.standbyEdgeIds.filter((e) => e !== edgeId), edgeId]
      : origin.standbyEdgeIds.filter((e) => e !== edgeId),
    publicationEpoch: epoch,
    updatedAt: now,
  });
  await refreshTemplateEdges(ctx, origin);
  await writeAuditLog(ctx, {
    actorType: opts.actorAdminId ? 'admin' : 'system',
    actorId: opts.actorAdminId ?? undefined,
    action: 'edge.unpublished',
    targetType: 'edge',
    targetId: edgeId,
    payload: { relaySlug: origin.slug, edgeId, poolIndex, epoch },
  });
  await scheduleMirrorRefresh(ctx);
  return { epoch };
}

/**
 * A published edge that vanished at the provider or was destroyed by an
 * operator: remove it from the pool without a drain and bump the epoch.
 */
export const dropFromPool = internalMutation({
  args: {
    relayId: v.id('relays'),
    edgeId: v.id('edges'),
    reason: v.string(),
    force: v.optional(v.boolean()),
  },
  handler: async (ctx, { relayId, edgeId, reason, force }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return { ok: false as const };
    // `force` waives the rotation guard, never the restore lock.
    assertNoRestore(origin);
    if (!force) await assertNoRotationOrQuarantine(ctx.db, origin);
    const edge = await ctx.db.get(edgeId);
    if (!edge) {
      const inPool = origin.publishedEdgeIds.includes(edgeId);
      const inStandby = origin.standbyEdgeIds.includes(edgeId);
      if (!inPool && !inStandby) return { ok: true as const, dropped: false };
      await ctx.db.patch(relayId, {
        publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
        standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: Date.now(),
      });
      await refreshTemplateEdges(ctx, origin);
      if (inPool) await scheduleMirrorRefresh(ctx);
      return { ok: true as const, dropped: true };
    }
    const r = await dropEdgeFromPool(ctx, origin, edge, { reason });
    await refreshTemplateEdges(ctx, origin);
    return { ok: true as const, dropped: r.dropped };
  },
});

/**
 * Coverage upkeep for the reconcile cron: raise / expand `desiredPublished`
 * for the origin's listeners (lib/edges/poolCapacity.ts). Returns what changed
 * and how many uncovered listeners no expansion can make room for.
 */
export const ensureCapacity = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    return ensurePoolCapacity(ctx, relay);
  },
});

/**
 * Make room in a pool at its cap: unpublish ONE removable edge (highest pool
 * index first) back to standby so upkeep can publish what the origin lacks
 * into the freed slot. Removable: published, not its listener's template edge,
 * and its removal does not increase the coverage deficit (lib/edges/providerSet.ts
 * `removableUnder`; a pool that is already short somewhere can still give up a
 * redundant copy). Never automatic: it changes what members receive. Refusals:
 * `edge.no_duplicate` (nothing removable), the usual rotation / quarantine guard.
 */
export const rebalance = internalMutation({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { relayId, actorAdminId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    await assertNoRunningSetup(ctx.db, origin);
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const listeners = await listenersOf(ctx, relayId);
    const templates = new Set(
      listeners.map((l) => l.templateEdgeId as string | undefined).filter(Boolean),
    );
    const state = await setStateOf(ctx.db, origin);
    let pick: Doc<'edges'> | null = null;
    for (let i = state.published.length - 1; i >= 0; i--) {
      const edgeId = state.published[i]!.edgeId;
      if (templates.has(edgeId as string)) continue;
      if (!removableUnder(state.requirement, state.published, i)) continue;
      const e = await ctx.db.get(edgeId);
      if (e && e.publication === 'published') {
        pick = e;
        break;
      }
    }
    if (!pick)
      throw new ConvexError({
        code: 'edge.no_duplicate',
        message:
          "No published edge can go without costing coverage (each is its listener's template edge or the only one of its group or pick)",
      });
    const picked = pick;
    const now = Date.now();
    const poolIndex = picked.poolIndex ?? null;
    await ctx.db.patch(picked._id, {
      publication: 'unpublished',
      poolIndex: undefined,
      updatedAt: now,
    });
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(relayId, {
      publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, picked._id),
      standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== picked._id), picked._id],
      publicationEpoch: epoch,
      updatedAt: now,
    });
    await refreshTemplateEdges(ctx, origin);
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'edge.relay.rebalanced',
      targetType: 'relay',
      targetId: relayId,
      payload: { relaySlug: origin.slug, edgeId: picked._id, poolIndex, epoch },
    });
    await scheduleMirrorRefresh(ctx);
    return { ok: true as const, edgeId: picked._id, poolIndex, epoch };
  },
});

export { publishAddressOf };
