/**
 * RELAYS: an ORIGIN members reach only through edges. A relay's origin is a
 * panel node, a whole backend server or a hand-described address
 * (lib/edges/origin.ts); its LISTENERS (relayListeners.ts) say what the origin
 * speaks; its published POOL of edges is what members are handed. Owns the
 * relay CRUD (admin + the node role's by-slug registration), edge adoption,
 * the delivery binding that keeps subscriptions of the origin edge-required,
 * and the published-pool bookkeeping (publish / unpublish with pool-index
 * inheritance and the publication epoch the render cache keys on). Rotation
 * state lives in edgeRotations.ts; edge rows in edges.ts.
 */
import { ConvexError, v } from 'convex/values';
import { resolveModeCatalog } from './lib/connectionModes';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, DatabaseWriter, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { isTerminalPhase } from './lib/edges/rotation';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { resolveEdgeConfig, edgeMs, MAX_DESIRED_PUBLISHED } from './lib/edgeConfig';
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
import { protocolTransport, protocolUsesSni } from './lib/edges/protocols';
import {
  EDGE_PROVIDER_CAPABILITIES,
  edgeAddressKindOf,
  edgeLayerOf,
  protocolCarriedBy,
  providerHealthSatisfies,
  zoneModeGovernsOrigin,
} from './lib/edges/providers/capabilities';
import {
  buildProvisionIntent,
  IntentError,
  parseIntent,
  parseObservedSettings,
} from './lib/edges/intent';
import {
  qualificationBinding,
  qualificationRefusal,
  qualificationVerdict,
} from './lib/edges/frontCheck/binding';
import {
  allocatePoolIndex,
  coverageListeners,
  withEdgeAt,
  withoutEdge,
  publishedCount,
  type PoolListener,
} from './lib/edges/pool';
import { ensurePoolCapacity } from './lib/edges/poolCapacity';
import { assertAdmission } from './lib/edges/maintenance';
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
  bumpEpochAndRefresh,
  liveEdgesOfRelay,
  scheduleMirrorRefresh,
} from './lib/edges/relayGuards';
import {
  activeNames,
  applyRegistration,
  listenerSpecValidator,
  listenersOf,
} from './relayListeners';
import type { ListenerSpecInput } from './lib/edges/registration';

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
  const { EDGE_LIVE_STATUSES, LIVE_EDGE_SCAN_LIMIT } = await import('./lib/edges/pool');
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

/** Two origins describe the same place with the same node identity (a re-registration of it). */
function sameOrigin(a: RelayOrigin, b: RelayOrigin): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'manual') return true;
  if (a.kind === 'panel-node' && b.kind === 'panel-node')
    return (
      a.backendServerId === b.backendServerId &&
      a.nodeName === b.nodeName &&
      (a.nodeUuid ?? null) === (b.nodeUuid ?? null)
    );
  return originBackendServerId(a) === originBackendServerId(b);
}

/**
 * One relay per place: per (backend server, node) for a panel node, per
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
      message: 'Drain or destroy every edge of this relay before changing originAddress',
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
 * relay row. `policyVersion` bumps whenever the binding is (re)claimed so the
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
  // node stay unavailable until another relay claims it (or an operator releases).
}

/** The active binding covering (backend server, node) or the whole server; null = raw delivery. */
export async function deliveryBindingFor(
  db: Db,
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<Doc<'edgeDeliveryBindings'> | null> {
  if (nodeName) {
    const byNode = await db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) =>
        q.eq('backendServerId', backendServerId).eq('nodeName', nodeName),
      )
      .unique();
    if (byNode && byNode.state === 'active') return byNode;
  }
  const byServer = await db
    .query('edgeDeliveryBindings')
    .withIndex('by_server_node', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeName', undefined),
    )
    .unique();
  return byServer && byServer.state === 'active' ? byServer : null;
}

export const deliveryBinding = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: (ctx, { backendServerId, nodeName }) =>
    deliveryBindingFor(ctx.db, backendServerId, nodeName),
});

/** Operator release of a `keep-dark` binding left behind by a deleted relay. */
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
      throw new ConvexError({ code: 'conflict', message: 'The binding’s relay still exists' });
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

export function mapRelayAdmin(r: Doc<'relays'>) {
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
    standbyPerRelay: r.standbyPerRelay,
    standbyPerListener: r.standbyPerListener ?? null,
    bindingDeferred: r.bindingDeferred ?? false,
    setupOwned: r.setupOwned ?? false,
    cooldownMinutes: Math.round(r.cooldownMs / 60_000),
    maxRotationsPerDay: r.maxRotationsPerDay,
    drainMinutes: Math.round(r.drainMs / 60_000),
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
    suspicion: r.suspicion
      ? {
          ...r.suspicion,
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
  handler: async (ctx) =>
    (await ctx.db.query('relays').collect())
      .sort((a, b) => a.slug.localeCompare(b.slug))
      .map(mapRelayAdmin),
});

export const get = internalQuery({
  args: { id: v.id('relays') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

export const getBySlug = internalQuery({
  args: { slug: v.string() },
  handler: (ctx, { slug }) =>
    ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique(),
});

/** Every relay (small, operator-managed table) for the reconcile cron. */
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
 * The relay behind a subscription's resolved place: the panel node it was
 * pinned to, or the whole backend server. The attribution + render lookup.
 */
export async function relayForBackendNode(
  db: Db,
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<Doc<'relays'> | null> {
  if (nodeName) {
    const byNode = await db
      .query('relays')
      .withIndex('by_node', (q) =>
        q.eq('backendServerId', backendServerId).eq('nodeName', nodeName),
      )
      .unique();
    if (byNode) return byNode;
  }
  const rows = await db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', backendServerId))
    .collect();
  return rows.find((r) => r.origin.kind === 'backend-server') ?? null;
}

export const forNode = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: (ctx, { backendServerId, nodeName }) =>
    relayForBackendNode(ctx.db, backendServerId, nodeName),
});

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

/** The origin as the node role names it (by backend slug: the role never knows ids). */
export const wireOriginValidator = v.union(
  v.object({
    kind: v.literal('panel-node'),
    backendSlug: v.string(),
    nodeName: v.string(),
    nodeUuid: v.optional(v.union(v.string(), v.null())),
  }),
  v.object({ kind: v.literal('backend-server'), backendSlug: v.string() }),
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
type WireOriginArg =
  | { kind: 'panel-node'; backendSlug: string; nodeName: string; nodeUuid?: string | null }
  | { kind: 'backend-server'; backendSlug: string }
  | { kind: 'manual' };

async function resolveWireOrigin(db: Db, o: WireOriginArg): Promise<AdminOriginArg> {
  if (o.kind === 'manual') return o;
  const server = await db
    .query('backendServers')
    .withIndex('by_slug', (q) => q.eq('slug', o.backendSlug))
    .unique();
  if (!server) throw new ConvexError({ code: 'validation', message: 'unknown backend slug' });
  return o.kind === 'panel-node'
    ? {
        kind: 'panel-node',
        backendServerId: server._id,
        nodeName: o.nodeName,
        nodeUuid: o.nodeUuid,
      }
    : { kind: 'backend-server', backendServerId: server._id };
}

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
  standbyPerRelay?: number;
  standbyPerListener?: number;
  cooldownMinutes?: number;
  maxRotationsPerDay?: number;
  drainMinutes?: number;
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
  if (a.standbyPerRelay !== undefined && (a.standbyPerRelay < 0 || a.standbyPerRelay > 2))
    throw new ConvexError({ code: 'validation', message: 'standbyPerRelay must be 0..2' });
  if (
    a.standbyPerListener !== undefined &&
    (!Number.isInteger(a.standbyPerListener) ||
      a.standbyPerListener < 0 ||
      a.standbyPerListener > 2)
  )
    throw new ConvexError({ code: 'validation', message: 'standbyPerListener must be 0..2' });
  if (a.cooldownMinutes !== undefined && (a.cooldownMinutes < 10 || a.cooldownMinutes > 1440))
    throw new ConvexError({ code: 'validation', message: 'cooldownMinutes must be 10..1440' });
  if (a.maxRotationsPerDay !== undefined && (a.maxRotationsPerDay < 1 || a.maxRotationsPerDay > 12))
    throw new ConvexError({ code: 'validation', message: 'maxRotationsPerDay must be 1..12' });
  if (a.drainMinutes !== undefined && (a.drainMinutes < 1 || a.drainMinutes > 7 * 1440))
    throw new ConvexError({ code: 'validation', message: 'drainMinutes must be 1..10080' });
  if (
    a.locationCode !== undefined &&
    a.locationCode !== null &&
    !/^[A-Za-z0-9-]{1,16}$/.test(a.locationCode)
  )
    throw new ConvexError({ code: 'validation', message: 'invalid locationCode' });
}

const hostModeValidator = v.union(v.literal('fcp'), v.literal('operator'), v.literal('none'));

/** Operator-owned knobs (admin form); the role never sets any of them. */
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
  standbyPerRelay: v.optional(v.number()),
  standbyPerListener: v.optional(v.number()),
  cooldownMinutes: v.optional(v.number()),
  maxRotationsPerDay: v.optional(v.number()),
  drainMinutes: v.optional(v.number()),
  // The connection mode whose placement the L7 qualification user is minted on
  // (null = the panel's default placement).
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
  standbyPerRelay?: number;
  standbyPerListener?: number;
  cooldownMinutes?: number;
  maxRotationsPerDay?: number;
  drainMinutes?: number;
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
  if (a.standbyPerRelay !== undefined) p.standbyPerRelay = a.standbyPerRelay;
  if (a.standbyPerListener !== undefined) p.standbyPerListener = a.standbyPerListener;
  if (a.cooldownMinutes !== undefined) p.cooldownMs = a.cooldownMinutes * 60_000;
  if (a.maxRotationsPerDay !== undefined) p.maxRotationsPerDay = a.maxRotationsPerDay;
  if (a.drainMinutes !== undefined) p.drainMs = a.drainMinutes * 60_000;
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
 * delivery binding to go-live (`claimDeliveryBinding`) and mark the relay as
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
  a: OriginWrite & { hostModeRequest?: HostMode },
  opts: InsertRelayOptions = {},
): Promise<Id<'relays'>> {
  if (!SLUG_RE.test(slug)) throw new ConvexError({ code: 'validation', message: 'invalid slug' });
  if (!a.originAddress)
    throw new ConvexError({ code: 'validation', message: 'originAddress is required' });
  const cfg = await resolveEdgeConfig(ctx.db);
  const p = patchFrom(a);
  await assertOriginUnbound(ctx.db, origin, null);
  await assertOriginIsNotAnEdge(ctx.db, p.originAddress!, null);
  const caps = await backendCapsOf(ctx.db, origin);
  const derived = deriveHostMode(origin, caps);
  const requested = a.hostModeRequest ?? p.hostMode;
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
    standbyPerRelay: p.standbyPerRelay ?? cfg.standbyPerRelay,
    // An OVERRIDE of the global `edge.standbyPerListener`: persisted only when
    // the caller set it, so a later change of the global applies to this relay
    // (the reconcile reads `origin.standbyPerListener ?? cfg.standbyPerListener`).
    ...(p.standbyPerListener !== undefined ? { standbyPerListener: p.standbyPerListener } : {}),
    cooldownMs: p.cooldownMs ?? edgeMs.cooldown(cfg),
    maxRotationsPerDay: p.maxRotationsPerDay ?? cfg.maxRotationsPerRelayPerDay,
    drainMs: p.drainMs ?? edgeMs.drain(cfg),
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
 * Claim the deferred delivery binding of a relay (the go-live step): upsert the
 * binding (policy version bump + mirror refresh, exactly as an insert does) and
 * clear `bindingDeferred`. Not wired to any route yet: the activation policy
 * (`require-edges`) that decides WHEN this may run is a later release.
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
    if (dup) throw new ConvexError({ code: 'conflict', message: 'A relay with this slug exists' });
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
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
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
    return { ok: true as const };
  },
});

// --- node-role registration (by slug) ------------------------------------------------------------

/** The boundary an `admin:edges:register` token carries (apiTokens.edgeRegistration). */
export const registrationBoundaryValidator = v.object({
  backendServerIds: v.array(v.id('backendServers')),
  nodeNames: v.optional(v.array(v.string())),
});
export type RegistrationBoundary = {
  backendServerIds: Id<'backendServers'>[];
  nodeNames?: string[];
};

/** A register-scoped caller may only touch origins inside its boundary; manual origins never. */
export function assertWithinBoundary(
  origin: RelayOrigin,
  boundary: RegistrationBoundary | undefined,
) {
  if (!boundary) return;
  const serverId = originBackendServerId(origin);
  if (!serverId || !boundary.backendServerIds.includes(serverId))
    throw new ConvexError({
      code: 'edge.registration_boundary',
      message: 'this registration token may not register for that backend server',
    });
  if (boundary.nodeNames && boundary.nodeNames.length > 0) {
    const node = originNodeName(origin);
    if (!node || !boundary.nodeNames.includes(node))
      throw new ConvexError({
        code: 'edge.registration_boundary',
        message: 'this registration token may not register for that node',
      });
  }
}

/** Legacy manual-relay adoption carried by `operation_mode=adopt_relay` (docs/edges.md). */
const adoptionValidator = v.object({
  edge: v.object({ address: v.string(), port: v.number() }),
  hosts: v.array(
    v.object({
      uuid: v.string(),
      remark: v.string(),
      inboundUuid: v.string(),
      sni: v.optional(v.string()),
    }),
  ),
});

/**
 * Idempotent registration keyed by slug (the node role's hook, also the CMS
 * "register manually" path with `source:'admin'`). One body carries the origin
 * and every listener the caller owns; an identical body changes nothing but
 * `lastRegisteredAt`. Refusals: `edge.deleting`, `edge.relay_reparent_locked`,
 * `edge.origin_kind_locked`, `edge.origin_address_locked`, `edge.node_already_bound`
 * / `edge.server_already_bound`, `edge.origin_is_edge`, `edge.listener_in_use`,
 * `edge.listener_key_owned`, `edge.match_rule_overlap`, `edge.registration_boundary`.
 */
export const registerBySlug = internalMutation({
  args: {
    slug: v.string(),
    origin: wireOriginValidator,
    originAddress: v.string(),
    locationCode: v.optional(v.union(v.string(), v.null())),
    label: v.optional(v.union(v.string(), v.null())),
    listeners: v.array(listenerSpecValidator),
    pruneListeners: v.optional(v.boolean()),
    /** Legacy adoption asks for operator-owned Hosts before FCP ever writes one. */
    hostModeRequest: v.optional(v.literal('operator')),
    adoption: v.optional(adoptionValidator),
    source: v.optional(v.union(v.literal('role'), v.literal('admin'))),
    boundary: v.optional(registrationBoundaryValidator),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    await assertAdmission(ctx.db, 'registration');
    const source = a.source ?? 'role';
    const origin = await checkOrigin(ctx.db, await resolveWireOrigin(ctx.db, a.origin));
    assertWithinBoundary(origin, a.boundary);
    const existing = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    let id: Id<'relays'>;
    let created = false;
    let changed: string[] = [];
    const now = Date.now();
    if (existing) {
      id = existing._id;
      if (existing.deleting)
        throw new ConvexError({
          code: 'edge.deleting',
          message: 'This relay is being deleted; wait for the teardown to finish',
        });
      // The caller inside a boundary must be allowed to touch the EXISTING row too.
      assertWithinBoundary(existing.origin, a.boundary);
      const p: Partial<Doc<'relays'>> = {};
      const field = patchFrom({
        originAddress: a.originAddress,
        locationCode: a.locationCode,
        label: a.label,
      });
      if (field.originAddress !== undefined) p.originAddress = field.originAddress;
      if (a.locationCode !== undefined) p.locationCode = field.locationCode;
      if (a.label !== undefined) p.label = field.label;
      await assertAddressChangeAllowed(ctx.db, existing, p.originAddress);
      if (p.originAddress !== undefined && !sameAddress(p.originAddress, existing.originAddress))
        await assertOriginIsNotAnEdge(ctx.db, p.originAddress, id);
      // Field-by-field: a stored document comes back with its keys re-ordered,
      // so a JSON compare would report every identical body as a re-parent.
      const originChanged = !sameOrigin(existing.origin, origin);
      if (originChanged) {
        const edges = await liveEdgesOfRelay(ctx.db, id);
        if (existing.origin.kind !== origin.kind)
          throw new ConvexError({
            code: 'edge.origin_kind_locked',
            message: 'A relay’s origin kind cannot change; register a new relay',
          });
        if (edges.length > 0)
          throw new ConvexError({
            code: 'edge.relay_reparent_locked',
            message: 'Destroy every edge of this relay before moving it to another backend or node',
          });
        await assertOriginUnbound(ctx.db, origin, id);
        p.origin = origin;
        p.backendServerId = originBackendServerId(origin);
        p.nodeName = originNodeName(origin);
      }
      changed = changedFields(existing, p).changed;
      await ctx.db.patch(id, {
        ...p,
        lastRegisteredAt: now,
        updatedAt: changed.length ? now : existing.updatedAt,
      });
      // A deferred relay stays deferred through a re-registration: the binding
      // is claimed at go-live only.
      if (originChanged && !existing.bindingDeferred)
        await upsertDeliveryBinding(ctx, { origin, slug: a.slug });
    } else {
      id = await insertRelay(ctx, a.slug, origin, {
        originAddress: a.originAddress,
        locationCode: a.locationCode,
        label: a.label,
        autoRotate: false,
        hostModeRequest: a.hostModeRequest,
      });
      await ctx.db.patch(id, { lastRegisteredAt: now });
      created = true;
    }
    const row = (await ctx.db.get(id))!;
    const reg = await applyRegistration(ctx, row, a.listeners as ListenerSpecInput[], source, {
      prune: a.pruneListeners ?? true,
      actorAdminId: a.actorAdminId,
    });
    let adopted: { edgeId: Id<'edges'>; poolIndex: number | null } | null = null;
    if (a.adoption) adopted = await applyLegacyAdoption(ctx, (await ctx.db.get(id))!, a.adoption);
    // Coverage: one published slot per deployed listener (raised, never shrunk).
    const capacity = await ensurePoolCapacity(ctx, (await ctx.db.get(id))!);
    const warnings: string[] = [];
    if (capacity.raised) warnings.push('edge.pool_raised');
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.registered',
      targetType: 'relay',
      targetId: id,
      payload: {
        slug: a.slug,
        created,
        changed: created || changed.length > 0 || reg.changed,
        listenersCreated: reg.created.length,
        listenersUpdated: reg.updated.length,
        listenersRetired: reg.retired.length,
        ...(adopted ? { adopted: true } : {}),
        ...(capacity.raised ? { poolRaised: true } : {}),
      },
    });
    return {
      id,
      created,
      changed: created || changed.length > 0 || reg.changed || capacity.to !== capacity.from,
      listeners: reg,
      adopted,
      warnings,
    };
  },
});

/**
 * Legacy adoption: the node already sits behind a manually run proxy with
 * panel Hosts the operator created. Record every legacy Host on the listener
 * whose inbound it carries (FCP never deletes them; the renderer keeps
 * matching their remarks), import the proxy as an observe-only edge and publish
 * it at index 0 (operator hostMode: no flip). The operator validates and
 * adopts each Host in the CMS afterwards, then switches hostMode to `fcp`.
 */
async function applyLegacyAdoption(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
  adoption: {
    edge: { address: string; port: number };
    hosts: Array<{ uuid: string; remark: string; inboundUuid: string; sni?: string }>;
  },
): Promise<{ edgeId: Id<'edges'>; poolIndex: number | null }> {
  if (relay.hostMode === 'fcp')
    throw new ConvexError({
      code: 'edge.adoption_requires_operator_hosts',
      message: 'legacy adoption needs hostMode operator (pass hostModeRequest)',
    });
  const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired);
  for (const h of adoption.hosts) {
    const l = listeners.find(
      (x) => x.panelBinding?.configProfileInboundUuid === h.inboundUuid.toLowerCase(),
    );
    if (!l)
      throw new ConvexError({
        code: 'validation',
        message: `legacy Host ${h.remark} names an inbound no listener carries`,
      });
    const legacy = [
      ...(l.legacyHosts ?? []).filter((x) => x.uuid !== h.uuid),
      { uuid: h.uuid, remark: h.remark, sni: h.sni },
    ];
    await ctx.db.patch(l._id, { legacyHosts: legacy, updatedAt: Date.now() });
  }
  // The listener the proxy fronts: the one whose legacy Hosts were named, else
  // the first deployed listener.
  const target =
    listeners.find((l) =>
      adoption.hosts.some(
        (h) => h.inboundUuid.toLowerCase() === l.panelBinding?.configProfileInboundUuid,
      ),
    ) ?? listeners.find((l) => l.deployed);
  if (!target)
    throw new ConvexError({ code: 'validation', message: 'adoption needs a deployed listener' });
  const existingEdges = await liveEdgesOfRelay(ctx.db, relay._id);
  const already = existingEdges.find(
    (e) => !e.managed && e.addresses.v4 && sameAddress(e.addresses.v4, adoption.edge.address),
  );
  if (already) return { edgeId: already._id, poolIndex: already.poolIndex ?? null };
  const fam = addressFamily(adoption.edge.address);
  // The adoption payload IS the operator's statement that this proxy already
  // serves members (the role only sends it for a running deployment): the
  // import carries it as a `named_connection` verification, without which
  // the publication gate would refuse the publish (`edge.unverified_endpoint`).
  const r = await insertAdoptedEdge(ctx, relay, target, {
    ipv4: fam === 'v4' ? adoption.edge.address : undefined,
    hostname: fam ? undefined : adoption.edge.address,
    port: adoption.edge.port,
    publish: true,
    verified: true,
    accountRow: null,
    resources: [],
    inspection: undefined,
  });
  return { edgeId: r.edgeId, poolIndex: r.poolIndex };
}

/**
 * Mark a relay for teardown; the edge-reconcile cron drains/destroys its edges
 * and removes the row. `disposition` says what happens to the delivery binding
 * of the origin: `restore-direct` releases it (raw delivery returns),
 * `keep-dark` keeps members on the node unavailable until another relay claims it.
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
      if (['active', 'standby', 'verifying'].includes(e.status)) {
        await ctx.db.patch(e._id, {
          status: 'draining',
          publication: 'draining',
          drainUntil: force ? now : now + row.drainMs,
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
    return { ok: true as const, deleted: false };
  },
});

/**
 * Remove the relay row once every managed edge is destroyed and no FCP-owned
 * panel Host remains (the Host cleanup runs in the reconcile cron and deletes
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
    // The qualification credential is a panel user: deactivate it after the row
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
          });
    }
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
    const { resolveTemplateFor } = await import('./edgeTemplates');
    const template = await resolveTemplateFor(
      ctx,
      accountRow!.provider,
      null,
      accountRow!.defaultTemplateId ?? null,
      accountRow!._id,
    );
    const dnsAccountId = (accountRow!.settings as { dnsAccountId?: string }).dnsAccountId;
    const dnsAccount = dnsAccountId
      ? await ctx.db.get(dnsAccountId as Id<'edgeProviderAccounts'>)
      : null;
    try {
      provisionIntent = JSON.stringify(
        buildProvisionIntent({
          account: {
            id: accountRow!._id as string,
            provider: accountRow!.provider,
            settings: accountRow!.settings as Record<string, unknown>,
            observedSettings: parseObservedSettings(accountRow!.observedSettings),
          },
          dnsAccount: dnsAccount
            ? {
                id: dnsAccount._id as string,
                provider: dnsAccount.provider,
                settings: dnsAccount.settings as Record<string, unknown>,
                observedSettings: parseObservedSettings(dnsAccount.observedSettings),
              }
            : null,
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
    const binding = verificationBinding(inserted, listener);
    if (binding)
      await ctx.db.patch(edgeId, {
        verification: {
          rung: 'verified',
          by: 'admin',
          at: now,
          method: 'named_connection',
          ...binding,
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
      listener._id,
      await poolListenersOf(ctx.db, origin._id),
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
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const listener = await ctx.db.get(a.listenerId);
    await assertAdmission(ctx.db, 'adopt');
    if (!listener || listener.relayId !== a.relayId)
      throw new ConvexError({
        code: 'validation',
        message: 'listener does not belong to the relay',
      });
    let accountRow: Doc<'edgeProviderAccounts'> | null = null;
    if (a.accountId) {
      accountRow = await ctx.db.get(a.accountId);
      if (!accountRow) throw new ConvexError({ code: 'validation', message: 'unknown account' });
    }
    return insertAdoptedEdge(ctx, origin, listener, {
      ipv4: a.ipv4,
      ipv6: a.ipv6,
      hostname: a.hostname,
      port: a.port,
      accountRow,
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
        : 'The free pool slots are reserved for listeners that have no published edge yet',
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
 * this configuration and has not expired.
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
  if (protocolTransport(listener) === 'udp' && !udpProviderAvailable())
    return { ok: false, code: 'transport_not_carried' };
  const l7Host = l7HostHeaderFor(
    edge.addresses.hostname ?? intent?.hostname,
    (intent?.templateParams as { overrideHost?: unknown } | undefined)?.overrideHost,
  );
  if (edge.provider) {
    if (!protocolCarriedBy(edge.provider, listener))
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
  // An L4 endpoint goes live only with the operator's OWN confirmation against
  // the configuration it holds now (lib/edges/verification.ts): nothing
  // server-side can prove an L4 address, and a stale tick (listener revision
  // bump, re-addressing) is no tick at all. The L7 proof above is the L7 form.
  if (
    !opts.skipVerification &&
    needsEndpointVerification(edge) &&
    !verificationCurrent(edge, listener)
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
      throw new ConvexError({ code: 'not_found', message: 'Relay/edge not found' });
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
      edge.listenerId,
      await poolListenersOf(ctx.db, relayId),
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
    // would leave the panel sending everyone to the previous address: the
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
          'Publishing the listener’s template edge needs the panel-Host flip; start a publish rotation',
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
      throw new ConvexError({ code: 'not_found', message: 'Relay/edge not found' });
    await assertNoRotationOrQuarantine(ctx.db, origin);
    if (edge.publication !== 'published')
      return { ok: true as const, epoch: origin.publicationEpoch };
    const now = Date.now();
    const poolIndex = edge.poolIndex ?? null;
    if (keepActive) {
      await ctx.db.patch(edgeId, {
        publication: 'unpublished',
        poolIndex: undefined,
        updatedAt: now,
      });
    } else {
      await ctx.db.patch(edgeId, {
        publication: 'draining',
        status: 'draining',
        drainUntil: now + (drainMs ?? origin.drainMs),
        poolIndex: undefined,
        statusChangedAt: now,
        updatedAt: now,
      });
    }
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(relayId, {
      publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
      standbyEdgeIds: keepActive
        ? [...origin.standbyEdgeIds.filter((e) => e !== edgeId), edgeId]
        : origin.standbyEdgeIds.filter((e) => e !== edgeId),
      publicationEpoch: epoch,
      updatedAt: now,
    });
    await refreshTemplateEdges(ctx, origin);
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'edge.unpublished',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin.slug, edgeId, poolIndex, epoch },
    });
    await scheduleMirrorRefresh(ctx);
    return { ok: true as const, epoch };
  },
});

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
 * for the relay's listeners (lib/edges/poolCapacity.ts). Returns what changed
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
 * Make room in a pool at its cap: unpublish ONE duplicate (a published edge
 * that is not its listener's template edge, highest pool index first) back to
 * standby so upkeep can publish an uncovered listener into the freed slot.
 * Never automatic: it changes what members receive. Refusals: `edge.no_duplicate`
 * (every published edge is a template edge), the usual rotation / quarantine guard.
 */
export const rebalance = internalMutation({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { relayId, actorAdminId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const listeners = await listenersOf(ctx, relayId);
    const templates = new Set(
      listeners.map((l) => l.templateEdgeId as string | undefined).filter(Boolean),
    );
    let pick: Doc<'edges'> | null = null;
    for (let i = origin.publishedEdgeIds.length - 1; i >= 0; i--) {
      const edgeId = origin.publishedEdgeIds[i];
      if (!edgeId || templates.has(edgeId as string)) continue;
      const e = await ctx.db.get(edgeId);
      if (e && e.publication === 'published') {
        pick = e;
        break;
      }
    }
    if (!pick)
      throw new ConvexError({
        code: 'edge.no_duplicate',
        message: 'Every published edge is the template edge of its listener; nothing to unpublish',
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

export const bumpEpoch = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return null;
    await bumpEpochAndRefresh(ctx, origin);
    return null;
  },
});

export { publishAddressOf };
