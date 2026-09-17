/**
 * Relay ORIGINS: one REALITY node fronted by a pool of published edges. Owns
 * the origin CRUD (admin + the Ansible by-slug upsert), edge adoption, and the
 * PUBLISHED-pool bookkeeping (publish/unpublish with pool-index inheritance and
 * the publication epoch the render cache keys on). Rotation/provisioning state
 * lives in edgeRotations.ts; edge rows in edges.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { isTerminalPhase } from './lib/edges/rotation';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { resolveEdgeConfig, edgeMs } from './lib/edgeConfig';
import {
  isPublicIpLiteral,
  addressFamily,
  publishAddressOf,
  hasPublishableAddress,
} from './lib/edges/ip';
import { sameAddress } from './lib/edges/hosts';
import { isValidHostname } from './lib/edges/hostname';
import { l7HostHeaderFor, slotAllowsLayer, zoneModeCarriesOrigin } from './lib/edges/layers';
import { PROTOCOL_TRANSPORT, protocolUsesSni } from './lib/edges/protocols';
import {
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
// The binding derivation is shared with the checker that records the
// qualification (lib/edges/frontCheck/binding.ts): one entry point, so the
// proof and the gate cannot hash the same configuration differently.
import {
  qualificationBinding,
  qualificationRefusal,
  qualificationVerdict,
} from './lib/edges/frontCheck/binding';
import {
  nextFreePoolIndex,
  withEdgeAt,
  withoutEdge,
  publishedCount,
  EDGE_LIVE_STATUSES,
  LIVE_EDGE_SCAN_LIMIT,
} from './lib/edges/pool';
import { assertAdmission } from './lib/edges/maintenance';

type Db = import('./_generated/server').DatabaseReader;

/**
 * Every NON-DESTROYED edge of a relay, read through the `(relayId, status)`
 * index one status at a time and bounded per status. A relay keeps its
 * destroyed edges until the retention sweep prunes them, so collecting the
 * relay's whole edge list grows without limit; the callers here only ever care
 * about live rows.
 */
export async function liveEdgesOfRelay(db: Db, relayId: Id<'relays'>): Promise<Doc<'edges'>[]> {
  const out: Doc<'edges'>[] = [];
  for (const status of EDGE_LIVE_STATUSES) {
    out.push(
      ...(await db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relayId).eq('status', status))
        .take(LIVE_EDGE_SCAN_LIMIT)),
    );
  }
  return out;
}

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

/**
 * One origin per backend node: rendering and report attribution resolve the
 * origin from (backendServerId, nodeHostname) and take the first match.
 */
async function assertNodeUnbound(
  db: Db,
  backendServerId: Id<'backendServers'>,
  nodeHostname: string,
  selfId: Id<'relays'> | null,
) {
  const rows = await db
    .query('relays')
    .withIndex('by_node_hostname', (q) => q.eq('nodeHostname', nodeHostname))
    .collect();
  const other = rows.find((r) => r.backendServerId === backendServerId && r._id !== selfId);
  if (other) {
    throw new ConvexError({
      code: 'edge.node_already_bound',
      message: `Origin ${other.slug} already covers this node on this backend`,
    });
  }
}

/**
 * `originAddress` is baked into every provisioned edge's listener members; FCP
 * has no member-update operation, so a change while edges exist would leave the
 * balancers dialing the old target while FCP reports the new one. Refuse until
 * the origin's edges are drained/destroyed (or the origin is recreated).
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

/** Nothing bypasses a quarantine (docs/edges.md): the operator resolves it first. */
export function assertNotQuarantined(origin: Doc<'relays'>) {
  if (origin.quarantine) {
    throw new ConvexError({
      code: 'edge.quarantined',
      message: 'Origin is quarantined; resolve it first',
    });
  }
}

/**
 * The shared gate for every pool / edge write that is NOT the running rotation
 * itself (publish, unpublish, adopt+publish, delete, operator resolutions, pool
 * drops): refused while the origin is quarantined or a rotation is in flight,
 * so no two writers touch the published pool or the template Host at once.
 */
export async function assertNoRotationOrQuarantine(db: Db, origin: Doc<'relays'>) {
  assertNotQuarantined(origin);
  if (origin.activeRotationId) {
    const rot = await db.get(origin.activeRotationId);
    if (rot && !isTerminalPhase(rot.phase)) {
      throw new ConvexError({
        code: 'edge.rotation_running',
        message: 'A rotation is running on this origin; wait for it to finish',
      });
    }
  }
}

/** Members must stop receiving an edge that left the pool: refresh the S3 mirrors once. */
export async function scheduleMirrorRefresh(ctx: MutationCtx) {
  await ctx.scheduler.runAfter(0, internal.storage.refreshActiveMirrors, {});
}

/**
 * Remove an edge from the published pool / standby list WITHOUT a drain (the
 * provider no longer has it, or an operator forgot it) and bump the epoch so
 * renders stop emitting it. Shared by `dropFromPool` and the describe(gone)
 * transition in edges.ts so the drop happens in the SAME mutation as the status
 * change. Audits `edge.unpublished` + `edge.drift` when it held a pool index.
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

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
const HOSTNAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function mapRelayAdmin(r: Doc<'relays'>) {
  return {
    id: r._id as string,
    slug: r.slug,
    backendServerId: r.backendServerId as string,
    nodeHostname: r.nodeHostname,
    nodeUuid: r.nodeUuid ?? null,
    originAddress: r.originAddress,
    locationCode: r.locationCode ?? null,
    modeSlugs: r.modeSlugs,
    enabled: r.enabled,
    autoRotate: r.autoRotate,
    hostManaged: r.hostManaged,
    probeNode: r.probeNode ?? false,
    qualificationCredential: !!r.qualificationUserId,
    reachability: r.reachability
      ? {
          byCountry: r.reachability.byCountry.map((c) => ({
            ...c,
            lastAt: new Date(c.lastAt).toISOString(),
          })),
          updatedAt: new Date(r.reachability.updatedAt).toISOString(),
        }
      : null,
    providerAffinity: r.providerAffinity,
    providerPreference: r.providerPreference ?? null,
    desiredPublished: r.desiredPublished,
    standbyPerRelay: r.standbyPerRelay,
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

// --- reads -------------------------------------------------------------------------

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

/** Origin behind a pinned node on an instance (the attribution + render lookup). */
export const forNode = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeHostname: v.string() },
  handler: async (ctx, { backendServerId, nodeHostname }) => {
    const rows = await ctx.db
      .query('relays')
      .withIndex('by_node_hostname', (q) => q.eq('nodeHostname', nodeHostname))
      .collect();
    return rows.find((r) => r.backendServerId === backendServerId) ?? null;
  },
});

// --- validation ------------------------------------------------------------------------

function checkOriginFields(a: {
  nodeHostname?: string;
  originAddress?: string;
  modeSlugs?: string[];
  desiredPublished?: number;
  standbyPerRelay?: number;
  cooldownMinutes?: number;
  maxRotationsPerDay?: number;
  drainMinutes?: number;
  locationCode?: string | null;
}) {
  if (a.nodeHostname !== undefined && !HOSTNAME_RE.test(a.nodeHostname)) {
    throw new ConvexError({
      code: 'validation',
      message: 'nodeHostname must be a lowercase host label',
    });
  }
  if (a.originAddress !== undefined) {
    const fam = addressFamily(a.originAddress);
    const isName = /^[a-z0-9.-]{1,253}$/i.test(a.originAddress);
    if (!fam && !isName)
      throw new ConvexError({
        code: 'validation',
        message: 'originAddress must be an IP or hostname',
      });
  }
  if (a.modeSlugs !== undefined) {
    if (a.modeSlugs.length === 0 || a.modeSlugs.some((m) => !/^[a-z0-9-]{1,64}$/.test(m))) {
      throw new ConvexError({ code: 'validation', message: 'modeSlugs must be 1+ mode slugs' });
    }
  }
  if (a.desiredPublished !== undefined && (a.desiredPublished < 1 || a.desiredPublished > 4)) {
    throw new ConvexError({ code: 'validation', message: 'desiredPublished must be 1..4' });
  }
  if (a.standbyPerRelay !== undefined && (a.standbyPerRelay < 0 || a.standbyPerRelay > 2)) {
    throw new ConvexError({ code: 'validation', message: 'standbyPerRelay must be 0..2' });
  }
  if (a.cooldownMinutes !== undefined && (a.cooldownMinutes < 10 || a.cooldownMinutes > 1440)) {
    throw new ConvexError({ code: 'validation', message: 'cooldownMinutes must be 10..1440' });
  }
  if (
    a.maxRotationsPerDay !== undefined &&
    (a.maxRotationsPerDay < 1 || a.maxRotationsPerDay > 12)
  ) {
    throw new ConvexError({ code: 'validation', message: 'maxRotationsPerDay must be 1..12' });
  }
  if (a.drainMinutes !== undefined && (a.drainMinutes < 1 || a.drainMinutes > 7 * 1440)) {
    throw new ConvexError({ code: 'validation', message: 'drainMinutes must be 1..10080' });
  }
  if (
    a.locationCode !== undefined &&
    a.locationCode !== null &&
    !/^[A-Za-z0-9-]{1,16}$/.test(a.locationCode)
  ) {
    throw new ConvexError({ code: 'validation', message: 'invalid locationCode' });
  }
}

const originWriteArgs = {
  nodeHostname: v.optional(v.string()),
  nodeUuid: v.optional(v.union(v.string(), v.null())),
  originAddress: v.optional(v.string()),
  locationCode: v.optional(v.union(v.string(), v.null())),
  modeSlugs: v.optional(v.array(v.string())),
  enabled: v.optional(v.boolean()),
  autoRotate: v.optional(v.boolean()),
  hostManaged: v.optional(v.boolean()),
  probeNode: v.optional(v.boolean()),
  providerAffinity: v.optional(v.union(v.literal('rotate'), v.literal('sticky'))),
  providerPreference: v.optional(v.union(edgeProviderIdValidator, v.null())),
  desiredPublished: v.optional(v.number()),
  standbyPerRelay: v.optional(v.number()),
  cooldownMinutes: v.optional(v.number()),
  maxRotationsPerDay: v.optional(v.number()),
  drainMinutes: v.optional(v.number()),
  actorAdminId: v.optional(v.id('adminUsers')),
};

type OriginWrite = {
  nodeHostname?: string;
  nodeUuid?: string | null;
  originAddress?: string;
  locationCode?: string | null;
  modeSlugs?: string[];
  enabled?: boolean;
  autoRotate?: boolean;
  hostManaged?: boolean;
  probeNode?: boolean;
  providerAffinity?: 'rotate' | 'sticky';
  providerPreference?: Doc<'relays'>['providerPreference'] | null;
  desiredPublished?: number;
  standbyPerRelay?: number;
  cooldownMinutes?: number;
  maxRotationsPerDay?: number;
  drainMinutes?: number;
};

function patchFrom(a: OriginWrite): Partial<Doc<'relays'>> {
  checkOriginFields(a);
  const p: Partial<Doc<'relays'>> = {};
  if (a.nodeHostname !== undefined) p.nodeHostname = a.nodeHostname;
  if (a.nodeUuid !== undefined) p.nodeUuid = a.nodeUuid ?? undefined;
  if (a.originAddress !== undefined) p.originAddress = a.originAddress;
  if (a.locationCode !== undefined) p.locationCode = a.locationCode ?? undefined;
  if (a.modeSlugs !== undefined) p.modeSlugs = a.modeSlugs;
  if (a.enabled !== undefined) p.enabled = a.enabled;
  if (a.autoRotate !== undefined) p.autoRotate = a.autoRotate;
  if (a.hostManaged !== undefined) p.hostManaged = a.hostManaged;
  if (a.probeNode !== undefined) p.probeNode = a.probeNode;
  if (a.providerAffinity !== undefined) p.providerAffinity = a.providerAffinity;
  if (a.providerPreference !== undefined) p.providerPreference = a.providerPreference ?? undefined;
  if (a.desiredPublished !== undefined) p.desiredPublished = a.desiredPublished;
  if (a.standbyPerRelay !== undefined) p.standbyPerRelay = a.standbyPerRelay;
  if (a.cooldownMinutes !== undefined) p.cooldownMs = a.cooldownMinutes * 60_000;
  if (a.maxRotationsPerDay !== undefined) p.maxRotationsPerDay = a.maxRotationsPerDay;
  if (a.drainMinutes !== undefined) p.drainMs = a.drainMinutes * 60_000;
  return p;
}

/**
 * Audit view of a write: the names of the fields it actually changed (never
 * their values — addresses stay out of the log) plus the operator-owned boolean
 * knobs' new values when they flipped.
 */
function changedFields(
  before: Doc<'relays'> | null,
  p: Partial<Doc<'relays'>>,
): { changed: string[]; autoRotate?: boolean; hostManaged?: boolean; enabled?: boolean } {
  const changed: string[] = [];
  for (const [k, val] of Object.entries(p)) {
    if (val === undefined) continue;
    const prev = before ? (before as unknown as Record<string, unknown>)[k] : undefined;
    if (before && JSON.stringify(prev) === JSON.stringify(val)) continue;
    changed.push(k);
  }
  const flips: { autoRotate?: boolean; hostManaged?: boolean; enabled?: boolean } = {};
  for (const k of ['autoRotate', 'hostManaged', 'enabled'] as const) {
    if (changed.includes(k) && typeof p[k] === 'boolean') flips[k] = p[k];
  }
  return { changed: changed.sort(), ...flips };
}

/** Fields the Ansible role may set through the by-slug upsert (docs/edges.md, node role contract). */
const ROLE_UPDATE_FIELDS = new Set<string>([
  'nodeHostname',
  'nodeUuid',
  'originAddress',
  'locationCode',
  'modeSlugs',
]);

async function insertOrigin(
  ctx: { db: import('./_generated/server').DatabaseWriter },
  slug: string,
  backendServerId: Id<'backendServers'>,
  a: OriginWrite,
): Promise<Id<'relays'>> {
  if (!SLUG_RE.test(slug)) throw new ConvexError({ code: 'validation', message: 'invalid slug' });
  if (!a.nodeHostname || !a.originAddress) {
    throw new ConvexError({
      code: 'validation',
      message: 'nodeHostname and originAddress are required',
    });
  }
  const cfg = await resolveEdgeConfig(ctx.db);
  const p = patchFrom(a);
  await assertNodeUnbound(ctx.db, backendServerId, p.nodeHostname!, null);
  const now = Date.now();
  return ctx.db.insert('relays', {
    slug,
    backendServerId,
    nodeHostname: p.nodeHostname!,
    nodeUuid: p.nodeUuid,
    originAddress: p.originAddress!,
    locationCode: p.locationCode,
    modeSlugs: p.modeSlugs ?? ['freedom-reality'],
    enabled: p.enabled ?? true,
    autoRotate: p.autoRotate ?? false,
    hostManaged: p.hostManaged ?? true,
    probeNode: p.probeNode ?? false,
    providerAffinity: p.providerAffinity ?? cfg.providerAffinity,
    providerPreference: p.providerPreference,
    desiredPublished: p.desiredPublished ?? cfg.desiredPublishedDefault,
    standbyPerRelay: p.standbyPerRelay ?? cfg.standbyPerRelay,
    cooldownMs: p.cooldownMs ?? edgeMs.cooldown(cfg),
    maxRotationsPerDay: p.maxRotationsPerDay ?? cfg.maxRotationsPerRelayPerDay,
    drainMs: p.drainMs ?? edgeMs.drain(cfg),
    publicationEpoch: 0,
    publishedEdgeIds: [],
    standbyEdgeIds: [],
    rotationsToday: 0,
    updatedAt: now,
  });
}

// --- CRUD ------------------------------------------------------------------------------

export const create = internalMutation({
  args: { slug: v.string(), backendServerId: v.id('backendServers'), ...originWriteArgs },
  handler: async (ctx, { slug, backendServerId, actorAdminId, ...a }) => {
    await assertAdmission(ctx.db, 'registration');
    const dup = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    if (dup)
      throw new ConvexError({ code: 'conflict', message: 'An origin with this slug exists' });
    if (!(await ctx.db.get(backendServerId)))
      throw new ConvexError({ code: 'validation', message: 'unknown backend server' });
    const id = await insertOrigin(ctx, slug, backendServerId, a);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.create',
      targetType: 'relay',
      targetId: id,
      payload: { slug },
    });
    return { id };
  },
});

export const update = internalMutation({
  args: { id: v.id('relays'), ...originWriteArgs },
  handler: async (ctx, { id, actorAdminId, ...a }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const p = patchFrom(a);
    await assertAddressChangeAllowed(ctx.db, row, p.originAddress);
    if (p.nodeHostname !== undefined && p.nodeHostname !== row.nodeHostname)
      await assertNodeUnbound(ctx.db, row.backendServerId, p.nodeHostname, id);
    // The flip decision was taken from `hostManaged` at publish time: flipping
    // it under a running rotation would change what the run must do mid-way.
    if (p.hostManaged !== undefined && p.hostManaged !== row.hostManaged && row.activeRotationId) {
      const rot = await ctx.db.get(row.activeRotationId);
      if (rot && !isTerminalPhase(rot.phase)) {
        throw new ConvexError({
          code: 'edge.rotation_running',
          message: 'hostManaged cannot change while a rotation is running',
        });
      }
    }
    // Publication-affecting edits bump the epoch (render cache + assignment).
    const affects =
      p.desiredPublished !== undefined || p.modeSlugs !== undefined || p.enabled !== undefined;
    await ctx.db.patch(id, {
      ...p,
      ...(affects ? { publicationEpoch: row.publicationEpoch + 1 } : {}),
      updatedAt: Date.now(),
    });
    // The epoch bump re-renders the fronted route within one request; S3
    // mirrors only change when refreshed, so every epoch bump schedules one.
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

/** Idempotent upsert keyed by slug (the Ansible hook). `backendServerSlug` names the panel. */
export const upsertBySlug = internalMutation({
  args: { slug: v.string(), backendServerSlug: v.string(), ...originWriteArgs },
  handler: async (ctx, { slug, backendServerSlug, actorAdminId, ...a }) => {
    await assertAdmission(ctx.db, 'registration');
    const server = await ctx.db
      .query('backendServers')
      .withIndex('by_slug', (q) => q.eq('slug', backendServerSlug))
      .unique();
    if (!server)
      throw new ConvexError({ code: 'validation', message: 'unknown backendServerSlug' });
    const existing = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    let id: Id<'relays'>;
    let created = false;
    let changed: string[] = [];
    if (existing) {
      id = existing._id;
      if (existing.deleting) {
        throw new ConvexError({
          code: 'edge.deleting',
          message: 'This relay is being deleted; wait for the teardown to finish',
        });
      }
      // The role owns the node's identity only. Every operator-owned knob
      // (automation, Host management, pool sizing, limits) is dropped from a
      // role write; the documented body never carries them.
      const full = patchFrom(a) as Record<string, unknown>;
      const p: Partial<Doc<'relays'>> = {};
      for (const k of Object.keys(full)) {
        if (ROLE_UPDATE_FIELDS.has(k)) (p as Record<string, unknown>)[k] = full[k];
      }
      await assertAddressChangeAllowed(ctx.db, existing, p.originAddress);
      const host = p.nodeHostname ?? existing.nodeHostname;
      if (server._id !== existing.backendServerId) {
        // Edges dial the node behind ONE panel; moving the relay to another
        // panel while any edge still exists would strand them.
        const edges = await liveEdgesOfRelay(ctx.db, id);
        if (edges.length > 0) {
          throw new ConvexError({
            code: 'edge.relay_reparent_locked',
            message: 'Destroy every edge of this relay before moving it to another backend server',
          });
        }
        p.backendServerId = server._id;
      }
      if (host !== existing.nodeHostname || server._id !== existing.backendServerId)
        await assertNodeUnbound(ctx.db, server._id, host, id);
      changed = changedFields(existing, p).changed;
      await ctx.db.patch(id, { ...p, updatedAt: Date.now() });
    } else {
      // A fresh registration is filtered like an update: the role never sets an
      // operator-owned knob, and never opts a relay into automatic rotation.
      const fresh: Record<string, unknown> = {};
      for (const k of Object.keys(a)) {
        if (ROLE_UPDATE_FIELDS.has(k)) fresh[k] = (a as Record<string, unknown>)[k];
      }
      id = await insertOrigin(ctx, slug, server._id, {
        ...(fresh as OriginWrite),
        autoRotate: false,
      });
      created = true;
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.upsert',
      targetType: 'relay',
      targetId: id,
      payload: { slug, created, changed },
    });
    return { id, created };
  },
});

/**
 * Mark an origin for teardown; the edge-reconcile cron drains/destroys its
 * edges and removes the row. Live edges drain for the relay's `drainMs` (members
 * still hold them) unless `force` skips the drain.
 */
export const requestDelete = internalMutation({
  args: {
    id: v.id('relays'),
    force: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, force, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const, deleted: true };
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
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.delete',
      targetType: 'relay',
      targetId: id,
      payload: { slug: row.slug, force: force ?? false },
    });
    await scheduleMirrorRefresh(ctx);
    return { ok: true as const, deleted: false };
  },
});

/** Reconcile removes the row once every managed edge is destroyed. */
export const finalizeDelete = internalMutation({
  args: { id: v.id('relays') },
  handler: async (ctx, { id }) => {
    const row = await ctx.db.get(id);
    if (!row?.deleting) return { removed: false };
    const edges = await ctx.db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', id))
      .collect();
    if (edges.some((e) => e.status !== 'destroyed')) return { removed: false };
    const slots = await ctx.db
      .query('relaySlots')
      .withIndex('by_relay', (q) => q.eq('relayId', id))
      .collect();
    for (const s of slots) await ctx.db.delete(s._id);
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
    if (owedUsers.length > 0) {
      const server = await ctx.db.get(row.backendServerId);
      if (server)
        for (const backendUserId of new Set(owedUsers))
          await ctx.scheduler.runAfter(0, internal.relayQualification.removeBackendUser, {
            backend: server.backend,
            backendUserId,
          });
    }
    await ctx.db.delete(id);
    return { removed: true };
  },
});

// --- adoption -----------------------------------------------------------------------------

/**
 * The ledger `meta` of one imported child: whatever the adapter reported, plus
 * `shared:true` on the SERVICE-kind child of a resource that also serves other
 * hostnames. The destroy walk reads that flag to choose the per-service version
 * workflow (remove our domain) over deleting the service outright.
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
      // A meta blob FCP cannot read is kept verbatim: it is the adapter's.
      return { meta: r.meta.slice(0, 4_000) };
    }
  }
  if (sharedService && isService) parsed.shared = true;
  return { meta: JSON.stringify(parsed).slice(0, 4_000) };
}

/**
 * A child the adapter read back as NOT fronted (`meta.proxied:false`): a
 * DNS-only record answers with the origin's own address, so importing it would
 * publish the node itself as an edge and hand members the address the front
 * exists to hide. The adapter refuses it too; this is the orchestrator's half,
 * so an inspection taken before the record was un-proxied cannot slip through.
 */
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

/**
 * Adopt an edge that exists outside FCP's ledger: observe-only (`managed:false`,
 * only the address + port known; never destroyed) or managed (account +
 * resource ids supplied). The address is of the ACCOUNT's kind: an IPv4 literal
 * for an L4 provider, a hostname for an L7 front (and, with no account, of
 * whichever kind the operator supplied). Optionally publish it right away at the
 * next free pool index.
 */
export const adoptEdge = internalMutation({
  args: {
    relayId: v.id('relays'),
    slotId: v.id('relaySlots'),
    ipv4: v.optional(v.string()),
    ipv6: v.optional(v.union(v.string(), v.null())),
    /** L7: the fronted hostname (never an IP literal, never the origin itself). */
    hostname: v.optional(v.string()),
    port: v.optional(v.number()),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    resources: v.optional(
      v.array(
        v.object({
          kind: v.string(),
          resourceId: v.string(),
          /** Everything discovery / describe / destroy needs (versions, ids). */
          meta: v.optional(v.string()),
          ownership: v.optional(v.union(v.literal('created'), v.literal('adopted'))),
        }),
      ),
    ),
    /**
     * What the adapter read at the provider (`edgeProviderOps.inspectForAdoption`).
     * Required for a MANAGED L7 import: it is the ownership proof (the resource
     * dials the relay's own origin and serves the hostname) and it says whether
     * the resource is shared with other hostnames.
     */
    inspection: v.optional(
      v.object({
        hostnames: v.array(v.string()),
        shared: v.boolean(),
        content: v.optional(v.string()),
      }),
    ),
    publish: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const slot = await ctx.db.get(a.slotId);
    await assertAdmission(ctx.db, 'adopt');
    if (!slot || slot.relayId !== a.relayId)
      throw new ConvexError({ code: 'validation', message: 'slot does not belong to the origin' });
    const port = a.port ?? 443;
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new ConvexError({ code: 'validation', message: 'port out of range' });
    let accountRow: Doc<'edgeProviderAccounts'> | null = null;
    if (a.accountId) {
      accountRow = await ctx.db.get(a.accountId);
      if (!accountRow) throw new ConvexError({ code: 'validation', message: 'unknown account' });
      const profile = await ctx.db.get(slot.profileId);
      if (profile?.provider && profile.provider !== accountRow.provider)
        throw new ConvexError({
          code: 'validation',
          message: 'account provider does not match the slot profile',
        });
    }
    // The address kind follows the ACCOUNT's provider: an L7 front is a
    // hostname and has no IP of its own to adopt, an L4 balancer is a literal.
    // Without an account (observe-only) the operator's own input decides.
    const kind = accountRow
      ? edgeAddressKindOf(accountRow.provider)
      : a.hostname
        ? 'hostname'
        : 'ip';
    const layer = accountRow ? edgeLayerOf(accountRow.provider) : kind === 'hostname' ? 'l7' : 'l4';
    let hostname: string | undefined;
    if (kind === 'hostname') {
      const h = (a.hostname ?? '').trim().toLowerCase().replace(/\.$/, '');
      // A hostname, not an IP typed into the hostname field: an IP literal here
      // would be adopted as an L7 front and published without a name to present.
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
        throw new ConvexError({
          code: 'validation',
          message: 'ipv4 must be a public IPv4 literal',
        });
      if (a.ipv6 && (!isPublicIpLiteral(a.ipv6) || addressFamily(a.ipv6) !== 'v6'))
        throw new ConvexError({
          code: 'validation',
          message: 'ipv6 must be a public IPv6 literal',
        });
      if (sameAddress(a.ipv4, origin.originAddress))
        throw new ConvexError({
          code: 'validation',
          message: 'the edge address is the origin itself (anti-leak)',
        });
    }
    // Adopting is a bookkeeping insert; PUBLISHING touches the pool, so it takes
    // the same gate as every other pool writer.
    if (a.publish) await assertNoRotationOrQuarantine(ctx.db, origin);
    if (unproxiedChild(a.resources ?? []))
      throw new ConvexError({
        code: 'edge.record_not_proxied',
        message: 'the record is DNS only: nothing fronts this hostname',
      });
    const managed = !!accountRow && (a.resources?.length ?? 0) > 0;
    const now = Date.now();
    // A MANAGED L7 import: FCP will describe, qualify, rotate and (partially)
    // destroy this front, so it needs the same frozen intent a provisioned edge
    // carries — with the hostname the operator's resource already serves, not a
    // minted one. Without it the edge could never qualify or be described.
    let provisionIntent: string | undefined;
    let sharedService = false;
    if (managed && layer === 'l7') {
      const insp = a.inspection;
      if (!insp)
        throw new ConvexError({
          code: 'validation',
          message: 'an L7 import needs the provider inspection',
        });
      // Ownership: the resource must dial THIS relay's origin and actually serve
      // the hostname being imported. Anything else belongs to someone else.
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
            slot,
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
      relayId: a.relayId,
      slotId: a.slotId,
      accountId: accountRow?._id,
      provider: accountRow?.provider,
      managed,
      name: `adopted-${origin.slug}-${now.toString(36)}`,
      steps: [],
      resources: (a.resources ?? []).map((r) => ({
        stepId: 'adopted',
        kind: r.kind,
        resourceId: r.resourceId,
        // An imported child is always `adopted`: FCP did not create it, and the
        // destroy walk must never treat it as its own.
        ownership: 'adopted' as const,
        deleteState: 'present' as const,
        // A SHARED service is stamped on its own resource: the destroy walk
        // reads it to pick the version workflow over an outright delete.
        ...metaFor(r, sharedService),
      })),
      listeners: [
        {
          edgePort: port,
          originAddress: origin.originAddress,
          originPort: slot.originPort,
          transport: PROTOCOL_TRANSPORT[(await ctx.db.get(slot.profileId))?.protocol ?? 'reality'],
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
    let poolIndex: number | null = null;
    // An L7 import is never published on the operator's word alone: it takes the
    // ordinary gate, which for a front means a CURRENT end-to-end proof. A
    // refusal must not throw, though, or the whole import (including the
    // provider inspection that paid for it) would roll back with it: the edge
    // stays as a standby and the refusal comes back as a code.
    const softRefusal = layer === 'l7' && managed;
    let refusedCode: string | null = null;
    if (a.publish) {
      const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
      if (idx === null) {
        if (!softRefusal)
          throw new ConvexError({ code: 'edge.pool_full', message: 'The published pool is full' });
        refusedCode = 'pool_full';
      }
      // Adoption is not a way around the publish preconditions: an adopted edge
      // whose slot is undeployed, whose profile has no name to present or whose
      // layer the slot cannot carry would be rendered to members as a working
      // endpoint. Same check every other publisher runs.
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
    if (a.publish && !refusedCode) {
      const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished)!;
      poolIndex = idx;
      await ctx.db.patch(edgeId, {
        publication: 'published',
        poolIndex: idx,
        publishedAt: now,
        updatedAt: now,
      });
      await ctx.db.patch(a.relayId, {
        publishedEdgeIds: withEdgeAt(origin.publishedEdgeIds, idx, edgeId),
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: now,
      });
      // The epoch bump only re-renders the fronted route; stored mirrors need
      // an explicit refresh to start carrying the adopted edge.
      await scheduleMirrorRefresh(ctx);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.adopted',
      targetType: 'relay',
      targetId: a.relayId,
      payload: {
        slug: origin.slug,
        edgeId,
        managed,
        publication: poolIndex !== null ? 'published' : 'unpublished',
        ...(refusedCode ? { refused: refusedCode } : {}),
        ...(sharedService ? { shared: true } : {}),
      },
    });
    return { edgeId, poolIndex, code: refusedCode };
  },
});

// --- published pool -------------------------------------------------------------------------

export interface PublishCheck {
  ok: boolean;
  code?: string;
}

/**
 * Publication preconditions: the edge is active + unpublished, has the address
 * of ITS layer's kind, its slot is deployed (not retired) and its profile is
 * enabled with ≥1 active SNI, the edge's provider matches the profile's, the
 * provider can actually carry the slot's protocol at the slot's layer, and,
 * for an L7 front, an authenticated end-to-end session has proven exactly
 * this configuration and has not expired.
 *
 * `forceGeoEvidence` is NOT an input here: it waives only the geographic
 * evidence gate in the rotation, never the transport proof below.
 */
export async function checkPublishable(
  ctx: { db: import('./_generated/server').DatabaseReader },
  edge: Doc<'edges'>,
  requireHealth: boolean,
): Promise<PublishCheck> {
  if (edge.status !== 'active') return { ok: false, code: 'edge_not_active' };
  if (edge.publication === 'published') return { ok: false, code: 'already_published' };
  if (!hasPublishableAddress(edge)) return { ok: false, code: 'no_address' };
  const slot = await ctx.db.get(edge.slotId);
  if (!slot || !slot.deployed || slot.retired) return { ok: false, code: 'slot_not_deployed' };
  // The slot's profile must be enabled, still have a selectable server name
  // when its protocol presents one, and (when provider-scoped) match the edge.
  const profile = await ctx.db.get(slot.profileId);
  if (!profile || !profile.enabled) return { ok: false, code: 'profile_disabled' };
  const layer = edge.layer ?? edgeLayerOf(edge.provider);
  const intent = parseIntent(edge.provisionIntent);
  // Behind an L7 front the name a member presents is the edge HOSTNAME, so a
  // name-free HTTP-transport profile is perfectly publishable there; only an L4
  // edge needs one of the profile's own names to select.
  if (
    layer === 'l4' &&
    protocolUsesSni(profile.protocol) &&
    !profile.serverNames.some((s) => s.status === 'active')
  )
    return { ok: false, code: 'profile_no_active_sni' };
  if (edge.provider && profile.provider && profile.provider !== edge.provider)
    return { ok: false, code: 'provider_mismatch' };
  // The Host header the front would send the origin decides whether the node
  // would answer at all (`acceptsHostHeader:'names'`); it comes from the frozen
  // intent, never from the account's current template.
  const l7Host = l7HostHeaderFor(
    edge.addresses.hostname ?? intent?.hostname,
    (intent?.templateParams as { overrideHost?: unknown } | undefined)?.overrideHost,
  );
  if (edge.provider) {
    // Two independent questions: can this provider carry the protocol at all
    // (an L7 front carries only the HTTP transports it declares), and does the
    // complete client-to-origin chain allow this LAYER in front of the slot
    // (a plaintext origin cannot sit behind a raw TCP forwarder).
    if (!protocolCarriedBy(edge.provider, profile.protocol))
      return { ok: false, code: 'protocol_not_carried' };
    if (!slotAllowsLayer(slot, profile, edgeLayerOf(edge.provider), { l7Host }))
      return { ok: false, code: 'layer_mismatch' };
  }
  if (layer === 'l7') {
    // The zone's encryption mode decides how the front dials the origin; a
    // plaintext origin behind a mode that dials HTTPS (or the other way round)
    // never completes a member connection. It says that only for the provider
    // that proxies the zone itself: a front whose records are unproxied CNAMEs
    // in someone else's zone dials the origin by its own configuration, and an
    // intent frozen before that distinction must not refuse it now.
    if (
      intent?.zoneSslMode &&
      zoneModeGovernsOrigin(edge.provider) &&
      !zoneModeCarriesOrigin(intent.zoneSslMode, intent.originTransport)
    )
      return { ok: false, code: 'origin_tls_mismatch' };
    // The binding is re-derived HERE, inside the publishing transaction, from
    // the current slot/profile/intent: a proof taken against an older
    // configuration is not a proof of what would now be published.
    if (!intent) return { ok: false, code: 'front_unqualified' };
    const verdict = qualificationVerdict(
      edge.frontQualification,
      qualificationBinding({ slot, profile, intent, params: slot.transportParams ?? {} }),
      Date.now(),
    );
    const refusal = qualificationRefusal(verdict);
    if (refusal) return { ok: false, code: refusal };
  }
  // An account-scoped profile binds the slot to ONE qualified account, not to
  // any account of that provider.
  if (edge.accountId && profile.accountId && profile.accountId !== edge.accountId)
    return { ok: false, code: 'account_mismatch' };
  // A provider without member health never reports `online`; `unknown` passes for it.
  if (edge.managed && !providerHealthSatisfies(edge.provider, edge.health, requireHealth))
    return { ok: false, code: 'edge_unhealthy' };
  return { ok: true };
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
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const cfg = await resolveEdgeConfig(ctx.db);
    const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
    if (!check.ok)
      throw new ConvexError({
        code: `edge.${check.code}`,
        message: `Edge cannot be published: ${check.code}`,
      });
    let idx = poolIndex ?? nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
    if (idx === null)
      throw new ConvexError({ code: 'edge.pool_full', message: 'The published pool is full' });
    if (idx < 0 || idx >= Math.max(origin.desiredPublished, origin.publishedEdgeIds.length))
      idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished) ?? 0;
    const occupant = origin.publishedEdgeIds[idx];
    if (occupant && occupant !== edgeId)
      throw new ConvexError({ code: 'edge.pool_index_taken', message: 'Pool index is occupied' });
    // Pool index 0 is the index the template Host points at. On a Host-managed
    // origin this direct path would publish the edge WITHOUT the flip, leaving
    // the panel sending everyone to the previous address while FCP reports the
    // new one: that is the rotation machine's job (kind `publish`), not a
    // direct pool write.
    if (idx === 0 && origin.hostManaged) {
      throw new ConvexError({
        code: 'edge.needs_rotation',
        message:
          'Publishing at pool index 0 needs the template-Host flip; start a publish rotation',
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
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId ?? undefined,
      action: 'edge.published',
      targetType: 'edge',
      targetId: edgeId,
      payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
    });
    // The epoch bump re-renders the fronted route within one request; S3 mirrors
    // only change when refreshed, so a new pool member needs one too, or
    // mirror readers keep receiving the pool without it until something else bumps.
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
    await assertNoRotationOrQuarantine(ctx.db, origin);
    if (edge.publication !== 'published')
      return { ok: true as const, epoch: origin.publicationEpoch };
    const now = Date.now();
    const poolIndex = edge.poolIndex ?? null;
    if (keepActive) {
      // Back to standby (still active, still paid for, not rendered).
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
 * A published edge that vanished at the provider (describe → gone) or was
 * destroyed by an operator: remove it from the pool without a drain (there is
 * nothing left to drain to) and bump the epoch so renders stop emitting it.
 * Gated like every pool writer; `force` is for internal callers that already
 * hold the origin (the describe(gone) path drops inside its own mutation).
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
      // A vanished row: heal the lists without an edge to patch.
      const inPool = origin.publishedEdgeIds.includes(edgeId);
      const inStandby = origin.standbyEdgeIds.includes(edgeId);
      if (!inPool && !inStandby) return { ok: true as const, dropped: false };
      await ctx.db.patch(relayId, {
        publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
        standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: Date.now(),
      });
      if (inPool) await scheduleMirrorRefresh(ctx);
      return { ok: true as const, dropped: true };
    }
    const r = await dropEdgeFromPool(ctx, origin, edge, { reason });
    return { ok: true as const, dropped: r.dropped };
  },
});

export const bumpEpoch = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return null;
    await ctx.db.patch(relayId, {
      publicationEpoch: origin.publicationEpoch + 1,
      updatedAt: Date.now(),
    });
    return null;
  },
});
