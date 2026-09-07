/**
 * Relay ORIGINS: one REALITY node fronted by a pool of published edges. Owns
 * the origin CRUD (admin + the Ansible by-slug upsert), edge adoption, and the
 * PUBLISHED-pool bookkeeping (publish/unpublish with pool-index inheritance and
 * the publication epoch the render cache keys on). Rotation/provisioning state
 * lives in relayRotations.ts; edge rows in relayEdges.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { resolveRelayConfig, relayMs } from './lib/relayConfig';
import { isPublicIpLiteral, addressFamily } from './lib/relays/ip';
import { sameAddress } from './lib/relays/hosts';
import { PROTOCOL_TRANSPORT, protocolUsesSni } from './lib/relays/protocols';
import { nextFreePoolIndex, withEdgeAt, withoutEdge, publishedCount } from './lib/relays/pool';

type Db = import('./_generated/server').DatabaseReader;

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
      code: 'relay.node_already_bound',
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
  const edges = await db
    .query('edges')
    .withIndex('by_relay_status', (q) => q.eq('relayId', origin._id))
    .collect();
  if (edges.some((e) => e.status !== 'destroyed')) {
    throw new ConvexError({
      code: 'relay.origin_address_locked',
      message: 'Drain or destroy every edge of this origin before changing originAddress',
    });
  }
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
  const cfg = await resolveRelayConfig(ctx.db);
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
    cooldownMs: p.cooldownMs ?? relayMs.cooldown(cfg),
    maxRotationsPerDay: p.maxRotationsPerDay ?? cfg.maxRotationsPerRelayPerDay,
    drainMs: p.drainMs ?? relayMs.drain(cfg),
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
    // Publication-affecting edits bump the epoch (render cache + assignment).
    const affects =
      p.desiredPublished !== undefined || p.modeSlugs !== undefined || p.enabled !== undefined;
    await ctx.db.patch(id, {
      ...p,
      ...(affects ? { publicationEpoch: row.publicationEpoch + 1 } : {}),
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.update',
      targetType: 'relay',
      targetId: id,
      payload: { slug: row.slug },
    });
    return { ok: true as const };
  },
});

/** Idempotent upsert keyed by slug (the Ansible hook). `backendServerSlug` names the panel. */
export const upsertBySlug = internalMutation({
  args: { slug: v.string(), backendServerSlug: v.string(), ...originWriteArgs },
  handler: async (ctx, { slug, backendServerSlug, actorAdminId, ...a }) => {
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
    if (existing) {
      id = existing._id;
      const p = patchFrom(a);
      // The role must not silently flip operator-owned automation knobs.
      delete p.autoRotate;
      await assertAddressChangeAllowed(ctx.db, existing, p.originAddress);
      const host = p.nodeHostname ?? existing.nodeHostname;
      if (host !== existing.nodeHostname || server._id !== existing.backendServerId)
        await assertNodeUnbound(ctx.db, server._id, host, id);
      await ctx.db.patch(id, { ...p, backendServerId: server._id, updatedAt: Date.now() });
    } else {
      id = await insertOrigin(ctx, slug, server._id, a);
      created = true;
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.upsert',
      targetType: 'relay',
      targetId: id,
      payload: { slug, created },
    });
    return { id, created };
  },
});

/** Mark an origin for teardown; relayEdges.reconcile drains/destroys and removes it. */
export const requestDelete = internalMutation({
  args: { id: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const, deleted: true };
    if (row.quarantine)
      throw new ConvexError({
        code: 'relay.quarantined',
        message: 'Resolve the quarantine before deleting',
      });
    if (row.activeRotationId) {
      const rot = await ctx.db.get(row.activeRotationId);
      if (rot && ['host_flipping', 'confirming', 'rolling_back'].includes(rot.phase)) {
        throw new ConvexError({
          code: 'relay.busy',
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
    const edges = await ctx.db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', id))
      .collect();
    for (const e of edges) {
      if (e.status === 'destroyed') continue;
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
          drainUntil: now,
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
      payload: { slug: row.slug },
    });
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
    for (const e of edges) await ctx.db.delete(e._id);
    await ctx.db.delete(id);
    return { removed: true };
  },
});

// --- adoption -----------------------------------------------------------------------------

/**
 * Adopt an edge that exists outside FCP's ledger: observe-only (`managed:false`,
 * only {ip, port} known; never destroyed) or managed (account + resource ids
 * supplied). Optionally publish it right away at the next free pool index.
 */
export const adoptEdge = internalMutation({
  args: {
    relayId: v.id('relays'),
    slotId: v.id('relaySlots'),
    ipv4: v.string(),
    ipv6: v.optional(v.union(v.string(), v.null())),
    port: v.optional(v.number()),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    resources: v.optional(v.array(v.object({ kind: v.string(), resourceId: v.string() }))),
    publish: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const slot = await ctx.db.get(a.slotId);
    if (!slot || slot.relayId !== a.relayId)
      throw new ConvexError({ code: 'validation', message: 'slot does not belong to the origin' });
    if (!isPublicIpLiteral(a.ipv4) || addressFamily(a.ipv4) !== 'v4')
      throw new ConvexError({ code: 'validation', message: 'ipv4 must be a public IPv4 literal' });
    if (a.ipv6 && (!isPublicIpLiteral(a.ipv6) || addressFamily(a.ipv6) !== 'v6'))
      throw new ConvexError({ code: 'validation', message: 'ipv6 must be a public IPv6 literal' });
    if (sameAddress(a.ipv4, origin.originAddress))
      throw new ConvexError({
        code: 'validation',
        message: 'the edge address is the origin itself (anti-leak)',
      });
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
    const managed = !!accountRow && (a.resources?.length ?? 0) > 0;
    const now = Date.now();
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
        ownership: 'adopted' as const,
        deleteState: 'present' as const,
      })),
      listeners: [
        {
          edgePort: port,
          originAddress: origin.originAddress,
          originPort: slot.originPort,
          transport: PROTOCOL_TRANSPORT[(await ctx.db.get(slot.profileId))?.protocol ?? 'reality'],
        },
      ],
      addresses: { v4: a.ipv4, v6: a.ipv6 ?? undefined },
      publication: 'unpublished',
      status: 'active',
      statusChangedAt: now,
      health: 'unknown',
      destroyAttempts: 0,
      updatedAt: now,
    });
    let poolIndex: number | null = null;
    if (a.publish) {
      const idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
      if (idx === null)
        throw new ConvexError({ code: 'relay.pool_full', message: 'The published pool is full' });
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
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.edge.adopted',
      targetType: 'relay',
      targetId: a.relayId,
      payload: {
        slug: origin.slug,
        edgeId,
        managed,
        publication: a.publish ? 'published' : 'unpublished',
      },
    });
    return { edgeId, poolIndex };
  },
});

// --- published pool -------------------------------------------------------------------------

export interface PublishCheck {
  ok: boolean;
  code?: string;
}

/**
 * Publication preconditions: the edge is active + unpublished, has an IPv4,
 * its slot is deployed (not retired) and its profile is enabled with ≥1 active
 * SNI, and the edge's provider matches the profile's.
 */
export async function checkPublishable(
  ctx: { db: import('./_generated/server').DatabaseReader },
  edge: Doc<'edges'>,
  requireHealth: boolean,
): Promise<PublishCheck> {
  if (edge.status !== 'active') return { ok: false, code: 'edge_not_active' };
  if (edge.publication === 'published') return { ok: false, code: 'already_published' };
  if (!edge.addresses.v4) return { ok: false, code: 'no_ipv4' };
  const slot = await ctx.db.get(edge.slotId);
  if (!slot || !slot.deployed || slot.retired) return { ok: false, code: 'slot_not_deployed' };
  // The slot's profile must be enabled, still have a selectable server name
  // when its protocol presents one, and (when provider-scoped) match the edge.
  const profile = await ctx.db.get(slot.profileId);
  if (!profile || !profile.enabled) return { ok: false, code: 'profile_disabled' };
  if (protocolUsesSni(profile.protocol) && !profile.serverNames.some((s) => s.status === 'active'))
    return { ok: false, code: 'profile_no_active_sni' };
  if (edge.provider && profile.provider && profile.provider !== edge.provider)
    return { ok: false, code: 'provider_mismatch' };
  if (requireHealth && edge.managed && edge.health !== 'online')
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
    const origin = await ctx.db.get(relayId);
    const edge = await ctx.db.get(edgeId);
    if (!origin || !edge || edge.relayId !== relayId)
      throw new ConvexError({ code: 'not_found', message: 'Origin/edge not found' });
    const cfg = await resolveRelayConfig(ctx.db);
    const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth);
    if (!check.ok)
      throw new ConvexError({
        code: `relay.${check.code}`,
        message: `Edge cannot be published: ${check.code}`,
      });
    let idx = poolIndex ?? nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished);
    if (idx === null)
      throw new ConvexError({ code: 'relay.pool_full', message: 'The published pool is full' });
    if (idx < 0 || idx >= Math.max(origin.desiredPublished, origin.publishedEdgeIds.length))
      idx = nextFreePoolIndex(origin.publishedEdgeIds, origin.desiredPublished) ?? 0;
    const occupant = origin.publishedEdgeIds[idx];
    if (occupant && occupant !== edgeId)
      throw new ConvexError({ code: 'relay.pool_index_taken', message: 'Pool index is occupied' });
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
      action: 'relay.edge.published',
      targetType: 'relay_edge',
      targetId: edgeId,
      payload: { relaySlug: origin.slug, edgeId, poolIndex: idx, epoch },
    });
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
      action: 'relay.edge.unpublished',
      targetType: 'relay_edge',
      targetId: edgeId,
      payload: { relaySlug: origin.slug, edgeId, poolIndex, epoch },
    });
    return { ok: true as const, epoch };
  },
});

/**
 * A published edge that vanished at the provider (describe → gone) or was
 * destroyed by an operator: remove it from the pool without a drain (there is
 * nothing left to drain to) and bump the epoch so renders stop emitting it.
 */
export const dropFromPool = internalMutation({
  args: { relayId: v.id('relays'), edgeId: v.id('edges'), reason: v.string() },
  handler: async (ctx, { relayId, edgeId, reason }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) return { ok: false as const };
    const now = Date.now();
    const inPool = origin.publishedEdgeIds.includes(edgeId);
    const inStandby = origin.standbyEdgeIds.includes(edgeId);
    if (!inPool && !inStandby) return { ok: true as const, dropped: false };
    const edge = await ctx.db.get(edgeId);
    if (edge && edge.publication !== 'unpublished') {
      await ctx.db.patch(edgeId, {
        publication: 'unpublished',
        poolIndex: undefined,
        updatedAt: now,
      });
    }
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(relayId, {
      publishedEdgeIds: withoutEdge(origin.publishedEdgeIds, edgeId),
      standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== edgeId),
      publicationEpoch: epoch,
      updatedAt: now,
    });
    if (inPool) {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.edge.unpublished',
        targetType: 'relay_edge',
        targetId: edgeId,
        payload: { relaySlug: origin.slug, edgeId, poolIndex: edge?.poolIndex ?? null, epoch },
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.drift',
        targetType: 'relay',
        targetId: relayId,
        payload: {
          relaySlug: origin.slug,
          edgeId,
          mismatched: 1,
          total: publishedCount(origin.publishedEdgeIds),
        },
      });
    }
    void reason;
    return { ok: true as const, dropped: true };
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
