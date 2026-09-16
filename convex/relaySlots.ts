/**
 * Relay SLOTS: one inbound on the relay node (port + panel inbound uuid)
 * deployed by the node role, with its single template Host (stable remark
 * `<node>-relay-<slotKey>`). The slot's PROTOCOL PROFILE says what the inbound
 * speaks (REALITY / TLS / plain, lib/edges/protocols.ts) and carries its server
 * names; a provider-scoped profile only accepts edges of that provider. Edges
 * bind to one slot.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { isSlotKey, templateHostRemark } from './lib/edges/hosts';
import { isValidHostname } from './lib/edges/hostname';
import { slotLayers } from './lib/edges/layers';
import { assertNoRotationOrQuarantine, liveEdgesOfRelay, scheduleMirrorRefresh } from './relays';

/**
 * A slot change alters what renders for the origin (its template remark set,
 * its profile): bump the publication epoch (the /sub cache token) and refresh
 * stored mirrors once so they stop carrying the previous shape.
 */
async function invalidateOrigin(ctx: MutationCtx, origin: Doc<'relays'>) {
  await ctx.db.patch(origin._id, {
    publicationEpoch: origin.publicationEpoch + 1,
    updatedAt: Date.now(),
  });
  await scheduleMirrorRefresh(ctx);
}

/**
 * `originTransport` declares how the node is reached BEHIND a front: the scheme,
 * whether the origin certificate is publicly trusted, the names it carries and
 * whether the node accepts an arbitrary Host header. The whole client-to-origin
 * chain is decided from it (lib/edges/layers.ts), so it is validated strictly:
 * certificate names are hostnames or single leftmost wildcards, never IPs.
 */
const originTransportValidator = v.object({
  scheme: v.union(v.literal('http'), v.literal('https')),
  certPublic: v.boolean(),
  certNames: v.array(v.string()),
  acceptsHostHeader: v.union(v.literal('any'), v.literal('names')),
});

const transportParamsValidator = v.object({
  path: v.optional(v.string()),
  host: v.optional(v.string()),
  serviceName: v.optional(v.string()),
  upgradeToken: v.optional(v.string()),
});

type OriginTransportArg = {
  scheme: 'http' | 'https';
  certPublic: boolean;
  certNames: string[];
  acceptsHostHeader: 'any' | 'names';
};

function checkOriginTransport(t: OriginTransportArg): OriginTransportArg {
  if (t.certNames.length > 16)
    throw new ConvexError({ code: 'validation', message: 'certNames takes at most 16 entries' });
  const names: string[] = [];
  for (const raw of t.certNames) {
    const n = raw.trim().toLowerCase().replace(/\.$/, '');
    // A wildcard is exactly one leftmost `*` label (RFC 6125); `f*.example` and
    // `*.*.example` are not names a certificate can carry that way.
    const body = n.startsWith('*.') ? n.slice(2) : n;
    if (n.includes('*') && !n.startsWith('*.'))
      throw new ConvexError({ code: 'validation', message: `invalid certificate name: ${n}` });
    if (!isValidHostname(body))
      throw new ConvexError({ code: 'validation', message: `invalid certificate name: ${n}` });
    if (!names.includes(n)) names.push(n);
  }
  if (t.scheme === 'https' && t.certPublic && names.length === 0) {
    throw new ConvexError({
      code: 'validation',
      message: 'a publicly trusted origin must name its certificate',
    });
  }
  return { ...t, certNames: names };
}

export function mapSlotAdmin(r: Doc<'relaySlots'>, profile?: Doc<'protocolProfiles'> | null) {
  return {
    id: r._id as string,
    relayId: r.relayId as string,
    slotKey: r.slotKey,
    protocol: profile?.protocol ?? 'reality',
    originTransport: r.originTransport ?? null,
    transportParams: r.transportParams ?? null,
    // Which edge layers can front this slot given the complete chain; empty
    // means nothing can (the operator sees why in the exclusions).
    layers: profile ? slotLayers(r, profile).layers : ['l4'],
    revision: r.revision ?? 0,
    profileId: r.profileId as string,
    profileSlug: profile?.slug ?? null,
    provider: profile?.provider ?? null,
    inboundTag: r.inboundTag,
    configProfileUuid: r.configProfileUuid,
    configProfileInboundUuid: r.configProfileInboundUuid,
    originPort: r.originPort,
    templateHostUuid: r.templateHostUuid ?? null,
    templateHostRemark: r.templateHostRemark,
    deployed: r.deployed,
    deployedAt: r.deployedAt ? new Date(r.deployedAt).toISOString() : null,
    retired: r.retired,
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export const listByRelay = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const rows = await ctx.db
      .query('relaySlots')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    const out = [];
    for (const r of rows) out.push(mapSlotAdmin(r, await ctx.db.get(r.profileId)));
    return out.sort((a, b) => a.slotKey.localeCompare(b.slotKey));
  },
});

/** Slots with their profile rows (the eligibility view the pool/renderer needs). */
export async function slotsWithProfiles(
  ctx: { db: import('./_generated/server').DatabaseReader },
  relayId: Id<'relays'>,
): Promise<Array<{ slot: Doc<'relaySlots'>; profile: Doc<'protocolProfiles'> | null }>> {
  const rows = await ctx.db
    .query('relaySlots')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .collect();
  const out = [];
  for (const slot of rows) out.push({ slot, profile: await ctx.db.get(slot.profileId) });
  return out;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Idempotent upsert keyed by (relay, slotKey) — the node role's hook. The
 * profile is addressed by slug. Re-running with the same values is a no-op;
 * changing the inbound uuid marks the slot deployed again with the new
 * binding (the template Host must be re-created by the role).
 */
export const upsert = internalMutation({
  args: {
    relayId: v.id('relays'),
    slotKey: v.string(),
    profileSlug: v.string(),
    inboundTag: v.string(),
    configProfileUuid: v.string(),
    configProfileInboundUuid: v.string(),
    originPort: v.number(),
    /** How the node is reached behind an L7 front; absent = a legacy raw-TCP slot. */
    originTransport: v.optional(v.union(originTransportValidator, v.null())),
    /**
     * The HTTP-transport parameters the inbound is deployed with (path + upgrade
     * token for ws/httpupgrade, service name for grpc). The front qualification
     * sends exactly these and binds to their hash, so a change here expires the
     * proof through the revision bump below.
     */
    transportParams: v.optional(v.union(transportParamsValidator, v.null())),
    deployed: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    if (!isSlotKey(a.slotKey))
      throw new ConvexError({
        code: 'validation',
        message: 'slotKey must be 1-16 lowercase alphanumerics',
      });
    if (!UUID_RE.test(a.configProfileUuid) || !UUID_RE.test(a.configProfileInboundUuid)) {
      throw new ConvexError({
        code: 'validation',
        message: 'config profile / inbound uuids must be UUIDs',
      });
    }
    if (!Number.isInteger(a.originPort) || a.originPort < 1 || a.originPort > 65535) {
      throw new ConvexError({ code: 'validation', message: 'originPort out of range' });
    }
    if (!/^[A-Z0-9_]{1,64}$/.test(a.inboundTag))
      throw new ConvexError({ code: 'validation', message: 'inboundTag must be [A-Z0-9_]' });
    const origin = await ctx.db.get(a.relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const profile = await ctx.db
      .query('protocolProfiles')
      .withIndex('by_slug', (q) => q.eq('slug', a.profileSlug))
      .unique();
    if (!profile) throw new ConvexError({ code: 'validation', message: 'unknown profile slug' });
    const existing = (
      await ctx.db
        .query('relaySlots')
        .withIndex('by_relay', (q) => q.eq('relayId', a.relayId))
        .collect()
    ).find((s) => s.slotKey === a.slotKey);
    const now = Date.now();
    const remark = templateHostRemark(origin.nodeHostname, a.slotKey);
    const originTransport =
      a.originTransport === undefined
        ? existing?.originTransport
        : a.originTransport === null
          ? undefined
          : checkOriginTransport(a.originTransport);
    const transportParams =
      a.transportParams === undefined
        ? existing?.transportParams
        : (a.transportParams ?? undefined);
    const fields = {
      profileId: profile._id,
      inboundTag: a.inboundTag,
      configProfileUuid: a.configProfileUuid,
      configProfileInboundUuid: a.configProfileInboundUuid,
      originPort: a.originPort,
      originTransport,
      transportParams,
      templateHostRemark: remark,
      deployed: a.deployed ?? true,
      retired: false,
      // Every write bumps the revision: a front qualification binds to it, so a
      // slot edited after a proof was taken invalidates that proof by itself.
      revision: (existing?.revision ?? 0) + 1,
      updatedAt: now,
    };
    let id: Id<'relaySlots'>;
    let created = false;
    if (existing) {
      id = existing._id;
      const rebound =
        existing.configProfileInboundUuid !== a.configProfileInboundUuid ||
        existing.profileId !== profile._id;
      // Edges (and their provider listeners) were provisioned against this
      // slot's inbound + origin port: a rebind or port change under them would
      // forward to an obsolete inbound while rendering the new profile. The
      // role must drain/destroy the slot's edges first (or use a new slotKey).
      if (rebound || existing.originPort !== a.originPort) {
        const live = (await liveEdgesOfRelay(ctx.db, a.relayId)).filter(
          (e) => e.slotId === existing._id,
        );
        if (live.length > 0)
          throw new ConvexError({
            code: 'conflict',
            message: `${live.length} edge(s) still use slot ${a.slotKey}; destroy them before rebinding its inbound, profile or port`,
          });
      }
      await ctx.db.patch(id, {
        ...fields,
        deployedAt: rebound || !existing.deployed ? now : existing.deployedAt,
        // A re-bound inbound gets a NEW template Host; forget the old uuid.
        templateHostUuid: rebound ? undefined : existing.templateHostUuid,
      });
    } else {
      id = await ctx.db.insert('relaySlots', {
        relayId: a.relayId,
        slotKey: a.slotKey,
        ...fields,
        deployedAt: now,
      });
      created = true;
    }
    await invalidateOrigin(ctx, origin);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.slot.upsert',
      targetType: 'relay_slot',
      targetId: id,
      payload: { relaySlug: origin.slug, slotKey: a.slotKey, created },
    });
    return { id, created, templateHostRemark: remark };
  },
});

export const retire = internalMutation({
  args: {
    relayId: v.id('relays'),
    slotKey: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, slotKey, actorAdminId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const slot = (
      await ctx.db
        .query('relaySlots')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .collect()
    ).find((s) => s.slotKey === slotKey);
    if (!slot) return { ok: true as const };
    // A rotation in flight on this relay is about to publish, flip or roll back
    // against a slot: retiring it underneath would strand the run (its target
    // slot is gone) or leave the panel pointing at an edge the pool no longer
    // renders. Same gate every other pool writer takes.
    await assertNoRotationOrQuarantine(ctx.db, origin);
    const live = await ctx.db
      .query('edges')
      .withIndex('by_relay_publication', (q) =>
        q.eq('relayId', relayId).eq('publication', 'published'),
      )
      .collect();
    if (live.some((e) => e.slotId === slot._id)) {
      throw new ConvexError({
        code: 'conflict',
        message: 'A published edge still uses this slot; unpublish it first',
      });
    }
    await ctx.db.patch(slot._id, {
      retired: true,
      deployed: false,
      revision: (slot.revision ?? 0) + 1,
      updatedAt: Date.now(),
    });
    // The retired slot's template entry must vanish from every stored mirror,
    // not just from the next fronted fetch.
    await invalidateOrigin(ctx, origin);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.slot.retire',
      targetType: 'relay_slot',
      targetId: slot._id,
      payload: { relaySlug: origin.slug, slotKey },
    });
    return { ok: true as const };
  },
});

/** Record the template Host uuid once discovered on the panel (drift/flip bookkeeping). */
export const setTemplateHost = internalMutation({
  args: { slotId: v.id('relaySlots'), templateHostUuid: v.union(v.string(), v.null()) },
  handler: async (ctx, { slotId, templateHostUuid }) => {
    const slot = await ctx.db.get(slotId);
    if (!slot) return null;
    await ctx.db.patch(slotId, {
      templateHostUuid: templateHostUuid ?? undefined,
      updatedAt: Date.now(),
    });
    return null;
  },
});
