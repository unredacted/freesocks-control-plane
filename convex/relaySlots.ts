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
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { isSlotKey, templateHostRemark } from './lib/edges/hosts';

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
  await ctx.scheduler.runAfter(0, internal.storage.refreshActiveMirrors, {});
}

export function mapSlotAdmin(r: Doc<'relaySlots'>, profile?: Doc<'protocolProfiles'> | null) {
  return {
    id: r._id as string,
    relayId: r.relayId as string,
    slotKey: r.slotKey,
    protocol: profile?.protocol ?? 'reality',
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
    const fields = {
      profileId: profile._id,
      inboundTag: a.inboundTag,
      configProfileUuid: a.configProfileUuid,
      configProfileInboundUuid: a.configProfileInboundUuid,
      originPort: a.originPort,
      templateHostRemark: remark,
      deployed: a.deployed ?? true,
      retired: false,
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
        const live = (
          await ctx.db
            .query('edges')
            .withIndex('by_relay_status', (q) => q.eq('relayId', a.relayId))
            .collect()
        ).filter((e) => e.slotId === existing._id && e.status !== 'destroyed');
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
    await ctx.db.patch(slot._id, { retired: true, deployed: false, updatedAt: Date.now() });
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
