/**
 * Protocol profiles: what a relay slot's inbound speaks (`reality` / `tls` /
 * `plain`, lib/relays/protocols.ts) and the data the renderer needs for it: the
 * approved server names (REALITY SNIs, or a real certificate's names) and, for
 * REALITY, the impersonated target. Optionally scoped to one provider's network
 * (REALITY names are only plausible near the edge network). Operator data,
 * never adapter code.
 *
 * SNI lifecycle: `active` names are selectable for new assignments; `retired`
 * names stop being selected but stay accepted server-side until `drainUntil`
 * (the role removes them from the inbound's serverNames after that), so a
 * subscriber holding a retired name keeps working through the drain.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { resolveRelayConfig, relayMs } from './lib/relayConfig';
import {
  isSlotProtocol,
  protocolNeedsTarget,
  protocolUsesSni,
  type SlotProtocol,
} from './lib/relays/protocols';

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export function normalizeSni(s: unknown): string | null {
  if (typeof s !== 'string') return null;
  const t = s.trim().toLowerCase().replace(/\.$/, '');
  return HOSTNAME_RE.test(t) ? t : null;
}

/**
 * A profile edit changes what renders for every origin whose slots use it
 * (active SNI set, enabled flag, target): bump those origins' publication
 * epoch (the /sub cache token + assignment) and refresh stored mirrors once.
 */
async function invalidateOrigins(ctx: MutationCtx, profileId: Id<'protocolProfiles'>) {
  const slots = await ctx.db
    .query('relaySlots')
    .withIndex('by_profile', (q) => q.eq('profileId', profileId))
    .collect();
  const originIds = [...new Set(slots.map((s) => s.relayId))];
  if (originIds.length === 0) return 0;
  const now = Date.now();
  for (const relayId of originIds) {
    const origin = await ctx.db.get(relayId);
    if (!origin) continue;
    await ctx.db.patch(relayId, { publicationEpoch: origin.publicationEpoch + 1, updatedAt: now });
  }
  await ctx.scheduler.runAfter(0, internal.storage.refreshActiveMirrors, {});
  return originIds.length;
}

export function mapProfileAdmin(r: Doc<'protocolProfiles'>) {
  return {
    id: r._id as string,
    slug: r.slug,
    name: r.name,
    protocol: r.protocol,
    provider: r.provider ?? null,
    accountId: (r.accountId as string | undefined) ?? null,
    targetAddress: r.targetAddress ?? null,
    targetPort: r.targetPort ?? null,
    serverNames: r.serverNames.map((s) => ({
      sni: s.sni,
      status: s.status,
      retiredAt: s.retiredAt ? new Date(s.retiredAt).toISOString() : null,
      drainUntil: s.drainUntil ? new Date(s.drainUntil).toISOString() : null,
    })),
    enabled: r.enabled,
    qualification: r.qualification
      ? {
          checkedAt: new Date(r.qualification.checkedAt).toISOString(),
          edgeAsn: r.qualification.edgeAsn ?? null,
          targetAsn: r.qualification.targetAsn ?? null,
          sameAsn: r.qualification.sameAsn ?? null,
          tlsOk: r.qualification.tlsOk,
          authOk: r.qualification.authOk,
        }
      : null,
    notes: r.notes ?? null,
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

export const list = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await ctx.db.query('protocolProfiles').collect())
      .sort(
        (a, b) =>
          (a.provider ?? '').localeCompare(b.provider ?? '') || a.slug.localeCompare(b.slug),
      )
      .map(mapProfileAdmin),
});

export const get = internalQuery({
  args: { id: v.id('protocolProfiles') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r ? mapProfileAdmin(r) : null;
  },
});

export const getBySlug = internalQuery({
  args: { slug: v.string() },
  handler: (ctx, { slug }) =>
    ctx.db
      .query('protocolProfiles')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique(),
});

function parseSnis(raw: unknown, protocol: SlotProtocol): string[] {
  if (raw === undefined || raw === null) raw = [];
  if (!Array.isArray(raw))
    throw new ConvexError({ code: 'validation', message: 'serverNames must be a list' });
  if (!protocolUsesSni(protocol)) {
    if (raw.length > 0)
      throw new ConvexError({
        code: 'validation',
        message: 'a plain profile carries no server names',
      });
    return [];
  }
  const out: string[] = [];
  for (const s of raw) {
    const n = normalizeSni(s);
    if (!n)
      throw new ConvexError({
        code: 'validation',
        message: `invalid server name: ${String(s).slice(0, 64)}`,
      });
    if (!out.includes(n)) out.push(n);
  }
  if (out.length === 0 || out.length > 32) {
    throw new ConvexError({ code: 'validation', message: 'serverNames needs 1..32 entries' });
  }
  return out;
}

function checkTarget(
  address: unknown,
  port: unknown,
): { targetAddress: string; targetPort: number } {
  const a =
    normalizeSni(address) ??
    (typeof address === 'string' && /^[0-9a-f:.[\]]+$/i.test(address) ? address : null);
  if (!a)
    throw new ConvexError({
      code: 'validation',
      message: 'targetAddress must be a hostname or IP',
    });
  const p = typeof port === 'number' ? port : 443;
  if (!Number.isInteger(p) || p < 1 || p > 65535)
    throw new ConvexError({ code: 'validation', message: 'targetPort out of range' });
  return { targetAddress: a, targetPort: p };
}

export const create = internalMutation({
  args: {
    slug: v.string(),
    name: v.string(),
    /** Defaults to `reality` (the original contract). */
    protocol: v.optional(v.string()),
    /** Absent/null = usable behind any provider. */
    provider: v.optional(v.union(edgeProviderIdValidator, v.null())),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    targetAddress: v.optional(v.union(v.string(), v.null())),
    targetPort: v.optional(v.union(v.number(), v.null())),
    serverNames: v.optional(v.any()),
    enabled: v.optional(v.boolean()),
    notes: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    if (!SLUG_RE.test(a.slug))
      throw new ConvexError({ code: 'validation', message: 'invalid slug' });
    if (!a.name.trim() || a.name.length > 64)
      throw new ConvexError({ code: 'validation', message: 'invalid name' });
    const dup = await ctx.db
      .query('protocolProfiles')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique();
    if (dup)
      throw new ConvexError({ code: 'conflict', message: 'A profile with this slug exists' });
    const protocolRaw = a.protocol ?? 'reality';
    if (!isSlotProtocol(protocolRaw))
      throw new ConvexError({ code: 'validation', message: 'unknown protocol' });
    const protocol: SlotProtocol = protocolRaw;
    const provider = a.provider ?? undefined;
    if (a.accountId) {
      const acct = await ctx.db.get(a.accountId);
      if (!acct || (provider && acct.provider !== provider))
        throw new ConvexError({ code: 'validation', message: 'account/provider mismatch' });
    }
    const target = protocolNeedsTarget(protocol)
      ? checkTarget(a.targetAddress, a.targetPort ?? undefined)
      : {};
    const snis = parseSnis(a.serverNames, protocol);
    const now = Date.now();
    const id = await ctx.db.insert('protocolProfiles', {
      slug: a.slug,
      name: a.name.trim(),
      protocol,
      provider,
      accountId: a.accountId ?? undefined,
      ...target,
      serverNames: snis.map((sni) => ({ sni, status: 'active' as const })),
      enabled: a.enabled ?? true,
      notes: a.notes?.slice(0, 500),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.profile.create',
      targetType: 'relay_profile',
      targetId: id,
      payload: { slug: a.slug, provider: provider ?? null, protocol },
    });
    return { id };
  },
});

export const update = internalMutation({
  args: {
    id: v.id('protocolProfiles'),
    name: v.optional(v.string()),
    /** null = any provider. */
    provider: v.optional(v.union(edgeProviderIdValidator, v.null())),
    accountId: v.optional(v.union(v.id('edgeProviderAccounts'), v.null())),
    targetAddress: v.optional(v.string()),
    targetPort: v.optional(v.number()),
    /** Full replacement of the ACTIVE set: new names are added active, absent
     *  active names are retired (drain starts), retired names are kept. */
    serverNames: v.optional(v.any()),
    enabled: v.optional(v.boolean()),
    notes: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Profile not found' });
    const patch: Partial<Doc<'protocolProfiles'>> = { updatedAt: Date.now() };
    if (a.name !== undefined) {
      if (!a.name.trim() || a.name.length > 64)
        throw new ConvexError({ code: 'validation', message: 'invalid name' });
      patch.name = a.name.trim();
    }
    if (a.provider !== undefined) patch.provider = a.provider ?? undefined;
    const provider = a.provider !== undefined ? (a.provider ?? undefined) : row.provider;
    if (a.accountId !== undefined) {
      if (a.accountId) {
        const acct = await ctx.db.get(a.accountId);
        if (!acct || (provider && acct.provider !== provider))
          throw new ConvexError({ code: 'validation', message: 'account/provider mismatch' });
      }
      patch.accountId = a.accountId ?? undefined;
    }
    if (
      protocolNeedsTarget(row.protocol) &&
      (a.targetAddress !== undefined || a.targetPort !== undefined)
    ) {
      const t = checkTarget(
        a.targetAddress ?? row.targetAddress,
        a.targetPort ?? row.targetPort ?? undefined,
      );
      patch.targetAddress = t.targetAddress;
      patch.targetPort = t.targetPort;
      // A different target invalidates the qualification facts.
      if (t.targetAddress !== row.targetAddress || t.targetPort !== row.targetPort)
        patch.qualification = undefined;
    }
    if (a.serverNames !== undefined) {
      const wanted = parseSnis(a.serverNames, row.protocol);
      const cfg = await resolveRelayConfig(ctx.db);
      const now = Date.now();
      const next = row.serverNames.map((s) => {
        if (wanted.includes(s.sni))
          return s.status === 'active' ? s : { sni: s.sni, status: 'active' as const };
        if (s.status === 'active') {
          return {
            sni: s.sni,
            status: 'retired' as const,
            retiredAt: now,
            drainUntil: now + relayMs.sniDrain(cfg),
          };
        }
        return s;
      });
      for (const sni of wanted)
        if (!next.some((s) => s.sni === sni)) next.push({ sni, status: 'active' });
      patch.serverNames = next;
    }
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.notes !== undefined) patch.notes = a.notes.slice(0, 500);
    await ctx.db.patch(a.id, patch);
    const affectsRender =
      (patch.enabled !== undefined && patch.enabled !== row.enabled) ||
      (patch.serverNames !== undefined &&
        JSON.stringify(patch.serverNames) !== JSON.stringify(row.serverNames)) ||
      (patch.targetAddress !== undefined &&
        (patch.targetAddress !== row.targetAddress || patch.targetPort !== row.targetPort));
    if (affectsRender) await invalidateOrigins(ctx, a.id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.profile.update',
      targetType: 'relay_profile',
      targetId: a.id,
      payload: { slug: row.slug, provider: row.provider ?? null },
    });
    return { ok: true as const };
  },
});

export const retireSni = internalMutation({
  args: {
    id: v.id('protocolProfiles'),
    snis: v.array(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, snis, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Profile not found' });
    const cfg = await resolveRelayConfig(ctx.db);
    const now = Date.now();
    const targets = new Set(snis.map((s) => normalizeSni(s)).filter((s): s is string => !!s));
    let count = 0;
    const next = row.serverNames.map((s) => {
      if (targets.has(s.sni) && s.status === 'active') {
        count++;
        return {
          sni: s.sni,
          status: 'retired' as const,
          retiredAt: now,
          drainUntil: now + relayMs.sniDrain(cfg),
        };
      }
      return s;
    });
    if (protocolUsesSni(row.protocol) && !next.some((s) => s.status === 'active')) {
      throw new ConvexError({
        code: 'conflict',
        message: 'A profile keeps at least one active server name',
      });
    }
    await ctx.db.patch(id, { serverNames: next, updatedAt: now });
    if (count > 0) await invalidateOrigins(ctx, id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.sni.retire',
      targetType: 'relay_profile',
      targetId: id,
      payload: { profileSlug: row.slug, count },
    });
    return { ok: true as const, retired: count };
  },
});

export const reactivateSni = internalMutation({
  args: {
    id: v.id('protocolProfiles'),
    snis: v.array(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, snis, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Profile not found' });
    const targets = new Set(snis.map((s) => normalizeSni(s)).filter((s): s is string => !!s));
    let count = 0;
    const next = row.serverNames.map((s) => {
      if (targets.has(s.sni) && s.status === 'retired') {
        count++;
        return { sni: s.sni, status: 'active' as const };
      }
      return s;
    });
    await ctx.db.patch(id, { serverNames: next, updatedAt: Date.now() });
    if (count > 0) await invalidateOrigins(ctx, id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.sni.reactivate',
      targetType: 'relay_profile',
      targetId: id,
      payload: { profileSlug: row.slug, count },
    });
    return { ok: true as const, reactivated: count };
  },
});

export const recordQualification = internalMutation({
  args: {
    id: v.id('protocolProfiles'),
    tlsOk: v.boolean(),
    authOk: v.boolean(),
    edgeAsn: v.optional(v.string()),
    targetAsn: v.optional(v.string()),
    checkedFromEdgeId: v.optional(v.id('edges')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Profile not found' });
    await ctx.db.patch(a.id, {
      qualification: {
        checkedAt: Date.now(),
        edgeAsn: a.edgeAsn,
        targetAsn: a.targetAsn,
        sameAsn: a.edgeAsn && a.targetAsn ? a.edgeAsn === a.targetAsn : undefined,
        tlsOk: a.tlsOk,
        authOk: a.authOk,
        checkedFromEdgeId: a.checkedFromEdgeId,
      },
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.profile.qualified',
      targetType: 'relay_profile',
      targetId: a.id,
      payload: { slug: row.slug, provider: row.provider, tlsOk: a.tlsOk, authOk: a.authOk },
    });
    return { ok: true as const };
  },
});

export const remove = internalMutation({
  args: { id: v.id('protocolProfiles'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    const slot = await ctx.db
      .query('relaySlots')
      .withIndex('by_profile', (q) => q.eq('profileId', id))
      .first();
    if (slot) throw new ConvexError({ code: 'conflict', message: 'Slots still use this profile' });
    await ctx.db.delete(id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.profile.delete',
      targetType: 'relay_profile',
      targetId: id,
      payload: { slug: row.slug, provider: row.provider ?? null },
    });
    return { ok: true as const };
  },
});
