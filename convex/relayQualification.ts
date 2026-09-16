/**
 * The L7 front-qualification CREDENTIAL: a panel account FCP mints on the
 * relay's placement so the authenticated test session (lib/edges/frontCheck)
 * travels exactly the path a member's key takes. The account is a normal
 * member-shaped user with a tiny traffic cap and no expiry, tagged so an
 * operator recognises it on the panel; only its protocol UUID is kept
 * (`relays.qualificationUserId`) plus the panel user id needed to deactivate it.
 * Nothing here is logged or audited beyond booleans.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { backendIdValidator } from './lib/backendIds';
import { writeAuditLog } from './lib/audit';
import { resolvePlacementTarget } from './lib/remnawavePlacement';

/** Enough for many qualification sessions (each moves a few kilobytes), never for real use. */
export const QUALIFICATION_TRAFFIC_LIMIT_BYTES = 50 * 1024 * 1024;
export const QUALIFICATION_TAG = 'fcp-qualify';

export function qualificationUsername(relaySlug: string, nonceHex8: string): string {
  const slug = relaySlug
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .slice(0, 20);
  return `fcp-qualify-${slug}-${nonceHex8}`;
}

/** What minting needs: the relay, its panel and a placement pinned to that panel. */
export const mintContext = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    // The relay's first mode decides the placement; every mode a node serves
    // is homed on that node, so any of them reaches the inbound under test.
    let modeId: string | null = null;
    for (const slug of relay.modeSlugs) {
      const mode = await ctx.db
        .query('connectionModes')
        .withIndex('by_slug', (q) => q.eq('slug', slug))
        .unique();
      if (mode) {
        modeId = mode._id as string;
        break;
      }
    }
    const { placement } = await resolvePlacementTarget(ctx.db, modeId, {
      onlyServerId: server._id as string,
    });
    return {
      slug: relay.slug,
      backend: server.backend,
      backendServerId: server._id,
      placement,
      previousBackendUserId: relay.qualificationBackendUserId ?? null,
    };
  },
});

export const store = internalMutation({
  args: {
    relayId: v.id('relays'),
    protocolUuid: v.string(),
    backendUserId: v.string(),
    replaced: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await ctx.db.patch(a.relayId, {
      qualificationUserId: a.protocolUuid,
      qualificationBackendUserId: a.backendUserId,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.qualification_credential',
      targetType: 'relay',
      targetId: a.relayId,
      payload: { slug: relay.slug, minted: true, replaced: a.replaced },
    });
    return { ok: true as const };
  },
});

export const clear = internalMutation({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) return { ok: true as const };
    await ctx.db.patch(a.relayId, {
      qualificationUserId: undefined,
      qualificationBackendUserId: undefined,
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.qualification_credential',
      targetType: 'relay',
      targetId: a.relayId,
      payload: { slug: relay.slug, revoked: true },
    });
    return { ok: true as const };
  },
});

/** Deactivate a panel user (best effort; a leftover is a capped test account). */
export const removeBackendUser = internalAction({
  args: { backend: backendIdValidator, backendUserId: v.string() },
  handler: async (ctx, { backend, backendUserId }): Promise<{ ok: boolean }> => {
    try {
      await ctx.runAction(internal.backends.deleteUser, { backend, backendUserId });
      return { ok: true };
    } catch {
      console.warn('[relayQualification] could not remove a qualification account');
      return { ok: false };
    }
  },
});

/**
 * Mint (or re-mint) the credential. The previous account, if any, is removed
 * only after the new one is stored, so a failed mint keeps the old credential.
 */
export const mint = internalAction({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { relayId, actorAdminId }): Promise<{ ok: boolean; code?: string }> => {
    const c = await ctx.runQuery(internal.relayQualification.mintContext, { relayId });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const nonce = new Uint8Array(4);
    crypto.getRandomValues(nonce);
    const hex = Array.from(nonce, (b) => b.toString(16).padStart(2, '0')).join('');
    const issued = await ctx.runAction(internal.backends.issueUser, {
      backend: c.backend,
      pinServerId: c.backendServerId as Id<'backendServers'>,
      spec: {
        username: qualificationUsername(c.slug, hex),
        trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
        expireAt: null,
        tag: QUALIFICATION_TAG,
        description: 'FCP front qualification (automated, capped)',
        placement: c.placement,
      },
    });
    if (!issued.protocolUuid) {
      // This backend cannot back the check: do not keep an account nobody can use.
      await ctx.runAction(internal.relayQualification.removeBackendUser, {
        backend: c.backend,
        backendUserId: issued.backendUserId,
      });
      return { ok: false, code: 'qualification_credential_unsupported' };
    }
    await ctx.runMutation(internal.relayQualification.store, {
      relayId,
      protocolUuid: issued.protocolUuid,
      backendUserId: issued.backendUserId,
      replaced: c.previousBackendUserId !== null,
      actorAdminId,
    });
    if (c.previousBackendUserId) {
      await ctx.runAction(internal.relayQualification.removeBackendUser, {
        backend: c.backend,
        backendUserId: c.previousBackendUserId,
      });
    }
    return { ok: true };
  },
});

export const revoke = internalAction({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { relayId, actorAdminId }): Promise<{ ok: boolean }> => {
    const c = await ctx.runQuery(internal.relayQualification.mintContext, { relayId });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await ctx.runMutation(internal.relayQualification.clear, { relayId, actorAdminId });
    if (c.previousBackendUserId) {
      await ctx.runAction(internal.relayQualification.removeBackendUser, {
        backend: c.backend,
        backendUserId: c.previousBackendUserId,
      });
    }
    return { ok: true };
  },
});
