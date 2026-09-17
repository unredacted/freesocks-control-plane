/**
 * The L7 front-qualification CREDENTIAL: a panel account FCP mints on the
 * relay's placement so the authenticated test session (lib/edges/frontCheck)
 * travels exactly the path a member's key takes. The account is a normal
 * member-shaped user with a tiny traffic cap and no expiry, tagged so an
 * operator recognises it on the panel; only its protocol UUID is kept
 * (`relays.qualificationUserId`) plus the panel user id needed to deactivate it.
 *
 * Deactivation is never assumed: a panel delete that fails is recorded on the
 * relay (`qualificationRemovalPending`) and retried on the next mint, revoke or
 * relay delete, so a capped test account cannot be silently orphaned. Nothing
 * here is logged or audited beyond booleans.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { backendIdValidator, type BackendId } from './lib/backendIds';
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

/** Test seam: replace the panel-user removal (to simulate a transient panel failure). */
type Remover = (backend: BackendId, backendUserId: string) => Promise<boolean>;
let removerOverride: Remover | null = null;
export function __setQualificationRemoverForTests(f: Remover | null): void {
  removerOverride = f;
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
      pendingRemovals: relay.qualificationRemovalPending ?? [],
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

/** Replace the relay's list of panel users whose deactivation is still owed. */
export const setPendingRemovals = internalMutation({
  args: { relayId: v.id('relays'), pending: v.array(v.string()) },
  handler: async (ctx, { relayId, pending }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const unique = [...new Set(pending)].slice(0, 50);
    await ctx.db.patch(relayId, {
      qualificationRemovalPending: unique.length > 0 ? unique : undefined,
      updatedAt: Date.now(),
    });
    return null;
  },
});

async function removeOnce(
  ctx: { runAction: (fn: never, args: never) => Promise<unknown> },
  backend: BackendId,
  backendUserId: string,
): Promise<boolean> {
  if (removerOverride) return removerOverride(backend, backendUserId);
  try {
    await (ctx.runAction as (fn: unknown, args: unknown) => Promise<unknown>)(
      internal.backends.deleteUser,
      { backend, backendUserId },
    );
    return true;
  } catch {
    console.warn('[relayQualification] could not remove a qualification account');
    return false;
  }
}

/** Deactivate a panel user; `ok:false` means the caller must keep the id for a retry. */
export const removeBackendUser = internalAction({
  args: { backend: backendIdValidator, backendUserId: v.string() },
  handler: async (ctx, { backend, backendUserId }): Promise<{ ok: boolean }> => ({
    ok: await removeOnce(ctx as never, backend, backendUserId),
  }),
});

/**
 * Retry every owed deactivation plus the ids just handed in; whatever still
 * fails is persisted for the next attempt. Returns the ids still pending.
 */
async function settleRemovals(
  ctx: { runAction: never; runMutation: never },
  relayId: Id<'relays'>,
  backend: BackendId,
  owed: string[],
): Promise<string[]> {
  const still: string[] = [];
  for (const id of [...new Set(owed)]) {
    if (!(await removeOnce(ctx as never, backend, id))) still.push(id);
  }
  await (ctx.runMutation as unknown as (fn: unknown, args: unknown) => Promise<unknown>)(
    internal.relayQualification.setPendingRemovals,
    { relayId, pending: still },
  );
  return still;
}

/**
 * Mint (or re-mint) the credential. The previous account, if any, is removed
 * only after the new one is stored, so a failed mint keeps the old credential;
 * a removal that fails is owed, never forgotten.
 */
export const mint = internalAction({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (
    ctx,
    { relayId, actorAdminId },
  ): Promise<{ ok: boolean; code?: string; pendingRemovals?: number }> => {
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
      const still = await settleRemovals(ctx as never, relayId, c.backend, [
        ...c.pendingRemovals,
        issued.backendUserId,
      ]);
      return {
        ok: false,
        code: 'qualification_credential_unsupported',
        pendingRemovals: still.length,
      };
    }
    await ctx.runMutation(internal.relayQualification.store, {
      relayId,
      protocolUuid: issued.protocolUuid,
      backendUserId: issued.backendUserId,
      replaced: c.previousBackendUserId !== null,
      actorAdminId,
    });
    const owed = [
      ...c.pendingRemovals,
      ...(c.previousBackendUserId ? [c.previousBackendUserId] : []),
    ];
    const still = await settleRemovals(ctx as never, relayId, c.backend, owed);
    return { ok: true, pendingRemovals: still.length };
  },
});

/**
 * Revoke: the panel account is deactivated FIRST; only a successful removal
 * clears the stored credential. A failed removal keeps the credential (the
 * operator sees it is still minted) and reports `backend_delete_failed`.
 */
export const revoke = internalAction({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (
    ctx,
    { relayId, actorAdminId },
  ): Promise<{ ok: boolean; code?: string; pendingRemovals?: number }> => {
    const c = await ctx.runQuery(internal.relayQualification.mintContext, { relayId });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    // Owed removals from earlier attempts are retried whatever happens below.
    const stillOwed = await settleRemovals(ctx as never, relayId, c.backend, c.pendingRemovals);
    if (c.previousBackendUserId) {
      const removed = await removeOnce(ctx as never, c.backend, c.previousBackendUserId);
      if (!removed)
        return { ok: false, code: 'backend_delete_failed', pendingRemovals: stillOwed.length };
    }
    await ctx.runMutation(internal.relayQualification.clear, { relayId, actorAdminId });
    return { ok: true, pendingRemovals: stillOwed.length };
  },
});
