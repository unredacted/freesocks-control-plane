/**
 * The L7 front-qualification CREDENTIAL: a panel account FCP mints on the
 * relay's placement so the authenticated test session (lib/edges/frontCheck)
 * travels exactly the path a member's key takes. The account is a normal
 * member-shaped user with a tiny traffic cap and no expiry, tagged so an
 * operator recognises it on the panel; only its protocol UUID is kept
 * (`relays.qualificationUserId`) plus the panel user id needed to deactivate it
 * and its own subscription locator (the test link + the empty-node rehearsal
 * fetch that body).
 *
 * Minting is a PERSISTED OPERATION (`relays.qualificationMint`, docs/edges.md
 * § "Publication"): the deterministic username is written BEFORE any panel
 * call, so a crash between `issueUser` and `store` is settled on the next
 * `ensure` by re-finding the user by name (the version-neutral by-username
 * read) and adopting it instead of minting a second one. A stored credential
 * is reused only when its binding {backendServerId, placement, modeSlug}
 * equals the request; a different binding (after the operator chose another
 * mode) replaces it, and the old panel user goes through the same owed-removal
 * ledger every removal uses.
 *
 * Deactivation is never assumed: a panel delete that fails is recorded on the
 * relay (`qualificationRemovalPending`) and retried on the next mint, revoke or
 * relay delete, so a capped test account cannot be silently orphaned. Nothing
 * here is logged or audited beyond booleans.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { backendIdValidator, type BackendId } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import type { IssuedUser } from './lib/backends/types';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { resolvePlacementTarget } from './lib/remnawavePlacement';

/** Enough for many qualification sessions (each moves a few kilobytes), never for real use. */
export const QUALIFICATION_TRAFFIC_LIMIT_BYTES = 50 * 1024 * 1024;
export const QUALIFICATION_TAG = 'fcp-qualify';

/**
 * The settle rule for a pending mint whose user cannot be found: the panel
 * must have had this long AND this many quiet by-username looks since the
 * claim before a new user is issued under a new name (a create that lost its
 * response may still land).
 */
export const MINT_SETTLE_MS = 2 * 60_000;
export const MINT_SETTLE_LOOKS = 2;

export function qualificationUsername(relaySlug: string, nonceHex8: string): string {
  const slug = relaySlug
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .slice(0, 20);
  return `fcp-qualify-${slug}-${nonceHex8}`;
}

export type MintOp = NonNullable<Doc<'relays'>['qualificationMint']>;
export type MintBinding = Pick<MintOp, 'backendServerId' | 'placement' | 'modeSlug'>;

export function sameMintBinding(a: MintBinding, b: MintBinding): boolean {
  return (
    (a.backendServerId as string) === (b.backendServerId as string) &&
    (a.placement ?? null) === (b.placement ?? null) &&
    (a.modeSlug ?? null) === (b.modeSlug ?? null)
  );
}

/** Test seam: replace the panel-user removal (to simulate a transient panel failure). */
type Remover = (
  backend: BackendId,
  backendUserId: string,
  backendServerId?: Id<'backendServers'>,
) => Promise<boolean>;
let removerOverride: Remover | null = null;
export function __setQualificationRemoverForTests(f: Remover | null): void {
  removerOverride = f;
}

/** Test seam: crash `ensure` at a point of the mint operation (a lost response, a killed action). */
export type EnsureFailpoint = 'after_claim' | 'after_issue' | 'after_issued';
let failpoint: ((point: EnsureFailpoint, issued: IssuedUser | null) => void) | null = null;
export function __setEnsureFailpointForTests(f: typeof failpoint): void {
  failpoint = f;
}

const purposeValidator = v.union(v.literal('qualification'), v.literal('rehearsal'));

/**
 * What ensuring needs, read in one transaction: the relay, its panel, the
 * binding the request resolves to (an explicit placement, else the mode's
 * placement on this panel), the pending or stored operation, and the owed
 * removals. Null for a manual origin (nothing to mint on).
 */
export const ensureContext = internalQuery({
  args: {
    relayId: v.id('relays'),
    placement: v.optional(v.string()),
    modeSlug: v.optional(v.string()),
  },
  handler: async (ctx, { relayId, placement, modeSlug }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    if (!relay.backendServerId) return null; // a manual origin has no panel to mint on
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    const caps = capabilitiesOf(server.backend);
    // The mode decides the placement (absent = the resolver's default pool for
    // this panel); an explicit placement wins. A backend without a placement
    // concept binds to null.
    const slug: string | null = modeSlug ?? relay.qualificationModeSlug ?? null;
    let resolved: string | null = null;
    if (placement !== undefined) resolved = placement;
    else if (caps.placement) {
      resolved = (
        await resolvePlacementTarget(ctx.db, slug, { onlyServerId: server._id as string })
      ).placement;
    }
    return {
      slug: relay.slug,
      backend: server.backend,
      backendServerId: server._id,
      placement: resolved,
      modeSlug: slug,
      placementRequired: caps.placement,
      lookupSupported: caps.userLookupByUsername,
      op: relay.qualificationMint ?? null,
      stored: !!relay.qualificationUserId,
      previousBackendUserId: relay.qualificationBackendUserId ?? null,
      pendingRemovals: relay.qualificationRemovalPending ?? [],
    };
  },
});

/** Legacy read (the admin routes still call it): the binding of a plain mint. */
export const mintContext = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    if (!relay.backendServerId) return null;
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    const modeId: string | null = relay.qualificationModeSlug ?? null;
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

const mintOpValidator = v.object({
  opId: v.string(),
  username: v.string(),
  backendServerId: v.id('backendServers'),
  placement: v.union(v.string(), v.null()),
  modeSlug: v.union(v.string(), v.null()),
  claimedAt: v.number(),
});

/** Step 1 of the operation: the intent (username included) lands before any panel call. */
export const claimMint = internalMutation({
  args: { relayId: v.id('relays'), op: mintOpValidator },
  handler: async (ctx, { relayId, op }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await ctx.db.patch(relayId, {
      qualificationMint: { ...op, state: 'intended', looks: 0 },
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Move the CURRENT operation (matched by opId) to a state; a stale opId changes nothing. */
export const setMintState = internalMutation({
  args: {
    relayId: v.id('relays'),
    opId: v.string(),
    state: v.union(v.literal('issued'), v.literal('unresolved')),
    looks: v.optional(v.number()),
  },
  handler: async (ctx, { relayId, opId, state, looks }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.qualificationMint || relay.qualificationMint.opId !== opId) return null;
    await ctx.db.patch(relayId, {
      qualificationMint: {
        ...relay.qualificationMint,
        state,
        ...(looks !== undefined ? { looks } : {}),
      },
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Drop a pending operation (a definitive create failure, or a settled-absent user). */
export const clearMint = internalMutation({
  args: { relayId: v.id('relays'), opId: v.string() },
  handler: async (ctx, { relayId, opId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.qualificationMint || relay.qualificationMint.opId !== opId) return null;
    await ctx.db.patch(relayId, { qualificationMint: undefined, updatedAt: Date.now() });
    return null;
  },
});

export const store = internalMutation({
  args: {
    relayId: v.id('relays'),
    protocolUuid: v.string(),
    backendUserId: v.string(),
    backendShortId: v.optional(v.string()),
    subscriptionUrl: v.optional(v.string()),
    replaced: v.boolean(),
    /** The user was re-found by username after a lost response, not created by this call. */
    adopted: v.optional(v.boolean()),
    op: v.optional(mintOpValidator),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await ctx.db.patch(a.relayId, {
      qualificationUserId: a.protocolUuid,
      qualificationBackendUserId: a.backendUserId,
      qualificationSubscription:
        a.backendShortId && a.subscriptionUrl
          ? { backendShortId: a.backendShortId, subscriptionUrl: a.subscriptionUrl }
          : undefined,
      ...(a.op ? { qualificationMint: { ...a.op, state: 'stored' } } : {}),
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'relay.qualification_credential',
      targetType: 'relay',
      targetId: a.relayId,
      payload: { slug: relay.slug, minted: true, replaced: a.replaced, adopted: !!a.adopted },
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
      qualificationSubscription: undefined,
      qualificationMint: undefined,
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

type RunActionCtx = { runAction: (fn: never, args: never) => Promise<unknown> };
type RunCtx = RunActionCtx & { runMutation: (fn: never, args: never) => Promise<unknown> };

/**
 * One panel delete. The instance is passed as a HINT: a qualification user has
 * no subscription row, so without it the dispatch could not resolve the panel
 * and would report an absent key as already gone.
 */
async function removeOnce(
  ctx: RunActionCtx,
  backend: BackendId,
  backendUserId: string,
  backendServerId?: Id<'backendServers'>,
): Promise<boolean> {
  if (removerOverride) return removerOverride(backend, backendUserId, backendServerId);
  try {
    await (ctx.runAction as (fn: unknown, args: unknown) => Promise<unknown>)(
      internal.backends.deleteUser,
      { backend, backendUserId, ...(backendServerId ? { backendServerId } : {}) },
    );
    return true;
  } catch {
    console.warn('[relayQualification] could not remove a qualification account');
    return false;
  }
}

/** Deactivate a panel user; `ok:false` means the caller must keep the id for a retry. */
export const removeBackendUser = internalAction({
  args: {
    backend: backendIdValidator,
    backendUserId: v.string(),
    backendServerId: v.optional(v.id('backendServers')),
  },
  handler: async (ctx, { backend, backendUserId, backendServerId }): Promise<{ ok: boolean }> => ({
    ok: await removeOnce(ctx as never, backend, backendUserId, backendServerId),
  }),
});

/**
 * Deactivate a panel user known only by the USERNAME of an unsettled mint
 * operation (the relay row is gone; nothing else can owe it). Best effort:
 * a user that is not there is success.
 */
export const removeByUsername = internalAction({
  args: { backendServerId: v.id('backendServers'), username: v.string() },
  handler: async (ctx, { backendServerId, username }): Promise<{ ok: boolean }> => {
    try {
      const found = await ctx.runAction(internal.backends.findUserByUsername, {
        backendServerId,
        username,
      });
      if (!found) return { ok: true };
      await ctx.runAction(internal.backends.deleteUser, {
        backend: (await ctx.runQuery(internal.backendServers.getById, { id: backendServerId }))!
          .backend,
        backendUserId: found.backendUserId,
        backendServerId,
      });
      return { ok: true };
    } catch {
      console.warn('[relayQualification] could not remove an unsettled qualification account');
      return { ok: false };
    }
  },
});

/**
 * Retry every owed deactivation plus the ids just handed in; whatever still
 * fails is persisted for the next attempt. Returns the ids still pending.
 */
async function settleRemovals(
  ctx: RunCtx,
  relayId: Id<'relays'>,
  backend: BackendId,
  owed: string[],
  backendServerId?: Id<'backendServers'>,
): Promise<string[]> {
  const still: string[] = [];
  for (const id of [...new Set(owed)]) {
    if (!(await removeOnce(ctx, backend, id, backendServerId))) still.push(id);
  }
  await (ctx.runMutation as unknown as (fn: unknown, args: unknown) => Promise<unknown>)(
    internal.relayQualification.setPendingRemovals,
    { relayId, pending: still },
  );
  return still;
}

/** Whether a create failure PROVES nothing was created (a definitive 4xx or a typed refusal). */
function definitiveCreateFailure(err: unknown): boolean {
  if (err instanceof ConvexError) return true;
  const status = (err as { meta?: { status?: unknown } })?.meta?.status;
  return typeof status === 'number' && status < 500;
}

export interface EnsureResult {
  ok: boolean;
  code?: string;
  reused: boolean;
  /** The user was re-found by username after a lost response (no second user was created). */
  adopted?: boolean;
  pendingRemovals?: number;
}

/**
 * Ensure the relay holds a qualification credential covering the requested
 * binding (plan: the persisted mint operation). Idempotent under retry:
 *
 *  1. a stored credential with the same binding is reused (no panel call);
 *     `force` re-mints regardless (the operator's explicit re-mint);
 *  2. a pending operation (`intended` / `issued` / `unresolved`) is settled by
 *     the by-username read: found -> adopted into the store; not found -> the
 *     settle rule (`MINT_SETTLE_MS` + `MINT_SETTLE_LOOKS` quiet looks) before a
 *     new user is issued under a new name (`credential_unresolved` meanwhile);
 *  3. only then a fresh operation: claim (username persisted) -> `issueUser`
 *     -> `issued` -> `store` -> `stored`. A definitive create failure drops the
 *     claim (nothing was created); an ambiguous one leaves it `unresolved`.
 *
 * The previous credential (a replaced binding, an adopted stray) always goes
 * through the owed-removal ledger, never left behind. Refusals (no throw):
 * `choose_mode` (a placement backend with no usable placement),
 * `use_manual_setup` (a rehearsal on a backend with no name lookup: Outline),
 * `qualification_credential_unsupported` (the backend mints no protocol
 * credential), `credential_unresolved` (the settle rule is still running).
 */
export const ensure = internalAction({
  args: {
    relayId: v.id('relays'),
    placement: v.optional(v.string()),
    modeSlug: v.optional(v.string()),
    purpose: purposeValidator,
    force: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<EnsureResult> => {
    const read = () =>
      ctx.runQuery(internal.relayQualification.ensureContext, {
        relayId: a.relayId,
        ...(a.placement !== undefined ? { placement: a.placement } : {}),
        ...(a.modeSlug !== undefined ? { modeSlug: a.modeSlug } : {}),
      });
    let c = await read();
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    // The empty-node rehearsal body must come from a REAL placement (the node's
    // squad), or it proves nothing about the node; the operator's explicit
    // qualification mint keeps minting on the panel default as before.
    if (a.purpose === 'rehearsal' && c.placementRequired && c.placement === null)
      return { ok: false, code: 'choose_mode', reused: false };
    if (!c.lookupSupported) {
      // Outline: no placement, no user lookup by name, no rehearsal credential
      // path (an empty Outline server is outside Autopilot), and no protocol
      // credential either. Nothing is minted that could be orphaned.
      return {
        ok: false,
        code:
          a.purpose === 'rehearsal' ? 'use_manual_setup' : 'qualification_credential_unsupported',
        reused: false,
      };
    }
    const wanted: MintBinding = {
      backendServerId: c.backendServerId,
      placement: c.placement,
      modeSlug: c.modeSlug,
    };
    const now = Date.now();

    // 1. Reuse.
    if (!a.force && c.op?.state === 'stored' && c.stored && sameMintBinding(c.op, wanted)) {
      return { ok: true, reused: true, pendingRemovals: c.pendingRemovals.length };
    }

    // 2. Settle a pending operation before anything else is created.
    if (c.op && c.op.state !== 'stored') {
      const op = c.op;
      const found = await ctx.runAction(internal.backends.findUserByUsername, {
        backendServerId: op.backendServerId,
        username: op.username,
      });
      if (found) {
        if (!found.protocolUuid) {
          const still = await settleRemovals(
            ctx as never,
            a.relayId,
            c.backend,
            [...c.pendingRemovals, found.backendUserId],
            c.backendServerId,
          );
          await ctx.runMutation(internal.relayQualification.clearMint, {
            relayId: a.relayId,
            opId: op.opId,
          });
          return {
            ok: false,
            code: 'qualification_credential_unsupported',
            reused: false,
            pendingRemovals: still.length,
          };
        }
        await ctx.runMutation(internal.relayQualification.store, {
          relayId: a.relayId,
          protocolUuid: found.protocolUuid,
          backendUserId: found.backendUserId,
          backendShortId: found.backendShortId,
          subscriptionUrl: found.subscriptionUrl,
          replaced: c.previousBackendUserId !== null,
          adopted: true,
          op: {
            opId: op.opId,
            username: op.username,
            backendServerId: op.backendServerId,
            placement: op.placement,
            modeSlug: op.modeSlug,
            claimedAt: op.claimedAt,
          },
          actorAdminId: a.actorAdminId,
        });
        const still = await settleRemovals(
          ctx as never,
          a.relayId,
          c.backend,
          [...c.pendingRemovals, ...(c.previousBackendUserId ? [c.previousBackendUserId] : [])],
          c.backendServerId,
        );
        if (!a.force && sameMintBinding(op, wanted))
          return { ok: true, reused: false, adopted: true, pendingRemovals: still.length };
        // Adopted for a binding that is no longer wanted: replace it below.
        c = (await read())!;
      } else {
        const looks = (op.looks ?? 0) + 1;
        if (looks < MINT_SETTLE_LOOKS || now - op.claimedAt < MINT_SETTLE_MS) {
          await ctx.runMutation(internal.relayQualification.setMintState, {
            relayId: a.relayId,
            opId: op.opId,
            state: 'unresolved',
            looks,
          });
          return { ok: false, code: 'credential_unresolved', reused: false };
        }
        // Settled absent: the create never landed. A fresh operation may run.
        await ctx.runMutation(internal.relayQualification.clearMint, {
          relayId: a.relayId,
          opId: op.opId,
        });
      }
    }

    // 3. A fresh operation under a new deterministic username.
    const op = {
      opId: randomHex(8),
      username: qualificationUsername(c.slug, randomHex(4)),
      backendServerId: c.backendServerId,
      placement: c.placement,
      modeSlug: c.modeSlug,
      claimedAt: Date.now(),
    };
    await ctx.runMutation(internal.relayQualification.claimMint, { relayId: a.relayId, op });
    failpoint?.('after_claim', null);
    let issued: IssuedUser;
    try {
      issued = await ctx.runAction(internal.backends.issueUser, {
        backend: c.backend,
        pinServerId: c.backendServerId as Id<'backendServers'>,
        spec: {
          username: op.username,
          trafficLimitBytes: QUALIFICATION_TRAFFIC_LIMIT_BYTES,
          expireAt: null,
          tag: QUALIFICATION_TAG,
          description:
            a.purpose === 'rehearsal'
              ? 'FCP delivery rehearsal (automated, capped)'
              : 'FCP front qualification (automated, capped)',
          placement: c.placement,
        },
      });
    } catch (err) {
      if (definitiveCreateFailure(err)) {
        await ctx.runMutation(internal.relayQualification.clearMint, {
          relayId: a.relayId,
          opId: op.opId,
        });
      } else {
        await ctx.runMutation(internal.relayQualification.setMintState, {
          relayId: a.relayId,
          opId: op.opId,
          state: 'unresolved',
        });
      }
      throw err;
    }
    failpoint?.('after_issue', issued);
    await ctx.runMutation(internal.relayQualification.setMintState, {
      relayId: a.relayId,
      opId: op.opId,
      state: 'issued',
    });
    failpoint?.('after_issued', issued);
    if (!issued.protocolUuid) {
      // This backend cannot back the check: do not keep an account nobody can use.
      const still = await settleRemovals(
        ctx as never,
        a.relayId,
        c.backend,
        [...c.pendingRemovals, issued.backendUserId],
        c.backendServerId,
      );
      await ctx.runMutation(internal.relayQualification.clearMint, {
        relayId: a.relayId,
        opId: op.opId,
      });
      return {
        ok: false,
        code: 'qualification_credential_unsupported',
        reused: false,
        pendingRemovals: still.length,
      };
    }
    await ctx.runMutation(internal.relayQualification.store, {
      relayId: a.relayId,
      protocolUuid: issued.protocolUuid,
      backendUserId: issued.backendUserId,
      backendShortId: issued.backendShortId,
      subscriptionUrl: issued.subscriptionUrl,
      replaced: c.previousBackendUserId !== null,
      op,
      actorAdminId: a.actorAdminId,
    });
    const owed = [
      ...c.pendingRemovals,
      ...(c.previousBackendUserId ? [c.previousBackendUserId] : []),
    ];
    const still = await settleRemovals(ctx as never, a.relayId, c.backend, owed, c.backendServerId);
    return { ok: true, reused: false, pendingRemovals: still.length };
  },
});

/**
 * Mint (or re-mint) the credential: the operator's explicit action, always a
 * fresh account (`ensure` with `force`). The previous account, if any, is
 * removed only after the new one is stored, so a failed mint keeps the old
 * credential; a removal that fails is owed, never forgotten.
 */
export const mint = internalAction({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (
    ctx,
    { relayId, actorAdminId },
  ): Promise<{ ok: boolean; code?: string; pendingRemovals?: number }> => {
    const r: EnsureResult = await ctx.runAction(internal.relayQualification.ensure, {
      relayId,
      purpose: 'qualification',
      force: true,
      actorAdminId,
    });
    return {
      ok: r.ok,
      ...(r.code ? { code: r.code } : {}),
      ...(r.pendingRemovals !== undefined ? { pendingRemovals: r.pendingRemovals } : {}),
    };
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
    const stillOwed = await settleRemovals(
      ctx as never,
      relayId,
      c.backend,
      c.pendingRemovals,
      c.backendServerId,
    );
    if (c.previousBackendUserId) {
      const removed = await removeOnce(
        ctx as never,
        c.backend,
        c.previousBackendUserId,
        c.backendServerId,
      );
      if (!removed)
        return { ok: false, code: 'backend_delete_failed', pendingRemovals: stillOwed.length };
    }
    await ctx.runMutation(internal.relayQualification.clear, { relayId, actorAdminId });
    return { ok: true, pendingRemovals: stillOwed.length };
  },
});
