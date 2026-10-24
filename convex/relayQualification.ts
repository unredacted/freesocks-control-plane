/**
 * The L7 front-qualification CREDENTIAL: a backend account FCP mints on the
 * origin's placement so the authenticated test session (lib/edges/frontCheck)
 * travels exactly the path a member's key takes. The account is a normal
 * member-shaped user with a tiny traffic cap and no expiry, tagged so an
 * operator recognises it on the backend; only its protocol UUID is kept
 * (`origins.qualificationUserId`) plus the backend user id needed to deactivate it
 * and its own subscription locator (the test link + the empty-node rehearsal
 * fetch that body).
 *
 * Minting is a PERSISTED OPERATION (`origins.qualificationMint`, docs/edges.md
 * § "Publication"): the deterministic username is written BEFORE any backend
 * call, so a crash between `issueUser` and `store` is settled on the next
 * `ensure` by re-finding the user by name (the version-neutral by-username
 * read) and adopting it instead of minting a second one. A stored credential
 * is reused only when its binding {backendServerId, placement, modeSlug}
 * equals the request; a different binding (after the operator chose another
 * mode) replaces it, and the old backend user goes through the same owed-removal
 * ledger every removal uses.
 *
 * Deactivation is never assumed: a backend delete that fails is recorded on the
 * origin (`qualificationRemovalPending`) and retried on the next mint, revoke or
 * origin delete, so a capped test account cannot be silently orphaned. Nothing
 * here is logged or audited beyond booleans.
 *
 * The account is kept usable before each use (`keepUsable`): a test profile
 * left connected in a client spends the cap, the backend then limits the
 * account, and every test link, rehearsal body and front check through it
 * fails without saying why. A limited, disabled or expired account, or one
 * past half its cap, has its traffic reset (and is re-enabled) first.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { backendIdValidator, type BackendId } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import {
  farFutureExpiryIso,
  type IssuedUser,
  type ObservedModeGroup,
  type UserState,
} from './lib/backends/types';
import { boundedUsername } from './lib/backends/username';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { resolvePlacementTarget } from './lib/remnawavePlacement';
import { protocolL7Proof } from './lib/edges/protocols';

/** Enough for many qualification sessions (each moves a few kilobytes), never for real use. */
export const QUALIFICATION_TRAFFIC_LIMIT_BYTES = 50 * 1024 * 1024;
export const QUALIFICATION_TAG = 'fcp-qualify';
/** Past this share of its cap the account is reset before use: an operator's test needs headroom. */
export const QUALIFICATION_RESET_AT_SHARE = 0.5;

/**
 * The settle rule for a pending mint whose user cannot be found: the backend
 * must have had this long AND this many quiet by-username looks since the
 * claim before a new user is issued under a new name (a create that lost its
 * response may still land).
 */
export const MINT_SETTLE_MS = 2 * 60_000;
export const MINT_SETTLE_LOOKS = 2;

/** Within the backend's username cap: the origin name is cut first, never the nonce. */
export function qualificationUsername(relaySlug: string, nonceHex8: string): string {
  return boundedUsername('fcp-qualify-', relaySlug, nonceHex8);
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

/** Test seam: replace the backend-user removal (to simulate a transient backend failure). */
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

/** The mode an enrolled node serves (its credential belongs in that mode's group); null otherwise. */
async function enrolledModeOf(db: QueryCtx['db'], relay: Doc<'relays'>): Promise<string | null> {
  if (relay.origin.kind !== 'panel-node' || !relay.backendServerId) return null;
  const nodeName = relay.origin.nodeName;
  const intent = await db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) =>
      q.eq('backendServerId', relay.backendServerId!).eq('name', nodeName),
    )
    .unique();
  return intent?.mode ?? null;
}

/**
 * What ensuring needs, read in one transaction: the origin, its backend, the
 * binding the request resolves to (an explicit placement, else the mode's
 * placement on this backend), the pending or stored operation, and the owed
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
    if (!relay.backendServerId) return null; // a manual origin has no backend to mint on
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    const caps = capabilitiesOf(server.backend);
    // The mode decides the placement (absent = the resolver's default pool for
    // this backend); an explicit placement wins. A backend without a placement
    // concept binds to null. An ENROLLED node's credential lives in the node's
    // own mode: a member-shaped credential of another mode's group never sees
    // this node's transport (its body carries no entry to prove or rehearse).
    const slug: string | null =
      modeSlug ?? relay.qualificationModeSlug ?? (await enrolledModeOf(ctx.db, relay)) ?? null;
    let resolved: string | null = null;
    if (placement !== undefined) resolved = placement;
    else if (caps.placement) {
      // FCP's own check credential: an inactive instance (out of the issuance
      // pool, its members still served) is tested where its nodes are.
      resolved = (
        await resolvePlacementTarget(ctx.db, slug, {
          onlyServerId: server._id as string,
          includeInactive: true,
        })
      ).placement;
    }
    // A Trojan transport's L7 proof authenticates with the account's Trojan
    // password, which a credential minted before Trojan proofs never stored.
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect();
    const trojanProofNeeded = listeners.some((l) => !l.retired && protocolL7Proof(l) === 'trojan');
    return {
      slug: relay.slug,
      backend: server.backend,
      backendServerId: server._id,
      placement: resolved,
      modeSlug: slug,
      // A placement or mode someone chose (the request, the operator's
      // qualification mode): it stands as it is.
      chosen: placement !== undefined || !!modeSlug || !!relay.qualificationModeSlug,
      // The transports the origin protects (its live listeners'): the account
      // must sit in a mode group holding them all, or the node refuses it there.
      protectedInbounds: listeners
        .filter((l) => !l.retired && l.deployed && l.enabled && l.panelBinding)
        .map((l) => l.panelBinding!.configProfileInboundUuid.toLowerCase()),
      placementRequired: caps.placement,
      lookupSupported: caps.userLookupByUsername,
      op: relay.qualificationMint ?? null,
      stored: !!relay.qualificationUserId,
      trojanMissing: trojanProofNeeded && !relay.qualificationTrojanPassword,
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
    const modeId: string | null =
      relay.qualificationModeSlug ?? (await enrolledModeOf(ctx.db, relay)) ?? null;
    const { placement } = await resolvePlacementTarget(ctx.db, modeId, {
      onlyServerId: server._id as string,
      includeInactive: true,
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

/** Step 1 of the operation: the intent (username included) lands before any backend call. */
export const claimMint = internalMutation({
  args: { relayId: v.id('relays'), op: mintOpValidator },
  handler: async (ctx, { relayId, op }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
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
    trojanPassword: v.optional(v.string()),
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
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    await ctx.db.patch(a.relayId, {
      qualificationUserId: a.protocolUuid,
      qualificationTrojanPassword: a.trojanPassword,
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

/**
 * Keep the Trojan password of the STORED credential (re-read from the backend
 * by its username): only for the current operation, and only when none is
 * stored, so a concurrent re-mint is never overwritten with an old secret.
 */
export const backfillTrojanPassword = internalMutation({
  args: { relayId: v.id('relays'), opId: v.string(), trojanPassword: v.string() },
  handler: async (ctx, { relayId, opId, trojanPassword }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.qualificationMint || relay.qualificationMint.opId !== opId) return null;
    if (relay.qualificationMint.state !== 'stored' || relay.qualificationTrojanPassword)
      return null;
    await ctx.db.patch(relayId, {
      qualificationTrojanPassword: trojanPassword,
      updatedAt: Date.now(),
    });
    return null;
  },
});

export const clear = internalMutation({
  args: { relayId: v.id('relays'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) return { ok: true as const };
    await ctx.db.patch(a.relayId, {
      qualificationUserId: undefined,
      qualificationTrojanPassword: undefined,
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

/** Replace the origin's list of backend users whose deactivation is still owed. */
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
 * One backend delete. The instance is passed as a HINT: a qualification user has
 * no subscription row, so without it the dispatch could not resolve the backend
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

/** Deactivate a backend user; `ok:false` means the caller must keep the id for a retry. */
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
 * Deactivate a backend user known only by the USERNAME of an unsettled mint
 * operation (the origin row is gone; nothing else can owe it). Best effort:
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

/**
 * The mode groups of the backend that hold every one of `inbounds`, by uuid
 * (sorted, so the same panel gives the same answer); empty when none does,
 * null when the panel could not be read (unknown, never "none").
 */
async function groupsHolding(
  ctx: { runAction: ActionCtx['runAction'] },
  backendServerId: Id<'backendServers'>,
  inbounds: readonly string[],
): Promise<string[] | null> {
  const groups: ObservedModeGroup[] | null = await ctx
    .runAction(internal.backends.listModeGroups, { backendServerId })
    .catch(() => null);
  if (!groups) return null;
  return groups
    .filter((g) => {
      const held = new Set(g.inboundUuids.map((u) => u.toLowerCase()));
      return inbounds.every((u) => held.has(u));
    })
    .map((g) => g.squadUuid)
    .sort();
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
 * Ensure the origin holds a qualification credential covering the requested
 * binding (plan: the persisted mint operation). Idempotent under retry:
 *
 *  1. a stored credential with the same binding is reused (no backend call);
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
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    // A test entry built from a transport carries this account, and the node
    // accepts it there only from a mode group holding that transport. Unless a
    // placement or mode was chosen, a group the panel says holds every
    // transport the origin protects wins over the default (or the enrolled
    // mode's group, when it lacks one); the group a stored account already sits
    // in is kept while it still holds them. A panel that cannot be read keeps
    // the stored account's group (unknown is not "none": no re-mint over an
    // outage), and changes nothing when there is none.
    if (!c.chosen && c.placementRequired && c.protectedInbounds.length > 0) {
      const holding = await groupsHolding(ctx, c.backendServerId, c.protectedInbounds);
      const stored = c.op?.state === 'stored' && c.stored ? c.op.placement : null;
      const placement =
        holding === null
          ? stored
          : holding.includes(c.placement ?? '')
            ? null
            : stored && holding.includes(stored)
              ? stored
              : (holding[0] ?? null);
      if (placement && placement !== c.placement) {
        c = await ctx.runQuery(internal.relayQualification.ensureContext, {
          relayId: a.relayId,
          placement,
          ...(c.modeSlug ? { modeSlug: c.modeSlug } : {}),
        });
        if (!c) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
      }
    }
    // The empty-node rehearsal body must come from a REAL placement (the node's
    // mode group), or it proves nothing about the node; the operator's explicit
    // qualification mint keeps minting on the backend default as before.
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

    // 1. Reuse. A credential minted before Trojan proofs carries no Trojan
    // password: re-read the same account once (by its username) and keep it,
    // rather than replacing an account that is otherwise fine.
    if (!a.force && c.op?.state === 'stored' && c.stored && sameMintBinding(c.op, wanted)) {
      if (c.trojanMissing) {
        const found = await ctx
          .runAction(internal.backends.findUserByUsername, {
            backendServerId: c.op.backendServerId,
            username: c.op.username,
          })
          .catch(() => null);
        if (found?.trojanPassword && found.backendUserId === c.previousBackendUserId)
          await ctx.runMutation(internal.relayQualification.backfillTrojanPassword, {
            relayId: a.relayId,
            opId: c.op.opId,
            trojanPassword: found.trojanPassword,
          });
      }
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
          trojanPassword: found.trojanPassword,
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
        ownCheck: true,
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
      trojanPassword: issued.trojanPassword,
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
 * Revoke: the backend account is deactivated FIRST; only a successful removal
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
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
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

// --- keeping the account usable ---------------------------------------------------------------

type AccountState = Pick<UserState, 'status' | 'usedTrafficBytes' | 'trafficLimitBytes'>;

/** Reset before use: limited, disabled or expired, or past `QUALIFICATION_RESET_AT_SHARE` of its cap. */
export function qualificationNeedsReset(state: AccountState): boolean {
  if (state.status === 'limited' || state.status === 'disabled' || state.status === 'expired')
    return true;
  return (
    state.trafficLimitBytes !== null &&
    state.usedTrafficBytes >= state.trafficLimitBytes * QUALIFICATION_RESET_AT_SHARE
  );
}

/** Whether the account carries a session as it is (a failed reset of a nearly-spent one still does). */
function carriesSession(state: AccountState): boolean {
  return (
    state.status === 'active' &&
    (state.trafficLimitBytes === null || state.usedTrafficBytes < state.trafficLimitBytes)
  );
}

/** The stored account and the instance it lives on; null when none is stored. */
export const usableContext = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.qualificationBackendUserId || !relay.backendServerId) return null;
    const server = await ctx.db.get(relay.backendServerId);
    if (!server) return null;
    return {
      backend: server.backend,
      backendServerId: server._id,
      backendUserId: relay.qualificationBackendUserId,
    };
  },
});

export const recordReset = internalMutation({
  args: {
    relayId: v.id('relays'),
    reset: v.boolean(),
    reenabled: v.boolean(),
    nearCap: v.boolean(),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.qualification_reset',
      targetType: 'relay',
      targetId: a.relayId,
      payload: {
        slug: relay?.slug ?? '',
        reset: a.reset,
        failed: !a.reset,
        reenabled: a.reenabled,
        nearCap: a.nearCap,
      },
    });
    return null;
  },
});

export interface UsableResult {
  ok: boolean;
  /** `test_account_used_up`: the account carries no session and could not be reset. */
  code?: 'test_account_used_up';
  /** The account's state was read (false: none is stored, or the read failed). */
  checked: boolean;
  reset: boolean;
}

/**
 * Before the account is used (a test link, a rehearsal body, a front check):
 * read it on its own instance, and reset its traffic (and re-enable it) when
 * `qualificationNeedsReset`. Every reset is audited, booleans only. A read
 * that fails changes nothing (the use goes ahead and fails on its own if the
 * backend is down); a reset that fails refuses only when the account carries
 * no session as it is.
 */
export const keepUsable = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<UsableResult> => {
    const c = await ctx.runQuery(internal.relayQualification.usableContext, { relayId });
    if (!c) return { ok: true, checked: false, reset: false };
    let state: UserState;
    try {
      state = await ctx.runAction(internal.backends.getUser, c);
    } catch {
      console.warn('[relayQualification] could not read the qualification account');
      return { ok: true, checked: false, reset: false };
    }
    if (!qualificationNeedsReset(state)) return { ok: true, checked: true, reset: false };
    const reenable = state.status !== 'active';
    let reset = true;
    try {
      // An expired account gets the no-expiry date back first, or enabling it does not hold.
      if (state.status === 'expired')
        await ctx.runAction(internal.backends.updateUser, {
          ...c,
          patch: { expireAt: farFutureExpiryIso() },
        });
      await ctx.runAction(internal.backends.resetUserTraffic, c);
      if (reenable) await ctx.runAction(internal.backends.setUserStatus, { ...c, active: true });
    } catch {
      reset = false;
      console.warn('[relayQualification] could not reset the qualification account');
    }
    await ctx.runMutation(internal.relayQualification.recordReset, {
      relayId,
      reset,
      reenabled: reset && reenable,
      nearCap: !reenable,
    });
    if (reset || carriesSession(state)) return { ok: true, checked: true, reset };
    return { ok: false, code: 'test_account_used_up', checked: true, reset: false };
  },
});
