/**
 * The issuance saga (P5c): the read→act→write decomposition of the old
 * SubscriptionDeliveryService.issueNew. A plain helper (not a registered
 * function) invoked from within an action (account.regenerate / switchBackend),
 * so it shares the caller's ActionCtx instead of paying an action-to-action hop.
 *
 * Flow: backend create (HTTP) → persist the row → point the user at it. On any
 * post-create failure it deletes the backend user (compensation) and rethrows;
 * the caller owns slot/tier bookkeeping.
 *
 * S3 mirrors are NOT created here. They're opt-in + lazy: a member provisions
 * one only if they can't reach the normal subscription URL (storage.provisionMirror),
 * so a fresh sub's content is never proactively copied to third-party storage.
 */
import type { ActionCtx } from '../_generated/server';
import type { Id } from '../_generated/dataModel';
import { internal } from '../_generated/api';
import type { BackendId, IssueUserSpec } from './backends/types';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface IssueResult {
  subscriptionId: Id<'subscriptions'>;
  backend: BackendId;
  backendUserId: string;
  backendShortId: string;
  subscriptionUrl: string;
  mirrors: { provider: string; publicUrl: string; objectPath?: string; status?: 'ok' | 'failed' }[];
}

export async function issueNewSubscription(
  ctx: ActionCtx,
  input: {
    userId: Id<'users'>;
    backend: 'remnawave' | 'outline';
    spec: IssueUserSpec;
    // Pin to one instance — set when node placement resolved the (placement,
    // panel) pair together (the squad only exists on that panel).
    pinServerId?: Id<'backendServers'> | null;
  },
): Promise<IssueResult> {
  const issued = await ctx.runAction(internal.backends.issueUser, {
    backend: input.backend,
    spec: input.spec,
    pinServerId: input.pinServerId ?? undefined,
  });
  let subscriptionId: Id<'subscriptions'> | null = null;
  try {
    subscriptionId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
      userId: input.userId,
      backend: input.backend,
      backendUserId: issued.backendUserId,
      backendShortId: issued.backendShortId,
      backendServerId: issued.backendServerId,
      subscriptionUrl: issued.subscriptionUrl,
      subscriptionMirrors: [],
      rawContentHash: undefined,
      // Persist the opaque placement the key was issued into, so tier pushes
      // re-send the SAME placement instead of re-picking (Remnawave only).
      placement: input.backend === 'remnawave' ? (input.spec.placement ?? undefined) : undefined,
    });
    await ctx.runMutation(internal.subscriptions.setCurrentSubscription, {
      userId: input.userId,
      subscriptionId,
    });

    return {
      subscriptionId,
      backend: input.backend,
      backendUserId: issued.backendUserId,
      backendShortId: issued.backendShortId,
      subscriptionUrl: issued.subscriptionUrl,
      mirrors: [],
    };
  } catch (err) {
    // The backend user exists but we couldn't finish. Compensate in full:
    //   1. delete the backend user (bounded retry — one transient blip must not
    //      leak a proxy account with no local row),
    //   2. delete the LOCAL row too (an `active` row pointing at a deleted
    //      backend user would otherwise be served as the member's key forever —
    //      no sweep reclaims stray active rows),
    //   3. return the instance keyCount the issue bumped (+1), so pool scoring /
    //      the maxKeys cap don't drift upward on every failed issuance.
    // A delete that still fails is audited loudly (operator cleanup queue).
    let backendDeleted = false;
    for (let attempt = 0; attempt < 3 && !backendDeleted; attempt++) {
      try {
        if (attempt > 0) await sleep(250 * 2 ** attempt);
        await ctx.runAction(internal.backends.deleteUser, {
          backend: input.backend,
          backendUserId: issued.backendUserId,
          backendServerId: issued.backendServerId,
        });
        backendDeleted = true;
      } catch {
        /* retried below / audited after the loop */
      }
    }
    if (subscriptionId) {
      try {
        await ctx.runMutation(internal.subscriptions.markSubscriptionDeleted, { subscriptionId });
      } catch {
        /* the row points at a gone backend user; retention deletes it eventually */
      }
    }
    if (issued.backendServerId) {
      try {
        await ctx.runMutation(internal.backendServers.bumpKeyCount, {
          id: issued.backendServerId,
          delta: -1,
        });
      } catch {
        /* instance pool scoring self-corrects at the next healthcheck */
      }
    }
    if (!backendDeleted) {
      console.warn(
        `[issuance] compensation delete failed for ${input.backend} user — orphan backend account`,
      );
      try {
        await ctx.runMutation(internal.audit.record, {
          actorType: 'system',
          action: 'subscription.compensation_failed',
          targetType: 'subscription',
          targetId: subscriptionId ?? undefined,
          payload: { backend: input.backend, backendUserId: issued.backendUserId },
        });
      } catch {
        /* the saga's original error takes precedence */
      }
    }
    throw err;
  }
}

/**
 * Tear a subscription down everywhere: delete the backend user, drop its S3
 * mirrors, then mark the local row deleted. Used by free-tier cleanup + the
 * tombstone sweep.
 *
 * ORDERING MATTERS (P1-5): the backend delete happens FIRST and is NOT swallowed.
 * If it throws, we propagate WITHOUT marking the local row deleted, so the row
 * stays selectable and the next sweep retries — otherwise a transient backend
 * blip would mark the row `deleted` (no sweep scans deleted rows) and the proxy
 * key would keep routing forever. `deleteUser` is expected to treat an
 * already-absent backend user as success, so a retry after a partial run is safe.
 */
export async function deleteSubscriptionEverywhere(
  ctx: ActionCtx,
  input: { backend: 'remnawave' | 'outline'; backendUserId: string },
): Promise<void> {
  const sub = await ctx.runQuery(internal.subscriptions.byBackendUserId, {
    backendUserId: input.backendUserId,
  });
  // 1. Delete the backend user first. A throw here propagates (the caller's
  //    sweep counts this as not-removed and retries next tick) and we do NOT
  //    touch local state, so the key never silently keeps routing.
  await ctx.runAction(internal.backends.deleteUser, {
    backend: input.backend,
    backendUserId: input.backendUserId,
    backendServerId: sub?.backendServerId,
  });
  // 2. Backend user is gone. Best-effort drop S3 mirrors, then mark the row.
  if (sub) {
    const items = sub.subscriptionMirrors
      .filter((m): m is typeof m & { objectPath: string } => typeof m.objectPath === 'string')
      .map((m) => ({ provider: m.provider, objectPath: m.objectPath }));
    if (items.length > 0) {
      try {
        await ctx.runAction(internal.storage.deleteMirrors, { items });
      } catch {
        /* best-effort: mirrors are a hedge, not the routing key */
      }
    }
    await ctx.runMutation(internal.subscriptions.markSubscriptionDeleted, {
      subscriptionId: sub._id,
    });
    // P2: keep the instance's load estimate honest (issue bumps +1; teardown -1)
    // so multi-instance pool scoring stays balanced between healthchecks.
    if (sub.backendServerId) {
      await ctx.runMutation(internal.backendServers.bumpKeyCount, {
        id: sub.backendServerId,
        delta: -1,
      });
    }
  }
}
