/**
 * The issuance saga (P5c): the read→act→write decomposition of the old
 * SubscriptionDeliveryService.issueNew. A plain helper (not a registered
 * function) invoked from within an action (account.regenerate / switchBackend),
 * so it shares the caller's ActionCtx instead of paying an action-to-action hop.
 *
 * Flow: backend create (HTTP) → mirror content to S3 → persist the row →
 * point the user at it. On any post-create failure it deletes the backend user
 * (compensation) and rethrows; the caller owns slot/tier bookkeeping.
 */
import type { ActionCtx } from '../_generated/server';
import type { Id } from '../_generated/dataModel';
import { api, internal } from '../_generated/api';
import { sha256Hex } from './crypto';
import type { BackendId, IssueUserSpec } from './backends/types';

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
  input: { userId: Id<'users'>; backend: 'remnawave' | 'outline'; spec: IssueUserSpec },
): Promise<IssueResult> {
  const issued = await ctx.runAction(internal.backends.issueUser, {
    backend: input.backend,
    spec: input.spec,
  });
  try {
    // Mirror to S3; skipped entirely when mirroring is off / no providers, so
    // we don't even fetch the content (matches the old mirrorSubscription).
    let mirrors: IssueResult['mirrors'] = [];
    let rawContentHash: string | undefined;
    const s3On =
      process.env.S3_MIRRORS_ENABLED === 'true' && Number(process.env.S3_PROVIDER_COUNT ?? '0') > 0;
    if (s3On) {
      const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: input.backend,
        backendServerId: issued.backendServerId,
        backendShortId: issued.backendShortId,
      });
      rawContentHash = await sha256Hex(fetched.content);
      mirrors = await ctx.runAction(internal.storage.mirrorContent, {
        objectPath: `subs/${issued.backendShortId}/${rawContentHash.slice(0, 12)}`,
        content: fetched.content,
        contentType: fetched.contentType,
      });
    }

    const subscriptionId = await ctx.runMutation(internal.subscriptions.insertSubscription, {
      userId: input.userId,
      backend: input.backend,
      backendUserId: issued.backendUserId,
      backendShortId: issued.backendShortId,
      backendServerId: issued.backendServerId,
      subscriptionUrl: issued.subscriptionUrl,
      subscriptionMirrors: mirrors,
      rawContentHash: mirrors.length > 0 ? rawContentHash : undefined,
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
      mirrors,
    };
  } catch (err) {
    // The backend user exists but we couldn't finish, so delete it: a transient
    // failure doesn't leak a backend account with no local row.
    try {
      await ctx.runAction(internal.backends.deleteUser, {
        backend: input.backend,
        backendUserId: issued.backendUserId,
        backendServerId: issued.backendServerId,
      });
    } catch {
      /* best-effort compensation */
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
  const sub = await ctx.runQuery(api.subscriptions.byBackendUserId, {
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
  }
}
