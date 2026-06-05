/**
 * The issuance saga (P5c) — the read→act→write decomposition of the old
 * SubscriptionDeliveryService.issueNew. A plain helper (not a registered
 * function) invoked from within an action (free-tier issueOrReissue, and later
 * regenerate/switch-backend), so it shares the caller's ActionCtx instead of
 * paying an action-to-action hop.
 *
 * Flow: backend create (HTTP) → mirror content to S3 → persist the row →
 * point the user at it. On any post-create failure it deletes the backend user
 * (compensation) and rethrows; the caller owns slot/tier bookkeeping.
 */
import type { ActionCtx } from '../_generated/server';
import type { Id } from '../_generated/dataModel';
import { internal } from '../_generated/api';
import { sha256Hex } from './crypto';
import type { IssueUserSpec } from './backends/types';

export interface IssueResult {
  subscriptionId: Id<'subscriptions'>;
  backend: 'remnawave' | 'outline';
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
    // Mirror to S3 — skipped entirely when mirroring is off / no providers, so
    // we don't even fetch the content (matches the old mirrorSubscription).
    let mirrors: IssueResult['mirrors'] = [];
    let rawContentHash: string | undefined;
    const s3On =
      process.env.S3_MIRRORS_ENABLED === 'true' &&
      Number(process.env.S3_PROVIDER_COUNT ?? '0') > 0;
    if (s3On) {
      const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: input.backend,
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
      outlineServerId: issued.outlineServerId,
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
    // The backend user exists but we couldn't finish — delete it so a transient
    // failure doesn't leak a backend account with no local row.
    try {
      await ctx.runAction(internal.backends.deleteUser, {
        backend: input.backend,
        backendUserId: issued.backendUserId,
      });
    } catch {
      /* best-effort compensation */
    }
    throw err;
  }
}
