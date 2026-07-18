'use node';
/**
 * S3 subscription-content mirrors as a Node action (ported from
 * src/server/providers/storage/*). `@aws-sdk/client-s3` needs the Node runtime,
 * so this whole file is `"use node"`; it can't define queries/mutations.
 *
 * Mirrors are the censorship-resistance hedge: the proxy subscription content is
 * uploaded to S3-compatible providers so a client can fetch it even if the
 * control plane is blocked. They are OPT-IN + LAZY: a member calls
 * `provisionMirror` only when they can't reach the normal subscription URL — so
 * the non-opted-in majority's configs never touch third-party storage. Each
 * mirror is country-tiered (the DB picks the host least likely to be blocked
 * where they are) and capped per user.
 *
 * Config is fully DB-driven (the `mirrorProviders` table, CMS-managed via
 * Admin → Storage; replaced the old S3_PROVIDER_* and S3_MIRRORS_ENABLED env vars).
 * Because this file is `"use node"` it can't define queries, so each action
 * pulls the provider list from `internal.mirrorProviders.*`.
 */
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import { heartbeatFromAction } from './cronHeartbeat';
import { v } from 'convex/values';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { randomHex, sha256Hex } from './lib/crypto';
import type { MirrorContext } from './subscriptions';
import type { ActiveMirrorPage } from './subscriptions';

export interface S3Provider {
  name: string;
  endpoint: string;
  bucket: string;
  publicUrl: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface SubscriptionMirror {
  provider: string;
  publicUrl: string;
  objectPath: string;
  status: 'ok';
}

function clientFor(p: S3Provider): S3Client {
  return new S3Client({
    region: p.region,
    endpoint: p.endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: p.accessKeyId, secretAccessKey: p.secretAccessKey },
  });
}

/**
 * One S3 operation against one provider. Injected (default = the real SDK call)
 * so the parallel/aggregate logic in uploadToProviders / deleteFromProviders is
 * unit-testable with a plain stub, without the AWS SDK or the Convex runtime.
 */
export type S3Op =
  | { kind: 'put'; key: string; body: string; contentType: string }
  | { kind: 'delete'; key: string };
export type S3Send = (provider: S3Provider, op: S3Op) => Promise<void>;

const realSend: S3Send = async (p, op) => {
  const client = clientFor(p);
  if (op.kind === 'put') {
    await client.send(
      new PutObjectCommand({
        Bucket: p.bucket,
        Key: op.key,
        Body: op.body,
        ContentType: op.contentType,
      }),
    );
  } else {
    await client.send(new DeleteObjectCommand({ Bucket: p.bucket, Key: op.key }));
  }
};

/**
 * Upload `content` to every given provider in parallel. Returns the successful
 * mirrors in the subscription-mirror shape. No providers → []. All uploads
 * failed → throws (so the saga knows mirroring is broken). The provider list +
 * send fn are injected so this is unit-testable without the Convex runtime.
 */
export async function uploadToProviders(
  providers: S3Provider[],
  {
    objectPath,
    content,
    contentType,
  }: { objectPath: string; content: string; contentType?: string },
  send: S3Send = realSend,
): Promise<SubscriptionMirror[]> {
  if (providers.length === 0) return [];
  const results = await Promise.allSettled(
    providers.map(async (p): Promise<SubscriptionMirror> => {
      await send(p, {
        kind: 'put',
        key: objectPath,
        body: content,
        contentType: contentType ?? 'text/plain',
      });
      return {
        provider: p.name,
        publicUrl: `${p.publicUrl.replace(/\/$/, '')}/${objectPath}`,
        objectPath,
        status: 'ok',
      };
    }),
  );
  const successes = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
  if (successes.length === 0) throw new Error('All S3 mirror uploads failed');
  return successes;
}

/** Best-effort delete of mirror objects across providers (injected list + send). */
export async function deleteFromProviders(
  providers: S3Provider[],
  items: { provider: string; objectPath: string }[],
  send: S3Send = realSend,
): Promise<void> {
  await Promise.allSettled(
    items.map(async (it) => {
      const p = providers.find((x) => x.name === it.provider);
      if (!p) return;
      await send(p, { kind: 'delete', key: it.objectPath });
    }),
  );
}

export interface ProvisionResult {
  status: 'ok' | 'capped' | 'exhausted' | 'no_subscription' | 'error';
  publicUrl?: string;
  provider?: string;
  remaining: number;
}

/**
 * Opt-in lazy mirror: provision ONE more S3 mirror for the member's active sub,
 * picking the next country-tiered provider they haven't tried. Bounded by the
 * `mirror.maxPerUser` setting. Reuses the sub's capability object path across
 * providers (one unguessable token per sub; content identical, only the host
 * differs). `countryCode` is used transiently to pick a nearby host — never stored.
 */
export const provisionMirror = internalAction({
  args: { userId: v.id('users'), countryCode: v.union(v.string(), v.null()) },
  handler: async (ctx, { userId, countryCode }): Promise<ProvisionResult> => {
    const context: MirrorContext | null = await ctx.runQuery(
      internal.subscriptions.mirrorContextForUser,
      { userId },
    );
    if (!context) return { status: 'no_subscription', remaining: 0 };

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const cap = Math.max(0, Number(settings['mirror.maxPerUser'] ?? 3));
    const used = context.triedProviders.length;
    if (used >= cap) return { status: 'capped', remaining: 0 };

    const next = await ctx.runQuery(internal.mirrorProviders.selectNextProvider, {
      countryCode,
      tried: context.triedProviders,
    });
    if (!next) return { status: 'exhausted', remaining: Math.max(0, cap - used) };

    // Re-resolve the secret-bearing provider by name (active only).
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    const provider = providers.find((p) => p.name === next.name);
    if (!provider) return { status: 'exhausted', remaining: Math.max(0, cap - used) };

    let fetched: { content: string; contentType?: string };
    try {
      fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: context.backend,
        backendServerId: context.backendServerId ?? undefined,
        backendShortId: context.backendShortId,
        subscriptionUrl: context.subscriptionUrl,
      });
    } catch {
      return { status: 'error', remaining: Math.max(0, cap - used) };
    }
    const hash = await sha256Hex(fetched.content);
    // One capability token per sub, reused across providers (stable + unguessable).
    const objectPath = context.objectPath ?? `mirrors/${randomHex(16)}`;

    let entry: SubscriptionMirror | undefined;
    try {
      const mirrors = await uploadToProviders([provider], {
        objectPath,
        content: fetched.content,
        contentType: fetched.contentType,
      });
      entry = mirrors[0];
    } catch {
      return { status: 'error', remaining: Math.max(0, cap - used) };
    }
    if (!entry) return { status: 'error', remaining: Math.max(0, cap - used) };

    await ctx.runMutation(internal.subscriptions.appendMirror, {
      subscriptionId: context.subscriptionId,
      mirror: entry,
      rawContentHash: hash,
    });
    return {
      status: 'ok',
      publicUrl: entry.publicUrl,
      provider: provider.name,
      remaining: Math.max(0, cap - used - 1),
    };
  },
});

/** Remove all of the member's mirrors (reset): clear the list + delete the objects. */
export const clearMirrorsForUser = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ removed: number }> => {
    const context: MirrorContext | null = await ctx.runQuery(
      internal.subscriptions.mirrorContextForUser,
      { userId },
    );
    if (!context) return { removed: 0 };
    const { items } = await ctx.runMutation(internal.subscriptions.clearMirrors, {
      subscriptionId: context.subscriptionId,
    });
    if (items.length > 0) {
      const providers = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
      await deleteFromProviders(providers, items);
    }
    return { removed: items.length };
  },
});

/** Best-effort delete of mirror objects (tombstone sweep / teardown). Uses ALL
 *  providers (incl. since-deactivated ones) so stale objects get cleaned. */
export const deleteMirrors = internalAction({
  args: { items: v.array(v.object({ provider: v.string(), objectPath: v.string() })) },
  handler: async (ctx, { items }) => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listAllWithSecret, {});
    await deleteFromProviders(providers, items);
    return null;
  },
});

/**
 * Admin test: confirm a provider's connection details work BEFORE saving, by
 * writing a tiny health object to the bucket (also validates write perms, which
 * is what mirroring needs). The secret is never echoed back or put in the error
 * (the SDK error name/message carries no credential).
 */
export const testProviderConnection = internalAction({
  args: {
    endpoint: v.string(),
    bucket: v.string(),
    region: v.optional(v.string()),
    accessKeyId: v.string(),
    secretAccessKey: v.string(),
  },
  handler: async (_ctx, a): Promise<{ ok: true } | { ok: false; error: string }> => {
    if (!a.endpoint || !a.bucket || !a.accessKeyId || !a.secretAccessKey) {
      return { ok: false, error: 'endpoint, bucket, access key ID and secret are all required' };
    }
    const provider: S3Provider = {
      name: '__test__',
      endpoint: a.endpoint,
      bucket: a.bucket,
      publicUrl: '',
      region: a.region?.trim() || 'us-east-1',
      accessKeyId: a.accessKeyId,
      secretAccessKey: a.secretAccessKey,
    };
    try {
      await clientFor(provider).send(
        new PutObjectCommand({
          Bucket: provider.bucket,
          Key: '__fcp_healthcheck',
          Body: 'ok',
          ContentType: 'text/plain',
        }),
      );
      return { ok: true };
    } catch (err) {
      const msg = err instanceof Error ? `${err.name}: ${err.message}` : 'connection failed';
      return { ok: false, error: msg.slice(0, 200) };
    }
  },
});

// Bounded per run: drain up to MAX_PAGES × PAGE active subs, continuing from the
// cursor persisted at the END of the last run so the window rotates through the
// whole fleet over successive ticks (a per-run cold start re-scans the same
// oldest window forever and starves every mirrored sub beyond it — M3).
const REFRESH_MAX_PAGES = 50;
const REFRESH_PAGE = 50;

/**
 * Cron: keep EXISTING (opt-in) mirrors fresh. Pages only subs that already have a
 * mirror (never creates one) and re-uploads each sub's current content to ITS OWN
 * providers at the SAME object path — so the mirror URL the member already holds
 * stays valid with up-to-date content. Skips a sub whose content is unchanged
 * (hash match), so steady state is cheap. No-op when no provider is enabled.
 */
export const refreshActiveMirrors = internalAction({
  args: {},
  handler: async (ctx): Promise<{ refreshed: number; scanned: number }> => {
    await heartbeatFromAction(ctx, 'mirror-refresh');
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    if (providers.length === 0) {
      return { refreshed: 0, scanned: 0 };
    }
    const byName = new Map(providers.map((p) => [p.name, p]));
    let cursor: string | null = await ctx.runQuery(internal.mirrorProviders.getRefreshCursor, {});
    let refreshed = 0;
    let scanned = 0;
    for (let page = 0; page < REFRESH_MAX_PAGES; page++) {
      // Annotated (not inferred) to break the internal-API self-reference cycle.
      let res: ActiveMirrorPage;
      try {
        res = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
          cursor,
          numItems: REFRESH_PAGE,
        });
      } catch (err) {
        // A stale/invalid cursor (e.g. after an index change) must not wedge the
        // sweep: reset to the start and continue from there next run.
        if (cursor === null) throw err;
        console.warn('[mirror-refresh] cursor rejected; restarting from the beginning');
        cursor = null;
        res = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
          cursor,
          numItems: REFRESH_PAGE,
        });
      }
      for (const sub of res.items) {
        scanned++;
        // Re-upload only to THIS sub's providers that are still active.
        const targets = sub.providers.map((n) => byName.get(n)).filter((p): p is S3Provider => !!p);
        if (targets.length === 0 || !sub.objectPath) continue;
        try {
          const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
            backend: sub.backend,
            backendServerId: sub.backendServerId ?? undefined,
            backendShortId: sub.backendShortId,
            subscriptionUrl: sub.subscriptionUrl,
          });
          const hash = await sha256Hex(fetched.content);
          if (hash === sub.rawContentHash) continue; // unchanged → no re-upload
          const mirrors = await uploadToProviders(targets, {
            objectPath: sub.objectPath,
            content: fetched.content,
            contentType: fetched.contentType,
          });
          // Providers we attempted but that didn't come back a success this round →
          // updateMirrors keeps their existing entry marked failed (Review #2),
          // rather than dropping it. (uploadToProviders throws only if ALL fail,
          // caught above → the sub is skipped, entries untouched.)
          const succeeded = new Set(mirrors.map((m) => m.provider));
          const failedProviders = targets.map((t) => t.name).filter((n) => !succeeded.has(n));
          await ctx.runMutation(internal.subscriptions.updateMirrors, {
            subscriptionId: sub.id,
            successes: mirrors,
            failedProviders,
            rawContentHash: hash,
          });
          refreshed++;
        } catch {
          /* best-effort per sub: one backend/S3 hiccup must not stall the sweep */
        }
      }
      if (res.isDone) {
        // Full pass complete: restart from the beginning next tick.
        await ctx.runMutation(internal.mirrorProviders.setRefreshCursor, { cursor: null });
        return { refreshed, scanned };
      }
      cursor = res.continueCursor;
    }
    // Hit the per-run page cap: persist where we stopped so the NEXT tick
    // continues forward instead of re-scanning the same window (M3).
    await ctx.runMutation(internal.mirrorProviders.setRefreshCursor, { cursor });
    return { refreshed, scanned };
  },
});
