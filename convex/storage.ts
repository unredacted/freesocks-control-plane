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
import { runWithCronOutcome } from './cronHeartbeat';
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

    let fetched: { content: string; contentType?: string; pinnedNode?: string };
    try {
      fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: context.backend,
        backendServerId: context.backendServerId ?? undefined,
        backendShortId: context.backendShortId,
        subscriptionUrl: context.subscriptionUrl,
        // The same exclusion the live /sub route and the refresh apply. Node
        // pinning is deterministic, so provisioning a FIRST mirror without it
        // uploads the very node the member just switched away from.
        excludeNode: context.excludeNode ?? undefined,
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

    const appended = await ctx.runMutation(internal.subscriptions.appendMirror, {
      subscriptionId: context.subscriptionId,
      mirror: entry,
      rawContentHash: hash,
      cap,
    });
    // The object was uploaded but the row didn't change. Two causes, and they
    // need different answers: a lost cap race (Review D-#8) really is capped,
    // but a SUPERSEDED row means a re-issue overtook us — the member is not
    // capped at all and a retry will provision against their live key, so report
    // it as a retryable error. Either way the uploaded object is residue.
    if (!appended.appended) {
      return appended.reason === 'superseded'
        ? { status: 'error', remaining: Math.max(0, cap - used) }
        : { status: 'capped', remaining: 0 };
    }
    // Record the node only now: the object is uploaded AND the row references
    // it, so this is the first moment the pin describes what the member is
    // actually served. For someone who only ever uses the mirror, this is also
    // the only place it gets written — without it their next switch-server finds
    // no pin to rotate and refuses with `no_alternative`.
    if (fetched.pinnedNode) {
      await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
        subscriptionId: context.subscriptionId,
        node: fetched.pinnedNode,
      });
    }
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
  handler: async (ctx): Promise<{ refreshed: number; scanned: number }> =>
    runWithCronOutcome(ctx, 'mirror-refresh', async () => {
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
          const targets = sub.providers
            .map((n) => byName.get(n))
            .filter((p): p is S3Provider => !!p);
          if (targets.length === 0 || !sub.objectPath) continue;
          try {
            const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
              backend: sub.backend,
              backendServerId: sub.backendServerId ?? undefined,
              backendShortId: sub.backendShortId,
              subscriptionUrl: sub.subscriptionUrl,
              // Same exclusion the live /sub route applies, or the deterministic
              // pin regenerates the node the member switched AWAY from — and the
              // unchanged hash below would then skip the re-upload, leaving the
              // mirror pointed at it indefinitely.
              excludeNode: sub.excludeNode ?? undefined,
            });
            // Record the node this landed on, exactly as the live /sub routes do.
            // For a member who only ever uses the mirror URL this is the ONLY
            // place the pin gets written, and without it their next switch-server
            // finds no pin to rotate and refuses with `no_alternative` even
            // though the squad has other nodes.
            //
            // The pin must describe the node the member's mirror ACTUALLY serves,
            // so it is written at exactly the two points where that is true:
            // unchanged content (the mirror already holds this node's config), or
            // a successful upload. Writing it before a failed upload would record
            // a node the member is not on, and their next switch would then
            // exclude the wrong one.
            const recordPin = async () => {
              if (!fetched.pinnedNode) return;
              await ctx.runMutation(internal.subscriptions.recordPinnedNode, {
                subscriptionId: sub.id,
                node: fetched.pinnedNode,
              });
            };
            const hash = await sha256Hex(fetched.content);
            if (hash === sub.rawContentHash) {
              // Nothing to re-upload — but the pin can move while the bytes stay
              // identical, and the mirror is already correct, so record it.
              await recordPin();
              continue;
            }
            // Throws only if EVERY provider failed (caught below → sub skipped,
            // pin deliberately unrecorded: the mirror still serves the old node).
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
            // A PARTIAL round leaves at least one provider serving the previous
            // content, so neither the hash nor the pin may advance yet:
            //  - the hash is subscription-wide, and advancing it would make the
            //    next run take the unchanged-content short-circuit and never
            //    retry the stale provider — stranding it permanently;
            //  - the pin would then describe a node some mirror URL does not
            //    serve, so a later switch-server would exclude the wrong node.
            // Holding both means the next run retries (one extra re-upload to
            // the healthy providers every 6h until the broken one recovers) and
            // both advance together on the first clean round.
            const allSucceeded = failedProviders.length === 0;
            await ctx.runMutation(internal.subscriptions.updateMirrors, {
              subscriptionId: sub.id,
              successes: mirrors,
              failedProviders,
              ...(allSucceeded ? { rawContentHash: hash } : {}),
            });
            if (allSucceeded) await recordPin();
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
    }),
});
