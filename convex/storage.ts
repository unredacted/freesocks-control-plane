'use node';
/**
 * S3 subscription-content mirrors as a Node action (ported from
 * src/server/providers/storage/*). `@aws-sdk/client-s3` needs the Node runtime,
 * so this whole file is `"use node"`; it can't define queries/mutations.
 *
 * Mirrors are the censorship-resistance hedge: the proxy subscription content
 * is uploaded to N S3-compatible providers so a client can fetch it even if the
 * control plane is blocked. The issuance saga (P5) calls `mirrorContent` and
 * persists the returned list on the subscription row.
 *
 * Config is fully DB-driven (the `mirrorProviders` table, CMS-managed via
 * Admin → Storage; replaced the old S3_PROVIDER_* and S3_MIRRORS_ENABLED env vars).
 * Because this file is `"use node"` it can't define queries, so each action
 * pulls the provider list from `internal.mirrorProviders.*`. Mirroring is active
 * iff ≥1 provider row is enabled.
 */
import { internalAction } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { sha256Hex } from './lib/crypto';
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

/**
 * Upload `content` to every configured provider in parallel. The issuance saga
 * calls this and persists the returned list on the subscription row.
 */
export const mirrorContent = internalAction({
  args: { objectPath: v.string(), content: v.string(), contentType: v.optional(v.string()) },
  handler: async (ctx, args): Promise<SubscriptionMirror[]> => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    return uploadToProviders(providers, args);
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

// Bounded per run: drain up to MAX_PAGES × PAGE active subs. Beta/early-prod fits
// in one run; a larger set catches up over subsequent ticks.
const REFRESH_MAX_PAGES = 50;
const REFRESH_PAGE = 50;

/**
 * Cron: keep the S3 mirrors fresh. Re-fetch each active subscription's current
 * content from its backend and re-upload it to the SAME object path (so the
 * mirror URL the member already holds stays valid, with up-to-date content).
 * Skips a sub whose content is unchanged (hash match), so steady state is cheap.
 * No-op unless ≥1 mirror provider is configured + enabled (same gate as issuance).
 */
export const refreshActiveMirrors = internalAction({
  args: {},
  handler: async (ctx): Promise<{ refreshed: number; scanned: number }> => {
    const providers = await ctx.runQuery(internal.mirrorProviders.listActiveWithSecret, {});
    if (providers.length === 0) {
      return { refreshed: 0, scanned: 0 };
    }
    let cursor: string | null = null;
    let refreshed = 0;
    let scanned = 0;
    for (let page = 0; page < REFRESH_MAX_PAGES; page++) {
      // Annotated (not inferred) to break the internal-API self-reference cycle.
      const res: ActiveMirrorPage = await ctx.runQuery(internal.subscriptions.pageActiveForMirror, {
        cursor,
        numItems: REFRESH_PAGE,
      });
      for (const sub of res.items) {
        scanned++;
        try {
          const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
            backend: sub.backend,
            backendServerId: sub.backendServerId ?? undefined,
            backendShortId: sub.backendShortId,
          });
          const hash = await sha256Hex(fetched.content);
          if (hash === sub.rawContentHash) continue; // unchanged → no re-upload
          // Reuse the existing object path so the mirror URL is stable; only the
          // first-ever mirror for a sub (none yet) gets a content-addressed path.
          const objectPath = sub.objectPath ?? `subs/${sub.backendShortId}/${hash.slice(0, 12)}`;
          const mirrors = await uploadToProviders(providers, {
            objectPath,
            content: fetched.content,
            contentType: fetched.contentType,
          });
          await ctx.runMutation(internal.subscriptions.updateMirrors, {
            subscriptionId: sub.id,
            mirrors,
            rawContentHash: hash,
          });
          refreshed++;
        } catch {
          /* best-effort per sub: one backend/S3 hiccup must not stall the sweep */
        }
      }
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    return { refreshed, scanned };
  },
});
