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
 * Config (Convex env vars): S3_PROVIDER_COUNT and, per provider i in 1..count,
 *   S3_PROVIDER_i_{NAME,ENDPOINT,BUCKET,PUBLIC_URL,REGION,ACCESS_KEY_ID,SECRET_ACCESS_KEY}
 */
import { internalAction } from './_generated/server';
import { v } from 'convex/values';
import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

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

export function parseProviders(): S3Provider[] {
  const count = parseInt(process.env.S3_PROVIDER_COUNT ?? '0', 10);
  const out: S3Provider[] = [];
  for (let i = 1; i <= count; i++) {
    const g = (k: string): string | undefined => process.env[`S3_PROVIDER_${i}_${k}`];
    const name = g('NAME');
    const endpoint = g('ENDPOINT');
    const bucket = g('BUCKET');
    const publicUrl = g('PUBLIC_URL');
    const accessKeyId = g('ACCESS_KEY_ID');
    const secretAccessKey = g('SECRET_ACCESS_KEY');
    if (name && endpoint && bucket && publicUrl && accessKeyId && secretAccessKey) {
      out.push({
        name,
        endpoint,
        bucket,
        publicUrl,
        region: g('REGION') ?? 'us-east-1',
        accessKeyId,
        secretAccessKey,
      });
    }
  }
  return out;
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
      new PutObjectCommand({ Bucket: p.bucket, Key: op.key, Body: op.body, ContentType: op.contentType }),
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
  { objectPath, content, contentType }: { objectPath: string; content: string; contentType?: string },
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
  handler: async (_ctx, args) => uploadToProviders(parseProviders(), args),
});

/** Best-effort delete of mirror objects (tombstone sweep / teardown). */
export const deleteMirrors = internalAction({
  args: { items: v.array(v.object({ provider: v.string(), objectPath: v.string() })) },
  handler: async (_ctx, { items }) => {
    await deleteFromProviders(parseProviders(), items);
    return null;
  },
});
