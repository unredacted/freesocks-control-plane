'use node';
/**
 * S3 subscription-content mirrors as a Node action (ported from
 * src/server/providers/storage/*). `@aws-sdk/client-s3` needs the Node runtime,
 * so this whole file is `"use node"` — it can't define queries/mutations.
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

interface S3Provider {
  name: string;
  endpoint: string;
  bucket: string;
  publicUrl: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}

function parseProviders(): S3Provider[] {
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
 * Upload `content` to every configured provider in parallel. Returns the
 * successful mirrors in the subscription-mirror shape. No providers configured
 * → []. All uploads failed → throws (so the saga knows mirroring is broken).
 */
export const mirrorContent = internalAction({
  args: { objectPath: v.string(), content: v.string(), contentType: v.optional(v.string()) },
  handler: async (_ctx, { objectPath, content, contentType }) => {
    const providers = parseProviders();
    if (providers.length === 0) return [];
    const results = await Promise.allSettled(
      providers.map(async (p) => {
        await clientFor(p).send(
          new PutObjectCommand({
            Bucket: p.bucket,
            Key: objectPath,
            Body: content,
            ContentType: contentType ?? 'text/plain',
          }),
        );
        return {
          provider: p.name,
          publicUrl: `${p.publicUrl.replace(/\/$/, '')}/${objectPath}`,
          objectPath,
          status: 'ok' as const,
        };
      }),
    );
    const successes = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
    if (successes.length === 0) throw new Error('All S3 mirror uploads failed');
    return successes;
  },
});

/** Best-effort delete of mirror objects (tombstone sweep / teardown). */
export const deleteMirrors = internalAction({
  args: { items: v.array(v.object({ provider: v.string(), objectPath: v.string() })) },
  handler: async (_ctx, { items }) => {
    const providers = parseProviders();
    await Promise.allSettled(
      items.map(async (it) => {
        const p = providers.find((x) => x.name === it.provider);
        if (!p) return;
        await clientFor(p).send(new DeleteObjectCommand({ Bucket: p.bucket, Key: it.objectPath }));
      }),
    );
    return null;
  },
});
