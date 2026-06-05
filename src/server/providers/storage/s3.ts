import type { Logger } from '../../lib/logger';
import type { S3ProviderConfig } from '../../platform/interface';
import type { StorageProvider, UploadResult } from './interface';

export class S3StorageProvider implements StorageProvider {
  constructor(
    public readonly providers: ReadonlyArray<S3ProviderConfig>,
    private readonly logger: Logger,
  ) {}

  async uploadToAll(
    objectPath: string,
    content: string | Uint8Array,
    contentType = 'text/plain',
  ): Promise<UploadResult[]> {
    if (this.providers.length === 0) return [];
    const results = await Promise.allSettled(
      this.providers.map(async (p): Promise<UploadResult> => {
        const url = await this.putObject(p, objectPath, content, contentType);
        return { provider: p.name, publicUrl: url, objectPath };
      }),
    );
    const successes: UploadResult[] = [];
    const failures: { provider: string; error: string }[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      const p = this.providers[i];
      if (!r || !p) continue;
      if (r.status === 'fulfilled') successes.push(r.value);
      else failures.push({ provider: p.name, error: String(r.reason) });
    }
    if (failures.length > 0) {
      this.logger.warn('s3_partial_upload_failures', { failures });
    }
    if (successes.length === 0) {
      throw new Error(`All S3 uploads failed: ${JSON.stringify(failures)}`);
    }
    return successes;
  }

  async deleteObject(providerName: string, objectPath: string): Promise<void> {
    const provider = this.providers.find((p) => p.name === providerName);
    if (!provider) return;
    const { S3Client, DeleteObjectCommand } = await import('@aws-sdk/client-s3');
    const client = this.buildClient(S3Client, provider);
    await client.send(new DeleteObjectCommand({ Bucket: provider.bucket, Key: objectPath }));
  }

  async deleteFromAll(items: { provider: string; objectPath: string }[]): Promise<void> {
    await Promise.allSettled(
      items.map((it) =>
        this.deleteObject(it.provider, it.objectPath).catch((err) => {
          this.logger.warn('s3_delete_failed', { provider: it.provider, error: String(err) });
        }),
      ),
    );
  }

  private async putObject(
    provider: S3ProviderConfig,
    objectPath: string,
    content: string | Uint8Array,
    contentType: string,
  ): Promise<string> {
    const { S3Client, PutObjectCommand } = await import('@aws-sdk/client-s3');
    const client = this.buildClient(S3Client, provider);
    await client.send(
      new PutObjectCommand({
        Bucket: provider.bucket,
        Key: objectPath,
        Body: typeof content === 'string' ? content : Buffer.from(content),
        ContentType: contentType,
      }),
    );
    return `${provider.publicUrl.replace(/\/$/, '')}/${objectPath}`;
  }

  private buildClient(S3Ctor: any, provider: S3ProviderConfig): any {
    return new S3Ctor({
      region: provider.region,
      endpoint: provider.endpoint,
      forcePathStyle: true,
      credentials: {
        accessKeyId: provider.accessKeyId,
        secretAccessKey: provider.secretAccessKey,
      },
    });
  }
}
