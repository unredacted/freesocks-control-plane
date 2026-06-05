import type { S3ProviderConfig } from '../../platform/interface';

export function parseS3Providers(env: Record<string, unknown>): S3ProviderConfig[] {
  const count = parseInt(String(env.S3_PROVIDER_COUNT ?? '0'), 10);
  const providers: S3ProviderConfig[] = [];
  for (let i = 1; i <= count; i++) {
    const name = env[`S3_PROVIDER_${i}_NAME`];
    const endpoint = env[`S3_PROVIDER_${i}_ENDPOINT`];
    const bucket = env[`S3_PROVIDER_${i}_BUCKET`];
    const publicUrl = env[`S3_PROVIDER_${i}_PUBLIC_URL`];
    const region = env[`S3_PROVIDER_${i}_REGION`] ?? 'us-east-1';
    const accessKeyId = env[`S3_PROVIDER_${i}_ACCESS_KEY_ID`];
    const secretAccessKey = env[`S3_PROVIDER_${i}_SECRET_ACCESS_KEY`];
    if (
      typeof name === 'string' &&
      typeof endpoint === 'string' &&
      typeof bucket === 'string' &&
      typeof publicUrl === 'string' &&
      typeof accessKeyId === 'string' &&
      typeof secretAccessKey === 'string'
    ) {
      providers.push({
        name,
        endpoint,
        bucket,
        publicUrl,
        region: String(region),
        accessKeyId,
        secretAccessKey,
      });
    }
  }
  return providers;
}
