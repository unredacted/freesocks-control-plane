import type { S3ProviderConfig } from '../../platform/interface';

export interface UploadResult {
  provider: string;
  publicUrl: string;
  objectPath: string;
}

export interface UploadFailure {
  provider: string;
  error: string;
}

export interface StorageProvider {
  /**
   * Upload to all configured providers in parallel.
   * Returns successful uploads. If all fail, throws.
   */
  uploadToAll(
    objectPath: string,
    content: string | Uint8Array,
    contentType?: string,
  ): Promise<UploadResult[]>;

  /**
   * Delete an object from a single provider.
   */
  deleteObject(providerName: string, objectPath: string): Promise<void>;

  /**
   * Delete from multiple providers (best-effort).
   */
  deleteFromAll(items: { provider: string; objectPath: string }[]): Promise<void>;

  /** The list of configured providers. */
  readonly providers: ReadonlyArray<S3ProviderConfig>;
}
