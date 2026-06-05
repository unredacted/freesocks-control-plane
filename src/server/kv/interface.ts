export interface KvPutOptions {
  expirationTtl?: number;
  expiration?: number;
}

export interface KvListResult<TMetadata = unknown> {
  keys: { name: string; expiration?: number; metadata?: TMetadata }[];
  list_complete: boolean;
  cursor?: string;
}

export interface KvStore {
  get(key: string): Promise<string | null>;
  getJson<T>(key: string): Promise<T | null>;
  put(key: string, value: string, opts?: KvPutOptions): Promise<void>;
  putJson(key: string, value: unknown, opts?: KvPutOptions): Promise<void>;
  delete(key: string): Promise<void>;
  list<TMetadata = unknown>(prefix?: string, cursor?: string): Promise<KvListResult<TMetadata>>;
}
