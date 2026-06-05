import type { KvListResult, KvPutOptions, KvStore } from './interface';

export class CloudflareKvStore implements KvStore {
  constructor(private readonly ns: KVNamespace) {}

  async get(key: string): Promise<string | null> {
    return this.ns.get(key);
  }

  async getJson<T>(key: string): Promise<T | null> {
    return this.ns.get<T>(key, 'json');
  }

  async put(key: string, value: string, opts?: KvPutOptions): Promise<void> {
    await this.ns.put(key, value, {
      expirationTtl: opts?.expirationTtl,
      expiration: opts?.expiration,
    });
  }

  async putJson(key: string, value: unknown, opts?: KvPutOptions): Promise<void> {
    await this.put(key, JSON.stringify(value), opts);
  }

  async delete(key: string): Promise<void> {
    await this.ns.delete(key);
  }

  async list<TMetadata = unknown>(
    prefix?: string,
    cursor?: string,
  ): Promise<KvListResult<TMetadata>> {
    const result = await this.ns.list<TMetadata>({ prefix, cursor });
    return {
      keys: result.keys.map((k) => ({
        name: k.name,
        expiration: k.expiration,
        metadata: k.metadata,
      })),
      list_complete: result.list_complete,
      cursor: 'cursor' in result ? result.cursor : undefined,
    };
  }
}
