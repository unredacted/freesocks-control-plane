import { and, eq, gt, isNull, like, or, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { kvTable } from '../db/schema';
import type { KvListResult, KvPutOptions, KvStore } from './interface';

export class SqliteKvStore implements KvStore {
  constructor(
    private readonly db: Db,
    private readonly namespace: string,
  ) {}

  private now(): number {
    return Date.now();
  }

  async get(key: string): Promise<string | null> {
    const row = await this.db
      .select()
      .from(kvTable)
      .where(and(eq(kvTable.namespace, this.namespace), eq(kvTable.key, key)))
      .limit(1)
      .all();
    const r = row[0];
    if (!r) return null;
    if (r.expiresAt !== null && r.expiresAt !== undefined && r.expiresAt < this.now()) {
      await this.delete(key);
      return null;
    }
    if (!r.value) return null;
    return new TextDecoder().decode(r.value);
  }

  async getJson<T>(key: string): Promise<T | null> {
    const raw = await this.get(key);
    if (raw === null) return null;
    return JSON.parse(raw) as T;
  }

  async put(key: string, value: string, opts?: KvPutOptions): Promise<void> {
    const expiresAt = opts?.expiration
      ? opts.expiration * 1000
      : opts?.expirationTtl
        ? this.now() + opts.expirationTtl * 1000
        : null;
    const data = new TextEncoder().encode(value);
    await this.db
      .insert(kvTable)
      .values({
        namespace: this.namespace,
        key,
        value: Buffer.from(data),
        metadata: null,
        expiresAt,
        updatedAt: this.now(),
      })
      .onConflictDoUpdate({
        target: [kvTable.namespace, kvTable.key],
        set: {
          value: Buffer.from(data),
          metadata: null,
          expiresAt,
          updatedAt: this.now(),
        },
      });
  }

  async putJson(key: string, value: unknown, opts?: KvPutOptions): Promise<void> {
    await this.put(key, JSON.stringify(value), opts);
  }

  async delete(key: string): Promise<void> {
    await this.db
      .delete(kvTable)
      .where(and(eq(kvTable.namespace, this.namespace), eq(kvTable.key, key)));
  }

  async list<TMetadata = unknown>(
    prefix?: string,
    cursor?: string,
  ): Promise<KvListResult<TMetadata>> {
    const limit = 100;
    const conditions = [eq(kvTable.namespace, this.namespace)];
    if (prefix) conditions.push(like(kvTable.key, `${prefix}%`));
    if (cursor) conditions.push(sql`${kvTable.key} > ${cursor}`);
    conditions.push(or(isNull(kvTable.expiresAt), gt(kvTable.expiresAt, this.now()))!);

    const rows = await this.db
      .select()
      .from(kvTable)
      .where(and(...conditions))
      .orderBy(kvTable.key)
      .limit(limit + 1)
      .all();

    const hasMore = rows.length > limit;
    const sliced = rows.slice(0, limit);
    const last = sliced[sliced.length - 1];

    return {
      keys: sliced.map((r) => ({
        name: r.key,
        expiration: r.expiresAt ? Math.floor(r.expiresAt / 1000) : undefined,
        metadata: r.metadata ? (JSON.parse(r.metadata) as TMetadata) : undefined,
      })),
      list_complete: !hasMore,
      cursor: hasMore && last ? last.key : undefined,
    };
  }
}
