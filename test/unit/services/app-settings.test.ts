import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { describe, expect, it, beforeEach } from 'vitest';
import { AppSettingsService } from '../../../src/server/services/app-settings';
import { Logger } from '../../../src/server/lib/logger';
import type { KvStore } from '../../../src/server/kv/interface';

/**
 * `AppSettingsService` is the durable home for admin-toggleable runtime
 * config. These tests pin its three load-bearing behaviors:
 *
 *   1. Reads layer compiled-in defaults under any DB-stored overrides, so
 *      a fresh DB without an `app_settings` row still gives correct values.
 *   2. Writes round-trip through the Zod validator — invalid values throw,
 *      not corrupt the row.
 *   3. The KV cache is invalidated on write so the next read goes to DB.
 *
 * We use an in-memory SQLite for the DB and a Map-backed KvStore stub. Real
 * Drizzle queries run against the schema (CREATE TABLE mirrors the
 * migration), so column-name typos would be caught here.
 */

function makeDb() {
  const sqlite = new Database(':memory:');
  sqlite.exec(`
    CREATE TABLE app_settings (
      key                 TEXT PRIMARY KEY,
      value               TEXT NOT NULL,
      updated_at          INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_by_admin_id INTEGER
    );
  `);
  return drizzle(sqlite);
}

/** Minimal in-memory KvStore that records puts/deletes for assertions. */
function makeKv(): KvStore & { _store: Map<string, string>; _deletes: string[] } {
  const store = new Map<string, string>();
  const deletes: string[] = [];
  const kv: KvStore = {
    async get(key) {
      return store.get(key) ?? null;
    },
    async getJson<T>(key: string) {
      const v = store.get(key);
      return v ? (JSON.parse(v) as T) : null;
    },
    async put(key, value) {
      store.set(key, value as string);
    },
    async putJson(key, value) {
      store.set(key, JSON.stringify(value));
    },
    async delete(key) {
      store.delete(key);
      deletes.push(key);
    },
    async list() {
      return { keys: [], list_complete: true };
    },
  };
  return Object.assign(kv, { _store: store, _deletes: deletes });
}

describe('AppSettingsService', () => {
  let svc: AppSettingsService;
  let kv: ReturnType<typeof makeKv>;

  beforeEach(() => {
    const db = makeDb();
    kv = makeKv();
    svc = new AppSettingsService(db, kv, new Logger('error'));
  });

  it('returns compiled-in defaults when the DB is empty', async () => {
    const all = await svc.getAll();
    expect(all['outline.enabled']).toBe(false);
    expect(all['remnawave.enabled']).toBe(true);
    expect(all['subscription.default_backend']).toBe('remnawave');
    expect(all['subscription.user_choice_enabled']).toBe(false);
  });

  it('layers DB overrides over the defaults', async () => {
    await svc.set('outline.enabled', true, 1);
    const all = await svc.getAll();
    expect(all['outline.enabled']).toBe(true);
    // Untouched keys should still come from defaults.
    expect(all['remnawave.enabled']).toBe(true);
  });

  it('round-trips a string-record (backend_labels) without mangling JSON', async () => {
    await svc.set('subscription.backend_labels', { remnawave: 'Modern', outline: 'Classic' }, 1);
    const labels = await svc.get('subscription.backend_labels');
    expect(labels).toEqual({ remnawave: 'Modern', outline: 'Classic' });
  });

  it('throws when set() gets a value that fails its schema', async () => {
    // `subscription.default_backend` is an enum — 'wireguard' is invalid.
    await expect(
      svc.set('subscription.default_backend', 'wireguard' as never, 1),
    ).rejects.toThrow();
  });

  it('throws on an unknown key', async () => {
    await expect(svc.set('not.a.real.key' as never, 'whatever' as never, 1)).rejects.toThrow(
      /Unknown setting key/,
    );
  });

  it('invalidates the KV cache on write so the next read goes to DB', async () => {
    // Prime the cache.
    await svc.getAll();
    expect(kv._store.has('app:settings:all')).toBe(true);

    // Write — should drop the cache key.
    await svc.set('outline.enabled', true, 1);
    expect(kv._deletes).toContain('app:settings:all');
    expect(kv._store.has('app:settings:all')).toBe(false);

    // Next read sees the new value (not the stale cached default).
    const all = await svc.getAll();
    expect(all['outline.enabled']).toBe(true);
  });

  it('setMany applies all keys atomically (well, sequentially) and validates each', async () => {
    await svc.setMany(
      {
        'outline.enabled': true,
        'subscription.default_backend': 'outline',
      },
      1,
    );
    const all = await svc.getAll();
    expect(all['outline.enabled']).toBe(true);
    expect(all['subscription.default_backend']).toBe('outline');
  });

  it('knownKeys() exposes the registered key list (used for OpenAPI generation)', () => {
    const keys = AppSettingsService.knownKeys();
    expect(keys).toContain('outline.enabled');
    expect(keys).toContain('subscription.default_backend');
  });

  it('skips DB rows for unknown keys without crashing (forward compat with future versions)', async () => {
    // Simulate a row from a future version that has settings we don't know
    // about. The service should ignore it rather than throw.
    // Note: we bypass set() and write directly to the underlying DB to
    // simulate the future-row scenario.
    const db = (svc as unknown as { db: ReturnType<typeof makeDb> }).db;
    db.run(`INSERT INTO app_settings (key, value) VALUES ('future.feature', '"on"')`);

    const all = await svc.getAll();
    // Defaults still come through.
    expect(all['outline.enabled']).toBe(false);
    // The unknown row is silently skipped — no crash, no entry in `all`.
    expect((all as Record<string, unknown>)['future.feature']).toBeUndefined();
  });
});
