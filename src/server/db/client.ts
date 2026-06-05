import { drizzle as drizzleD1, type DrizzleD1Database } from 'drizzle-orm/d1';
import { drizzle as drizzleSqlite, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import type { LibSQLDatabase } from 'drizzle-orm/libsql';
import * as schema from './schema';

/**
 * `Db` covers every supported runtime. Drizzle's three SQLite drivers all
 * expose the same query builder surface, so service-layer code is identical
 * across all three.
 *
 * Concrete driver picked at platform-adapter boot:
 *   - Cloudflare Workers → `createD1Client` (D1 binding)
 *   - Bun / Node self-host → `createSqliteClient` (better-sqlite3 file)
 *   - Fastly Compute → `createLibsqlClient` (Turso libSQL over HTTP)
 *
 * Migrations are SQLite-compatible across all three — Turso uses libSQL which
 * is a SQLite fork, and D1 is SQLite under the hood. Schema in
 * `db/schema.ts` is the single source of truth.
 */
export type Db =
  | DrizzleD1Database<typeof schema>
  | BetterSQLite3Database<typeof schema>
  | LibSQLDatabase<typeof schema>;

export function createD1Client(d1: D1Database): Db {
  return drizzleD1(d1, { schema });
}

export function createSqliteClient(filePath: string): Db {
  // Lazy import to avoid pulling better-sqlite3 into the Workers bundle.
  // On Workers this code path never runs.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Database = require('better-sqlite3');
  const sqlite = new Database(filePath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  return drizzleSqlite(sqlite, { schema });
}

/**
 * Connect to a Turso (or any libSQL-HTTP-compatible) database for the Fastly
 * Compute target. Both halves are lazily imported so the libsql client stays
 * out of the Workers and Node bundles — bundlers only pull it in for builds
 * that actually reference this function.
 *
 * Use `drizzle-orm/libsql/web` + `@libsql/client/web` for edge runtimes
 * (Fastly, Cloudflare Workers) — those subpaths use fetch under the hood and
 * avoid any Node-specific dependencies. The non-`/web` variants pull in
 * better-sqlite3-style native bindings that won't compile to WASM.
 */
export async function createLibsqlClient(opts: { url: string; authToken?: string }): Promise<Db> {
  const [{ createClient }, { drizzle }] = await Promise.all([
    import('@libsql/client/web'),
    import('drizzle-orm/libsql/web'),
  ]);
  const client = createClient({ url: opts.url, authToken: opts.authToken });
  return drizzle(client, { schema });
}

export { schema };
