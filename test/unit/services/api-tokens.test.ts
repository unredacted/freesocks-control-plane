import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { eq } from 'drizzle-orm';
import * as schema from '../../../src/server/db/schema';
import { ApiTokenService, TOKEN_PREFIX } from '../../../src/server/services/api-tokens';
import { Logger } from '../../../src/server/lib/logger';

function makeDb() {
  const sqlite = new Database(':memory:');
  sqlite.pragma('journal_mode = MEMORY');
  // Recreate just the tables we need (we don't run the migration files in unit tests).
  sqlite.exec(`
    CREATE TABLE admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      email TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      last_login_at INTEGER
    );
    CREATE TABLE tiers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT,
      monthly_traffic_gb INTEGER NOT NULL DEFAULT 0,
      device_limit INTEGER NOT NULL DEFAULT 1,
      hwid_limit INTEGER NOT NULL DEFAULT 1,
      hwid_enabled INTEGER NOT NULL DEFAULT 1,
      traffic_strategy TEXT NOT NULL DEFAULT 'MONTH',
      remnawave_squad_uuid TEXT,
      is_default_free INTEGER NOT NULL DEFAULT 0,
      is_active INTEGER NOT NULL DEFAULT 1,
      priority INTEGER NOT NULL DEFAULT 0,
      expiration_days_after_membership_lapse INTEGER NOT NULL DEFAULT 7,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      authentik_subject TEXT UNIQUE,
      email TEXT,
      email_verified_at INTEGER,
      tier_id INTEGER NOT NULL,
      current_subscription_id INTEGER,
      status TEXT NOT NULL DEFAULT 'active',
      disabled_reason TEXT,
      membership_expires_at INTEGER,
      last_membership_check_at INTEGER,
      suspended_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE TABLE api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      created_by_admin_id INTEGER NOT NULL,
      scopes TEXT NOT NULL DEFAULT '[]',
      subject_type TEXT NOT NULL DEFAULT 'service',
      subject_user_id INTEGER,
      expires_at INTEGER,
      last_used_at INTEGER,
      revoked_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
  `);
  const db = drizzle(sqlite, { schema });
  // Seed an admin user for the FK
  sqlite
    .prepare("INSERT INTO admin_users (id, username, display_name) VALUES (1, 'tester', 'Tester')")
    .run();
  return db as never;
}

describe('ApiTokenService', () => {
  let svc: ApiTokenService;
  let db: ReturnType<typeof makeDb>;

  beforeEach(() => {
    db = makeDb();
    svc = new ApiTokenService(db, new Logger('error'));
  });

  it('mints a token with the fsv1_ prefix', async () => {
    const result = await svc.create({
      name: 'test',
      scopes: ['subscription:read'],
      subjectType: 'service',
      createdByAdminId: 1,
    });
    expect(result.plaintext).toMatch(new RegExp(`^${TOKEN_PREFIX}[A-Za-z0-9_-]+$`));
    expect(result.prefix).toBe(result.plaintext.slice(0, 12));
    expect(result.id).toBeGreaterThan(0);
  });

  it('resolves a freshly minted token to its scopes', async () => {
    const minted = await svc.create({
      name: 'test',
      scopes: ['admin:tiers:read', 'admin:users:write'],
      subjectType: 'service',
      createdByAdminId: 1,
    });
    const resolved = await svc.resolve(minted.plaintext);
    expect(resolved).not.toBeNull();
    expect(resolved?.scopes).toEqual(['admin:tiers:read', 'admin:users:write']);
    expect(resolved?.subjectType).toBe('service');
  });

  it('refuses tokens lacking the fsv1_ prefix', async () => {
    expect(await svc.resolve('eyJhbGciOiJSUzI1NiIs.fake.jwt')).toBeNull();
    expect(await svc.resolve('')).toBeNull();
  });

  it('refuses revoked tokens', async () => {
    const minted = await svc.create({
      name: 'test',
      scopes: ['subscription:read'],
      subjectType: 'service',
      createdByAdminId: 1,
    });
    await svc.revoke(minted.id);
    expect(await svc.resolve(minted.plaintext)).toBeNull();
  });

  it('refuses expired tokens', async () => {
    const minted = await svc.create({
      name: 'test',
      scopes: ['subscription:read'],
      subjectType: 'service',
      expiresInDays: 1,
      createdByAdminId: 1,
    });
    // Backdate expires_at into the past
    await db
      .update(schema.apiTokens)
      .set({ expiresAt: Date.now() - 1000 })
      .where(eq(schema.apiTokens.id, minted.id));
    expect(await svc.resolve(minted.plaintext)).toBeNull();
  });

  it('two tokens minted in succession have different plaintexts', async () => {
    const a = await svc.create({
      name: 'a',
      scopes: ['subscription:read'],
      subjectType: 'service',
      createdByAdminId: 1,
    });
    const b = await svc.create({
      name: 'b',
      scopes: ['subscription:read'],
      subjectType: 'service',
      createdByAdminId: 1,
    });
    expect(a.plaintext).not.toBe(b.plaintext);
  });
});
