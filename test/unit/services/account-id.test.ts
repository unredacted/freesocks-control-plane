import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { eq } from 'drizzle-orm';
import * as schema from '../../../src/server/db/schema';
import { AccountIdService } from '../../../src/server/services/account-id';
import { sha256Hex } from '../../../src/server/lib/crypto';

function makeDb() {
  const sqlite = new Database(':memory:');
  sqlite.pragma('journal_mode = MEMORY');
  sqlite.exec(`
    CREATE TABLE tiers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT,
      backend TEXT NOT NULL DEFAULT 'remnawave',
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
      account_id_hash TEXT,
      account_id_prefix TEXT,
      account_id_created_at INTEGER,
      account_id_rotated_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE UNIQUE INDEX idx_users_account_id_hash ON users(account_id_hash) WHERE account_id_hash IS NOT NULL;
  `);
  return drizzle(sqlite, { schema }) as never;
}

async function seedUser(db: ReturnType<typeof makeDb>, status = 'active') {
  await db
    .insert(schema.tiers)
    .values({ slug: 'free', name: 'Free', isDefaultFree: 1 })
    .onConflictDoNothing();
  const tier = await db.select().from(schema.tiers).limit(1).all();
  const inserted = await db
    .insert(schema.users)
    .values({ tierId: tier[0]!.id, status })
    .returning();
  return inserted[0]!;
}

describe('AccountIdService static helpers', () => {
  it('normalize strips spaces and hyphens', () => {
    expect(AccountIdService.normalize(' 1234 5678-9012 3456 ')).toBe('1234567890123456');
  });

  it('isValidFormat accepts exactly 16 digits and rejects anything else', () => {
    expect(AccountIdService.isValidFormat('1234567890123456')).toBe(true);
    expect(AccountIdService.isValidFormat('123456789012345')).toBe(false); // 15
    expect(AccountIdService.isValidFormat('12345678901234567')).toBe(false); // 17
    expect(AccountIdService.isValidFormat('123456789012345a')).toBe(false);
  });

  it('format groups into four quads', () => {
    expect(AccountIdService.format('1234567890123456')).toBe('1234 5678 9012 3456');
  });

  it('generate yields 16 unbiased digits and varies between calls', () => {
    for (let i = 0; i < 50; i++) {
      const n = AccountIdService.generate();
      expect(n).toMatch(/^\d{16}$/);
    }
    // Two consecutive generations colliding is astronomically unlikely.
    expect(AccountIdService.generate()).not.toBe(AccountIdService.generate());
  });
});

describe('AccountIdService.assignToUser / findUserIdByAccountId', () => {
  let db: ReturnType<typeof makeDb>;
  let svc: AccountIdService;

  beforeEach(() => {
    db = makeDb();
    svc = new AccountIdService(db);
  });

  it('mints a number, stores its hash + prefix + createdAt, and round-trips on lookup', async () => {
    const user = await seedUser(db);
    const minted = await svc.assignToUser(user.id);
    expect(minted.plaintext).toMatch(/^\d{16}$/);
    expect(minted.prefix).toBe(minted.plaintext.slice(0, 4));

    const row = (
      await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all()
    )[0]!;
    expect(row.accountIdHash).toBe(await sha256Hex(minted.plaintext));
    expect(row.accountIdPrefix).toBe(minted.prefix);
    expect(row.accountIdCreatedAt).not.toBeNull();
    expect(row.accountIdRotatedAt).toBeNull();

    // Lookup by the same number (and a normalized, spaced variant) finds the user.
    expect(await svc.findUserIdByAccountId(minted.plaintext)).toBe(user.id);
    expect(
      await svc.findUserIdByAccountId(
        AccountIdService.normalize(AccountIdService.format(minted.plaintext)),
      ),
    ).toBe(user.id);
  });

  it('rotate stamps rotatedAt and invalidates the previous number', async () => {
    const user = await seedUser(db);
    const first = await svc.assignToUser(user.id);
    const second = await svc.assignToUser(user.id, { rotate: true });
    expect(second.plaintext).not.toBe(first.plaintext);

    const row = (
      await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all()
    )[0]!;
    expect(row.accountIdRotatedAt).not.toBeNull();

    // Old number no longer resolves; new one does.
    expect(await svc.findUserIdByAccountId(first.plaintext)).toBeNull();
    expect(await svc.findUserIdByAccountId(second.plaintext)).toBe(user.id);
  });

  it('returns null for an unknown number', async () => {
    expect(await svc.findUserIdByAccountId('0000000000000000')).toBeNull();
  });

  it('does not resolve disabled or deleted owners', async () => {
    const disabled = await seedUser(db, 'disabled');
    const m = await svc.assignToUser(disabled.id);
    expect(await svc.findUserIdByAccountId(m.plaintext)).toBeNull();
  });

  it('the partial UNIQUE index actually blocks duplicate hashes (collision-retry backstop)', async () => {
    const a = await seedUser(db);
    const b = await seedUser(db);
    const minted = await svc.assignToUser(a.id);
    // Forcing B to the same hash must throw — this is the constraint that
    // assignToUser's retry depends on.
    await expect(
      db.update(schema.users).set({ accountIdHash: minted.hash }).where(eq(schema.users.id, b.id)),
    ).rejects.toThrow();
  });
});
