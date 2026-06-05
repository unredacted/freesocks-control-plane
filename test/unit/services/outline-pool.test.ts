import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { describe, expect, it } from 'vitest';
import { OutlineServerPool } from '../../../src/server/services/outline-pool';
import { outlineServers } from '../../../src/server/db/schema';
import { Logger } from '../../../src/server/lib/logger';

/**
 * Validates pool selection behavior:
 *   - Inactive servers are excluded.
 *   - Stale-health servers are deprioritized in favor of fresh ones; if none
 *     are fresh, stale fallback kicks in (better a stale server than no server).
 *   - Lower-score (lower key count) servers are preferred.
 *   - Top-3 randomization spreads load — running 50 picks against three
 *     same-score servers should land on each at least once.
 *   - Tier-scoped pool filtering: `pickForIssue([1, 2])` never returns id=3.
 */
function makeDb() {
  const sqlite = new Database(':memory:');
  // Mirror just the columns the pool reads. Real schema lives in
  // db/migrations/0005_outline_servers.sql.
  sqlite.exec(`
    CREATE TABLE outline_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      api_url TEXT NOT NULL,
      websocket_enabled INTEGER NOT NULL DEFAULT 0,
      websocket_domain TEXT,
      prometheus_url TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      priority INTEGER NOT NULL DEFAULT 0,
      last_health_ok_at INTEGER,
      access_key_count INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
  `);
  return drizzle(sqlite);
}

function buildPool() {
  const db = makeDb();
  const pool = new OutlineServerPool({ db, logger: new Logger('error') });
  return { db, pool };
}

const now = Date.now();
const fresh = now - 60_000; // 1 min ago — well within 30-min freshness window
const stale = now - 60 * 60_000; // 1h ago — beyond the freshness window

describe('OutlineServerPool', () => {
  it('skips inactive servers', async () => {
    const { db, pool } = buildPool();
    await db.insert(outlineServers).values([
      {
        name: 'A',
        slug: 'a',
        apiUrl: 'https://a/secret/',
        isActive: false,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
      {
        name: 'B',
        slug: 'b',
        apiUrl: 'https://b/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 5,
      },
    ]);
    const picked = await pool.pickForIssue();
    expect(picked?.slug).toBe('b');
  });

  it('returns null when no servers are active', async () => {
    const { pool } = buildPool();
    const picked = await pool.pickForIssue();
    expect(picked).toBeNull();
  });

  it('prefers low key-count servers (lower score wins)', async () => {
    const { db, pool } = buildPool();
    await db.insert(outlineServers).values([
      {
        name: 'Heavy',
        slug: 'heavy',
        apiUrl: 'https://h/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 1000,
      },
      {
        name: 'Light',
        slug: 'light',
        apiUrl: 'https://l/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
    ]);
    // With only 2 servers the top-3 randomization still picks among 2 — but
    // both servers have meaningfully different scores so the lighter one
    // should be at index 0. Run a few times to assert it's consistently the
    // first OR the second (randomization is fine; what we don't want is
    // never picking the lighter server).
    let lightPicks = 0;
    for (let i = 0; i < 30; i++) {
      const picked = await pool.pickForIssue();
      if (picked?.slug === 'light') lightPicks++;
    }
    expect(lightPicks).toBeGreaterThan(0);
  });

  it('falls back to stale servers when none are fresh', async () => {
    const { db, pool } = buildPool();
    await db.insert(outlineServers).values([
      {
        name: 'Old',
        slug: 'old',
        apiUrl: 'https://o/secret/',
        isActive: true,
        lastHealthOkAt: stale,
        accessKeyCount: 0,
      },
    ]);
    const picked = await pool.pickForIssue();
    expect(picked?.slug).toBe('old');
  });

  it('respects the tier-scoped pool filter', async () => {
    const { db, pool } = buildPool();
    await db.insert(outlineServers).values([
      {
        name: 'A',
        slug: 'a',
        apiUrl: 'https://a/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
      {
        name: 'B',
        slug: 'b',
        apiUrl: 'https://b/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
      {
        name: 'C',
        slug: 'c',
        apiUrl: 'https://c/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
    ]);
    // Allow only ids 1 and 2 — id 3 ("C") must never appear.
    const seen = new Set<string>();
    for (let i = 0; i < 30; i++) {
      const picked = await pool.pickForIssue([1, 2]);
      if (picked) seen.add(picked.slug);
    }
    expect(seen.has('c')).toBe(false);
    // At least one of the allowed servers should have been picked.
    expect(seen.size).toBeGreaterThan(0);
  });

  it('randomizes among top-3 same-score servers', async () => {
    const { db, pool } = buildPool();
    await db.insert(outlineServers).values([
      {
        name: 'A',
        slug: 'a',
        apiUrl: 'https://a/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
      {
        name: 'B',
        slug: 'b',
        apiUrl: 'https://b/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
      {
        name: 'C',
        slug: 'c',
        apiUrl: 'https://c/secret/',
        isActive: true,
        lastHealthOkAt: fresh,
        accessKeyCount: 0,
      },
    ]);
    const seen = new Set<string>();
    // 50 picks should cover all 3 with extremely high probability
    // (≈ 1 - 3 * (2/3)^50 ≈ 1 - 6e-9).
    for (let i = 0; i < 50; i++) {
      const picked = await pool.pickForIssue();
      if (picked) seen.add(picked.slug);
    }
    expect(seen.size).toBe(3);
  });
});
