import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { eq, sql } from 'drizzle-orm';
import * as schema from '../../../src/server/db/schema';
import { FreeTierService, type FreeGrantContext } from '../../../src/server/services/free-tier';
import { RateLimitService } from '../../../src/server/services/rate-limit';
import { AuditService } from '../../../src/server/services/audit';
import { TierPolicyService } from '../../../src/server/services/tier-policy';
import { Logger } from '../../../src/server/lib/logger';
import { RateLimitError } from '../../../src/server/lib/errors';
import type { KvStore } from '../../../src/server/kv/interface';
import type { PlatformConfig } from '../../../src/server/platform/interface';
import type {
  SubscriptionDeliveryService,
  SubscriptionRecord,
} from '../../../src/server/services/subscription-delivery';

class InMemoryKv implements KvStore {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string) {
    const r = this.store.get(key);
    if (!r) return null;
    if (r.expiresAt && r.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return r.value;
  }
  async getJson<T>(key: string) {
    const v = await this.get(key);
    return v ? (JSON.parse(v) as T) : null;
  }
  async put(key: string, value: string, opts?: { expirationTtl?: number }) {
    const expiresAt = opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
  }
  async putJson(key: string, value: unknown, opts?: { expirationTtl?: number }) {
    await this.put(key, JSON.stringify(value), opts);
  }
  async delete(key: string) {
    this.store.delete(key);
  }
  async list() {
    return { keys: [], list_complete: true };
  }
}

function makeDb() {
  const sqlite = new Database(':memory:');
  sqlite.pragma('journal_mode = MEMORY');
  // Just the tables free-tier needs.
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
    CREATE TABLE subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      backend TEXT NOT NULL DEFAULT 'remnawave',
      backend_user_id TEXT NOT NULL UNIQUE,
      backend_short_id TEXT NOT NULL UNIQUE,
      outline_server_id INTEGER,
      subscription_url TEXT NOT NULL,
      subscription_mirrors TEXT NOT NULL DEFAULT '[]',
      raw_content_hash TEXT,
      state TEXT NOT NULL DEFAULT 'active',
      deleted_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE TABLE tier_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      from_tier_id INTEGER,
      to_tier_id INTEGER NOT NULL,
      reason TEXT NOT NULL,
      triggered_by TEXT NOT NULL,
      membership_snapshot_id INTEGER,
      changed_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
    CREATE TABLE free_grants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ip_hash TEXT NOT NULL,
      ip_country TEXT,
      asn INTEGER,
      tls_fingerprint TEXT,
      turnstile_action TEXT,
      turnstile_cdata TEXT,
      user_agent_hash TEXT,
      granted_day_bucket INTEGER NOT NULL,
      granted_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      slot INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX idx_free_grants_ip_day_slot ON free_grants (ip_hash, granted_day_bucket, slot);
    CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_type TEXT NOT NULL,
      actor_id TEXT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      payload TEXT,
      request_id TEXT,
      ip_hash TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
    );
  `);
  return drizzle(sqlite, { schema }) as never;
}

const config = {
  FREE_TIER_DAILY_CAP: 1,
  FREE_TIER_EXPIRY_DAYS: 90,
  IP_HASH_SALT: 'test-salt',
  EMAIL_REPLY_TO: 'reply@example.com',
} as unknown as PlatformConfig;

interface FakeSubscription {
  uuidCounter: number;
}

/**
 * Stub SubscriptionDeliveryService that just inserts a row in the test DB and
 * returns the record. We don't go anywhere near Remnawave or S3.
 */
function makeSubscriptionStub(
  db: ReturnType<typeof makeDb>,
  state: FakeSubscription,
): SubscriptionDeliveryService {
  return {
    issueNew: async ({
      userId,
      backend,
    }: {
      userId: number;
      backend: 'remnawave' | 'outline';
    }): Promise<SubscriptionRecord> => {
      state.uuidCounter += 1;
      const backendUserId = `${backend}-user-${state.uuidCounter}`;
      const backendShortId = `${backend}-short-${state.uuidCounter}`;
      const subscriptionUrl = `https://rw.example.com/${backendShortId}`;
      const mirrors = [
        {
          provider: 'r2',
          publicUrl: `https://m.example.com/${backendShortId}`,
          objectPath: `keys/${backendShortId}`,
        },
      ];
      const inserted = await db
        .insert(schema.subscriptions)
        .values({
          userId,
          backend,
          backendUserId,
          backendShortId,
          subscriptionUrl,
          subscriptionMirrors: JSON.stringify(mirrors),
          state: 'active',
        })
        .returning();
      return {
        id: inserted[0]!.id,
        userId,
        backend,
        backendUserId,
        backendShortId,
        subscriptionUrl,
        mirrors,
      };
    },
    deleteSubscription: async () => {
      // no-op for tests
    },
  } as unknown as SubscriptionDeliveryService;
}

function buildSvc() {
  const db = makeDb();
  const kv = new InMemoryKv();
  const logger = new Logger('error');
  const rateLimit = new RateLimitService(kv, 'test-salt');
  const tierPolicy = new TierPolicyService(db, kv, logger);
  const audit = new AuditService(db, logger);
  const fakeSubState: FakeSubscription = { uuidCounter: 0 };
  const subscription = makeSubscriptionStub(db, fakeSubState);
  // Seed default free tier
  return {
    db,
    kv,
    rateLimit,
    tierPolicy,
    audit,
    subscription,
    fakeSubState,
    svc: new FreeTierService({
      db,
      rateLimit,
      tierPolicy,
      subscription,
      audit,
      logger,
      config,
    }),
  };
}

async function seedFreeTier(db: ReturnType<typeof makeDb>) {
  await db.insert(schema.tiers).values({
    slug: 'free',
    name: 'Free',
    monthlyTrafficGb: 50,
    deviceLimit: 1,
    hwidLimit: 1,
    hwidEnabled: 1,
    trafficStrategy: 'MONTH',
    isDefaultFree: 1,
    isActive: 1,
    priority: 0,
    expirationDaysAfterMembershipLapse: 7,
  });
}

const baseCtx = (ip = '1.2.3.4'): FreeGrantContext => ({
  ip,
  ipCountry: 'US',
  asn: 7922,
  requestId: 'test-req-1',
});

describe('FreeTierService — collision (Flow H)', () => {
  let env: ReturnType<typeof buildSvc>;

  beforeEach(async () => {
    env = buildSvc();
    await seedFreeTier(env.db);
  });

  it('first request from an IP issues a fresh subscription', async () => {
    const out = await env.svc.issueOrReissue(baseCtx('10.0.0.1'));
    expect(out.reissued).toBe(false);
    expect(out.subscription.url).toMatch(/remnawave-short-1$/);
    // free_grants should have one row for this IP+day
    const grants = await env.db.select().from(schema.freeGrants).all();
    expect(grants).toHaveLength(1);
  });

  it('atomic slot claim rejects the (cap+1)-th grant for the same IP+day (closes H1 race)', async () => {
    // First issuance lands at slot 0.
    await env.svc.issueOrReissue(baseCtx('10.0.0.9'));
    const ipHash = await env.rateLimit.hashIp('10.0.0.9');
    const dayBucket = env.rateLimit.dayBucket();
    const grants = await env.db.select().from(schema.freeGrants).all();
    expect(grants).toHaveLength(1);
    expect(grants[0]!.slot).toBe(0);

    // A racing issuance that slipped past the count pre-check would recompute
    // slot = COUNT % cap = 1 % 1 = 0, colliding with the row above. Mimic that
    // exact insert and assert onConflictDoNothing makes it a no-op (empty
    // .returning()) rather than a 2nd grant — this IS the atomic cap, enforced
    // by the unique (ip_hash, granted_day_bucket, slot) index.
    const extraUser = await env.db
      .insert(schema.users)
      .values({ tierId: 1, status: 'active' })
      .returning();
    const claim = await env.db
      .insert(schema.freeGrants)
      .values({
        userId: extraUser[0]!.id,
        ipHash,
        grantedDayBucket: dayBucket,
        slot: sql`((SELECT COUNT(*) FROM free_grants WHERE ip_hash = ${ipHash} AND granted_day_bucket = ${dayBucket}) % 1)`,
      })
      .onConflictDoNothing({
        target: [
          schema.freeGrants.ipHash,
          schema.freeGrants.grantedDayBucket,
          schema.freeGrants.slot,
        ],
      })
      .returning();
    expect(claim).toHaveLength(0);
    const after = await env.db.select().from(schema.freeGrants).all();
    expect(after).toHaveLength(1);
  });

  it('second request from same IP same day returns the existing subscription with banner', async () => {
    await env.svc.issueOrReissue(baseCtx('10.0.0.2'));
    const out = await env.svc.issueOrReissue(baseCtx('10.0.0.2'));
    expect(out.reissued).toBe(true);
    expect(out.banner).toMatch(/already requested/i);
    // Same subscription returned
    expect(out.subscription.url).toMatch(/remnawave-short-1$/);
    // Still only one user, one grant — the second call did NOT issue a new key.
    const users = await env.db.select().from(schema.users).all();
    expect(users).toHaveLength(1);
    const subs = await env.db.select().from(schema.subscriptions).all();
    expect(subs).toHaveLength(1);
  });

  it('D1 backstop catches the case where KV lets a 2nd concurrent request slip through', async () => {
    // Issue once normally to seed free_grants.
    await env.svc.issueOrReissue(baseCtx('10.0.0.3'));

    // Simulate KV race: forcibly clear the rate-limit counter so the second
    // call sees 0/1 and would otherwise issue a fresh key. The D1 backstop
    // should still catch it via the priorGrants count check and return the
    // existing key with banner.
    const ipHash = await env.rateLimit.hashIp('10.0.0.3');
    const dayBucket = env.rateLimit.dayBucket();
    const key = `rl:free:ip:${ipHash}:${dayBucket}`;
    await env.kv.delete(key);

    const out = await env.svc.issueOrReissue(baseCtx('10.0.0.3'));
    expect(out.reissued).toBe(true);
    expect(out.banner).toMatch(/already requested/i);
    // Critically, no new user was inserted by the racey second request.
    const users = await env.db.select().from(schema.users).all();
    expect(users).toHaveLength(1);
  });

  it('NAT collision (≥2 grants from same IP+day) returns 429 instead of leaking a key', async () => {
    // Manually plant a second grant row to simulate NAT collision (multiple
    // distinct users behind the same IP earlier in the day).
    const first = await env.svc.issueOrReissue(baseCtx('10.0.0.4'));
    const ipHash = await env.rateLimit.hashIp('10.0.0.4');
    const dayBucket = env.rateLimit.dayBucket();
    // Insert a 2nd freeGrants row with a different user.
    const secondUser = await env.db
      .insert(schema.users)
      .values({ tierId: 1, status: 'active' })
      .returning();
    await env.db.insert(schema.freeGrants).values({
      userId: secondUser[0]!.id,
      ipHash,
      grantedDayBucket: dayBucket,
      // Distinct slot — two grants legitimately coexist for a NATed IP (the
      // backfill/atomic path assigns 0,1,…); the new request must still be
      // rejected because the count (2) is already over cap.
      slot: 1,
    });

    // Now any new request from the same IP must NOT return either of the keys.
    await expect(env.svc.issueOrReissue(baseCtx('10.0.0.4'))).rejects.toThrow(RateLimitError);

    // Sanity: original key still exists.
    expect(first.subscription.url).toMatch(/remnawave-short-1$/);
  });

  it('different IPs are independent — no collision across networks', async () => {
    const a = await env.svc.issueOrReissue(baseCtx('10.0.0.5'));
    const b = await env.svc.issueOrReissue(baseCtx('10.0.0.6'));
    expect(a.reissued).toBe(false);
    expect(b.reissued).toBe(false);
    expect(a.subscription.url).not.toBe(b.subscription.url);
    const grants = await env.db.select().from(schema.freeGrants).all();
    expect(grants).toHaveLength(2);
    // Each grant has a different ipHash
    expect(grants[0]!.ipHash).not.toBe(grants[1]!.ipHash);
  });
});

describe('FreeTierService — cleanupExpired', () => {
  it('marks free-tier users older than expiry as deleted', async () => {
    const env = buildSvc();
    await seedFreeTier(env.db);

    // Issue today, then back-date the user's createdAt to >90 days ago.
    const out = await env.svc.issueOrReissue(baseCtx('10.0.0.7'));
    const ninetyOneDaysAgo = Date.now() - 91 * 86_400_000;
    await env.db
      .update(schema.users)
      .set({ createdAt: ninetyOneDaysAgo })
      .where(eq(schema.users.id, out.user.id));

    const removed = await env.svc.cleanupExpired();
    expect(removed).toBe(1);
    const after = await env.db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, out.user.id))
      .all();
    expect(after[0]!.status).toBe('deleted');
  });
});
