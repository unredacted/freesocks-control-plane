import { env } from 'cloudflare:test';
import { describe, expect, it, beforeEach } from 'vitest';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import * as schema from '../../src/server/db/schema';
import { MembershipSyncService } from '../../src/server/services/membership-sync';
import { TierPolicyService } from '../../src/server/services/tier-policy';
import { AuditService } from '../../src/server/services/audit';
import { EmailDeliveryService } from '../../src/server/services/email-delivery';
import { ConsoleEmailProvider } from '../../src/server/providers/email/console';
import { BackendRegistry } from '../../src/server/services/backend-registry';
import { CloudflareKvStore } from '../../src/server/kv/cloudflare';
import { Logger } from '../../src/server/lib/logger';
import type { PlatformConfig } from '../../src/server/platform/interface';

const config = {
  WEBAUTHN_ORIGIN: 'https://example.com',
  EMAIL_REPLY_TO: 'reply@example.com',
} as unknown as PlatformConfig;

async function resetTables(): Promise<void> {
  const db = drizzle(env.DB, { schema });
  // FK-safe order
  await db.delete(schema.tierHistory).run();
  await db.delete(schema.subscriptions).run();
  await db.delete(schema.emailLog).run();
  await db.delete(schema.auditLog).run();
  await db.delete(schema.users).run();
  await db.delete(schema.tiers).run();
  await db.delete(schema.appState).run();
  const kv = new CloudflareKvStore(env.FS_CACHE_KV);
  await kv.delete('tiers:all');
}

async function seedTiers() {
  const db = drizzle(env.DB, { schema });
  const free = await db
    .insert(schema.tiers)
    .values({
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
    })
    .returning();
  const member = await db
    .insert(schema.tiers)
    .values({
      slug: 'member',
      name: 'Standard Member',
      monthlyTrafficGb: 500,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: 1,
      trafficStrategy: 'MONTH',
      isDefaultFree: 0,
      isActive: 1,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
    })
    .returning();
  return { free: free[0]!, member: member[0]! };
}

async function seedUser(opts: {
  email: string;
  tierId: number;
  status?: string;
  membershipExpiresAt?: number | null;
}) {
  const db = drizzle(env.DB, { schema });
  const inserted = await db
    .insert(schema.users)
    .values({
      email: opts.email,
      tierId: opts.tierId,
      status: opts.status ?? 'active',
      membershipExpiresAt: opts.membershipExpiresAt ?? null,
    })
    .returning();
  return inserted[0]!;
}

function buildSyncService(): MembershipSyncService {
  const db = drizzle(env.DB, { schema });
  const logger = new Logger('error');
  const kv = new CloudflareKvStore(env.FS_CACHE_KV);
  const tierPolicy = new TierPolicyService(db, kv, logger);
  const audit = new AuditService(db, logger);
  const email = new EmailDeliveryService(new ConsoleEmailProvider(), db, config, logger);
  // No active subscriptions are seeded, so the backend registry is never
  // invoked — pushTierToBackend / disableBackendForUser short-circuit when the
  // user has no active subscription. An empty registry is sufficient.
  const backends = new BackendRegistry(new Map());
  return new MembershipSyncService({
    db,
    backends,
    tierPolicy,
    audit,
    email,
    logger,
    config,
  });
}

describe('MembershipSyncService.setMembership (entitlement seam)', () => {
  beforeEach(async () => {
    await resetTables();
  });

  it('upgrades a free user to member tier, writes tier_history, and logs a welcome email', async () => {
    const { free, member } = await seedTiers();
    const user = await seedUser({ email: 'alice@example.com', tierId: free.id });

    const sync = buildSyncService();
    await sync.setMembership({
      userId: user.id,
      tierId: member.id,
      expiresAtMs: Date.parse('2026-12-31'),
      reason: 'billing.upgrade',
    });

    const db = drizzle(env.DB, { schema });
    const after = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all();
    expect(after[0]!.tierId).toBe(member.id);
    expect(after[0]!.membershipExpiresAt).toBe(Date.parse('2026-12-31'));

    const history = await db
      .select()
      .from(schema.tierHistory)
      .where(eq(schema.tierHistory.userId, user.id))
      .all();
    expect(history).toHaveLength(1);
    expect(history[0]!.fromTierId).toBe(free.id);
    expect(history[0]!.toTierId).toBe(member.id);
    expect(history[0]!.reason).toBe('billing.upgrade');

    // Welcome email log written with the dedupe key.
    const emails = await db.select().from(schema.emailLog).all();
    expect(emails).toHaveLength(1);
    expect(emails[0]!.templateKey).toBe('member.welcome');
    expect(emails[0]!.dedupeKey).toBe(`welcome:user:${user.id}:tier:${member.id}`);
  });

  it('updates only the expiry (no tier_history, no email) when the tier is unchanged', async () => {
    const { member } = await seedTiers();
    const user = await seedUser({
      email: 'renew@example.com',
      tierId: member.id,
      membershipExpiresAt: Date.parse('2026-06-30'),
    });

    const sync = buildSyncService();
    await sync.setMembership({
      userId: user.id,
      tierId: member.id,
      expiresAtMs: Date.parse('2027-06-30'),
      reason: 'billing.renew',
    });

    const db = drizzle(env.DB, { schema });
    const after = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all();
    expect(after[0]!.membershipExpiresAt).toBe(Date.parse('2027-06-30'));
    const history = await db.select().from(schema.tierHistory).all();
    expect(history).toHaveLength(0);
    const emails = await db.select().from(schema.emailLog).all();
    expect(emails).toHaveLength(0);
  });
});

describe('MembershipSyncService.runGraceSweep', () => {
  beforeEach(async () => {
    await resetTables();
  });

  it('transitions expired-active users to grace and emits a warning email', async () => {
    const { member } = await seedTiers();
    const yesterday = Date.now() - 86_400_000;
    const user = await seedUser({
      email: 'lapsed@example.com',
      tierId: member.id,
      status: 'active',
      membershipExpiresAt: yesterday,
    });

    const sync = buildSyncService();
    const result = await sync.runGraceSweep();
    expect(result.toGrace).toBeGreaterThanOrEqual(1);

    const db = drizzle(env.DB, { schema });
    const after = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all();
    expect(after[0]!.status).toBe('grace');

    const emails = await db.select().from(schema.emailLog).all();
    expect(emails.some((e) => e.templateKey === 'member.grace_warning')).toBe(true);
  });

  it('transitions long-expired grace users to disabled with a deduped email', async () => {
    const { member } = await seedTiers();
    const eightDaysAgo = Date.now() - 8 * 86_400_000;
    const user = await seedUser({
      email: 'long-lapsed@example.com',
      tierId: member.id,
      status: 'grace',
      membershipExpiresAt: eightDaysAgo,
    });

    const sync = buildSyncService();
    const result = await sync.runGraceSweep();
    expect(result.toDisabled).toBeGreaterThanOrEqual(1);

    const db = drizzle(env.DB, { schema });
    const after = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).all();
    expect(after[0]!.status).toBe('disabled');
    expect(after[0]!.disabledReason).toBe('membership_lapsed');

    const emails = await db.select().from(schema.emailLog).all();
    const disabledEmail = emails.find((e) => e.templateKey === 'member.disabled');
    expect(disabledEmail).toBeDefined();
    expect(disabledEmail!.dedupeKey).toBe(`disabled:user:${user.id}:expires:${eightDaysAgo}`);
  });
});
