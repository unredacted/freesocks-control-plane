/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seedFreeTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: 'free',
      name: 'Free',
      backend: 'remnawave',
      monthlyTrafficGb: 50,
      deviceLimit: 1,
      hwidLimit: 1,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      isActive: true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    }),
  );
}

describe('freeTier.claimFreeSlot', () => {
  // NOTE: claimFreeSlot's true OCC race-safety (two concurrent racers can never
  // both observe `< cap`) was proven against the LIVE Convex backend; convex-test
  // runs mutations single-threaded, so these calls are SEQUENTIAL; they assert
  // the cap arithmetic, not the concurrency guarantee.
  test('claims up to cap N, then refuses', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const cap = 3;
    const base = { ipHash: 'iphash-cap', dayBucket, cap, tierId };

    for (let i = 0; i < cap; i++) {
      const r = await t.mutation(internal.freeTier.claimFreeSlot, base);
      expect(r.claimed).toBe(true);
    }
    const over = await t.mutation(internal.freeTier.claimFreeSlot, base);
    expect(over.claimed).toBe(false);
  });

  test('distinct IPs have independent caps', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const a = { ipHash: 'ip-a', dayBucket, cap: 1, tierId };
    const b = { ipHash: 'ip-b', dayBucket, cap: 1, tierId };

    expect((await t.mutation(internal.freeTier.claimFreeSlot, a)).claimed).toBe(true);
    expect((await t.mutation(internal.freeTier.claimFreeSlot, a)).claimed).toBe(false);
    expect((await t.mutation(internal.freeTier.claimFreeSlot, b)).claimed).toBe(true);
  });

  test('a successful claim inserts a bare user + a grant', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const r = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-insert',
      dayBucket,
      cap: 1,
      tierId,
      ipCountry: 'IR',
    });
    expect(r.claimed).toBe(true);
    if (!r.claimed) throw new Error('unreachable');
    await t.run(async (ctx) => {
      const user = await ctx.db.get(r.userId);
      expect(user?.status).toBe('active');
      expect(user?.tierId).toBe(tierId);
      const grant = await ctx.db.get(r.grantId);
      expect(grant?.ipHash).toBe('ip-insert');
      expect(grant?.ipCountry).toBe('IR');
      expect(grant?.grantedDayBucket).toBe(dayBucket);
    });
  });
});

describe('freeTier.releaseFreeSlot', () => {
  test('deletes both the grant and the bare user', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const r = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-release',
      dayBucket,
      cap: 1,
      tierId,
    });
    if (!r.claimed) throw new Error('expected claim');

    await t.mutation(internal.freeTier.releaseFreeSlot, { userId: r.userId, grantId: r.grantId });
    await t.run(async (ctx) => {
      expect(await ctx.db.get(r.userId)).toBeNull();
      expect(await ctx.db.get(r.grantId)).toBeNull();
      // The freed slot is reclaimable.
    });
    const again = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-release',
      dayBucket,
      cap: 1,
      tierId,
    });
    expect(again.claimed).toBe(true);
  });
});

describe('freeTier.grantsForIpDay', () => {
  test('counts grants for the (ipHash, dayBucket)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket,
      cap: 5,
      tierId,
    });
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket,
      cap: 5,
      tierId,
    });
    // A different day bucket must not be counted.
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket: dayBucket - 1,
      cap: 5,
      tierId,
    });

    const grants = await t.query(internal.freeTier.grantsForIpDay, {
      ipHash: 'ip-count',
      dayBucket,
    });
    expect(grants).toHaveLength(2);
  });
});

describe('freeTier.createFreeAccount', () => {
  // Account creation is now decoupled from proxy issuance: no Turnstile (verified
  // upstream in http.ts) and no backend instance is required. These run the
  // action directly with env stubbed like auth.test.ts.
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    vi.stubEnv('FREE_TIER_DAILY_CAP', '1');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test('mints a user + account number + member session, with NO subscription or backend call', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);

    const res = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.20',
      ipCountry: 'IR',
      requestId: 'req-create-1',
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    // Reveal-once 32-digit number + a signed session cookie value.
    expect(res.accountId).toMatch(/^\d{32}$/);
    expect(res.signedCookieValue).toContain('.');
    expect(res.maxAgeSec).toBeGreaterThan(0);
    expect(res.tier.slug).toBe('free');
    expect(res.tier.backend).toBe('remnawave');

    await t.run(async (ctx) => {
      // The user is on the free tier with an account-number hash + prefix.
      const user = await ctx.db.get(res.userId);
      expect(user?.tierId).toBe(tierId);
      expect(user?.status).toBe('active');
      expect(typeof user?.accountIdHash).toBe('string');
      expect(res.accountId.startsWith(user!.accountIdPrefix!)).toBe(true);

      // A member session row exists for the user.
      const sessions = await ctx.db
        .query('sessions')
        .filter((q) => q.eq(q.field('userId'), res.userId))
        .collect();
      expect(sessions).toHaveLength(1);
      expect(sessions[0]!.kind).toBe('member');

      // tierHistory 'initial' + audit 'user.create.free' were written.
      const history = await ctx.db
        .query('tierHistory')
        .filter((q) => q.eq(q.field('userId'), res.userId))
        .collect();
      expect(history.some((h) => h.reason === 'initial')).toBe(true);
      const audits = await ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'user.create.free'))
        .collect();
      expect(audits.length).toBeGreaterThanOrEqual(1);

      // The decoupling guarantee: account creation creates NO subscription row.
      const subs = await ctx.db.query('subscriptions').collect();
      expect(subs).toHaveLength(0);
    });
  });

  test('binds the PoP public key onto the session when provided', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    const res = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.21',
      requestId: 'req-create-2',
      popPublicKey: 'pub-key-b64',
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    await t.run(async (ctx) => {
      const session = await ctx.db
        .query('sessions')
        .filter((q) => q.eq(q.field('userId'), res.userId))
        .unique();
      expect(session?.popPublicKey).toBe('pub-key-b64');
    });
  });

  test('a second account from the same IP/day is capped (cap_reached, no second user)', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    const first = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.22',
      requestId: 'req-cap-1',
    });
    expect(first.ok).toBe(true);
    const second = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.22',
      requestId: 'req-cap-2',
    });
    expect(second).toEqual({ ok: false, reason: 'cap_reached' });
    await t.run(async (ctx) => {
      const users = await ctx.db.query('users').collect();
      expect(users).toHaveLength(1);
    });
  });
});
