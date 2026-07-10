/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { bytesToB64Url } from '../src/shared/crypto/envelope';

const modules = import.meta.glob('./**/*.*s');

/** A real 65-byte P-256 public point (base64url) — sessions.create validates the
 *  byte length against the algorithm, so a placeholder string would not bind. */
async function p256PubB64(): Promise<string> {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return bytesToB64Url(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)));
}

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

/** Seed the W2 `freetier.create` policy (the per-(IP,day) cap) to `max`. */
async function seedFreeCap(t: ReturnType<typeof convexTest>, max: number): Promise<void> {
  await t.run(async (ctx) => {
    await ctx.db.insert('appSettings', {
      key: 'ratelimit.freetier.create',
      value: JSON.stringify({ max, windowMs: 86_400_000, enabled: true }),
      updatedAt: Date.now(),
    });
  });
}

describe('freeTier.createFreeUser / deleteFreeUser', () => {
  test('createFreeUser inserts a bare active user on the tier (no IP recorded)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const { userId } = await t.mutation(internal.freeTier.createFreeUser, { tierId });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.status).toBe('active');
      expect(user?.tierId).toBe(tierId);
      // The account-creation flow records NO freeGrants row (no stored IP).
      expect(await ctx.db.query('freeGrants').collect()).toHaveLength(0);
    });
  });

  test('deleteFreeUser removes the bare user', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const { userId } = await t.mutation(internal.freeTier.createFreeUser, { tierId });
    await t.mutation(internal.freeTier.deleteFreeUser, { userId });
    await t.run(async (ctx) => {
      expect(await ctx.db.get(userId)).toBeNull();
    });
  });
});

describe('freeTier.createFreeAccount', () => {
  // Account creation is decoupled from proxy issuance: no captcha here (verified
  // upstream in http.ts) and no backend instance is required. The per-(IP,day)
  // cap is the serializable `freetier.create` rate-limit counter; the IP is
  // hashed only to key that ephemeral bucket and is never stored durably.
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // A failure after the slot reservation must leave NO orphan — in particular no
  // member session pointing at the user the compensation deletes (the session is
  // created last, after cookie signing). Force mint to throw via an empty pepper.
  test('a failure after the slot claim leaves no orphan user/session/grant', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    vi.stubEnv('ACCOUNT_ID_PEPPER', ''); // mintForUser throws → catch → deleteFreeUser + release

    await expect(
      t.action(internal.freeTier.createFreeAccount, { ip: '203.0.113.99', requestId: 'req-fail' }),
    ).rejects.toThrow();

    await t.run(async (ctx) => {
      expect(await ctx.db.query('users').collect()).toHaveLength(0);
      expect(await ctx.db.query('sessions').collect()).toHaveLength(0);
      expect(await ctx.db.query('freeGrants').collect()).toHaveLength(0);
    });
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
    expect(res.accountId).toMatch(/^\d{32}$/);
    expect(res.signedCookieValue).toContain('.');
    expect(res.maxAgeSec).toBeGreaterThan(0);
    expect(res.tier.slug).toBe('free');
    expect(res.tier.backend).toBe('remnawave');

    await t.run(async (ctx) => {
      const user = await ctx.db.get(res.userId);
      expect(user?.tierId).toBe(tierId);
      expect(user?.status).toBe('active');
      expect(typeof user?.accountIdHash).toBe('string');
      expect(res.accountId.startsWith(user!.accountIdPrefix!)).toBe(true);

      const sessions = await ctx.db
        .query('sessions')
        .filter((q) => q.eq(q.field('userId'), res.userId))
        .collect();
      expect(sessions).toHaveLength(1);
      expect(sessions[0]!.kind).toBe('member');

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

  test('stores NO IP: freeGrants stays empty and the audit row carries no ipHash', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    const res = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.41',
      ipCountry: 'IR',
      requestId: 'req-noip',
    });
    expect(res.ok).toBe(true);
    await t.run(async (ctx) => {
      // No durable per-IP ledger row is written at all.
      expect(await ctx.db.query('freeGrants').collect()).toHaveLength(0);
      const audits = await ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'user.create.free'))
        .collect();
      expect(audits.length).toBeGreaterThanOrEqual(1);
      for (const a of audits) expect(a.ipHash).toBeUndefined();
      // The coarse, non-identifying country is still allowed (never the IP).
      expect(audits[0]!.payload?.ipCountry).toBe('IR');
    });
  });

  test('binds the PoP public key onto the session when provided', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    const popPublicKey = await p256PubB64();
    const res = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.21',
      requestId: 'req-create-2',
      popPublicKey,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    await t.run(async (ctx) => {
      const session = await ctx.db
        .query('sessions')
        .filter((q) => q.eq(q.field('userId'), res.userId))
        .unique();
      expect(session?.popPublicKey).toBe(popPublicKey);
      expect(session?.popAlg).toBe('ES256'); // no popAlg supplied → P-256 default
    });
  });

  test('the per-(IP,day) cap holds: a second account from the same IP is cap_reached', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    await seedFreeCap(t, 1); // cap of 1 for this test
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
      expect(await ctx.db.query('users').collect()).toHaveLength(1);
    });
  });

  test('distinct IPs have independent caps', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    await seedFreeCap(t, 1);
    expect(
      (await t.action(internal.freeTier.createFreeAccount, { ip: '198.51.100.1', requestId: 'a' }))
        .ok,
    ).toBe(true);
    expect(
      (await t.action(internal.freeTier.createFreeAccount, { ip: '198.51.100.1', requestId: 'a2' }))
        .ok,
    ).toBe(false);
    // A different IP is unaffected.
    expect(
      (await t.action(internal.freeTier.createFreeAccount, { ip: '198.51.100.2', requestId: 'b' }))
        .ok,
    ).toBe(true);
  });

  test('a released slot (failed create) is reclaimable under the cap', async () => {
    const t = convexTest(schema, modules);
    await seedFreeTier(t);
    await seedFreeCap(t, 1);
    // First attempt reserves the only slot, then fails in mint → the catch
    // releases the slot (decrements the counter).
    vi.stubEnv('ACCOUNT_ID_PEPPER', '');
    await expect(
      t.action(internal.freeTier.createFreeAccount, { ip: '203.0.113.30', requestId: 'r1' }),
    ).rejects.toThrow();
    // The slot was given back, so a fresh attempt from the SAME IP still succeeds
    // (it would be cap_reached if the failed attempt had burned the only slot).
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const ok = await t.action(internal.freeTier.createFreeAccount, {
      ip: '203.0.113.30',
      requestId: 'r2',
    });
    expect(ok.ok).toBe(true);
  });
});
