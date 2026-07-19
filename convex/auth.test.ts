/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { formatAccountId } from './lib/accountId';

const modules = import.meta.glob('./**/*.*s');

function stubFetch(success: boolean) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify({ success }), { status: 200 })),
  );
}

/** Seed a user with a freshly-minted account number; returns the plaintext + id. */
async function seedUserWithAccount(
  t: ReturnType<typeof convexTest>,
  status: 'active' | 'disabled' = 'active',
): Promise<{ userId: Id<'users'>; accountId: string }> {
  const userId = await t.run(async (ctx) => {
    const tierId = await ctx.db.insert('tiers', {
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
    });
    return ctx.db.insert('users', { tierId, status, updatedAt: Date.now() });
  });
  const minted = await t.action(internal.accountId.mintForUser, { userId });
  return { userId, accountId: minted.accountId };
}

describe('auth.accountLogin', () => {
  beforeEach(() => {
    // W1: self-hosted Cap captcha config (fetch is stubbed to return {success}).
    vi.stubEnv('CAP_API_ENDPOINT', 'http://cap:3000');
    vi.stubEnv('CAP_SITE_KEY', 'sk_test');
    vi.stubEnv('CAP_SECRET', 'secret_test');
    vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('correct number with passing Turnstile logs in', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    const { userId, accountId } = await seedUserWithAccount(t);

    const res = await t.action(internal.auth.accountLogin, {
      accountId,
      captchaToken: 'tok',
      ip: '203.0.113.7',
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    expect(res.userId).toBe(userId);
    expect(res.signedCookieValue).toContain('.');
    expect(res.maxAgeSec).toBeGreaterThan(0);
    expect(res.lapsedDowngrade).toBeFalsy(); // a normal (active) login didn't downgrade (Review #4)

    // A real session row was created for the user.
    await t.run(async (ctx) => {
      const sessions = await ctx.db
        .query('sessions')
        .filter((q) => q.eq(q.field('userId'), userId))
        .collect();
      expect(sessions).toHaveLength(1);
      expect(sessions[0]!.kind).toBe('member');
    });
  });

  test('accepts the formatted (spaced) form of the number', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId: formatAccountId(accountId),
      captchaToken: 'tok',
      ip: '203.0.113.8',
    });
    expect(res.ok).toBe(true);
  });

  test('wrong number returns the generic invalid failure', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId: '00000000000000000000000000000000',
      captchaToken: 'tok',
      ip: '203.0.113.9',
    });
    expect(res).toEqual({ ok: false, reason: 'invalid' });
  });

  test('a disabled owner is indistinguishable from unknown (invalid)', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserWithAccount(t, 'disabled');
    const res = await t.action(internal.auth.accountLogin, {
      accountId,
      captchaToken: 'tok',
      ip: '203.0.113.10',
    });
    expect(res).toEqual({ ok: false, reason: 'invalid' });
  });

  test('a lapsed member (membership_lapsed) logs in and is downgraded to free', async () => {
    stubFetch(true);
    // Mock backend so the scheduled re-enable push runs cleanly.
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const t = convexTest(schema, modules);
    const { userId, freeTierId } = await t.run(async (ctx) => {
      const freeTierId = await ctx.db.insert('tiers', {
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
      });
      const memberTierId = await ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 500,
        deviceLimit: 3,
        hwidLimit: 3,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 7,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId: memberTierId,
        status: 'disabled',
        disabledReason: 'membership_lapsed',
        suspendedAt: Date.now(),
        membershipExpiresAt: Date.now() - 86_400_000,
        updatedAt: Date.now(),
      });
      await ctx.db.insert('subscriptions', {
        userId,
        backend: 'remnawave',
        backendUserId: 'bu-login',
        backendShortId: 'bs-login',
        subscriptionUrl: 'https://x/sub',
        subscriptionMirrors: [],
        state: 'active',
        updatedAt: Date.now(),
      });
      return { userId, freeTierId };
    });
    const minted = await t.action(internal.accountId.mintForUser, { userId });

    const res = await t.action(internal.auth.accountLogin, {
      accountId: minted.accountId,
      captchaToken: 'tok',
      ip: '203.0.113.20',
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.lapsedDowngrade).toBe(true); // one-time "expired" banner signal (Review #4)

    // The lapsed member is downgraded to the free tier + re-activated (they now see
    // an upgrade prompt); the scheduled push re-enables the key against the mock.
    await t.finishInProgressScheduledFunctions();
    const u = await t.run((ctx) => ctx.db.get(userId));
    expect(u?.tierId).toBe(freeTierId);
    expect(u?.status).toBe('active');
    expect(u?.disabledReason).toBeUndefined();
  });

  test('a failed Turnstile returns the turnstile failure', async () => {
    stubFetch(false);
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId,
      captchaToken: 'bad',
      ip: '203.0.113.11',
    });
    expect(res).toEqual({ ok: false, reason: 'captcha' });
  });

  test('an unconfigured captcha returns a distinct config reason (→ 503), not a generic failure', async () => {
    // CAP_* unset and not dev-bypass → verifyCaptcha reports configured:false, so
    // accountLogin surfaces 'config' (mapped to 503), not a generic captcha/invalid.
    vi.stubEnv('CAP_API_ENDPOINT', '');
    vi.stubEnv('CAP_SITE_KEY', '');
    vi.stubEnv('CAP_SECRET', '');
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId,
      captchaToken: 'tok',
      ip: '203.0.113.30',
    });
    expect(res).toEqual({ ok: false, reason: 'config' });
  });

  test('a failure is padded to the constant-time floor (~300ms)', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    await seedUserWithAccount(t);
    const start = Date.now();
    const res = await t.action(internal.auth.accountLogin, {
      accountId: '00000000000000000000000000000000',
      captchaToken: 'tok',
      ip: '203.0.113.12',
    });
    const elapsed = Date.now() - start;
    expect(res.ok).toBe(false);
    // Non-flaky lower bound (floor is 300ms; assert >= 250 for slack).
    expect(elapsed).toBeGreaterThanOrEqual(250);
  });
});

describe('auth.rotateAccountId', () => {
  beforeEach(() => {
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  });
  afterEach(() => vi.unstubAllEnvs());

  // M1: rotation must evict sessions minted from the DEAD credential — else a
  // captured session keeps working for its full 30-day TTL after the victim
  // rotates (the advertised compromise remediation).
  test('rotation revokes every session EXCEPT the caller’s keepSid', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId } = await seedUserWithAccount(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('sessions', {
        sid: 's-current',
        kind: 'member',
        userId,
        expiresAt: Date.now() + 86_400_000,
      });
      await ctx.db.insert('sessions', {
        sid: 's-attacker',
        kind: 'member',
        userId,
        expiresAt: Date.now() + 86_400_000,
      });
    });
    const res = await t.action(internal.auth.rotateAccountId, {
      userId,
      keepSid: 's-current',
    });
    expect(res.accountId).toMatch(/^\d{32}$/);
    expect(res.accountId).not.toBe(accountId);
    await t.run(async (ctx) => {
      const sids = (await ctx.db.query('sessions').collect()).map((s) => s.sid);
      expect(sids).toEqual(['s-current']);
    });
  });

  test('rotation with no keepSid revokes ALL sessions (token-authenticated caller)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedUserWithAccount(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('sessions', {
        sid: 's-1',
        kind: 'member',
        userId,
        expiresAt: Date.now() + 86_400_000,
      });
    });
    await t.action(internal.auth.rotateAccountId, { userId });
    await t.run(async (ctx) => {
      expect(await ctx.db.query('sessions').collect()).toHaveLength(0);
    });
  });
});
