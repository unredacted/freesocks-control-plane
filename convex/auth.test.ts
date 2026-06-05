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
    vi.stubEnv('TURNSTILE_SECRET_KEY', 'x');
    vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
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
      turnstileToken: 'tok',
      ip: '203.0.113.7',
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    expect(res.userId).toBe(userId);
    expect(res.signedCookieValue).toContain('.');
    expect(res.maxAgeSec).toBeGreaterThan(0);

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
      turnstileToken: 'tok',
      ip: '203.0.113.8',
    });
    expect(res.ok).toBe(true);
  });

  test('wrong number returns the generic invalid failure', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId: '0000000000000000',
      turnstileToken: 'tok',
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
      turnstileToken: 'tok',
      ip: '203.0.113.10',
    });
    expect(res).toEqual({ ok: false, reason: 'invalid' });
  });

  test('a failed Turnstile returns the turnstile failure', async () => {
    stubFetch(false);
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserWithAccount(t);
    const res = await t.action(internal.auth.accountLogin, {
      accountId,
      turnstileToken: 'bad',
      ip: '203.0.113.11',
    });
    expect(res).toEqual({ ok: false, reason: 'turnstile' });
  });

  test('a failure is padded to the constant-time floor (~300ms)', async () => {
    stubFetch(true);
    const t = convexTest(schema, modules);
    await seedUserWithAccount(t);
    const start = Date.now();
    const res = await t.action(internal.auth.accountLogin, {
      accountId: '0000000000000000',
      turnstileToken: 'tok',
      ip: '203.0.113.12',
    });
    const elapsed = Date.now() - start;
    expect(res.ok).toBe(false);
    // Non-flaky lower bound (floor is 300ms; assert >= 250 for slack).
    expect(elapsed).toBeGreaterThanOrEqual(250);
  });
});
