/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

describe('rateLimits.checkAndIncrement', () => {
  test('allows up to max, then denies with a positive retryAfterMs', async () => {
    const t = convexTest(schema, modules);
    const args = { bucket: 'login:ip:abc', max: 3, windowMs: 60_000 };

    const r1 = await t.mutation(internal.rateLimits.checkAndIncrement, args);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);

    const r2 = await t.mutation(internal.rateLimits.checkAndIncrement, args);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);

    const r3 = await t.mutation(internal.rateLimits.checkAndIncrement, args);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);

    const r4 = await t.mutation(internal.rateLimits.checkAndIncrement, args);
    expect(r4.allowed).toBe(false);
    expect(r4.remaining).toBe(0);
    expect(r4.retryAfterMs).toBeGreaterThan(0);
    expect(r4.retryAfterMs).toBeLessThanOrEqual(60_000);
  });

  test('distinct buckets are independent', async () => {
    const t = convexTest(schema, modules);
    const a = { bucket: 'a', max: 1, windowMs: 60_000 };
    const b = { bucket: 'b', max: 1, windowMs: 60_000 };

    expect((await t.mutation(internal.rateLimits.checkAndIncrement, a)).allowed).toBe(true);
    // Bucket "a" is now exhausted, but "b" is untouched.
    expect((await t.mutation(internal.rateLimits.checkAndIncrement, a)).allowed).toBe(false);
    expect((await t.mutation(internal.rateLimits.checkAndIncrement, b)).allowed).toBe(true);
  });

  test('starts a fresh window once the old one has elapsed', async () => {
    const t = convexTest(schema, modules);
    const args = { bucket: 'expire-me', max: 1, windowMs: 1 };
    expect((await t.mutation(internal.rateLimits.checkAndIncrement, args)).allowed).toBe(true);
    // Seed an already-expired window directly, then the next call should reset.
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('rateLimits')
        .withIndex('by_bucket', (q) => q.eq('bucket', 'expire-me'))
        .unique();
      if (row) await ctx.db.patch(row._id, { expiresAt: Date.now() - 1000, count: 99 });
    });
    const after = await t.mutation(internal.rateLimits.checkAndIncrement, args);
    expect(after.allowed).toBe(true);
  });
});

describe('rateLimits.enforce (W2 policy-driven)', () => {
  test('uses the compiled default when no override row exists', async () => {
    const t = convexTest(schema, modules);
    // account.refresh-membership defaults to max 1 / 30s.
    const r1 = await t.mutation(internal.rateLimits.enforce, {
      policyKey: 'account.refresh-membership',
      subject: 'user-1',
    });
    expect(r1.allowed).toBe(true);
    const r2 = await t.mutation(internal.rateLimits.enforce, {
      policyKey: 'account.refresh-membership',
      subject: 'user-1',
    });
    expect(r2.allowed).toBe(false);
    // A different subject is independent.
    expect(
      (
        await t.mutation(internal.rateLimits.enforce, {
          policyKey: 'account.refresh-membership',
          subject: 'user-2',
        })
      ).allowed,
    ).toBe(true);
  });

  test('an admin override changes the effective limit', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'account.regenerate',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    expect(
      (
        await t.mutation(internal.rateLimits.enforce, {
          policyKey: 'account.regenerate',
          subject: 'u',
        })
      ).allowed,
    ).toBe(true);
    expect(
      (
        await t.mutation(internal.rateLimits.enforce, {
          policyKey: 'account.regenerate',
          subject: 'u',
        })
      ).allowed,
    ).toBe(false);
  });

  test('a disabled policy allows through unlimited', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'account-login.ip',
      max: 1,
      windowMs: 60_000,
      enabled: false,
    });
    for (let i = 0; i < 5; i++) {
      expect(
        (
          await t.mutation(internal.rateLimits.enforce, {
            policyKey: 'account-login.ip',
            subject: 'iphash',
          })
        ).allowed,
      ).toBe(true);
    }
  });

  test('a corrupt stored override falls back to the compiled default (fail-safe)', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'ratelimit.account.refresh-membership',
        value: 'not json{{{',
        updatedAt: Date.now(),
      });
    });
    const policy = await t.query(internal.rateLimits.getPolicy, {
      policyKey: 'account.refresh-membership',
    });
    expect(policy).toEqual({ max: 1, windowMs: 30_000, enabled: true });
  });

  test('setPolicy rejects out-of-bounds values', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.rateLimits.setPolicy, {
        policyKey: 'account.regenerate',
        max: 0,
        windowMs: 60_000,
        enabled: true,
      }),
    ).rejects.toThrow();
    await expect(
      t.mutation(internal.rateLimits.setPolicy, {
        policyKey: 'account.regenerate',
        max: 5,
        windowMs: 100, // < 1s
        enabled: true,
      }),
    ).rejects.toThrow();
    await expect(
      t.mutation(internal.rateLimits.setPolicy, {
        policyKey: 'totally.unknown',
        max: 5,
        windowMs: 60_000,
        enabled: true,
      }),
    ).rejects.toThrow();
  });

  test('listPolicies reports defaults and overrides', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'code.redeem',
      max: 99,
      windowMs: 60_000,
      enabled: true,
    });
    const policies = await t.query(internal.rateLimits.listPolicies, {});
    const redeem = policies.find((p) => p.key === 'code.redeem');
    expect(redeem).toMatchObject({ max: 99, windowMs: 60_000, enabled: true, isDefault: false });
    const login = policies.find((p) => p.key === 'account-login.ip');
    expect(login?.isDefault).toBe(true);
  });

  test('enforce throws (fail closed) on an unknown policy key', async () => {
    const t = convexTest(schema, modules);
    // A call-site typo must be a loud failure in development, never a silently
    // unthrottled route.
    await expect(
      t.mutation(internal.rateLimits.enforce, { policyKey: 'typo.key', subject: 'x' }),
    ).rejects.toThrow(/unknown policy key/);
  });
});

describe('rateLimits.sweepExpired', () => {
  test('deletes only the expired rows', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('rateLimits', { bucket: 'old', count: 1, expiresAt: now - 1000 });
      await ctx.db.insert('rateLimits', { bucket: 'fresh', count: 1, expiresAt: now + 60_000 });
    });
    const { removed } = await t.mutation(internal.rateLimits.sweepExpired, {});
    expect(removed).toBe(1);
    await t.run(async (ctx) => {
      const rows = await ctx.db.query('rateLimits').collect();
      expect(rows.map((r) => r.bucket)).toEqual(['fresh']);
    });
  });
});
