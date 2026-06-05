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
