/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

describe('replayGuard.consumeNonce', () => {
  // NOTE: like freeTier.claimFreeSlot, the true OCC race-safety (two concurrent
  // racers can never both consume the same (sid, nonce)) holds on the LIVE
  // backend; convex-test runs mutations single-threaded, so these assert the
  // set semantics, not the concurrency guarantee.
  test('first use of a (sid, nonce) succeeds; a replay is rejected', async () => {
    const t = convexTest(schema, modules);
    const base = { sid: 'sid-1', nonceHash: 'abc123', ttlMs: 90_000 };

    expect((await t.mutation(internal.replayGuard.consumeNonce, base)).ok).toBe(true);
    expect((await t.mutation(internal.replayGuard.consumeNonce, base)).ok).toBe(false);
    expect((await t.mutation(internal.replayGuard.consumeNonce, base)).ok).toBe(false);
  });

  test('the same nonce under a different sid is independent', async () => {
    const t = convexTest(schema, modules);
    const a = { sid: 'sid-a', nonceHash: 'shared-nonce', ttlMs: 90_000 };
    const b = { sid: 'sid-b', nonceHash: 'shared-nonce', ttlMs: 90_000 };

    expect((await t.mutation(internal.replayGuard.consumeNonce, a)).ok).toBe(true);
    // Same nonce, different session: not a replay of a's request.
    expect((await t.mutation(internal.replayGuard.consumeNonce, b)).ok).toBe(true);
    // But a's own nonce is now spent.
    expect((await t.mutation(internal.replayGuard.consumeNonce, a)).ok).toBe(false);
  });

  test('distinct nonces under one sid all succeed', async () => {
    const t = convexTest(schema, modules);
    for (let i = 0; i < 5; i++) {
      const r = await t.mutation(internal.replayGuard.consumeNonce, {
        sid: 'sid-multi',
        nonceHash: `nonce-${i}`,
        ttlMs: 90_000,
      });
      expect(r.ok).toBe(true);
    }
  });
});

describe('replayGuard.sweepExpired', () => {
  test('removes only rows past expiry', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('replayGuard', { sid: 's', nonceHash: 'stale', expiresAt: now - 1 });
      await ctx.db.insert('replayGuard', { sid: 's', nonceHash: 'fresh', expiresAt: now + 60_000 });
    });

    const { removed } = await t.mutation(internal.replayGuard.sweepExpired, {});
    expect(removed).toBe(1);

    await t.run(async (ctx) => {
      const rows = await ctx.db.query('replayGuard').collect();
      expect(rows).toHaveLength(1);
      expect(rows[0]?.nonceHash).toBe('fresh');
    });
  });
});
