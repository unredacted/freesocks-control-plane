/// <reference types="vite/client" />
/**
 * User-status counter tests (M2 / WS3): the maintained `appState` counter that
 * feeds `adminApi.statusSummary` must exactly track transitions and be exactly
 * recomputable by `reconcileUserCounts` (the self-heal).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { readUserCounts } from './lib/statusCounters';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

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
const counts = (t: ReturnType<typeof convexTest>) => t.run((ctx) => readUserCounts(ctx.db));

describe('userStats counters (WS3)', () => {
  test('reconcileUserCounts recomputes exact counts + is idempotent', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', {
        tierId,
        status: 'active',
        backendPushFailedAt: now,
        updatedAt: now,
      });
      await ctx.db.insert('users', { tierId, status: 'grace', updatedAt: now });
      await ctx.db.insert('users', {
        tierId,
        status: 'inactive',
        freeKeyExpiresAt: now,
        updatedAt: now,
      });
    });
    const c1 = await t.action(internal.userStats.reconcileUserCounts, {});
    expect(c1).toEqual({
      active: 2,
      grace: 1,
      disabled: 0,
      deleted: 0,
      inactive: 1,
      backendDrift: 1,
      freeActive: 2, // both active users sit on the default-free tier
    });
    expect(await counts(t)).toEqual(c1);
    // Idempotent: a second reconcile yields the same exact result.
    expect(await t.action(internal.userStats.reconcileUserCounts, {})).toEqual(c1);
  });

  // The old live+(scanned−baseline) delta write double-applied a change that
  // landed before the scan reached its row (review P1 on the session counter;
  // the user counter had the same flaw). The begin/scan/finish protocol is
  // exact in every ordering — pinned here with a 1-row page so the scan can be
  // interleaved with transitions deterministically.
  test('reconcile is exact when a transition races the scan (either side of scanPos)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const [u1, u2, u3] = await t.run(async (ctx) => {
      const mk = () => ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      return [await mk(), await mk(), await mk()];
    });
    await t.action(internal.userStats.reconcileUserCounts, {});
    expect(await counts(t)).toMatchObject({ active: 3, grace: 0, disabled: 0 });
    const freeTierIds = [tierId];

    const startTs = await t.mutation(internal.userStats.beginUserCountsReconcile, {});
    // Page 1 scans u1 (oldest) → scanPos = u1. Then u1 transitions: the scan saw
    // it ACTIVE, so the change must be journaled (c ≤ scanPos).
    expect(
      (await t.mutation(internal.userStats.scanUserCountsPage, { freeTierIds, pageSize: 1 })).done,
    ).toBe(false);
    await t.mutation(internal.adminApi.disableUser, { userId: u1! });
    // u3 (not yet scanned) transitions: the scan will see it DISABLED, so the
    // change must NOT be journaled (c > scanPos).
    await t.mutation(internal.adminApi.disableUser, { userId: u3! });
    // A user created mid-scan (c > startTs): outside the scan set → journaled.
    await t.mutation(internal.freeTier.createFreeUser, { tierId });
    for (let i = 0; i < 10; i++) {
      const r = await t.mutation(internal.userStats.scanUserCountsPage, {
        freeTierIds,
        pageSize: 1,
      });
      if (r.done) break;
    }
    expect(await t.mutation(internal.userStats.finishUserCountsReconcile, { token: startTs })).toBe(
      true,
    );
    // u2 + the new user active, u1 + u3 disabled — every change applied exactly once.
    expect(await counts(t)).toMatchObject({ active: 2, disabled: 2, grace: 0 });
    // And a fresh reconcile agrees (no drift was introduced).
    expect(await t.action(internal.userStats.reconcileUserCounts, {})).toMatchObject({
      active: 2,
      disabled: 2,
    });
    void u2;
  });

  test('a superseded user reconcile does not write', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {});
    const stale = await t.mutation(internal.userStats.beginUserCountsReconcile, {});
    await t.mutation(internal.userStats.beginUserCountsReconcile, {}); // newer run
    expect(await t.mutation(internal.userStats.finishUserCountsReconcile, { token: stale })).toBe(
      false,
    );
    expect((await counts(t)).active).toBe(1);
  });

  test('a page boundary never splits a shared _creationTime', async () => {
    // Rows inserted in ONE transaction share _creationTime. With pageSize=2 the
    // first page would end inside that group; the scan must pull the rest of
    // the timestamp in so scanPos stays exact.
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    await t.run(async (ctx) => {
      for (let i = 0; i < 5; i++) {
        await ctx.db.insert('users', { tierId, status: 'grace', updatedAt: Date.now() });
      }
    });
    const startTs = await t.mutation(internal.userStats.beginUserCountsReconcile, {});
    let pages = 0;
    for (let i = 0; i < 10; i++) {
      pages++;
      const r = await t.mutation(internal.userStats.scanUserCountsPage, {
        freeTierIds: [tierId],
        pageSize: 2,
      });
      if (r.done) break;
    }
    expect(await t.mutation(internal.userStats.finishUserCountsReconcile, { token: startTs })).toBe(
      true,
    );
    expect((await counts(t)).grace).toBe(5);
    expect(pages).toBeLessThanOrEqual(5);
  });

  test('grace/disable transitions move the buckets', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      // Lapsed expiry: the transition re-guards (M2) only flip a STILL-lapsed user.
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        membershipExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {}); // baseline active:1
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId });
    expect(await counts(t)).toMatchObject({ active: 0, grace: 1 });
    await t.mutation(internal.lifecycle.applyDisableTransition, { userId });
    expect(await counts(t)).toMatchObject({ grace: 0, disabled: 1 });
  });

  test('deactivate + reactivate move inactive/active', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', {
        tierId,
        status: 'active',
        freeKeyExpiresAt: Date.now() - DAY,
        updatedAt: Date.now(),
      }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {}); // active:1
    await t.mutation(internal.lifecycle.markUserInactive, { userId });
    expect(await counts(t)).toMatchObject({ active: 0, inactive: 1 });
    await t.mutation(internal.lifecycle.refreshFreeWindow, { userId });
    expect(await counts(t)).toMatchObject({ active: 1, inactive: 0 });
  });

  test('freeActive tallies only active users on default-free tiers, and survives status bumps', async () => {
    const t = convexTest(schema, modules);
    const freeTierId = await seedFreeTier(t);
    const paidTierId = await t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 3,
        hwidLimit: 3,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 30,
        updatedAt: Date.now(),
      }),
    );
    const graceFreeId = await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', { tierId: paidTierId, status: 'active', updatedAt: now }); // paid active — excluded
      await ctx.db.insert('users', { tierId: freeTierId, status: 'inactive', updatedAt: now }); // free but idle — excluded
      return ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        // Lapsed expiry so the grace transition's re-guard (M2) admits the flip.
        membershipExpiresAt: now - DAY,
        updatedAt: now,
      });
    });
    const c = await t.action(internal.userStats.reconcileUserCounts, {});
    expect(c).toMatchObject({ active: 3, freeActive: 2 });
    // A status transition bump (read-full/write-full) must not clobber freeActive.
    await t.mutation(internal.lifecycle.applyGraceTransition, { userId: graceFreeId });
    expect(await counts(t)).toMatchObject({ active: 2, grace: 1, freeActive: 2 });
  });

  test('refreshFreeActive recounts ONLY freeActive (targeted, other fields untouched)', async () => {
    const t = convexTest(schema, modules);
    const freeTierId = await seedFreeTier(t);
    const paidTierId = await t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 3,
        hwidLimit: 3,
        hwidEnabled: false,
        trafficStrategy: 'MONTH',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 30,
        updatedAt: Date.now(),
      }),
    );
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: now });
      await ctx.db.insert('users', { tierId: freeTierId, status: 'inactive', updatedAt: now }); // idle — excluded
      await ctx.db.insert('users', { tierId: paidTierId, status: 'active', updatedAt: now }); // paid — excluded
    });
    // A stale counter row (the donation-time case: signups since the last daily
    // reconcile aren't reflected) with a sentinel in an unrelated field.
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'stats:userCounts',
        value: JSON.stringify({ active: 42, freeActive: 0 }),
        updatedAt: Date.now(),
      }),
    );

    await t.action(internal.userStats.refreshFreeActive, {});

    const c = await counts(t);
    expect(c.freeActive).toBe(2); // exact recount
    expect(c.active).toBe(42); // untouched — the daily reconcile owns the rest
  });

  test('backend drift bumps exactly once (no double-count across setters)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.action(internal.userStats.reconcileUserCounts, {});
    await t.mutation(internal.lifecycle.setBackendDrift, { userId, failed: true });
    expect((await counts(t)).backendDrift).toBe(1);
    // Already drifted → a second signal (via recordPushFailure) must NOT re-count.
    await t.mutation(internal.lifecycle.recordPushFailure, { userId, detail: 'x' });
    expect((await counts(t)).backendDrift).toBe(1);
    // Clearing drops it back to 0.
    await t.mutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
    expect((await counts(t)).backendDrift).toBe(0);
  });
});

describe('session counter reconcile (2026-09-04)', () => {
  const live = async (t: ReturnType<typeof convexTest>) =>
    (await t.query(internal.userStats.getSessionCounts, {})).counts;
  const scanAll = async (t: ReturnType<typeof convexTest>, pageSize = 500) => {
    for (let i = 0; i < 50; i++) {
      const r = await t.mutation(internal.userStats.scanSessionCountsPage, { pageSize });
      if (r.done) return;
    }
    throw new Error('scan did not finish');
  };

  test('a delete racing the scan is applied exactly once (review P1 scenario)', async () => {
    // Two unbound sessions; the reconcile begins; one is deleted BEFORE its page
    // is scanned. The old live+(scanned−baseline) formula wrote 0 here (live=1,
    // scanned=1, baseline=2) and statusSummary would have reported "safe to
    // enable". Correct answer: 1.
    const t = convexTest(schema, modules);
    await t.action(internal.userStats.reconcileSessionCounts, {}); // initialize
    await t.mutation(internal.sessions.create, { sid: 'a', kind: 'member', ttlMs: 60_000 });
    await t.mutation(internal.sessions.create, { sid: 'b', kind: 'member', ttlMs: 60_000 });
    expect((await live(t)).unboundMember).toBe(2);

    const startTs = await t.mutation(internal.userStats.beginSessionCountsReconcile, {});
    await t.mutation(internal.sessions.deleteBySid, { sid: 'a' }); // before the scan reads it
    await scanAll(t);
    expect(
      await t.mutation(internal.userStats.finishSessionCountsReconcile, { token: startTs }),
    ).toBe(true);
    expect((await live(t)).unboundMember).toBe(1);
  });

  test('a delete of an ALREADY-scanned row is journaled (exact, not an overcount)', async () => {
    const t = convexTest(schema, modules);
    await t.action(internal.userStats.reconcileSessionCounts, {});
    await t.mutation(internal.sessions.create, { sid: 'a', kind: 'member', ttlMs: 60_000 });
    await t.mutation(internal.sessions.create, { sid: 'b', kind: 'member', ttlMs: 60_000 });
    const startTs = await t.mutation(internal.userStats.beginSessionCountsReconcile, {});
    // Page of 1 scans 'a' (oldest); then 'a' is deleted → journal −1.
    expect((await t.mutation(internal.userStats.scanSessionCountsPage, { pageSize: 1 })).done).toBe(
      false,
    );
    await t.mutation(internal.sessions.deleteBySid, { sid: 'a' });
    await scanAll(t, 1);
    expect(
      await t.mutation(internal.userStats.finishSessionCountsReconcile, { token: startTs }),
    ).toBe(true);
    expect((await live(t)).unboundMember).toBe(1);
  });

  test('creates (and deletes of those creates) during the scan are journaled, not lost', async () => {
    const t = convexTest(schema, modules);
    await t.action(internal.userStats.reconcileSessionCounts, {});
    await t.mutation(internal.sessions.create, { sid: 'old', kind: 'member', ttlMs: 60_000 });

    const startTs = await t.mutation(internal.userStats.beginSessionCountsReconcile, {});
    // Land after the boundary: excluded from the scan, carried by the journal.
    await t.mutation(internal.sessions.create, { sid: 'new-1', kind: 'admin', ttlMs: 60_000 });
    await t.mutation(internal.sessions.create, { sid: 'new-2', kind: 'admin', ttlMs: 60_000 });
    await t.mutation(internal.sessions.deleteBySid, { sid: 'new-2' }); // journal nets to +1 admin
    await scanAll(t);
    expect(
      await t.mutation(internal.userStats.finishSessionCountsReconcile, { token: startTs }),
    ).toBe(true);
    expect(await live(t)).toEqual({ bound: 0, unboundMember: 1, unboundAdmin: 1 });
  });

  test('a superseded reconcile does not write', async () => {
    const t = convexTest(schema, modules);
    await t.action(internal.userStats.reconcileSessionCounts, {});
    await t.mutation(internal.sessions.create, { sid: 'x', kind: 'member', ttlMs: 60_000 });
    const stale = await t.mutation(internal.userStats.beginSessionCountsReconcile, {});
    await t.mutation(internal.sessions.create, { sid: 'y', kind: 'member', ttlMs: 60_000 });
    await t.mutation(internal.userStats.beginSessionCountsReconcile, {}); // newer run
    expect(
      await t.mutation(internal.userStats.finishSessionCountsReconcile, { token: stale }),
    ).toBe(false);
    expect((await live(t)).unboundMember).toBe(2); // live bumps untouched
  });

  test('full reconcile is exact + idempotent and flips initialized', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      for (let i = 0; i < 7; i++) {
        await ctx.db.insert('sessions', {
          sid: `s-${i}`,
          kind: i % 2 ? 'admin' : 'member',
          expiresAt: Date.now() + 60_000,
          ...(i === 0 ? { popPublicKey: 'A'.repeat(43), popAlg: 'EdDSA' } : {}),
        });
      }
    });
    expect((await t.query(internal.userStats.getSessionCounts, {})).initialized).toBe(false);
    const total = await t.action(internal.userStats.reconcileSessionCounts, {});
    expect(total).toEqual({ bound: 1, unboundMember: 3, unboundAdmin: 3 });
    const again = await t.action(internal.userStats.reconcileSessionCounts, {});
    expect(again).toEqual(total);
    const st = await t.query(internal.userStats.getSessionCounts, {});
    expect(st.initialized).toBe(true);
    expect(st.counts).toEqual(total);
  });
});
