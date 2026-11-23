/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';
import { REPAIR_GRACE_MS } from './mirrorUploads';
import { RUNTIME_RECHECK_MS } from './edgeReconcileMutations';

const modules = import.meta.glob('./**/*.*s');

/** The functions a test run left scheduled, by name. */
async function scheduledNames(ctx: MutationCtx): Promise<string[]> {
  const rows = await ctx.db.system.query('_scheduled_functions').collect();
  return rows.map((r) => r.name);
}

async function heartbeat(ctx: MutationCtx, name: string) {
  return ctx.db
    .query('cronHeartbeats')
    .withIndex('by_name', (q) => q.eq('name', name))
    .first();
}

async function subscription(ctx: MutationCtx): Promise<Id<'subscriptions'>> {
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
  const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
  return ctx.db.insert('subscriptions', {
    userId,
    backend: 'remnawave',
    backendUserId: 'u-1',
    backendShortId: 's1',
    subscriptionUrl: 'https://panel.test/sub/s1',
    subscriptionMirrors: [],
    state: 'active',
    updatedAt: Date.now(),
  });
}

describe('cronGates: an idle tick starts no Node action', () => {
  test('sni-qualify with the feature off: only the auto-confirm sweep, run stamped ok', async () => {
    const t = convexTest(schema, modules);
    expect(await t.mutation(internal.cronGates.sniQualify, {})).toEqual({ scheduled: false });
    await t.run(async (ctx) => {
      const names = await scheduledNames(ctx);
      expect(names.some((n) => n.includes('sniQualifyOps'))).toBe(false);
      expect(names.some((n) => n.includes('sniAutoConfirm'))).toBe(true);
      const hb = await heartbeat(ctx, 'sni-qualify');
      expect(hb?.runCount).toBe(1);
      expect(typeof hb?.lastOkAt).toBe('number');
    });
  });

  test('mirror-barrier-repair: nothing open = skipped; an open obligation past its grace = scheduled', async () => {
    const t = convexTest(schema, modules);
    expect(await t.mutation(internal.cronGates.mirrorBarrierRepair, {})).toEqual({
      scheduled: false,
    });
    await t.run(async (ctx) => {
      expect(await scheduledNames(ctx)).toEqual([]);
      expect((await heartbeat(ctx, 'mirror-barrier-repair'))?.lastOkAt).toBeTypeOf('number');
      const subscriptionId = await subscription(ctx);
      // One still inside its in-flight grace: not due yet.
      await ctx.db.insert('mirrorUploads', {
        subscriptionId,
        objectPath: 'mirrors/a',
        providers: ['p1'],
        tokenBefore: null,
        kind: 'initial',
        state: 'open',
        attempts: 0,
        startedAt: Date.now(),
        updatedAt: Date.now(),
      });
    });
    expect(await t.mutation(internal.cronGates.mirrorBarrierRepair, {})).toEqual({
      scheduled: false,
    });
    await t.run(async (ctx) => {
      const old = Date.now() - REPAIR_GRACE_MS - 60_000;
      const row = await ctx.db.query('mirrorUploads').first();
      await ctx.db.patch(row!._id, { updatedAt: old, startedAt: old });
    });
    expect(await t.mutation(internal.cronGates.mirrorBarrierRepair, {})).toEqual({
      scheduled: true,
    });
    await t.run(async (ctx) => {
      expect(await scheduledNames(ctx)).toEqual(['storage:repairMirrorUploads']);
    });
  });

  test('mirror-verify: no copy = skipped; a never-read copy = scheduled', async () => {
    const t = convexTest(schema, modules);
    expect(await t.mutation(internal.cronGates.mirrorVerify, {})).toEqual({ scheduled: false });
    await t.run(async (ctx) => {
      expect(await scheduledNames(ctx)).toEqual([]);
      const subscriptionId = await subscription(ctx);
      await ctx.db.insert('mirrorCopies', {
        subscriptionId,
        provider: 'p1',
        objectPath: 'mirrors/a',
        state: 'never',
        since: Date.now(),
        failures: 0,
        updatedAt: Date.now(),
      });
    });
    expect(await t.mutation(internal.cronGates.mirrorVerify, {})).toEqual({ scheduled: true });
    await t.run(async (ctx) => {
      expect(await scheduledNames(ctx)).toEqual(['storage:verifyMirrorCopies']);
    });
  });

  test('one run at a time: a tick while the scheduled run is pending schedules no second copy', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const subscriptionId = await subscription(ctx);
      await ctx.db.insert('mirrorCopies', {
        subscriptionId,
        provider: 'p1',
        objectPath: 'mirrors/a',
        state: 'never',
        since: Date.now(),
        failures: 0,
        updatedAt: Date.now(),
      });
    });
    expect(await t.mutation(internal.cronGates.mirrorVerify, {})).toEqual({ scheduled: true });
    // The first run has not started (convex-test leaves it pending): still due, still leased.
    expect(await t.mutation(internal.cronGates.mirrorVerify, {})).toEqual({
      scheduled: false,
      running: true,
    });
    await t.run(async (ctx) => {
      expect(await scheduledNames(ctx)).toEqual(['storage:verifyMirrorCopies']);
      // A skipped overlapping tick stamps nothing, like a cron tick Convex skips.
      expect(await heartbeat(ctx, 'mirror-verify')).toBeNull();
      // Once that run is over, the next tick may schedule again.
      const job = (await ctx.db.system.query('_scheduled_functions').collect())[0]!;
      await ctx.scheduler.cancel(job._id);
    });
    expect(await t.mutation(internal.cronGates.mirrorVerify, {})).toEqual({ scheduled: true });
  });
});

describe('edge-reconcile reads the Node runtime version at most hourly', () => {
  test('runtimeCheckDue: no row, a fresh row, an old row', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    expect(await t.query(internal.edgeReconcileMutations.runtimeCheckDue, { now })).toBe(true);
    await t.mutation(internal.edgeReconcileMutations.recordRuntime, { nodeVersion: 'v22.0.0' });
    expect(await t.query(internal.edgeReconcileMutations.runtimeCheckDue, { now })).toBe(false);
    expect(
      await t.query(internal.edgeReconcileMutations.runtimeCheckDue, {
        // Well past the hour from when the row was written (after `now`).
        now: Date.now() + RUNTIME_RECHECK_MS + 60_000,
      }),
    ).toBe(true);
  });
});
