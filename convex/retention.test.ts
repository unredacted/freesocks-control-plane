/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test, vi, afterEach } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
const DAY = 86_400_000;

afterEach(() => vi.useRealTimers());

describe('retention sweeps (P2)', () => {
  // Review #5: the gift-reveal sweep scans a dedicated pending index, so a backlog
  // of paid self-orders can't starve it (the old by_status='paid' scan cleared
  // nothing once >PAGE paid orders predated the window), and recent reveals are kept.
  test('clearStaleGiftReveals clears stale pending gift reveals, keeps recent + self-orders', async () => {
    const t = convexTest(schema, modules);
    vi.useFakeTimers();
    const t0 = new Date('2026-01-01T00:00:00Z').getTime();
    vi.setSystemTime(t0);
    const { tierId, userId, staleGift, selfOrder } = await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 0,
        hwidLimit: 0,
        hwidEnabled: false,
        trafficStrategy: 'NO_RESET',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 7,
        updatedAt: t0,
      });
      const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: t0 });
      const mk = (opaqueRef: string, kind: 'self' | 'gift', pending: boolean) =>
        ctx.db.insert('billingOrders', {
          processor: 'nowpayments',
          opaqueRef,
          userId,
          tierId,
          durationDays: 91,
          amountCents: 1400,
          currency: 'USD',
          status: 'paid',
          paidAt: t0,
          kind,
          ...(pending ? { giftReveal: ['CODE-XYZ'], giftRevealPending: true } : {}),
          updatedAt: t0,
        });
      const staleGift = await mk('g-stale', 'gift', true);
      // Paid self-orders — the "backlog" that starved the old by_status='paid' scan.
      await mk('self-1', 'self', false);
      await mk('self-2', 'self', false);
      const selfOrder = await mk('self-3', 'self', false);
      return { tierId, userId, staleGift, selfOrder };
    });

    // Advance past the 24h TTL so the stale gift is due; a reveal created NOW is
    // within the window and must be kept.
    vi.setSystemTime(t0 + 25 * 60 * 60 * 1000);
    const recentGift = await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'g-recent',
        userId,
        tierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'paid',
        paidAt: Date.now(),
        kind: 'gift',
        giftReveal: ['CODE-RECENT'],
        giftRevealPending: true,
        updatedAt: Date.now(),
      }),
    );

    const res = await t.mutation(internal.retention.clearStaleGiftReveals, {});
    expect(res.cleared).toBe(1);

    await t.run(async (ctx) => {
      const stale = await ctx.db.get(staleGift);
      expect(stale?.giftReveal).toBeUndefined();
      expect(stale?.giftRevealPending).toBeUndefined();
      expect(stale?.giftRevealAck).toBe(true);
      const recent = await ctx.db.get(recentGift);
      expect(recent?.giftReveal).toEqual(['CODE-RECENT']); // within window → kept
      expect(recent?.giftRevealPending).toBe(true);
      const self = await ctx.db.get(selfOrder);
      expect(self?.status).toBe('paid'); // untouched
    });
  });

  // Review #5: gift orders paid before giftRevealPending existed carry a reveal but
  // no flag → invisible to clearStaleGiftReveals. The backfill flags exactly the
  // unacked pre-flag paid gift orders (not self orders, not acked, not already-flagged).
  test('backfillGiftRevealPending flags only unacked pre-flag paid gift orders', async () => {
    const t = convexTest(schema, modules);
    const ids = await t.run(async (ctx) => {
      const tierId = await ctx.db.insert('tiers', {
        slug: 'member',
        name: 'Member',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 0,
        hwidLimit: 0,
        hwidEnabled: false,
        trafficStrategy: 'NO_RESET',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 7,
        updatedAt: Date.now(),
      });
      const userId = await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const mk = (opaqueRef: string, kind: 'self' | 'gift', extra: Record<string, unknown>) =>
        ctx.db.insert('billingOrders', {
          processor: 'nowpayments',
          opaqueRef,
          userId,
          tierId,
          durationDays: 91,
          amountCents: 1400,
          currency: 'USD',
          status: 'paid',
          paidAt: Date.now(),
          kind,
          ...extra,
          updatedAt: Date.now(),
        });
      return {
        preFlag: await mk('g-preflag', 'gift', { giftReveal: ['CODE-A'] }), // no flag → should flag
        selfOrder: await mk('self-1', 'self', {}), // not a gift → skip
        acked: await mk('g-acked', 'gift', { giftReveal: ['CODE-C'], giftRevealAck: true }), // acked → skip
        alreadyFlagged: await mk('g-flagged', 'gift', {
          giftReveal: ['CODE-B'],
          giftRevealPending: true,
        }),
      };
    });

    const res = await t.mutation(internal.retention.backfillGiftRevealPending, {});
    expect(res.flagged).toBe(1);

    await t.run(async (ctx) => {
      expect((await ctx.db.get(ids.preFlag))?.giftRevealPending).toBe(true);
      expect((await ctx.db.get(ids.selfOrder))?.giftRevealPending).toBeUndefined();
      expect((await ctx.db.get(ids.acked))?.giftRevealPending).toBeUndefined();
      expect((await ctx.db.get(ids.alreadyFlagged))?.giftRevealPending).toBe(true); // untouched
    });
  });

  test('sweepAuditLog deletes only entries older than the window', async () => {
    const t = convexTest(schema, modules);
    // Insert an "old" row, then advance the clock so it's beyond 180 days.
    await t.run(async (ctx) => {
      await ctx.db.insert('auditLog', { actorType: 'system', action: 'old.event' });
    });
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 200 * DAY);
    await t.run(async (ctx) => {
      await ctx.db.insert('auditLog', { actorType: 'system', action: 'fresh.event' });
    });
    const { removed } = await t.mutation(internal.retention.sweepAuditLog, {});
    expect(removed).toBe(1);
    const left = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(left.map((r) => r.action)).toEqual(['fresh.event']);
  });
});

describe('deleteTier referential guard (P2)', () => {
  async function seedTier(
    t: ReturnType<typeof convexTest>,
    isDefaultFree: boolean,
  ): Promise<Id<'tiers'>> {
    return t.run((ctx) =>
      ctx.db.insert('tiers', {
        slug: isDefaultFree ? 'free' : 'patron',
        name: isDefaultFree ? 'Free' : 'Patron',
        backend: 'remnawave',
        monthlyTrafficGb: 50,
        deviceLimit: 1,
        hwidLimit: 1,
        hwidEnabled: true,
        trafficStrategy: 'MONTH',
        isDefaultFree,
        isActive: true,
        priority: 0,
        expirationDaysAfterMembershipLapse: 0,
        updatedAt: Date.now(),
      }),
    );
  }

  test('refuses to delete the default-free tier', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, true);
    await expect(t.mutation(internal.adminApi.deleteTier, { id })).rejects.toThrow();
  });

  test('refuses to delete a tier that still has users', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, false);
    await t.run((ctx) =>
      ctx.db.insert('users', { tierId: id, status: 'active', updatedAt: Date.now() }),
    );
    await expect(t.mutation(internal.adminApi.deleteTier, { id })).rejects.toThrow();
  });

  test('deletes an unreferenced non-default tier', async () => {
    const t = convexTest(schema, modules);
    const id = await seedTier(t, false);
    expect(await t.mutation(internal.adminApi.deleteTier, { id })).toEqual({ ok: true });
    expect(await t.run((ctx) => ctx.db.get(id))).toBeNull();
  });
});

describe('retention.sweepDeletedSubscriptions (pass 2)', () => {
  test('removes long-deleted rows; keeps recent-deleted and tombstoned ones', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    const { oldId, recentId, tombstoneId } = await t.run(async (ctx) => {
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
        updatedAt: now,
      });
      const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      const base = {
        userId,
        backend: 'remnawave' as const,
        backendShortId: 's',
        subscriptionUrl: 'https://sub.example/s',
        subscriptionMirrors: [],
        updatedAt: now,
      };
      const oldId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'old',
        state: 'deleted',
        deletedAt: now - 100 * DAY,
      });
      const recentId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'recent',
        state: 'deleted',
        deletedAt: now - DAY,
      });
      // A live tombstone (disabled, grace pending) must NOT be touched.
      const tombstoneId = await ctx.db.insert('subscriptions', {
        ...base,
        backendUserId: 'tomb',
        state: 'disabled',
        deletedAt: now - 100 * DAY,
      });
      return { oldId, recentId, tombstoneId };
    });

    const out = await t.mutation(internal.retention.sweepDeletedSubscriptions, {});
    expect(out.removed).toBe(1);
    await t.run(async (ctx) => {
      expect(await ctx.db.get(oldId)).toBeNull();
      expect(await ctx.db.get(recentId)).not.toBeNull();
      expect(await ctx.db.get(tombstoneId)).not.toBeNull();
    });
  });

  test('a full page re-queues the sweep (drains same-day); a short page stops', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
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
        updatedAt: now,
      });
      const userId = await ctx.db.insert('users', { tierId, status: 'active', updatedAt: now });
      for (let i = 0; i < 3; i++) {
        await ctx.db.insert('subscriptions', {
          userId,
          backend: 'remnawave',
          backendUserId: `drain-${i}`,
          backendShortId: 's',
          subscriptionUrl: 'https://sub.example/s',
          subscriptionMirrors: [],
          state: 'deleted',
          deletedAt: now - 100 * DAY,
          updatedAt: now,
        });
      }
    });
    const scheduled = () =>
      t.run(async (ctx) =>
        (await ctx.db.system.query('_scheduled_functions').collect()).filter((f) =>
          f.name.includes('sweepDeletedSubscriptions'),
        ),
      );
    // limit=2: the first call deletes a FULL page → re-queues a continuation…
    const first = await t.mutation(internal.retention.sweepDeletedSubscriptions, { limit: 2 });
    expect(first.removed).toBe(2);
    expect((await scheduled()).length).toBe(1);
    // …the continuation (invoked with rounds+1) deletes the short remainder and
    // does NOT queue another — the chain stops on a short page.
    const second = await t.mutation(internal.retention.sweepDeletedSubscriptions, {
      limit: 2,
      rounds: 1,
    });
    expect(second.removed).toBe(1);
    expect((await scheduled()).length).toBe(1); // unchanged: no new continuation
    await t.run(async (ctx) => {
      expect(await ctx.db.query('subscriptions').collect()).toHaveLength(0);
    });
  });
});

describe('maintenance holds and obligations', () => {
  async function server(t: ReturnType<typeof convexTest>) {
    return t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'panel-a',
        slug: 'panel-a',
        config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
  }
  const hold = (sid: Id<'backendServers'>, released: boolean, at: number, name = 'node-a') => ({
    backendServerId: sid,
    transitionId: `tr-${at}`,
    reason: 'profile edit',
    heldNodeNames: [name],
    closedIntentIds: [],
    released,
    since: at,
    updatedAt: at,
  });

  test('the gate reads only the open holds, however many were released', async () => {
    // A read budget far below the released history: reading every hold of the
    // backend (what each member fetch of an unmanaged node did) would exceed it.
    const t = convexTest({ schema, modules, transactionLimits: { documentsRead: 50 } });
    const sid = await server(t);
    await t.run(async (ctx) => {
      for (let i = 0; i < 60; i++) await ctx.db.insert('panelMaintenanceHolds', hold(sid, true, i));
      await ctx.db.insert('panelMaintenanceHolds', hold(sid, false, 100, 'node-b'));
    });
    const open = await t.query(internal.nodeIntents.holdsView, { backendServerId: sid });
    expect(open.map((h) => h.heldNodeNames)).toEqual([['node-b']]);
  });

  test('released holds past the window go; open ones stay whatever their age', async () => {
    const t = convexTest(schema, modules);
    const sid = await server(t);
    const now = Date.now();
    const ids = await t.run(async (ctx) => ({
      oldReleased: await ctx.db.insert('panelMaintenanceHolds', hold(sid, true, now - 100 * DAY)),
      recentReleased: await ctx.db.insert('panelMaintenanceHolds', hold(sid, true, now - DAY)),
      oldOpen: await ctx.db.insert('panelMaintenanceHolds', hold(sid, false, now - 100 * DAY)),
    }));
    const r = await t.mutation(internal.retention.sweepMaintenanceHolds, {});
    expect(r.removed).toBe(1);
    await t.run(async (ctx) => {
      expect(await ctx.db.get(ids.oldReleased)).toBeNull();
      expect(await ctx.db.get(ids.recentReleased)).not.toBeNull();
      expect(await ctx.db.get(ids.oldOpen)).not.toBeNull();
    });
  });

  test('settled obligations past the window go; outstanding ones and owned DNS records stay', async () => {
    vi.useFakeTimers();
    const t = convexTest(schema, modules);
    const sid = await server(t);
    const old = Date.now() - 100 * DAY;
    const ob = (
      kind: 'dns.record' | 'host',
      verb: 'create' | 'delete',
      state: 'pending' | 'sent' | 'unresolved' | 'confirmed' | 'failed',
      updatedAt = old,
    ) => ({
      backendServerId: sid,
      ownerKind: 'intent' as const,
      ownerId: 'intent-1',
      ownerGeneration: 1,
      attemptId: `a-${kind}-${verb}-${state}-${updatedAt}`,
      kind,
      identity: kind === 'dns.record' ? 'A:node-a.example.org' : 'host:node-a',
      verb,
      ownership: 'created' as const,
      state,
      intent: '{}',
      createdAt: updatedAt,
      updatedAt,
    });
    const ids = await t.run(async (ctx) => ({
      ownedRecord: await ctx.db.insert(
        'backendObligations',
        ob('dns.record', 'create', 'confirmed'),
      ),
      withdrawn: await ctx.db.insert('backendObligations', ob('dns.record', 'create', 'failed')),
      deleted: await ctx.db.insert('backendObligations', ob('dns.record', 'delete', 'confirmed')),
      host: await ctx.db.insert('backendObligations', ob('host', 'create', 'confirmed')),
      unresolved: await ctx.db.insert('backendObligations', ob('host', 'create', 'unresolved')),
      pending: await ctx.db.insert('backendObligations', ob('host', 'create', 'pending')),
      recent: await ctx.db.insert('backendObligations', ob('host', 'create', 'failed', Date.now())),
    }));
    await t.mutation(internal.retention.sweepObligations, {});
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    await t.run(async (ctx) => {
      for (const gone of [ids.withdrawn, ids.deleted, ids.host])
        expect(await ctx.db.get(gone)).toBeNull();
      for (const kept of [ids.ownedRecord, ids.unresolved, ids.pending, ids.recent])
        expect(await ctx.db.get(kept)).not.toBeNull();
    });
  });
});
