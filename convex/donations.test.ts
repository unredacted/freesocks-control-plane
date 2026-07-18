import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { gbToBytes } from './lib/backends/types';

const modules = import.meta.glob('./**/*.*s');

type BulkBody = { uuids: string[]; fields: { trafficLimitBytes: number } };

/** A bulk/update-capturing fetch stub (everything else → 200 {}). */
function captureBulk(bucket: BulkBody[]) {
  return vi.fn(async (input: string | URL, init?: RequestInit) => {
    if (String(input).includes('/api/users/bulk/update')) {
      bucket.push(JSON.parse(init!.body as string) as BulkBody);
    }
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
}

async function setup() {
  // Real-HTTP path (mock off) so the bulk update actually hits the stubbed fetch.
  vi.stubEnv('DEV_MOCK_BACKEND', '');
  vi.stubEnv('ENVIRONMENT', 'production');
  const t = convexTest(schema, modules);
  const { freeTierId, instanceId } = await t.run(async (ctx) => {
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
    const instanceId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'n1',
      slug: 'n1',
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    });
    const put = (k: string, v: unknown) =>
      ctx.db.insert('appSettings', { key: k, value: JSON.stringify(v), updatedAt: Date.now() });
    await put('billing.donation.enabled', true);
    await put('billing.donation.bonusGbPerUsd', 1);
    await put('billing.donation.monthlyBonusCapGb', 100);
    return { freeTierId, instanceId };
  });
  return { t, freeTierId, instanceId };
}

async function seedFreeKey(
  t: ReturnType<typeof convexTest>,
  tierId: Id<'tiers'>,
  instanceId: Id<'backendServers'>,
  backendUserId: string,
): Promise<void> {
  await t.run(async (ctx) => {
    const userId = await ctx.db.insert('users', {
      tierId,
      status: 'active',
      freeKeyExpiresAt: Date.now() + 86_400_000,
      updatedAt: Date.now(),
    });
    const subId = await ctx.db.insert('subscriptions', {
      userId,
      backend: 'remnawave',
      backendUserId,
      backendShortId: `${backendUserId}-s`,
      backendServerId: instanceId,
      subscriptionUrl: `https://panel.test/sub/${backendUserId}`,
      subscriptionMirrors: [],
      state: 'active',
      updatedAt: Date.now(),
    });
    await ctx.db.patch(userId, { currentSubscriptionId: subId });
  });
}

const thisMonth = () => new Date().toISOString().slice(0, 7); // YYYY-MM

describe('donations.applyFreeBonus', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('re-caps free keys to base+bonus and records the applied bonus', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    // $30 donated this month → +30 GB (rate 1 GB/$).
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 0 }),
        updatedAt: Date.now(),
      }),
    );
    const bulk: BulkBody[] = [];
    vi.stubGlobal('fetch', captureBulk(bulk));

    await t.action(internal.donations.applyFreeBonus, {});

    expect(bulk.length).toBe(1);
    expect(bulk[0]!.uuids).toEqual(['u-1']);
    expect(bulk[0]!.fields.trafficLimitBytes).toBe(gbToBytes(50 + 30));
    await t.run(async (ctx) => {
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).appliedBonusGb).toBe(30);
      // The cron stamps its heartbeat so the admin dashboard can alarm on a
      // stale/pending job (previously the only unstamped cron).
      const hb = await ctx.db
        .query('cronHeartbeats')
        .withIndex('by_name', (q) => q.eq('name', 'donation-bonus-reconcile'))
        .unique();
      expect(hb?.lastRunAt).toBeGreaterThan(0);
    });
  });

  test('no-op when the effective bonus already equals the applied bonus', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: thisMonth(), donatedCents: 3000, appliedBonusGb: 30 }),
        updatedAt: Date.now(),
      }),
    );
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    await t.action(internal.donations.applyFreeBonus, {});
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('resets free keys to base when the calendar month has rolled', async () => {
    const { t, freeTierId, instanceId } = await setup();
    await seedFreeKey(t, freeTierId, instanceId, 'u-1');
    // Last month's pool with a bonus still applied → this month must push base back.
    await t.run((ctx) =>
      ctx.db.insert('appState', {
        key: 'donation:freeBonus',
        value: JSON.stringify({ monthKey: '2000-01', donatedCents: 3000, appliedBonusGb: 30 }),
        updatedAt: Date.now(),
      }),
    );
    const bulk: BulkBody[] = [];
    vi.stubGlobal('fetch', captureBulk(bulk));

    await t.action(internal.donations.applyFreeBonus, {});

    expect(bulk[0]!.fields.trafficLimitBytes).toBe(gbToBytes(50)); // base, no bonus
    await t.run(async (ctx) => {
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).appliedBonusGb).toBe(0);
    });
  });
});

describe('donations.donationTotals', () => {
  test('sums only settled orders that carried a donation', async () => {
    const { t, freeTierId } = await setup();
    const { userId, otherId } = await t.run(async (ctx) => {
      const userId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const otherId = await ctx.db.insert('users', {
        tierId: freeTierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      const order = (over: Record<string, unknown>) =>
        ctx.db.insert('billingOrders', {
          processor: 'nowpayments',
          opaqueRef: `ref-${Math.random().toString(36).slice(2)}`,
          userId,
          durationDays: 0,
          amountCents: 1000,
          currency: 'USD',
          status: 'paid',
          kind: 'donation',
          updatedAt: Date.now(),
          ...over,
        });
      await order({ donationCents: 500 }); // counts
      await order({ donationCents: 300, kind: 'self', durationDays: 91 }); // ride-along counts
      await order({ donationCents: 700, status: 'pending' }); // unsettled — excluded
      await order({ donationCents: 0, kind: 'self', durationDays: 91 }); // no donation — excluded
      await order({ donationCents: 900, userId: otherId }); // other user — excluded
      return { userId, otherId };
    });
    expect(await t.query(internal.donations.donationTotals, { userId })).toEqual({
      donatedCentsTotal: 800,
      donationCount: 2,
    });
    expect(await t.query(internal.donations.donationTotals, { userId: otherId })).toEqual({
      donatedCentsTotal: 900,
      donationCount: 1,
    });
  });

  test('zeros for a user with no orders', async () => {
    const { t, freeTierId } = await setup();
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: freeTierId, status: 'active', updatedAt: Date.now() }),
    );
    expect(await t.query(internal.donations.donationTotals, { userId })).toEqual({
      donatedCentsTotal: 0,
      donationCount: 0,
    });
  });
});

describe('publicConfig donation impact projection', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('ships GB-only history (no dollar amounts) + the free-user count', async () => {
    const { t } = await setup();
    await t.run(async (ctx) => {
      const put = (key: string, value: unknown) =>
        ctx.db.insert('appState', {
          key,
          value: JSON.stringify(value),
          updatedAt: Date.now(),
        });
      // Two closed months in the ledger + a live current-month accumulator.
      await put('donation:history', [
        { monthKey: '2026-05', donatedCents: 2000, bonusGb: 20 },
        { monthKey: '2026-06', donatedCents: 4000, bonusGb: 40 },
      ]);
      await put('donation:freeBonus', {
        monthKey: thisMonth(),
        donatedCents: 1500,
        appliedBonusGb: 15,
      });
      await put('stats:userCounts', {
        active: 7,
        grace: 0,
        disabled: 0,
        deleted: 0,
        inactive: 0,
        backendDrift: 0,
        freeActive: 5,
      });
    });
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.billing.donation.freeUsersHelped).toBe(5);
    // Current month synthesized from the live accumulator ($15 × 1 GB/USD).
    expect(cfg.billing.donation.history).toEqual([
      { month: '2026-05', bonusGb: 20 },
      { month: '2026-06', bonusGb: 40 },
      { month: thisMonth(), bonusGb: 15 },
    ]);
    // GB only — the ledger's donatedCents never reaches the public projection.
    expect(JSON.stringify(cfg.billing.donation.history)).not.toContain('donatedCents');
  });

  test('empty history on a deployment with no impact yet', async () => {
    const { t } = await setup();
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.billing.donation.history).toEqual([]);
    expect(cfg.billing.donation.freeUsersHelped).toBe(0);
  });
});
