import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
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
