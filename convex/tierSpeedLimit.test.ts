/// <reference types="vite/client" />
/**
 * Per-plan speed limits (tiers.speedLimitMbps): the resolver, the admin write
 * path and its bounds, and the deploy seed that fills tiers made before the
 * field existed without touching an operator's value.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { CAPABILITIES } from './lib/backends/capabilities';
import {
  DEFAULT_FREE_SPEED_LIMIT_MBPS,
  MAX_SPEED_LIMIT_MBPS,
  resolveSpeedLimitMbps,
} from './lib/backends/types';
import { TierAdmin } from '../src/shared/contracts/admin';

const modules = import.meta.glob('./**/*.*s');

function tierUpsert(overrides: Record<string, unknown> = {}) {
  return {
    slug: 'pro',
    name: 'Pro',
    description: null,
    backend: 'remnawave' as const,
    monthlyTrafficGb: 100,
    deviceLimit: 2,
    hwidLimit: 2,
    hwidEnabled: false,
    trafficStrategy: 'MONTH' as const,
    isDefaultFree: false,
    isActive: true,
    priority: 5,
    expirationDaysAfterMembershipLapse: 7,
    ...overrides,
  };
}

const baseRow = {
  backend: 'remnawave' as const,
  monthlyTrafficGb: 0,
  deviceLimit: 0,
  hwidLimit: 0,
  hwidEnabled: false,
  trafficStrategy: 'MONTH' as const,
  isActive: true,
  priority: 0,
  expirationDaysAfterMembershipLapse: 0,
  updatedAt: 0,
};

describe('resolveSpeedLimitMbps', () => {
  test('0 and never-set are unlimited (null)', () => {
    expect(resolveSpeedLimitMbps({ speedLimitMbps: 0 })).toBeNull();
    expect(resolveSpeedLimitMbps({})).toBeNull();
  });
  test('a positive cap is returned as is', () => {
    expect(resolveSpeedLimitMbps({ speedLimitMbps: 100 })).toBe(100);
  });
});

describe('capability', () => {
  test('no backend applies a speed cap yet', () => {
    for (const caps of Object.values(CAPABILITIES)) expect(caps.speedLimit).toBe(false);
  });
});

describe('admin tier writes', () => {
  test('create stores the cap; omitted means unlimited (0)', async () => {
    const t = convexTest(schema, modules);
    const capped = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'capped', speedLimitMbps: 50 }),
    );
    expect(capped.speedLimitMbps).toBe(50);
    const open = await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'open' }));
    expect(open.speedLimitMbps).toBe(0);
    // The mapped shape parses against the client contract.
    expect(TierAdmin.parse(capped).speedLimitMbps).toBe(50);
  });

  test('update and upsert-by-slug change only the cap', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert());
    const updated = await t.mutation(internal.adminApi.updateTier, {
      id: created.id as never,
      speedLimitMbps: 250,
    });
    expect(updated.speedLimitMbps).toBe(250);
    expect(updated.monthlyTrafficGb).toBe(100);
    const upserted = await t.mutation(internal.adminApi.upsertTierBySlug, {
      slug: 'pro',
      speedLimitMbps: 0,
    });
    expect(upserted.speedLimitMbps).toBe(0);
    const made = await t.mutation(internal.adminApi.upsertTierBySlug, { slug: 'iac' });
    expect(made.speedLimitMbps).toBe(0);
  });

  test.each([-1, 1.5, MAX_SPEED_LIMIT_MBPS + 1])('refuses %s', async (bad) => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.adminApi.createTier, tierUpsert({ speedLimitMbps: bad })),
    ).rejects.toThrow(/speedLimitMbps/);
  });
});

describe('seed', () => {
  test('fresh tiers: free 100 Mbps, membership unlimited', async () => {
    const t = convexTest(schema, modules);
    const freeId = await t.mutation(internal.seed.seedDefaultFreeTier, {});
    const memberId = await t.mutation(internal.seed.seedMemberTier, {});
    const [free, member] = await t.run(async (ctx) => [
      await ctx.db.get(freeId),
      await ctx.db.get(memberId),
    ]);
    expect(free!.speedLimitMbps).toBe(DEFAULT_FREE_SPEED_LIMIT_MBPS);
    expect(member!.speedLimitMbps).toBe(0);
  });

  test('fills tiers that never had a cap, once, and keeps stored values', async () => {
    const t = convexTest(schema, modules);
    const ids = await t.run(async (ctx) => ({
      free: await ctx.db.insert('tiers', {
        ...baseRow,
        slug: 'free',
        name: 'Free',
        isDefaultFree: true,
      }),
      member: await ctx.db.insert('tiers', {
        ...baseRow,
        slug: 'member',
        name: 'Member',
        isDefaultFree: false,
      }),
      edited: await ctx.db.insert('tiers', {
        ...baseRow,
        slug: 'free-outline',
        name: 'Free (Outline)',
        backend: 'outline',
        isDefaultFree: true,
        speedLimitMbps: 0,
      }),
    }));
    expect(await t.mutation(internal.seed.seedTierSpeedLimits, {})).toEqual({ filled: 2 });
    const rows = await t.run(async (ctx) => ({
      free: await ctx.db.get(ids.free),
      member: await ctx.db.get(ids.member),
      edited: await ctx.db.get(ids.edited),
    }));
    expect(rows.free!.speedLimitMbps).toBe(DEFAULT_FREE_SPEED_LIMIT_MBPS);
    expect(rows.member!.speedLimitMbps).toBe(0);
    // An operator's 0 on a free tier stays 0.
    expect(rows.edited!.speedLimitMbps).toBe(0);

    // A later edit survives the next deploy's seed.
    await t.run((ctx) => ctx.db.patch(ids.free, { speedLimitMbps: 20 }));
    expect(await t.mutation(internal.seed.seedTierSpeedLimits, {})).toEqual({ filled: 0 });
    expect((await t.run((ctx) => ctx.db.get(ids.free)))!.speedLimitMbps).toBe(20);
  });
});
