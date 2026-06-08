/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { maskApiUrl } from './adminApi';

const modules = import.meta.glob('./**/*.*s');

/** Full TierUpsert payload (description + remnawaveSquadUuid are required-nullable). */
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
    remnawaveSquadUuid: null,
    isDefaultFree: false,
    isActive: true,
    priority: 5,
    expirationDaysAfterMembershipLapse: 7,
    ...overrides,
  };
}

describe('adminApi tiers', () => {
  test('createTier then tiersList contains it (mapped shape)', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert());
    expect(created.slug).toBe('pro');
    expect(created.id).toBeTruthy();
    expect(created.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO timestamp
    expect(created.description).toBeNull();

    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.map((x) => x.slug)).toContain('pro');
  });

  test('duplicate slug throws', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'dup' }));
    await expect(
      t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'dup', name: 'Other' })),
    ).rejects.toThrow(/already exists/);
  });

  test('updateTier patches selected fields', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'patchme' }));
    const updated = await t.mutation(internal.adminApi.updateTier, {
      id: created.id as never,
      name: 'Renamed',
      monthlyTrafficGb: 999,
    });
    expect(updated.name).toBe('Renamed');
    expect(updated.monthlyTrafficGb).toBe(999);
    expect(updated.slug).toBe('patchme'); // unchanged
  });

  test('updateTier can null out description', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(
      internal.adminApi.createTier,
      tierUpsert({ slug: 'desc', description: 'has one' }),
    );
    expect(created.description).toBe('has one');
    const updated = await t.mutation(internal.adminApi.updateTier, {
      id: created.id as never,
      description: null,
    });
    expect(updated.description).toBeNull();
  });

  test('deleteTier removes the row', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.adminApi.createTier, tierUpsert({ slug: 'gone' }));
    await t.mutation(internal.adminApi.deleteTier, { id: created.id as never });
    const { tiers } = await t.query(internal.adminApi.tiersList, {});
    expect(tiers.map((x) => x.slug)).not.toContain('gone');
  });
});

describe('adminApi usersSearch', () => {
  test('returns seeded users in the UserAdmin shape', async () => {
    const t = convexTest(schema, modules);
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
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', {
        tierId,
        status: 'active',
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'disabled', updatedAt: Date.now() });
    });

    const all = await t.query(internal.adminApi.usersSearch, {});
    expect(all.users.length).toBe(2);
    const row = all.users[0]!;
    // Contract shape: id, status, tierSlug, createdAt, backend, etc.
    expect(row).toHaveProperty('id');
    expect(row).toHaveProperty('status');
    expect(row.tierSlug).toBe('free');
    expect(row).toHaveProperty('createdAt');
    expect(row.backend).toBeNull(); // no subscription yet
  });

  test('status filter narrows the result set', async () => {
    const t = convexTest(schema, modules);
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
        updatedAt: Date.now(),
      });
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      await ctx.db.insert('users', { tierId, status: 'disabled', updatedAt: Date.now() });
    });
    const disabled = await t.query(internal.adminApi.usersSearch, { status: 'disabled' });
    expect(disabled.users).toHaveLength(1);
    expect(disabled.users[0]!.status).toBe('disabled');
  });
});

describe('adminApi.maskApiUrl', () => {
  test('keeps scheme+host and redacts the secret path', () => {
    expect(maskApiUrl('https://outline.example.com:8443/SeCrEtPaTh/abc')).toBe(
      'https://outline.example.com:8443/***',
    );
  });

  test('falls back to a bare sentinel for an unparseable value', () => {
    expect(maskApiUrl('not a url')).toBe('***');
  });
});
