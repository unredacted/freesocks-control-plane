/// <reference types="vite/client" />
/**
 * Device-limit enforcement master toggle (`devices.enforcementEnabled`): the
 * publicConfig exposure the SPA reads to gate app-compatibility UI, and the
 * one-time migration that preserves prior behavior for an existing deployment
 * while keeping a fresh install unlimited-by-default.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

const TIER = {
  slug: 'free',
  name: 'Free',
  backend: 'remnawave' as const,
  monthlyTrafficGb: 50,
  deviceLimit: 1,
  hwidLimit: 1,
  hwidEnabled: true,
  trafficStrategy: 'MONTH' as const,
  isDefaultFree: true,
  isActive: true,
  priority: 0,
  expirationDaysAfterMembershipLapse: 0,
};

describe('devices.enforcementEnabled', () => {
  test('publicConfig defaults enforcement OFF and reflects a set row', async () => {
    const t = convexTest(schema, modules);
    const off = await t.query(api.publicConfig.get, {});
    expect(off.devices.enforcementEnabled).toBe(false);

    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'devices.enforcementEnabled',
        value: JSON.stringify(true),
        updatedAt: Date.now(),
      }),
    );
    const on = await t.query(api.publicConfig.get, {});
    expect(on.devices.enforcementEnabled).toBe(true);
  });

  test('migration: a FRESH install (no users) stays OFF', async () => {
    const t = convexTest(schema, modules);
    await t.run((ctx) => ctx.db.insert('tiers', { ...TIER, updatedAt: Date.now() }));
    const res = await t.mutation(internal.seed.migrateDeviceEnforcementDefault, {});
    expect(res.seeded).toBe(false);
    const row = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'devices.enforcementEnabled'))
        .unique(),
    );
    expect(row).toBeNull();
  });

  test('migration: an EXISTING deployment (users + device-limited tier) seeds ON', async () => {
    const t = convexTest(schema, modules);
    const tierId = await t.run((ctx) => ctx.db.insert('tiers', { ...TIER, updatedAt: Date.now() }));
    await t.run((ctx) =>
      ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }),
    );
    const res = await t.mutation(internal.seed.migrateDeviceEnforcementDefault, {});
    expect(res.seeded).toBe(true);
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.devices.enforcementEnabled).toBe(true);
  });

  test('migration: never overrides an already-configured value', async () => {
    const t = convexTest(schema, modules);
    const tierId = await t.run((ctx) => ctx.db.insert('tiers', { ...TIER, updatedAt: Date.now() }));
    await t.run(async (ctx) => {
      await ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
      // Admin has explicitly turned it OFF — the migration must leave it alone.
      await ctx.db.insert('appSettings', {
        key: 'devices.enforcementEnabled',
        value: JSON.stringify(false),
        updatedAt: Date.now(),
      });
    });
    const res = await t.mutation(internal.seed.migrateDeviceEnforcementDefault, {});
    expect(res.seeded).toBe(false);
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.devices.enforcementEnabled).toBe(false);
  });
});
