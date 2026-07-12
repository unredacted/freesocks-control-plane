/// <reference types="vite/client" />
/**
 * Device-limit enforcement master toggle (`devices.enforcementEnabled`): the
 * publicConfig exposure the SPA reads to gate app-compatibility UI. OFF by
 * default (unlimited-by-default); an admin-set row flips it. The seed path
 * (`seedAppSettings` via `SETTINGS_DEFAULTS`) inserts the OFF default and never
 * overwrites an admin edit.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

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

  test('seedAppSettings seeds the OFF default on a fresh install', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.seed.seedAppSettings, {});
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.devices.enforcementEnabled).toBe(false);
    const row = await t.run((ctx) =>
      ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', 'devices.enforcementEnabled'))
        .unique(),
    );
    expect(row).not.toBeNull();
    expect(JSON.parse(row!.value)).toBe(false);
  });

  test('seedAppSettings never overrides an already-configured value', async () => {
    const t = convexTest(schema, modules);
    // Admin has explicitly turned it ON — the seed must leave it alone.
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'devices.enforcementEnabled',
        value: JSON.stringify(true),
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.seed.seedAppSettings, {});
    const cfg = await t.query(api.publicConfig.get, {});
    expect(cfg.devices.enforcementEnabled).toBe(true);
  });
});
