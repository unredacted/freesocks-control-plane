/// <reference types="vite/client" />
/**
 * `renameAppSettingKeys`: carries a stored admin override across an appSettings
 * key rename in code (2026-09-16 E2EE -> HPKE). Re-keys when the new key has no
 * row, drops the old row when the new key already has one, and is a no-op on a
 * clean deployment or a second run.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');
const OLD = 'ratelimit.e2ee.keys.fetch';
const NEW = 'ratelimit.hpke.keys.fetch';

async function putSetting(t: ReturnType<typeof convexTest>, key: string, value: unknown) {
  await t.run((ctx) =>
    ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() }),
  );
}
async function settingsByKey(t: ReturnType<typeof convexTest>) {
  const rows = await t.run((ctx) => ctx.db.query('appSettings').collect());
  return new Map(rows.map((r) => [r.key, JSON.parse(r.value) as unknown]));
}

describe('seed.renameAppSettingKeys', () => {
  test('re-keys a stored override to the renamed key; second run is a no-op', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, OLD, { max: 5, windowMs: 60_000, enabled: true });
    expect(await t.mutation(internal.seed.renameAppSettingKeys, {})).toEqual({
      renamed: 1,
      dropped: 0,
    });
    const after = await settingsByKey(t);
    expect(after.has(OLD)).toBe(false);
    expect(after.get(NEW)).toEqual({ max: 5, windowMs: 60_000, enabled: true });
    expect(await t.mutation(internal.seed.renameAppSettingKeys, {})).toEqual({
      renamed: 0,
      dropped: 0,
    });
  });

  test('drops the stale old row when the new key already has an override (newer edit wins)', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, OLD, { max: 5, windowMs: 60_000, enabled: true });
    await putSetting(t, NEW, { max: 9, windowMs: 60_000, enabled: true });
    expect(await t.mutation(internal.seed.renameAppSettingKeys, {})).toEqual({
      renamed: 0,
      dropped: 1,
    });
    const after = await settingsByKey(t);
    expect(after.has(OLD)).toBe(false);
    expect(after.get(NEW)).toEqual({ max: 9, windowMs: 60_000, enabled: true });
  });

  test('the renamed override is what the public epoch-key route enforces', async () => {
    const t = convexTest(schema, modules);
    await putSetting(t, OLD, { max: 1, windowMs: 60_000, enabled: true });
    await t.mutation(internal.seed.renameAppSettingKeys, {});
    vi.stubEnv('TRUSTED_PROXY', 'true');
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
    const headers = { 'x-forwarded-for': '203.0.113.80' };
    expect((await t.fetch('/api/v1/hpke/keys', { headers })).status).toBe(200);
    expect((await t.fetch('/api/v1/hpke/keys', { headers })).status).toBe(429);
  });
});
