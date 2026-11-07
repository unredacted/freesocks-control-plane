/// <reference types="vite/client" />
/**
 * Plan-card feature lines (src/shared/contracts/tierFeatures.ts) through the
 * admin tier writes and the public config: defaults while unset, a saved list
 * verbatim, null back to the defaults, and bad lines refused.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

async function setup() {
  const t = convexTest(schema, modules);
  const id = await t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: 'member',
      name: 'Member',
      backend: 'remnawave',
      monthlyTrafficGb: 0,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    }),
  );
  const publicFeatures = async () =>
    (await t.query(api.publicConfig.get, {})).tiers.find((x) => x.slug === 'member')!.features;
  return { t, id, publicFeatures };
}

describe('tier card features', () => {
  test('unset: the membership defaults, publicly and to the admin', async () => {
    const { t, id, publicFeatures } = await setup();
    expect((await publicFeatures()).map((f) => f.preset)).toEqual([
      'fasterSpeeds',
      'alternateLocations',
      'mirrors',
      'supportsFree',
    ]);
    const row = (await t.query(internal.adminApi.tiersList, {})).tiers.find((x) => x.id === id)!;
    expect(row.featuresDefault).toBe(true);
  });

  test('a saved list is served as saved; null goes back to the defaults', async () => {
    const { t, id, publicFeatures } = await setup();
    const saved = await t.mutation(internal.adminApi.updateTier, {
      id,
      features: [{ preset: null, iconId: 'heart', label: ' Priority support ' }],
    });
    expect(saved.featuresDefault).toBe(false);
    expect(await publicFeatures()).toEqual([
      { preset: null, iconId: 'heart', label: 'Priority support' },
    ]);
    await t.mutation(internal.adminApi.updateTier, { id, features: null });
    expect((await publicFeatures()).length).toBe(4);
    // An unrelated edit leaves the list alone.
    await t.mutation(internal.adminApi.updateTier, { id, features: [] });
    await t.mutation(internal.adminApi.updateTier, { id, name: 'Membership' });
    expect(await publicFeatures()).toEqual([]);
  });

  test('a bad line is refused and nothing is written', async () => {
    const { t, id, publicFeatures } = await setup();
    await expect(
      t.mutation(internal.adminApi.updateTier, {
        id,
        features: [{ preset: null, iconId: 'skull', label: 'x' }],
      }),
    ).rejects.toThrow(/unknown icon/);
    expect((await publicFeatures()).length).toBe(4);
  });
});
