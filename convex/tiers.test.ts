/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');
type T = ReturnType<typeof convexTest>;

async function seedTier(
  t: T,
  o: {
    slug: string;
    backend?: 'remnawave' | 'outline';
    isDefaultFree?: boolean;
    isActive?: boolean;
    peerTierId?: Id<'tiers'>;
  },
): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
      slug: o.slug,
      name: o.slug,
      backend: o.backend ?? 'remnawave',
      monthlyTrafficGb: 0,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      trafficStrategy: 'MONTH',
      isDefaultFree: o.isDefaultFree ?? false,
      isActive: o.isActive ?? true,
      priority: 0,
      expirationDaysAfterMembershipLapse: 0,
      ...(o.peerTierId ? { peerTierId: o.peerTierId } : {}),
      updatedAt: Date.now(),
    }),
  );
}

describe('tiers.getPeerTier (D-1 cross-backend peer resolution)', () => {
  test('a free tier resolves the per-backend default-free peer', async () => {
    const t = convexTest(schema, modules);
    const free = await seedTier(t, { slug: 'free', backend: 'remnawave', isDefaultFree: true });
    const freeOutline = await seedTier(t, {
      slug: 'free-ol',
      backend: 'outline',
      isDefaultFree: true,
    });
    const peer = await t.query(internal.tiers.getPeerTier, {
      tierId: free,
      targetBackend: 'outline',
    });
    expect(peer?._id).toBe(freeOutline);
  });

  test('a paid tier resolves its forward peerTierId link', async () => {
    const t = convexTest(schema, modules);
    const outline = await seedTier(t, { slug: 'member-ol', backend: 'outline' });
    const rw = await seedTier(t, { slug: 'member', backend: 'remnawave', peerTierId: outline });
    const peer = await t.query(internal.tiers.getPeerTier, {
      tierId: rw,
      targetBackend: 'outline',
    });
    expect(peer?._id).toBe(outline);
  });

  test('the link resolves in reverse (the target-backend tier points back)', async () => {
    const t = convexTest(schema, modules);
    const rw = await seedTier(t, { slug: 'member', backend: 'remnawave' });
    const outline = await seedTier(t, { slug: 'member-ol', backend: 'outline', peerTierId: rw });
    const peer = await t.query(internal.tiers.getPeerTier, {
      tierId: rw,
      targetBackend: 'outline',
    });
    expect(peer?._id).toBe(outline);
  });

  test('returns null for a paid tier with no link', async () => {
    const t = convexTest(schema, modules);
    const rw = await seedTier(t, { slug: 'member', backend: 'remnawave' });
    await seedTier(t, { slug: 'member-ol', backend: 'outline' }); // exists but unlinked
    expect(
      await t.query(internal.tiers.getPeerTier, { tierId: rw, targetBackend: 'outline' }),
    ).toBeNull();
  });

  test('an inactive linked peer is not resolved', async () => {
    const t = convexTest(schema, modules);
    const outline = await seedTier(t, { slug: 'member-ol', backend: 'outline', isActive: false });
    const rw = await seedTier(t, { slug: 'member', backend: 'remnawave', peerTierId: outline });
    expect(
      await t.query(internal.tiers.getPeerTier, { tierId: rw, targetBackend: 'outline' }),
    ).toBeNull();
  });

  test('a link to a tier on a different backend than requested is not resolved', async () => {
    const t = convexTest(schema, modules);
    // rw links to ANOTHER remnawave tier; asking for the outline peer must be null.
    const rw2 = await seedTier(t, { slug: 'member-2', backend: 'remnawave' });
    const rw = await seedTier(t, { slug: 'member', backend: 'remnawave', peerTierId: rw2 });
    expect(
      await t.query(internal.tiers.getPeerTier, { tierId: rw, targetBackend: 'outline' }),
    ).toBeNull();
  });
});
