/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function seedFreeTier(t: ReturnType<typeof convexTest>): Promise<Id<'tiers'>> {
  return t.run((ctx) =>
    ctx.db.insert('tiers', {
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
    }),
  );
}

describe('freeTier.claimFreeSlot', () => {
  // NOTE: claimFreeSlot's true OCC race-safety (two concurrent racers can never
  // both observe `< cap`) was proven against the LIVE Convex backend; convex-test
  // runs mutations single-threaded, so these calls are SEQUENTIAL — they assert
  // the cap arithmetic, not the concurrency guarantee.
  test('claims up to cap N, then refuses', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const cap = 3;
    const base = { ipHash: 'iphash-cap', dayBucket, cap, tierId };

    for (let i = 0; i < cap; i++) {
      const r = await t.mutation(internal.freeTier.claimFreeSlot, base);
      expect(r.claimed).toBe(true);
    }
    const over = await t.mutation(internal.freeTier.claimFreeSlot, base);
    expect(over.claimed).toBe(false);
  });

  test('distinct IPs have independent caps', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const a = { ipHash: 'ip-a', dayBucket, cap: 1, tierId };
    const b = { ipHash: 'ip-b', dayBucket, cap: 1, tierId };

    expect((await t.mutation(internal.freeTier.claimFreeSlot, a)).claimed).toBe(true);
    expect((await t.mutation(internal.freeTier.claimFreeSlot, a)).claimed).toBe(false);
    expect((await t.mutation(internal.freeTier.claimFreeSlot, b)).claimed).toBe(true);
  });

  test('a successful claim inserts a bare user + a grant', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const r = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-insert',
      dayBucket,
      cap: 1,
      tierId,
      ipCountry: 'IR',
    });
    expect(r.claimed).toBe(true);
    if (!r.claimed) throw new Error('unreachable');
    await t.run(async (ctx) => {
      const user = await ctx.db.get(r.userId);
      expect(user?.status).toBe('active');
      expect(user?.tierId).toBe(tierId);
      const grant = await ctx.db.get(r.grantId);
      expect(grant?.ipHash).toBe('ip-insert');
      expect(grant?.ipCountry).toBe('IR');
      expect(grant?.grantedDayBucket).toBe(dayBucket);
    });
  });
});

describe('freeTier.releaseFreeSlot', () => {
  test('deletes both the grant and the bare user', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    const r = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-release',
      dayBucket,
      cap: 1,
      tierId,
    });
    if (!r.claimed) throw new Error('expected claim');

    await t.mutation(internal.freeTier.releaseFreeSlot, { userId: r.userId, grantId: r.grantId });
    await t.run(async (ctx) => {
      expect(await ctx.db.get(r.userId)).toBeNull();
      expect(await ctx.db.get(r.grantId)).toBeNull();
      // The freed slot is reclaimable.
    });
    const again = await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-release',
      dayBucket,
      cap: 1,
      tierId,
    });
    expect(again.claimed).toBe(true);
  });
});

describe('freeTier.grantsForIpDay', () => {
  test('counts grants for the (ipHash, dayBucket)', async () => {
    const t = convexTest(schema, modules);
    const tierId = await seedFreeTier(t);
    const dayBucket = Math.floor(Date.now() / 86_400_000);
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket,
      cap: 5,
      tierId,
    });
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket,
      cap: 5,
      tierId,
    });
    // A different day bucket must not be counted.
    await t.mutation(internal.freeTier.claimFreeSlot, {
      ipHash: 'ip-count',
      dayBucket: dayBucket - 1,
      cap: 5,
      tierId,
    });

    const grants = await t.query(internal.freeTier.grantsForIpDay, {
      ipHash: 'ip-count',
      dayBucket,
    });
    expect(grants).toHaveLength(2);
  });
});
