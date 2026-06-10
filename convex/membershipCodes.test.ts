/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  generateMembershipCode,
  isValidMembershipCode,
  normalizeMembershipCode,
} from './lib/membershipCode';

const modules = import.meta.glob('./**/*.*s');

async function seedTiers(t: ReturnType<typeof convexTest>) {
  return t.run(async (ctx) => {
    const free = await ctx.db.insert('tiers', {
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
    const patron = await ctx.db.insert('tiers', {
      slug: 'patron',
      name: 'Patron',
      backend: 'remnawave',
      monthlyTrafficGb: 500,
      deviceLimit: 5,
      hwidLimit: 5,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
    const admin = await ctx.db.insert('adminUsers', {
      username: 'root',
      displayName: 'Root',
      isActive: true,
      updatedAt: Date.now(),
    });
    return { free, patron, admin };
  });
}

async function seedUser(t: ReturnType<typeof convexTest>, tierId: Id<'tiers'>) {
  return t.run((ctx) => ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() }));
}

describe('lib/membershipCode helpers', () => {
  test('generates valid FSM- codes with an unambiguous alphabet', () => {
    for (let i = 0; i < 50; i++) {
      const c = generateMembershipCode();
      expect(isValidMembershipCode(c)).toBe(true);
      expect(c).not.toMatch(/[ILOU]/);
    }
  });
  test('normalizes user input', () => {
    expect(normalizeMembershipCode('fsm 7k3m 9qx2 abcd')).toBe('FSM-7K3M-9QX2-ABCD');
    expect(isValidMembershipCode(normalizeMembershipCode('FSM-7K3M-9QX2-ABCD'))).toBe(true);
    expect(isValidMembershipCode('not-a-code')).toBe(false);
  });
});

describe('membershipCodes redeem flow', () => {
  beforeEach(() => {
    vi.stubEnv('IP_HASH_SALT', 'test-salt');
  });

  test('mint → redeem grants the tier and extends membership; code is single-use', async () => {
    const t = convexTest(schema, modules);
    const { patron, admin } = await seedTiers(t);
    const user = await seedUser(t, patron); // tier id reused only as a seed; user starts free-ish

    const { codes } = await t.action(internal.membershipCodes.mintCodes, {
      tierId: patron,
      durationDays: 30,
      count: 1,
      actorAdminId: admin,
    });
    expect(codes).toHaveLength(1);

    const res = await t.action(internal.membershipCodes.redeemCode, { userId: user, code: codes[0]! });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('unreachable');
    expect(res.tierSlug).toBe('patron');
    expect(res.durationDays).toBe(30);

    // Membership now set on the user.
    const after = await t.run((ctx) => ctx.db.get(user));
    expect(after?.membershipExpiresAt).toBeGreaterThan(Date.now());

    // The same code can't be redeemed again (single-use).
    const again = await t.action(internal.membershipCodes.redeemCode, {
      userId: user,
      code: codes[0]!,
    });
    expect(again.ok).toBe(false);
  });

  test('redeem extends from the current expiry, not from now', async () => {
    const t = convexTest(schema, modules);
    const { patron, admin } = await seedTiers(t);
    const user = await seedUser(t, patron);
    const future = Date.now() + 10 * 86_400_000;
    await t.run((ctx) => ctx.db.patch(user, { membershipExpiresAt: future }));

    const { codes } = await t.action(internal.membershipCodes.mintCodes, {
      tierId: patron,
      durationDays: 30,
      count: 1,
      actorAdminId: admin,
    });
    await t.action(internal.membershipCodes.redeemCode, { userId: user, code: codes[0]! });
    const after = await t.run((ctx) => ctx.db.get(user));
    // ~40 days out (10 remaining + 30 added), not 30.
    expect(after!.membershipExpiresAt!).toBeGreaterThan(future + 29 * 86_400_000);
  });

  test('an unknown or malformed code fails generically (no oracle)', async () => {
    const t = convexTest(schema, modules);
    const { patron } = await seedTiers(t);
    const user = await seedUser(t, patron);
    expect((await t.action(internal.membershipCodes.redeemCode, { userId: user, code: 'garbage' })).ok).toBe(
      false,
    );
    expect(
      (await t.action(internal.membershipCodes.redeemCode, { userId: user, code: 'FSM-0000-0000-0000' }))
        .ok,
    ).toBe(false);
  });

  test('a revoked code cannot be redeemed', async () => {
    const t = convexTest(schema, modules);
    const { patron, admin } = await seedTiers(t);
    const user = await seedUser(t, patron);
    const { codes } = await t.action(internal.membershipCodes.mintCodes, {
      tierId: patron,
      durationDays: 30,
      count: 1,
      actorAdminId: admin,
    });
    const list = await t.query(internal.membershipCodes.listCodes, {});
    await t.mutation(internal.membershipCodes.revokeCode, {
      id: list[0]!.id as Id<'redemptionCodes'>,
      actorAdminId: admin,
    });
    const res = await t.action(internal.membershipCodes.redeemCode, { userId: user, code: codes[0]! });
    expect(res.ok).toBe(false);
  });

  test('listCodes masks codes and reports status', async () => {
    const t = convexTest(schema, modules);
    const { patron, admin } = await seedTiers(t);
    await t.action(internal.membershipCodes.mintCodes, {
      tierId: patron,
      durationDays: 30,
      count: 3,
      note: 'launch batch',
      actorAdminId: admin,
    });
    const list = await t.query(internal.membershipCodes.listCodes, {});
    expect(list).toHaveLength(3);
    expect(list[0]).toMatchObject({ tierSlug: 'patron', durationDays: 30, status: 'active' });
    expect(list[0]!.codePrefix).toMatch(/^FSM-/);
    // No plaintext/hash leaks into the list shape.
    expect(JSON.stringify(list[0])).not.toMatch(/[0-9a-f]{64}/);
  });
});
