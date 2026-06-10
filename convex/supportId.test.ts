/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { generateSupportId, normalizeSupportId } from './lib/supportId';

const modules = import.meta.glob('./**/*.*s');

async function seedUser(t: ReturnType<typeof convexTest>): Promise<Id<'users'>> {
  return t.run(async (ctx) => {
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
    return ctx.db.insert('users', { tierId, status: 'active', updatedAt: Date.now() });
  });
}

describe('lib/supportId pure helpers', () => {
  test('generateSupportId is FS-XXXX-XXXX with an unambiguous alphabet', () => {
    for (let i = 0; i < 50; i++) {
      const id = generateSupportId();
      expect(id).toMatch(/^FS-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
      expect(id).not.toMatch(/[ILOU]/);
    }
  });

  test('normalizeSupportId canonicalizes user input', () => {
    expect(normalizeSupportId('fs7k3m9qx2')).toBe('FS-7K3M-9QX2');
    expect(normalizeSupportId('FS-7K3M-9QX2')).toBe('FS-7K3M-9QX2');
    expect(normalizeSupportId('7k3m 9qx2')).toBe('FS-7K3M-9QX2');
    // Crockford read-aliases: I/L→1, O→0.
    expect(normalizeSupportId('FS-O1IL-0000')).toBe('FS-0111-0000');
  });
});

describe('supportId.ensureForUser', () => {
  test('mints once and is idempotent (stable handle)', async () => {
    const t = convexTest(schema, modules);
    const userId = await seedUser(t);

    const first = await t.action(internal.supportId.ensureForUser, { userId });
    expect(first.supportId).toMatch(/^FS-/);

    const second = await t.action(internal.supportId.ensureForUser, { userId });
    expect(second.supportId).toBe(first.supportId);

    const stored = await t.run(async (ctx) => (await ctx.db.get(userId))?.supportId);
    expect(stored).toBe(first.supportId);
  });

  test('distinct users get distinct support IDs, and findBySupportId resolves them', async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t);
    const b = await seedUser(t);
    const idA = (await t.action(internal.supportId.ensureForUser, { userId: a })).supportId;
    const idB = (await t.action(internal.supportId.ensureForUser, { userId: b })).supportId;
    expect(idA).not.toBe(idB);

    expect(await t.query(internal.supportId.findBySupportId, { input: idA.toLowerCase() })).toBe(a);
    expect(await t.query(internal.supportId.findBySupportId, { input: idB })).toBe(b);
    expect(await t.query(internal.supportId.findBySupportId, { input: 'FS-0000-0000' })).toBeNull();
  });

  test('setSupportId rejects a collision with a different user', async () => {
    const t = convexTest(schema, modules);
    const a = await seedUser(t);
    const b = await seedUser(t);
    const idA = (await t.action(internal.supportId.ensureForUser, { userId: a })).supportId;
    await expect(
      t.mutation(internal.supportId.setSupportId, { userId: b, supportId: idA }),
    ).rejects.toThrow(/collision/);
  });
});
