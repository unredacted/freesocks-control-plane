/// <reference types="vite/client" />
/**
 * `fsv1_` service/user token mint + resolve (convex/apiTokens.ts). Covers the
 * hash-not-plaintext storage invariant, the resolve round-trip, the
 * revoked/expired/wrong-prefix null paths, and the ~5-min lastUsedAt debounce.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { sha256Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');

const LAST_USED_DEBOUNCE_MS = 5 * 60_000; // mirrors apiTokens.ts

/** An admin row to satisfy createToken's createdByAdminId. */
async function seedAdmin(t: ReturnType<typeof convexTest>): Promise<Id<'adminUsers'>> {
  return t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
}

describe('createToken', () => {
  test('returns an fsv1_-prefixed plaintext whose stored hash is not the plaintext', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);

    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'svc',
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
      createdByAdminId,
    });
    expect(minted.plaintext.startsWith('fsv1_')).toBe(true);
    expect(minted.prefix).toBe(minted.plaintext.slice(0, 12));

    const row = await t.run((ctx) => ctx.db.get(minted.id));
    expect(row).toBeTruthy();
    // The row stores only the SHA-256 hash + a short prefix, never the plaintext.
    expect(row!.tokenHash).not.toBe(minted.plaintext);
    expect(row!.tokenHash).toBe(await sha256Hex(minted.plaintext));
    expect(row!.tokenPrefix).toBe(minted.prefix);
    expect(row!.scopes).toEqual(['admin:tiers:read']);
  });
});

describe('resolveToken', () => {
  test('round-trips a valid plaintext to its scopes + subjectType', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);
    const userId = await t.run(async (ctx) => {
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
    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'usr',
      scopes: ['account:read', 'subscription:write'],
      subjectType: 'user',
      subjectUserId: userId,
      createdByAdminId,
    });

    const resolved = await t.action(internal.apiTokens.resolveToken, {
      plaintext: minted.plaintext,
    });
    expect(resolved).toBeTruthy();
    expect(resolved!.id).toBe(minted.id);
    expect(resolved!.scopes).toEqual(['account:read', 'subscription:write']);
    expect(resolved!.subjectType).toBe('user');
    expect(resolved!.subjectUserId).toBe(userId);
  });

  test('a revoked token resolves to null', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);
    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'svc',
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
      createdByAdminId,
    });
    await t.run((ctx) => ctx.db.patch(minted.id, { revokedAt: Date.now() }));

    expect(
      await t.action(internal.apiTokens.resolveToken, { plaintext: minted.plaintext }),
    ).toBeNull();
  });

  test('an expired token resolves to null', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);
    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'svc',
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
      createdByAdminId,
    });
    await t.run((ctx) => ctx.db.patch(minted.id, { expiresAt: Date.now() - 1_000 }));

    expect(
      await t.action(internal.apiTokens.resolveToken, { plaintext: minted.plaintext }),
    ).toBeNull();
  });

  test('a wrong-prefix plaintext short-circuits to null', async () => {
    const t = convexTest(schema, modules);
    // No matching row could exist; the prefix check must reject it before hashing.
    expect(
      await t.action(internal.apiTokens.resolveToken, { plaintext: 'nope_not-an-fsv1-token' }),
    ).toBeNull();
  });

  test('unknown (never-minted) plaintext resolves to null', async () => {
    const t = convexTest(schema, modules);
    expect(
      await t.action(internal.apiTokens.resolveToken, { plaintext: 'fsv1_deadbeefdeadbeef' }),
    ).toBeNull();
  });

  test('lastUsedAt is debounced: two rapid resolves write it once', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);
    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'svc',
      scopes: ['admin:tiers:read'],
      subjectType: 'service',
      createdByAdminId,
    });

    // Fresh row: no lastUsedAt yet.
    expect(await t.run(async (ctx) => (await ctx.db.get(minted.id))!.lastUsedAt)).toBeFalsy();

    await t.action(internal.apiTokens.resolveToken, { plaintext: minted.plaintext });
    const first = await t.run(async (ctx) => (await ctx.db.get(minted.id))!.lastUsedAt);
    expect(first).toBeTypeOf('number');

    // A second resolve well within the debounce window must NOT re-stamp.
    await t.action(internal.apiTokens.resolveToken, { plaintext: minted.plaintext });
    const second = await t.run(async (ctx) => (await ctx.db.get(minted.id))!.lastUsedAt);
    expect(second).toBe(first);

    // Backdate past the debounce window → the next resolve stamps a fresh value.
    const backdated = first! - LAST_USED_DEBOUNCE_MS - 1_000;
    await t.run((ctx) => ctx.db.patch(minted.id, { lastUsedAt: backdated }));
    await t.action(internal.apiTokens.resolveToken, { plaintext: minted.plaintext });
    const third = await t.run(async (ctx) => (await ctx.db.get(minted.id))!.lastUsedAt);
    // Re-stamped: the backdated value was overwritten with a current one.
    expect(third).toBeGreaterThan(backdated);
  });
});
