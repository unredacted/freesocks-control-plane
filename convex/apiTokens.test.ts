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

  test('a mint writes an admin.token.mint audit row (never the token)', async () => {
    const t = convexTest(schema, modules);
    const createdByAdminId = await seedAdmin(t);

    const minted = await t.action(internal.apiTokens.createToken, {
      name: 'svc-audit',
      scopes: ['admin:tiers:read', 'admin:tiers:write'],
      subjectType: 'service',
      createdByAdminId,
    });

    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      const mint = audits.find((a) => a.action === 'admin.token.mint');
      expect(mint).toBeDefined();
      expect(mint!.actorId).toBe(createdByAdminId);
      expect(mint!.targetId).toBe(minted.id);
      const payload = mint!.payload as Record<string, unknown>;
      expect(payload).toMatchObject({ name: 'svc-audit', scopeCount: 2, subjectType: 'service' });
      // Never the token or its hash anywhere in the audit row.
      expect(JSON.stringify(mint)).not.toContain(minted.plaintext);
      expect(JSON.stringify(mint)).not.toContain(await sha256Hex(minted.plaintext));
    });
  });
});

describe('registration boundary (admin:edges:register)', () => {
  const server = (t: ReturnType<typeof convexTest>, slug: string) =>
    t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: slug,
        slug,
        config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );

  test('a register token is minted with its boundary (ids and slugs merge; node names trimmed and deduped) and the audit carries counts only', async () => {
    const t = convexTest(schema, modules);
    const adminId = await seedAdmin(t);
    const a = await server(t, 'panel-a');
    await server(t, 'panel-b');
    const { id } = await t.action(internal.apiTokens.createToken, {
      name: 'node-role',
      scopes: ['admin:edges:register'],
      subjectType: 'service',
      createdByAdminId: adminId,
      edgeRegistration: {
        backendServerIds: [a],
        backendSlugs: ['panel-b', 'panel-a'],
        nodeNames: [' node-one ', 'node-one', ''],
      },
    });
    const row = await t.run((ctx) => ctx.db.get(id));
    expect(row?.edgeRegistration?.backendServerIds).toHaveLength(2);
    expect(row?.edgeRegistration?.nodeNames).toEqual(['node-one']);
    const view = await t.query(internal.adminApi.tokenById, { id });
    expect(view?.edgeRegistration).toEqual({
      backendServerIds: expect.arrayContaining([a]),
      nodeNames: ['node-one'],
    });
    const audit = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).find((r) => r.action === 'admin.token.mint'),
    );
    expect(audit?.payload).toMatchObject({ boundaryServers: 2, boundaryNodes: 1 });
    expect(JSON.stringify(audit?.payload)).not.toContain('panel-a');
  });

  test('the scope without a boundary, a boundary without the scope, and an unknown server are refused', async () => {
    const t = convexTest(schema, modules);
    const adminId = await seedAdmin(t);
    const a = await server(t, 'panel-a');
    const mint = (scopes: string[], edgeRegistration?: Record<string, unknown>) =>
      t.action(internal.apiTokens.createToken, {
        name: 'x',
        scopes,
        subjectType: 'service',
        createdByAdminId: adminId,
        ...(edgeRegistration ? { edgeRegistration } : {}),
      } as never);
    await expect(mint(['admin:edges:register'])).rejects.toThrow(/needs a registration boundary/);
    await expect(mint(['admin:servers:read'], { backendServerIds: [a] })).rejects.toThrow(
      /needs the admin:edges:register scope/,
    );
    await expect(mint(['admin:edges:register'], { backendSlugs: ['nope'] })).rejects.toThrow(
      /Unknown backend server slug/,
    );
    await expect(mint(['admin:edges:register'], { backendServerIds: [] })).rejects.toThrow(
      /names no backend server/,
    );
    expect(await t.run(async (ctx) => (await ctx.db.query('apiTokens').collect()).length)).toBe(0);
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
