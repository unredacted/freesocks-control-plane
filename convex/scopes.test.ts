/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { resolveAdmin, resolveMember } from './lib/http';
import { sha256Hex } from './lib/crypto';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

async function insertToken(
  t: ReturnType<typeof convexTest>,
  opts: {
    scopes: string[];
    subjectType: 'service' | 'user';
    subjectUserId?: Id<'users'>;
  },
): Promise<string> {
  // Plaintext must carry the fsv1_ prefix (resolveToken rejects others).
  const plaintext = `fsv1_${opts.scopes.join('.')}.${Math.floor(opts.scopes.length)}.${opts.subjectType}`;
  const tokenHash = await sha256Hex(plaintext);
  await t.run(async (ctx) => {
    const admin = await ctx.db.insert('adminUsers', {
      username: `tok-${plaintext.slice(-6)}`,
      displayName: 'T',
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('apiTokens', {
      name: 'test',
      tokenHash,
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: admin,
      scopes: opts.scopes,
      subjectType: opts.subjectType,
      subjectUserId: opts.subjectUserId,
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

function bearer(token: string): Request {
  return new Request('https://x/api/v1/admin/tiers', {
    headers: { authorization: `Bearer ${token}` },
  });
}

describe('P1-1 admin token scope enforcement', () => {
  test('a read-only token cannot reach a write-scoped route', async () => {
    const t = convexTest(schema, modules);
    const token = await insertToken(t, { scopes: ['admin:tiers:read'], subjectType: 'service' });
    const req = bearer(token);
    // Has the read scope:
    expect(
      await t.action(async (ctx) => resolveAdmin(ctx, req, 'admin:tiers:read')),
    ).not.toBeNull();
    // Lacks the write scope → rejected (this is the bug the audit found):
    expect(await t.action(async (ctx) => resolveAdmin(ctx, req, 'admin:tiers:write'))).toBeNull();
    // And cannot reach a DIFFERENT resource it wasn't granted:
    expect(await t.action(async (ctx) => resolveAdmin(ctx, req, 'admin:users:write'))).toBeNull();
  });

  test('a token with the exact scope is accepted', async () => {
    const t = convexTest(schema, modules);
    const token = await insertToken(t, { scopes: ['admin:users:write'], subjectType: 'service' });
    const req = bearer(token);
    expect(
      await t.action(async (ctx) => resolveAdmin(ctx, req, 'admin:users:write')),
    ).not.toBeNull();
  });

  test('a member token without the required member scope is rejected', async () => {
    const t = convexTest(schema, modules);
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
    const token = await insertToken(t, {
      scopes: ['subscription:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });
    const req = bearer(token);
    // read scope present:
    expect(
      (await t.action(async (ctx) => resolveMember(ctx, req, 'subscription:read')))?.userId,
    ).toBe(userId);
    // write scope absent → cannot regenerate/switch (subscription:write) or rotate:
    expect(await t.action(async (ctx) => resolveMember(ctx, req, 'subscription:write'))).toBeNull();
    expect(await t.action(async (ctx) => resolveMember(ctx, req, 'account:write'))).toBeNull();
  });

  test('a non-admin token cannot reach admin routes at all', async () => {
    const t = convexTest(schema, modules);
    const token = await insertToken(t, { scopes: ['subscription:read'], subjectType: 'service' });
    const req = bearer(token);
    expect(await t.action(async (ctx) => resolveAdmin(ctx, req, 'admin:tiers:read'))).toBeNull();
  });
});
