/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

describe('sessions', () => {
  test('create then bySid returns the live session', async () => {
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
    await t.mutation(internal.sessions.create, {
      sid: 'sid-live',
      kind: 'member',
      userId,
      ttlMs: 60_000,
    });
    const row = await t.query(internal.sessions.bySid, { sid: 'sid-live' });
    expect(row).not.toBeNull();
    expect(row!.kind).toBe('member');
    expect(row!.userId).toBe(userId);
  });

  test('bySid treats an expired session as absent', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('sessions', {
        sid: 'sid-stale',
        kind: 'admin',
        expiresAt: Date.now() - 1000,
      });
    });
    expect(await t.query(internal.sessions.bySid, { sid: 'sid-stale' })).toBeNull();
  });

  test('deleteBySid removes the row', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.sessions.create, { sid: 'sid-del', kind: 'admin', ttlMs: 60_000 });
    expect(await t.query(internal.sessions.bySid, { sid: 'sid-del' })).not.toBeNull();
    await t.mutation(internal.sessions.deleteBySid, { sid: 'sid-del' });
    expect(await t.query(internal.sessions.bySid, { sid: 'sid-del' })).toBeNull();
  });

  test('sweepExpired removes only expired sessions', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run(async (ctx) => {
      await ctx.db.insert('sessions', { sid: 'old', kind: 'member', expiresAt: now - 1000 });
      await ctx.db.insert('sessions', { sid: 'live', kind: 'member', expiresAt: now + 60_000 });
    });
    const { removed } = await t.mutation(internal.sessions.sweepExpired, {});
    expect(removed).toBe(1);
    await t.run(async (ctx) => {
      const rows = await ctx.db.query('sessions').collect();
      expect(rows.map((r) => r.sid)).toEqual(['live']);
    });
  });
});
