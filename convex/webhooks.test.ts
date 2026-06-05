/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');
const SECRET = 'test-webhook';

async function seedUserAndTiers(
  t: ReturnType<typeof convexTest>,
): Promise<{ userId: Id<'users'>; accountId: string; freeTierId: Id<'tiers'>; memberTierId: Id<'tiers'> }> {
  const { userId, freeTierId, memberTierId } = await t.run(async (ctx) => {
    const freeTierId = await ctx.db.insert('tiers', {
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
    const memberTierId = await ctx.db.insert('tiers', {
      slug: 'member',
      name: 'Member',
      backend: 'remnawave',
      monthlyTrafficGb: 500,
      deviceLimit: 3,
      hwidLimit: 3,
      hwidEnabled: true,
      trafficStrategy: 'MONTH',
      isDefaultFree: false,
      isActive: true,
      priority: 10,
      expirationDaysAfterMembershipLapse: 7,
      updatedAt: Date.now(),
    });
    const userId = await ctx.db.insert('users', {
      tierId: freeTierId,
      status: 'active',
      updatedAt: Date.now(),
    });
    return { userId, freeTierId, memberTierId };
  });
  const minted = await t.action(internal.accountId.mintForUser, { userId });
  return { userId, accountId: minted.accountId, freeTierId, memberTierId };
}

describe('webhooks.ingest', () => {
  beforeEach(() => {
    vi.stubEnv('WEBHOOK_SIGNING_SECRET', SECRET);
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
  });
  afterEach(() => vi.unstubAllEnvs());

  test('a valid event applies the tier change', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId, memberTierId } = await seedUserAndTiers(t);
    const body = JSON.stringify({
      eventId: 'evt-1',
      accountId,
      tierSlug: 'member',
      expiresAtMs: Date.now() + 30 * 86_400_000,
    });
    const signature = await hmacSha256Hex(SECRET, body);

    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, applied: true });

    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('a replayed eventId is a deduped no-op', async () => {
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserAndTiers(t);
    const body = JSON.stringify({ eventId: 'evt-dup', accountId, tierSlug: 'member' });
    const signature = await hmacSha256Hex(SECRET, body);

    const first = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(first.applied).toBe(true);
    const second = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(second).toEqual({ ok: true, duplicate: true, applied: false });
  });

  test('a bad signature throws', async () => {
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserAndTiers(t);
    const body = JSON.stringify({ eventId: 'evt-badsig', accountId, tierSlug: 'member' });
    await expect(
      t.action(internal.webhooks.ingest, { rawBody: body, signature: 'deadbeef' }),
    ).rejects.toThrow(/invalid signature/);
  });

  test('an unknown accountId is ACKed as applied:false', async () => {
    const t = convexTest(schema, modules);
    await seedUserAndTiers(t);
    const body = JSON.stringify({
      eventId: 'evt-unknown',
      accountId: '99998888777766665555444433332222',
      tierSlug: 'member',
    });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, applied: false, reason: 'unknown_user' });
  });

  test('an unknown tierSlug is ACKed as applied:false', async () => {
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserAndTiers(t);
    const body = JSON.stringify({ eventId: 'evt-badtier', accountId, tierSlug: 'nope' });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, applied: false, reason: 'unknown_tier' });
  });
});
