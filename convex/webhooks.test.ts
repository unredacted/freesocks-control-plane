/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex } from './lib/crypto';
import { ConvexError } from 'convex/values';

const modules = import.meta.glob('./**/*.*s');
const SECRET = 'test-webhook';

async function seedUserAndTiers(t: ReturnType<typeof convexTest>): Promise<{
  userId: Id<'users'>;
  accountId: string;
  freeTierId: Id<'tiers'>;
  memberTierId: Id<'tiers'>;
}> {
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

  test('a non-number expiresAtMs is ACKed processed (no retry churn, no grant)', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId, freeTierId } = await seedUserAndTiers(t);
    const body = JSON.stringify({
      eventId: 'evt-badexpiry',
      accountId,
      tierSlug: 'member',
      expiresAtMs: 'next-month', // permanently malformed
    });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, applied: false, reason: 'invalid_expiresAtMs' });
    await t.run(async (ctx) => {
      // No grant…
      expect((await ctx.db.get(userId))?.tierId).toBe(freeTierId);
      // …and the claim is TERMINAL (a redelivery dedupes instead of retrying).
      // The dedupe id is namespaced `generic:` (Review: cross-rail keyspace).
      const evt = await ctx.db
        .query('webhookEvents')
        .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-badexpiry'))
        .unique();
      expect(evt?.status).toBe('processed');
    });
  });

  test('a seconds-unit expiresAtMs is auto-corrected to ms', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId, memberTierId } = await seedUserAndTiers(t);
    const seconds = Math.floor((Date.now() + 30 * 86_400_000) / 1000);
    const body = JSON.stringify({
      eventId: 'evt-seconds',
      accountId,
      tierSlug: 'member',
      expiresAtMs: seconds, // a sender bug (seconds, not ms) — coerced, not a 1970 lapse
    });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res.applied).toBe(true);
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now() + 29 * 86_400_000);
    });
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

  test('the stored event payload redacts the account-number plaintext', async () => {
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserAndTiers(t);
    const body = JSON.stringify({ eventId: 'evt-redact', accountId, tierSlug: 'member' });
    const signature = await hmacSha256Hex(SECRET, body);
    await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-redact'))
        .unique();
      expect(ev).not.toBeNull();
      expect(ev!.payload).not.toContain(accountId); // full plaintext never stored
      expect(ev!.payload).toContain(accountId.slice(0, 4)); // 4-digit prefix retained
    });
  });

  test('an unknown tierSlug is ACKed as applied:false', async () => {
    const t = convexTest(schema, modules);
    const { accountId } = await seedUserAndTiers(t);
    const body = JSON.stringify({ eventId: 'evt-badtier', accountId, tierSlug: 'nope' });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, applied: false, reason: 'unknown_tier' });
  });

  // H-1: the dedupe row is a CLAIM, not a receipt. A grant that throws must
  // leave the event retryable — the old code committed the dedupe row first,
  // so the portal's retry was swallowed as duplicate and the paid grant lost.
  test('a failed grant leaves the event retryable; the retry applies exactly once', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId, memberTierId } = await seedUserAndTiers(t);
    const body = JSON.stringify({
      eventId: 'evt-retry',
      accountId,
      tierSlug: 'member',
      expiresAtMs: Date.now() + 30 * 86_400_000,
    });
    const signature = await hmacSha256Hex(SECRET, body);

    // Force a throw INSIDE the grant path (after the claim): hashAccountId
    // requires the pepper, so unsetting it fails the user lookup step.
    vi.stubEnv('ACCOUNT_ID_PEPPER', '');
    await expect(t.action(internal.webhooks.ingest, { rawBody: body, signature })).rejects.toThrow(
      /ACCOUNT_ID_PEPPER/,
    );
    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-retry'))
        .unique();
      expect(ev?.status).toBe('failed');
      expect(ev?.processedAt).toBeUndefined();
    });

    // The sender retries the same eventId: the failed claim re-opens and the
    // grant applies.
    vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
    const retry = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(retry).toEqual({ ok: true, applied: true });
    const expiryAfterRetry = await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-retry'))
        .unique();
      expect(ev?.status).toBe('processed');
      expect(ev?.processedAt).toBeGreaterThan(0);
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      return user?.membershipExpiresAt;
    });

    // A third delivery is now a terminal duplicate — nothing re-applies.
    const third = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(third).toEqual({ ok: true, duplicate: true, applied: false });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.membershipExpiresAt).toBe(expiryAfterRetry);
    });
  });

  // Legacy rows written before the status field existed have status:undefined
  // (+ processedAt). They must be treated as terminal, never re-granted. (The
  // `generic:` dedupe namespace predates this test's row; the "legacy" aspect
  // under test is the missing STATUS, not the prefix.)
  test('a legacy status-less event row is a terminal duplicate', async () => {
    const t = convexTest(schema, modules);
    const { userId, accountId, freeTierId } = await seedUserAndTiers(t);
    await t.run(async (ctx) => {
      await ctx.db.insert('webhookEvents', {
        eventId: 'generic:evt-legacy',
        source: 'billing',
        payload: '{}',
        processedAt: Date.now(),
      });
    });
    const body = JSON.stringify({ eventId: 'evt-legacy', accountId, tierSlug: 'member' });
    const signature = await hmacSha256Hex(SECRET, body);
    const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    expect(res).toEqual({ ok: true, duplicate: true, applied: false });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(freeTierId); // no re-grant
    });
  });

  test('unknown user/tier ACKs are marked processed (the sender must stop retrying)', async () => {
    const t = convexTest(schema, modules);
    await seedUserAndTiers(t);
    const body = JSON.stringify({
      eventId: 'evt-ack-processed',
      accountId: '99998888777766665555444433332222',
      tierSlug: 'member',
    });
    const signature = await hmacSha256Hex(SECRET, body);
    await t.action(internal.webhooks.ingest, { rawBody: body, signature });
    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-ack-processed'))
        .unique();
      expect(ev?.status).toBe('processed');
    });
  });

  // Review E-M2: the dedupe claim only covers the webhookEvents retention
  // window. A captured, validly-signed body replayed AFTER the sweep re-claims
  // — and without the stale guard it would re-apply the ORIGINAL expiry,
  // regressing (even lapsing) a since-renewed member on every replay.
  describe('stale-replay guard (Review E-M2)', () => {
    test('a replayed event with an EARLIER expiry than the member’s current one is refused', async () => {
      const t = convexTest(schema, modules);
      const { userId, accountId, memberTierId } = await seedUserAndTiers(t);
      // The member's current expiry: ~60 days out.
      const currentExpiry = Date.now() + 60 * 86_400_000;
      await t.run(async (ctx) => {
        await ctx.db.patch(userId, {
          tierId: memberTierId,
          membershipExpiresAt: currentExpiry,
          updatedAt: Date.now(),
        });
      });
      // Replay an OLD event (fresh eventId, as a post-retention replay would
      // be) whose original grant ended ~30 days out — EARLIER than current.
      const body = JSON.stringify({
        eventId: 'evt-stale',
        accountId,
        tierSlug: 'member',
        expiresAtMs: Date.now() + 30 * 86_400_000,
      });
      const signature = await hmacSha256Hex(SECRET, body);
      const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
      expect(res).toEqual({ ok: true, applied: false, reason: 'stale_replay' });
      await t.run(async (ctx) => {
        // The member's expiry did NOT regress…
        expect((await ctx.db.get(userId))?.membershipExpiresAt).toBe(currentExpiry);
        // …and the event is terminally processed (no retry churn).
        const ev = await ctx.db
          .query('webhookEvents')
          .withIndex('by_event_id', (q) => q.eq('eventId', 'generic:evt-stale'))
          .unique();
        expect(ev?.status).toBe('processed');
      });
    });

    test('a NEW event with a LATER expiry still applies (the guard only blocks regression)', async () => {
      const t = convexTest(schema, modules);
      const { userId, accountId, memberTierId } = await seedUserAndTiers(t);
      const currentExpiry = Date.now() + 10 * 86_400_000;
      await t.run(async (ctx) => {
        await ctx.db.patch(userId, {
          tierId: memberTierId,
          membershipExpiresAt: currentExpiry,
          updatedAt: Date.now(),
        });
      });
      const laterExpiry = Date.now() + 40 * 86_400_000;
      const body = JSON.stringify({
        eventId: 'evt-renew',
        accountId,
        tierSlug: 'member',
        expiresAtMs: laterExpiry,
      });
      const signature = await hmacSha256Hex(SECRET, body);
      const res = await t.action(internal.webhooks.ingest, { rawBody: body, signature });
      expect(res).toEqual({ ok: true, applied: true });
      await t.run(async (ctx) => {
        expect((await ctx.db.get(userId))?.membershipExpiresAt).toBe(laterExpiry);
      });
    });
  });
});

describe('webhooks.ingest config gate (pass 2)', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('unset secret throws the typed webhook.not_configured ConvexError', async () => {
    vi.stubEnv('WEBHOOK_SIGNING_SECRET', '');
    const t = convexTest(schema, modules);
    let thrown: unknown;
    try {
      await t.action(internal.webhooks.ingest, { rawBody: '{}', signature: 'x' });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ConvexError);
    expect((thrown as ConvexError<{ code: string }>).data.code).toBe('webhook.not_configured');
  });
});
