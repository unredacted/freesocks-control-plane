/// <reference types="vite/client" />
/**
 * Billing domain tests: checkout creation (stubbed processor fetch), the
 * NOWPayments IPN ingest → single grant, dedupe, the no-grant paths, and the
 * userId-scoped order poll. Mirrors webhooks.test.ts (action/mutation level).
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha256Hex, hmacSha512Hex } from './lib/crypto';
import { ConvexError } from 'convex/values';

const modules = import.meta.glob('./**/*.*s');
const IPN_SECRET = 'test-ipn-secret';

async function seedTiersAndUser(t: ReturnType<typeof convexTest>): Promise<{
  userId: Id<'users'>;
  freeTierId: Id<'tiers'>;
  memberTierId: Id<'tiers'>;
}> {
  return t.run(async (ctx) => {
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
      name: 'FreeSocks Membership',
      backend: 'remnawave',
      monthlyTrafficGb: 0,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      trafficStrategy: 'NO_RESET',
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
}

async function enableBilling(
  t: ReturnType<typeof convexTest>,
  durations: { months: number; amountCents: number }[] = [{ months: 3, amountCents: 1400 }],
) {
  await t.run(async (ctx) => {
    const put = (key: string, value: unknown) =>
      ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() });
    await put('billing.enabled', true);
    await put('billing.nowpayments.enabled', true);
    await put('billing.membership.durations', durations);
  });
}

async function insertPendingOrder(
  t: ReturnType<typeof convexTest>,
  userId: Id<'users'>,
  tierId: Id<'tiers'>,
  opaqueRef: string,
  durationDays = 91,
): Promise<Id<'billingOrders'>> {
  return t.run((ctx) =>
    ctx.db.insert('billingOrders', {
      processor: 'nowpayments',
      opaqueRef,
      userId,
      tierId,
      durationDays,
      amountCents: 1400,
      currency: 'USD',
      status: 'pending',
      updatedAt: Date.now(),
    }),
  );
}

/** Sign an IPN body the way nowpayments.verifyAndParse expects (sorted-key JSON, HMAC-SHA512). */
async function signIpn(payload: Record<string, unknown>): Promise<string> {
  // Flat payloads: JSON.stringify with a sorted key array == sortKeysDeep + stringify.
  const sorted = JSON.stringify(payload, Object.keys(payload).sort());
  return hmacSha512Hex(IPN_SECRET, sorted);
}

/**
 * Real `finished` IPNs carry the received-vs-expected crypto amounts; the
 * settle-tolerance guard downgrades a `finished` that lacks them (fail-safe),
 * so paid-grant fixtures must include a fully-paid pair.
 */
const FULL_AMOUNTS = { actually_paid: 1, pay_amount: 1 };

describe('hmacSha512Hex', () => {
  test('matches the canonical HMAC-SHA512 test vector', async () => {
    // key="key", msg="The quick brown fox jumps over the lazy dog"
    const out = await hmacSha512Hex('key', 'The quick brown fox jumps over the lazy dog');
    expect(out).toBe(
      'b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a',
    );
  });
});

describe('billing.createCheckout', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api.nowpayments.example');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('inserts a pending order bound to the user and returns the redirect URL', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await enableBilling(t);
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ id: 'inv_1', invoice_url: 'https://pay.example/i/inv_1' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
    });
    expect(res.redirectUrl).toBe('https://pay.example/i/inv_1');
    expect(res.orderRef).toMatch(/^[0-9a-f]{32}$/);
    expect(fetchMock).toHaveBeenCalledOnce();

    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.userId).toBe(userId);
      expect(order?.tierId).toBe(memberTierId);
      expect(order?.status).toBe('pending');
      expect(order?.amountCents).toBe(1400);
      expect(order?.durationDays).toBe(Math.round(3 * 30.44));
      expect(order?.processorRef).toBe('inv_1');
    });
  });

  test('leaves no order behind when the processor rejects the invoice', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await enableBilling(t);
    // NOWPayments rejects (e.g. an invalid sandbox key) — the adapter throws and
    // checkout must NOT persist a dangling pending order.
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              statusCode: 403,
              code: 'INVALID_API_KEY',
              message: 'Invalid api key.',
            }),
            { status: 403, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    await expect(
      t.action(internal.billing.createCheckout, { userId, processor: 'nowpayments', months: 3 }),
    ).rejects.toThrow();
    const orders = await t.run((ctx) => ctx.db.query('billingOrders').collect());
    expect(orders).toHaveLength(0);
  });

  test('refuses a crypto term below the crypto minimum (default 3 months), no order left', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    // Catalog includes a 1-month term, but cryptoMinMonths defaults to 3, so a
    // 1-month NOWPayments checkout is refused before any processor call.
    await enableBilling(t, [
      { months: 1, amountCents: 500 },
      { months: 3, amountCents: 1400 },
    ]);
    await expect(
      t.action(internal.billing.createCheckout, { userId, processor: 'nowpayments', months: 1 }),
    ).rejects.toThrow();
    const orders = await t.run((ctx) => ctx.db.query('billingOrders').collect());
    expect(orders).toHaveLength(0);
  });

  test("creates a BTCPay invoice on the operator's own server and persists the order", async () => {
    vi.stubEnv('BTCPAY_API_KEY', 'bp-key');
    vi.stubEnv('BTCPAY_API_URL', 'https://pay.freesocks.example');
    vi.stubEnv('BTCPAY_STORE_ID', 'store-1');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await enableBilling(t);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.btcpay.enabled',
        value: 'true',
        updatedAt: Date.now(),
      }),
    );
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ id: 'inv_bp', checkoutLink: 'https://pay.freesocks.example/i/inv_bp' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'btcpay',
      months: 3,
    });
    expect(res.redirectUrl).toBe('https://pay.freesocks.example/i/inv_bp');
    expect(fetchMock).toHaveBeenCalledOnce();
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.processor).toBe('btcpay');
      expect(order?.tierId).toBe(memberTierId);
      expect(order?.status).toBe('pending');
      expect(order?.processorRef).toBe('inv_bp');
    });
  });

  test('refuses a BTCPay checkout when the rail is enabled but unconfigured', async () => {
    // No BTCPAY_* env and no DB credentials: the dispatch must throw before any
    // fetch, leaving no dangling order.
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await enableBilling(t);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.btcpay.enabled',
        value: 'true',
        updatedAt: Date.now(),
      }),
    );
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(
      t.action(internal.billing.createCheckout, { userId, processor: 'btcpay', months: 3 }),
    ).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
    const orders = await t.run((ctx) => ctx.db.query('billingOrders').collect());
    expect(orders).toHaveLength(0);
  });

  test('refuses when billing is disabled', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    // billing.enabled defaults to false (no enableBilling call).
    await expect(
      t.action(internal.billing.createCheckout, { userId, processor: 'nowpayments', months: 3 }),
    ).rejects.toThrow();
  });

  test('refuses an unknown duration', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await enableBilling(t, [{ months: 1, amountCents: 500 }]);
    await expect(
      t.action(internal.billing.createCheckout, { userId, processor: 'nowpayments', months: 99 }),
    ).rejects.toThrow();
  });
});

describe('billing.ingestEvent (NOWPayments)', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', IPN_SECRET);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('a finished IPN marks the order paid and extends membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-finish', 91);
    const payload = {
      payment_status: 'finished',
      payment_id: 12345,
      order_id: 'ref-finish',
      price_amount: 14,
      price_currency: 'usd',
      ...FULL_AMOUNTS,
    };
    const signature = await signIpn(payload);
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(res).toEqual({ ok: true, applied: true });

    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-finish'))
        .unique();
      expect(order?.status).toBe('paid');
      expect(order?.paidAt).toBeTypeOf('number');
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('a confirming IPN advances status but does NOT grant', async () => {
    const t = convexTest(schema, modules);
    const { userId, freeTierId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-confirm');
    const payload = { payment_status: 'confirming', payment_id: 9, order_id: 'ref-confirm' };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res.applied).toBe(true);
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-confirm'))
        .unique();
      expect(order?.status).toBe('confirming');
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(freeTierId); // not granted
      expect(user?.membershipExpiresAt).toBeUndefined();
    });
  });

  test('a finished IPN paid only within tolerance is downgraded, audited, and never grants', async () => {
    const t = convexTest(schema, modules);
    const { userId, freeTierId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-under');
    const payload = {
      payment_status: 'finished',
      payment_id: 201,
      order_id: 'ref-under',
      actually_paid: 0.9, // merchant settle-tolerance: 90% paid, still "finished"
      pay_amount: 1,
    };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res.applied).toBe(true); // confirming applies; nothing granted
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-under'))
        .unique();
      expect(order?.status).toBe('confirming');
      expect((await ctx.db.get(userId))?.tierId).toBe(freeTierId);
      const audits = await ctx.db.query('auditLog').collect();
      const under = audits.find((a) => a.action === 'billing.underpayment_seen');
      expect(under).toBeDefined();
      expect(under!.targetId).toBe(order!._id);
    });
  });

  test('a finished IPN with MISSING amounts fails safe (confirming + audit, no grant)', async () => {
    const t = convexTest(schema, modules);
    const { userId, freeTierId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-noamount');
    const payload = { payment_status: 'finished', payment_id: 202, order_id: 'ref-noamount' };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res.applied).toBe(true);
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-noamount'))
        .unique();
      expect(order?.status).toBe('confirming');
      expect((await ctx.db.get(userId))?.tierId).toBe(freeTierId);
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.underpayment_seen')).toBe(true);
    });
  });

  test('a finished IPN with string-typed amounts still grants when fully paid', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-stramt');
    const payload = {
      payment_status: 'finished',
      payment_id: 203,
      order_id: 'ref-stramt',
      actually_paid: '1.0', // some account configs serialize amounts as strings
      pay_amount: '1',
    };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res.applied).toBe(true);
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-stramt'))
        .unique();
      expect(order?.status).toBe('paid');
    });
  });

  // Review #8: webhooks can arrive out of order (NOWPayments dedupe is
  // per-(payment,status), so a late DISTINCT status is not a duplicate). A non-paid
  // update must advance the order forward only — never regress.
  test('an out-of-order webhook cannot walk the order status backward', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-oo');
    const apply = (status: 'pending' | 'confirming' | 'failed' | 'expired', ref: string) =>
      t.mutation(internal.billing.applyEvent, {
        processor: 'nowpayments',
        orderRef: 'ref-oo',
        status,
        processorRef: ref,
      });
    const readStatus = async () =>
      (
        await t.run((ctx) =>
          ctx.db
            .query('billingOrders')
            .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-oo'))
            .unique(),
        )
      )?.status;

    await apply('confirming', 'p1');
    expect(await readStatus()).toBe('confirming');
    await apply('pending', 'p2'); // late 'pending' — must be ignored
    expect(await readStatus()).toBe('confirming');
    await apply('failed', 'p3'); // advance to a terminal state
    expect(await readStatus()).toBe('failed');
    await apply('confirming', 'p4'); // late 'confirming' after 'failed' — ignored
    expect(await readStatus()).toBe('failed');
  });

  test('a replayed IPN (same payment×status) is a deduped no-op', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-dup');
    const payload = {
      payment_status: 'finished',
      payment_id: 7,
      order_id: 'ref-dup',
      ...FULL_AMOUNTS,
    };
    const signature = await signIpn(payload);
    const first = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(first.applied).toBe(true);
    const expiryAfterFirst = await t.run(
      async (ctx) => (await ctx.db.get(userId))?.membershipExpiresAt,
    );
    const second = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(second).toEqual({ ok: true, duplicate: true, applied: false });
    const expiryAfterSecond = await t.run(
      async (ctx) => (await ctx.db.get(userId))?.membershipExpiresAt,
    );
    expect(expiryAfterSecond).toBe(expiryAfterFirst); // granted exactly once
    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_source', (q) => q.eq('source', 'billing.nowpayments'))
        .unique();
      expect(ev?.status).toBe('processed');
    });
  });

  // H-1: a grant that throws AFTER the dedupe claim must stay retryable — the
  // old code committed the dedupe row first, so the processor's IPN retry was
  // swallowed as duplicate and the paid membership silently lost.
  test('an applyEvent throw leaves the IPN retryable; the retry grants exactly once', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const orderId = await insertPendingOrder(t, userId, memberTierId, 'ref-retry', 91);
    // Force the grant to throw mid-mutation: applyMembership rejects a missing tier.
    await t.run((ctx) => ctx.db.delete(memberTierId));

    const payload = {
      payment_status: 'finished',
      payment_id: 77,
      order_id: 'ref-retry',
      ...FULL_AMOUNTS,
    };
    const signature = await signIpn(payload);
    await expect(
      t.action(internal.billing.ingestEvent, {
        processor: 'nowpayments',
        rawBody: JSON.stringify(payload),
        signature,
      }),
    ).rejects.toThrow(/tier not found/);

    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_source', (q) => q.eq('source', 'billing.nowpayments'))
        .unique();
      expect(ev?.status).toBe('failed');
      const order = await ctx.db.get(orderId);
      expect(order?.status).toBe('pending'); // the paid flip rolled back with the throw
    });

    // Operator fixes the tier; the processor's automatic retry then lands.
    const newTierId = await t.run(async (ctx) => {
      const id = await ctx.db.insert('tiers', {
        slug: 'member',
        name: 'FreeSocks Membership',
        backend: 'remnawave',
        monthlyTrafficGb: 0,
        deviceLimit: 0,
        hwidLimit: 0,
        hwidEnabled: false,
        trafficStrategy: 'NO_RESET',
        isDefaultFree: false,
        isActive: true,
        priority: 10,
        expirationDaysAfterMembershipLapse: 7,
        updatedAt: Date.now(),
      });
      await ctx.db.patch(orderId, { tierId: id });
      return id;
    });

    const retry = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(retry).toEqual({ ok: true, applied: true });

    const expiryAfterRetry = await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_source', (q) => q.eq('source', 'billing.nowpayments'))
        .unique();
      expect(ev?.status).toBe('processed');
      const order = await ctx.db.get(orderId);
      expect(order?.status).toBe('paid');
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(newTierId);
      return user?.membershipExpiresAt;
    });

    // A further replay is a terminal duplicate.
    const third = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(third).toEqual({ ok: true, duplicate: true, applied: false });
    const expiryAfterThird = await t.run(
      async (ctx) => (await ctx.db.get(userId))?.membershipExpiresAt,
    );
    expect(expiryAfterThird).toBe(expiryAfterRetry);
  });

  test('a bad signature is rejected', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-bad');
    const payload = { payment_status: 'finished', payment_id: 1, order_id: 'ref-bad' };
    await expect(
      t.action(internal.billing.ingestEvent, {
        processor: 'nowpayments',
        rawBody: JSON.stringify(payload),
        signature: 'deadbeef',
      }),
    ).rejects.toThrow();
  });

  test('an unknown order ref is ACKed without granting', async () => {
    const t = convexTest(schema, modules);
    await seedTiersAndUser(t);
    const payload = { payment_status: 'finished', payment_id: 2, order_id: 'no-such-ref' };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res).toEqual({ ok: true, applied: false });
  });

  test('the stored webhook payload carries no payer PII beyond allowlisted fields', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-redact');
    const payload = {
      payment_status: 'finished',
      payment_id: 3,
      order_id: 'ref-redact',
      customer_email: 'secret@example.com',
      ...FULL_AMOUNTS,
    };
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    await t.run(async (ctx) => {
      const ev = await ctx.db
        .query('webhookEvents')
        .withIndex('by_source', (q) => q.eq('source', 'billing.nowpayments'))
        .first();
      expect(ev).not.toBeNull();
      expect(ev!.payload).not.toContain('secret@example.com');
    });
  });

  test('unset IPN secret throws the typed billing.not_configured ConvexError', async () => {
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', '');
    const t = convexTest(schema, modules);
    let thrown: unknown;
    try {
      await t.action(internal.billing.ingestEvent, {
        processor: 'nowpayments',
        rawBody: '{}',
        signature: 'x',
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ConvexError);
    expect((thrown as ConvexError<{ code: string }>).data.code).toBe('billing.not_configured');
  });
});

describe('billing.ingestEvent (Stripe)', () => {
  const SECRET = 'stripe-whsec';
  const signStripe = async (rawBody: string): Promise<string> => {
    const t = Math.floor(Date.now() / 1000);
    return `t=${t},v1=${await hmacSha256Hex(SECRET, `${t}.${rawBody}`)}`;
  };
  beforeEach(() => vi.stubEnv('STRIPE_WEBHOOK_SECRET', SECRET));
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('a completed checkout session extends membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-stripe');
    const rawBody = JSON.stringify({
      id: 'evt_1',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_1', client_reference_id: 'ref-stripe', payment_status: 'paid' } },
    });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'stripe',
      rawBody,
      signature: await signStripe(rawBody),
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('a bad Stripe signature is rejected', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-stripe-bad');
    const rawBody = JSON.stringify({
      id: 'evt_2',
      type: 'checkout.session.completed',
      data: {
        object: { id: 'cs_2', client_reference_id: 'ref-stripe-bad', payment_status: 'paid' },
      },
    });
    await expect(
      t.action(internal.billing.ingestEvent, {
        processor: 'stripe',
        rawBody,
        signature: 't=1,v1=deadbeef',
      }),
    ).rejects.toThrow();
  });
});

describe('billing.ingestEvent (BTCPay)', () => {
  const SECRET = 'btcpay-whsec';
  const signBtcpay = async (rawBody: string): Promise<string> =>
    `sha256=${await hmacSha256Hex(SECRET, rawBody)}`;
  beforeEach(() => vi.stubEnv('BTCPAY_WEBHOOK_SECRET', SECRET));
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('a settled invoice marks the order paid and extends membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay');
    const rawBody = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_1',
      metadata: { orderId: 'ref-btcpay' },
    });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature: await signBtcpay(rawBody),
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-btcpay'))
        .unique();
      expect(order?.status).toBe('paid');
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('a processing event advances to confirming without granting', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId, freeTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay-conf');
    const rawBody = JSON.stringify({
      type: 'InvoiceProcessing',
      invoiceId: 'inv_2',
      metadata: { orderId: 'ref-btcpay-conf' },
    });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature: await signBtcpay(rawBody),
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-btcpay-conf'))
        .unique();
      expect(order?.status).toBe('confirming');
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(freeTierId); // NOT granted
    });
  });

  test('a Settled-at-partial invoice (store settle tolerance) never grants and is audited', async () => {
    // The store API is configured, so the settle path fetches the invoice
    // detail: additionalStatus=PaidPartial → confirming + underpayment audit.
    vi.stubEnv('BTCPAY_API_URL', 'https://btcpay.test');
    vi.stubEnv('BTCPAY_STORE_ID', 'store_1');
    vi.stubEnv('BTCPAY_API_KEY', 'k');
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              id: 'inv_p',
              amount: '14.00',
              currency: 'USD',
              status: 'Settled',
              additionalStatus: 'PaidPartial',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const t = convexTest(schema, modules);
    const { userId, memberTierId, freeTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay-partial');
    const rawBody = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_p',
      metadata: { orderId: 'ref-btcpay-partial' },
    });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature: await signBtcpay(rawBody),
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-btcpay-partial'))
        .unique();
      expect(order?.status).toBe('confirming'); // NOT paid
      expect((await ctx.db.get(userId))?.tierId).toBe(freeTierId);
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.underpayment_seen')).toBe(true);
    });
  });

  test('a redelivered settled event dedupes (no double grant)', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay-dup');
    const rawBody = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_3',
      metadata: { orderId: 'ref-btcpay-dup' },
    });
    const signature = await signBtcpay(rawBody);
    const first = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature,
    });
    expect(first).toEqual({ ok: true, applied: true });
    const expiryAfterFirst = await t.run(
      async (ctx) => (await ctx.db.get(userId))!.membershipExpiresAt,
    );
    const second = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature,
    });
    expect(second).toEqual({ ok: true, applied: false, duplicate: true });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBe(expiryAfterFirst);
    });
  });

  test('a bad signature is rejected', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay-bad');
    const rawBody = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_4',
      metadata: { orderId: 'ref-btcpay-bad' },
    });
    await expect(
      t.action(internal.billing.ingestEvent, {
        processor: 'btcpay',
        rawBody,
        signature: 'sha256=deadbeef',
      }),
    ).rejects.toThrow();
  });

  test('a non-invoice store event is acked without touching any order', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-btcpay-noop');
    const rawBody = JSON.stringify({ type: 'PayoutCreated', payoutId: 'p1' });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'btcpay',
      rawBody,
      signature: await signBtcpay(rawBody),
    });
    expect(res).toEqual({ ok: true, applied: false });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-btcpay-noop'))
        .unique();
      expect(order?.status).toBe('pending'); // untouched
    });
  });

  test('unset webhook secret throws the typed billing.not_configured ConvexError', async () => {
    vi.stubEnv('BTCPAY_WEBHOOK_SECRET', '');
    const t = convexTest(schema, modules);
    let thrown: unknown;
    try {
      await t.action(internal.billing.ingestEvent, {
        processor: 'btcpay',
        rawBody: '{}',
        signature: 'sha256=x',
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(ConvexError);
    expect((thrown as ConvexError<{ code: string }>).data.code).toBe('billing.not_configured');
  });
});

describe('billing.ingestEvent (PayPal)', () => {
  beforeEach(() => {
    vi.stubEnv('PAYPAL_CLIENT_ID', 'pp-client');
    vi.stubEnv('PAYPAL_SECRET', 'pp-secret');
    vi.stubEnv('PAYPAL_WEBHOOK_ID', 'wh-id');
    vi.stubEnv('PAYPAL_API_BASE', 'https://api-m.sandbox.paypal.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  function stubPayPal(verification = 'SUCCESS') {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const u = String(url);
        const ok = (body: unknown) =>
          new Response(JSON.stringify(body), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        if (u.includes('/v1/oauth2/token')) return ok({ access_token: 'tok' });
        if (u.includes('/verify-webhook-signature'))
          return ok({ verification_status: verification });
        if (u.includes('/capture')) return ok({ status: 'COMPLETED' });
        return new Response('{}', { status: 404 });
      }),
    );
  }

  const ppHeaders = {
    'paypal-auth-algo': 'SHA256withRSA',
    'paypal-cert-url': 'https://api.paypal.com/cert',
    'paypal-transmission-id': 'tx-1',
    'paypal-transmission-sig': 'sig',
    'paypal-transmission-time': '2026-06-11T00:00:00Z',
  };

  test('a verified PAYMENT.CAPTURE.COMPLETED extends membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-paypal');
    stubPayPal('SUCCESS');
    const rawBody = JSON.stringify({
      id: 'WH-1',
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      resource: { id: 'CAP-1', custom_id: 'ref-paypal' },
    });
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'paypal',
      rawBody,
      headers: ppHeaders,
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(memberTierId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });

  test('a FAILURE verification is rejected', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-paypal-fail');
    stubPayPal('FAILURE');
    const rawBody = JSON.stringify({
      id: 'WH-2',
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      resource: { id: 'CAP-2', custom_id: 'ref-paypal-fail' },
    });
    await expect(
      t.action(internal.billing.ingestEvent, { processor: 'paypal', rawBody, headers: ppHeaders }),
    ).rejects.toThrow();
  });
});

describe('processor secrets resolve from the DB (env fallback)', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('a NOWPayments IPN verifies against the DB-stored secret with no env set', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-dbsecret');
    const DB_SECRET = 'db-stored-ipn-secret';
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.secret.nowpayments.ipnSecret',
        value: JSON.stringify(DB_SECRET),
        updatedAt: Date.now(),
      }),
    );
    const payload = {
      payment_status: 'finished',
      payment_id: 55,
      order_id: 'ref-dbsecret',
      ...FULL_AMOUNTS,
    };
    const sorted = JSON.stringify(payload, Object.keys(payload).sort());
    const signature = await hmacSha512Hex(DB_SECRET, sorted); // signed with the DB secret
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature,
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user?.membershipExpiresAt).toBeGreaterThan(Date.now());
    });
  });
});

describe('billing.applyEvent single-grant guard', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('two paid events grant membership exactly once', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-once', 91);
    const first = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-once',
      status: 'paid',
      processorRef: 'p1',
    });
    expect(first).toEqual({ applied: true, granted: true });
    const expiry1 = await t.run(async (ctx) => (await ctx.db.get(userId))?.membershipExpiresAt);
    const second = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-once',
      status: 'paid',
      processorRef: 'p1',
    });
    expect(second).toEqual({ applied: false, granted: false });
    const expiry2 = await t.run(async (ctx) => (await ctx.db.get(userId))?.membershipExpiresAt);
    expect(expiry2).toBe(expiry1);
  });
});

describe('billing.applyEvent grant cross-checks', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('an underpaid amount refuses the grant and audits it', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const orderId = await insertPendingOrder(t, userId, memberTierId, 'ref-under');
    const res = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-under',
      status: 'paid',
      processorRef: 'p1',
      amountMinor: 1, // 1 cent against a $14.00 order
      amountCurrency: 'USD',
    });
    expect(res).toEqual({ applied: false, granted: false });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(orderId))!.status).toBe('pending'); // untouched
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBeUndefined();
      const audits = await ctx.db.query('auditLog').collect();
      const refused = audits.find((a) => a.action === 'billing.grant_refused');
      expect(refused).toBeTruthy();
      expect(refused!.payload).toMatchObject({ reason: 'amount_mismatch', reportedMinor: 1 });
    });
  });

  test('a wrong currency refuses; the exact amount (±1 cent) grants', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-cur');
    const wrongCurrency = await t.mutation(internal.billing.applyEvent, {
      processor: 'stripe',
      orderRef: 'ref-cur',
      status: 'paid',
      processorRef: 'cs_1',
      amountMinor: 1400,
      amountCurrency: 'EUR',
    });
    expect(wrongCurrency).toEqual({ applied: false, granted: false });
    const ok = await t.mutation(internal.billing.applyEvent, {
      processor: 'stripe',
      orderRef: 'ref-cur',
      status: 'paid',
      processorRef: 'cs_1',
      amountMinor: 1399, // within the 1-cent decimal-round-trip tolerance
      amountCurrency: 'USD',
    });
    expect(ok).toEqual({ applied: true, granted: true });
  });

  test('a checkoutRef that does not match the stored processorRef refuses (forged-invoice guard)', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const orderId = await insertPendingOrder(t, userId, memberTierId, 'ref-forged');
    // The checkout stored the invoice FCP minted; the settle event names another.
    await t.run((ctx) => ctx.db.patch(orderId, { processorRef: 'invoice-legit' }));
    const forged = await t.mutation(internal.billing.applyEvent, {
      processor: 'btcpay',
      orderRef: 'ref-forged',
      status: 'paid',
      processorRef: 'invoice-attacker',
      checkoutRef: 'invoice-attacker',
    });
    expect(forged).toEqual({ applied: false, granted: false });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(orderId))!.status).toBe('pending');
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.grant_refused')).toBe(true);
    });
    // The REAL invoice's settle event still grants.
    const legit = await t.mutation(internal.billing.applyEvent, {
      processor: 'btcpay',
      orderRef: 'ref-forged',
      status: 'paid',
      processorRef: 'invoice-legit',
      checkoutRef: 'invoice-legit',
    });
    expect(legit).toEqual({ applied: true, granted: true });
  });

  test('a refund-class event for an already-paid order audits billing.refund_seen', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-refund');
    await t.mutation(internal.billing.applyEvent, {
      processor: 'paypal',
      orderRef: 'ref-refund',
      status: 'paid',
      processorRef: 'cap_1',
    });
    const res = await t.mutation(internal.billing.applyEvent, {
      processor: 'paypal',
      orderRef: 'ref-refund',
      status: 'failed', // PAYMENT.CAPTURE.REFUNDED maps here
      processorRef: 'refund_1',
    });
    expect(res).toEqual({ applied: false, granted: false });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.refund_seen')).toBe(true);
      // Membership stays live (operator decides) — refund is a signal, not a revoke.
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBeTruthy();
    });
  });

  test('a refund unwinds the donation pool + voids pending/converted referrals (membership kept)', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    // Donation config + a referral row for the buyer (converted = mid-vest).
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.donation.enabled',
        value: 'true',
        updatedAt: 0,
      }),
    );
    const referrerId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    const referralId = await t.run((ctx) =>
      ctx.db.insert('referrals', {
        referrerUserId: referrerId,
        refereeUserId: userId,
        status: 'converted',
        updatedAt: Date.now(),
      }),
    );
    // A paid membership order that carried a $5 donation.
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'ref-refund2',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        donationCents: 500,
        currency: 'USD',
        status: 'pending',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-refund2',
      status: 'paid',
      processorRef: 'pay-r2',
    });
    // The pool got the $5 and the user aggregates bumped.
    await t.run(async (ctx) => {
      const pool = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      const poolState = JSON.parse(pool!.value);
      expect(poolState.donatedCents).toBe(500);
      // The daily impact series gets a cumulative snapshot for today (UTC).
      expect(poolState.days[new Date().toISOString().slice(0, 10)]).toBe(500);
      const u = await ctx.db.get(userId);
      expect(u!.donatedCentsTotal).toBe(500);
      expect(u!.donationCount).toBe(1);
      expect(u!.firstDonatedAt).toBeTypeOf('number');
    });

    // Refund lands: the pool drains back, the referral voids, membership stays.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-refund2',
      status: 'failed',
      processorRef: 'refund_r2',
    });
    await t.run(async (ctx) => {
      const pool = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      const drained = JSON.parse(pool!.value);
      expect(drained.donatedCents).toBe(0);
      // The refund re-snapshots today at the reduced total.
      expect(drained.days[new Date().toISOString().slice(0, 10)]).toBe(0);
      const ref = await ctx.db.get(referralId);
      expect(ref!.status).toBe('void');
      expect(ref!.voidReason).toBe('refund');
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBeTruthy();
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'referral.void' && a.targetId === referralId)).toBe(
        true,
      );
      // The refund schedules an IMMEDIATE fleet re-cap (symmetric with the
      // grant-side fundDonation) — the refunded bonus must not linger on the
      // fleet until the next hourly reconcile.
      const scheduled = await ctx.db.system.query('_scheduled_functions').collect();
      expect(scheduled.some((f) => f.name.includes('applyFreeBonus'))).toBe(true);
    });
  });

  test('a second paid event with a DIFFERENT payment id audits billing.overpayment_seen (no double grant)', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-overpay');
    // First payment settles the invoice and grants.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-overpay',
      status: 'paid',
      processorRef: 'pay-1',
    });
    const expiryAfterFirst = (await t.run((ctx) => ctx.db.get(userId)))!.membershipExpiresAt;
    // A second transaction finishes on the SAME invoice (a top-up after an
    // underpayment) — never grants again, and it's audited for refund review.
    const res = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-overpay',
      status: 'paid',
      processorRef: 'pay-2',
    });
    expect(res).toEqual({ applied: false, granted: false });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.overpayment_seen')).toBe(true);
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBe(expiryAfterFirst);
    });
    // A re-delivery of the SAME payment id does NOT audit (plain idempotency).
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-overpay',
      status: 'paid',
      processorRef: 'pay-1',
    });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.filter((a) => a.action === 'billing.overpayment_seen')).toHaveLength(1);
    });
  });

  test('a SECOND refund event does NOT re-unwind the donation; the donor badge unwinds once (Review C-F2/F5)', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'billing.donation.enabled',
        value: 'true',
        updatedAt: 0,
      }),
    );
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'stripe',
        opaqueRef: 'ref-refund3',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        donationCents: 500,
        currency: 'USD',
        status: 'pending',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.billing.applyEvent, {
      processor: 'stripe',
      orderRef: 'ref-refund3',
      status: 'paid',
      processorRef: 'ch_1',
    });
    // Simulate a LATER $10 donation landing in the same pool, so a double
    // unwind is observable (500 → 500 vs the buggy 500 → 0).
    await t.run(async (ctx) => {
      const pool = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      const state = JSON.parse(pool!.value) as Record<string, unknown>;
      await ctx.db.patch(pool!._id, {
        value: JSON.stringify({ ...state, donatedCents: 1500 }),
      });
    });
    // Stripe emits one charge.refunded per (partial) refund — distinct ids.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'stripe',
      orderRef: 'ref-refund3',
      status: 'failed',
      processorRef: 're_1',
    });
    await t.mutation(internal.billing.applyEvent, {
      processor: 'stripe',
      orderRef: 'ref-refund3',
      status: 'failed',
      processorRef: 're_2',
    });
    await t.run(async (ctx) => {
      const pool = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      // 1500 − 500 ONCE (not twice): the second refund event is an audit-only no-op.
      expect(JSON.parse(pool!.value).donatedCents).toBe(1000);
      const u = await ctx.db.get(userId);
      // Donor aggregates + badge unwound (and clamped — never negative).
      expect(u!.donatedCentsTotal).toBe(0);
      expect(u!.donationCount).toBe(0);
      expect(u!.firstDonatedAt).toBeUndefined();
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-refund3'))
        .unique();
      expect(order!.donationUnwoundAt).toBeTypeOf('number');
      // Both refund events still audited (the operator's queue keeps both).
      const refunds = (await ctx.db.query('auditLog').collect()).filter(
        (a) => a.action === 'billing.refund_seen',
      );
      expect(refunds).toHaveLength(2);
    });
  });

  test("PayPal's normal two-event flow does NOT false-positive overpayment (Review C-F1)", async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertPendingOrder(t, userId, memberTierId, 'ref-pp');
    // Event 1: CHECKOUT.ORDER.APPROVED → captured server-side → paid, storing
    // the ORDER id as the order's processorRef.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'paypal',
      orderRef: 'ref-pp',
      status: 'paid',
      processorRef: 'PP-ORDER-1',
      checkoutRef: 'PP-ORDER-1',
    });
    // Event 2: PAYMENT.CAPTURE.COMPLETED — distinct resource (capture id) but
    // the SAME payment (checkoutRef = the linked order id). Not an overpayment.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'paypal',
      orderRef: 'ref-pp',
      status: 'paid',
      processorRef: 'CAPTURE-9',
      checkoutRef: 'PP-ORDER-1',
    });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.some((a) => a.action === 'billing.overpayment_seen')).toBe(false);
    });
    // Control: a genuinely DIFFERENT payment (checkoutRef matches neither id)
    // still audits.
    await t.mutation(internal.billing.applyEvent, {
      processor: 'paypal',
      orderRef: 'ref-pp',
      status: 'paid',
      processorRef: 'CAPTURE-X',
      checkoutRef: 'PP-ORDER-OTHER',
    });
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.filter((a) => a.action === 'billing.overpayment_seen')).toHaveLength(1);
    });
  });

  test('a paid grant lifts an idle-deactivated (inactive) account back to active', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await t.run((ctx) => ctx.db.patch(userId, { status: 'inactive' }));
    await insertPendingOrder(t, userId, memberTierId, 'ref-inactive');
    const res = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-inactive',
      status: 'paid',
      processorRef: 'p1',
    });
    expect(res).toEqual({ applied: true, granted: true });
    await t.run(async (ctx) => {
      const user = await ctx.db.get(userId);
      expect(user!.status).toBe('active');
      expect(user!.tierId).toBe(memberTierId);
    });
  });
});

describe('billing pending sweep ↔ late payment', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('the sweep expires stale pending/confirming orders and NEVER grants', async () => {
    // Sub-millisecond TTL (a literal 0 falls back to the 48h default) + a short
    // sleep so the just-inserted rows age past the cutoff.
    vi.stubEnv('BILLING_PENDING_TTL_HOURS', '0.000001');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const pendingId = await insertPendingOrder(t, userId, memberTierId, 'ref-stale');
    const confirmingId = await insertPendingOrder(t, userId, memberTierId, 'ref-stale-2');
    await t.run((ctx) => ctx.db.patch(confirmingId, { status: 'confirming' }));
    await new Promise((r) => setTimeout(r, 15));

    const { expired } = await t.mutation(internal.retention.expireStalePendingOrders, {});
    expect(expired).toBe(2);
    await t.run(async (ctx) => {
      expect((await ctx.db.get(pendingId))!.status).toBe('expired');
      expect((await ctx.db.get(confirmingId))!.status).toBe('expired');
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBeUndefined();
    });
  });

  test('a LATE paid webhook still grants after the sweep expired the order', async () => {
    vi.stubEnv('BILLING_PENDING_TTL_HOURS', '0.000001');
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const orderId = await insertPendingOrder(t, userId, memberTierId, 'ref-late');
    await new Promise((r) => setTimeout(r, 15));
    await t.mutation(internal.retention.expireStalePendingOrders, {});
    await t.run(async (ctx) => {
      expect((await ctx.db.get(orderId))!.status).toBe('expired');
    });

    // A slow crypto confirmation lands after expiry: money must not be lost.
    const res = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-late',
      status: 'paid',
      processorRef: 'p1',
    });
    expect(res).toEqual({ applied: true, granted: true });
    await t.run(async (ctx) => {
      expect((await ctx.db.get(orderId))!.status).toBe('paid');
      expect((await ctx.db.get(userId))!.membershipExpiresAt).toBeTruthy();
    });
  });
});

describe('billing.getOrderStatus scoping', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('a member sees their own order but not another user’s', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    const otherUserId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    await insertPendingOrder(t, userId, memberTierId, 'ref-mine');

    const mine = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: 'ref-mine',
      userId,
    });
    expect(mine?.status).toBe('pending');

    const theirs = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: 'ref-mine',
      userId: otherUserId,
    });
    expect(theirs).toBeNull();
  });
});

describe('billing gift codes', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api.nowpayments.example');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', IPN_SECRET);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const insertGiftOrder = (
    t: ReturnType<typeof convexTest>,
    userId: Id<'users'>,
    tierId: Id<'tiers'>,
    opaqueRef: string,
    quantity: number,
  ): Promise<Id<'billingOrders'>> =>
    t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef,
        userId,
        tierId,
        durationDays: 91,
        amountCents: 1400 * quantity,
        currency: 'USD',
        status: 'pending',
        kind: 'gift',
        quantity,
        updatedAt: Date.now(),
      }),
    );

  test('a gift checkout inserts a gift order priced by quantity', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await enableBilling(t);
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ id: 'inv_g', invoice_url: 'https://pay.example/i/inv_g' }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      kind: 'gift',
      quantity: 2,
    });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.kind).toBe('gift');
      expect(order?.quantity).toBe(2);
      expect(order?.amountCents).toBe(2800);
      expect(order?.tierId).toBe(memberTierId);
    });
  });

  test('a finished IPN mints codes for the buyer WITHOUT extending their own membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, freeTierId, memberTierId } = await seedTiersAndUser(t);
    await insertGiftOrder(t, userId, memberTierId, 'ref-gift', 2);
    const payload = {
      payment_status: 'finished',
      payment_id: 100,
      order_id: 'ref-gift',
      ...FULL_AMOUNTS,
    };
    const res = await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    expect(res).toEqual({ ok: true, applied: true });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', 'ref-gift'))
        .unique();
      expect(order?.status).toBe('paid');
      expect(order?.giftReveal?.length).toBe(2);
      const codes = await ctx.db
        .query('redemptionCodes')
        .withIndex('by_purchaser', (q) => q.eq('purchasedByUserId', userId))
        .collect();
      expect(codes).toHaveLength(2);
      expect(codes.every((c) => c.status === 'active' && c.mintedByAdminId === undefined)).toBe(
        true,
      );
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(freeTierId); // membership NOT extended
      expect(user?.membershipExpiresAt).toBeUndefined();
    });
  });

  test('getOrderStatus reveals the codes once; ack clears the buffer', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertGiftOrder(t, userId, memberTierId, 'ref-gift2', 1);
    const payload = {
      payment_status: 'finished',
      payment_id: 101,
      order_id: 'ref-gift2',
      ...FULL_AMOUNTS,
    };
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    const status1 = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: 'ref-gift2',
      userId,
    });
    expect(status1?.kind).toBe('gift');
    expect(status1?.giftCodes).toHaveLength(1);
    await t.mutation(internal.billing.ackGiftReveal, { opaqueRef: 'ref-gift2', userId });
    const status2 = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: 'ref-gift2',
      userId,
    });
    expect(status2?.giftCodes).toHaveLength(0);
  });

  test('a replayed gift IPN does not mint extra codes', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertGiftOrder(t, userId, memberTierId, 'ref-gift3', 3);
    const payload = {
      payment_status: 'finished',
      payment_id: 102,
      order_id: 'ref-gift3',
      ...FULL_AMOUNTS,
    };
    const sig = await signIpn(payload);
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: sig,
    });
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: sig,
    });
    const count = await t.run(
      async (ctx) =>
        (
          await ctx.db
            .query('redemptionCodes')
            .withIndex('by_purchaser', (q) => q.eq('purchasedByUserId', userId))
            .collect()
        ).length,
    );
    expect(count).toBe(3);
  });

  test('listPurchasedCodes returns the buyer’s codes, masked, and reflects redemption', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertGiftOrder(t, userId, memberTierId, 'ref-gift4', 1);
    const payload = {
      payment_status: 'finished',
      payment_id: 103,
      order_id: 'ref-gift4',
      ...FULL_AMOUNTS,
    };
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await signIpn(payload),
    });
    let list = await t.query(internal.membershipCodes.listPurchasedCodes, { userId });
    expect(list).toHaveLength(1);
    expect(list[0].status).toBe('active');
    expect(list[0].codePrefix).toMatch(/^FSM-/);

    // The recipient (a different account) redeems the gift code.
    const recipientId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    const codeHash = await t.run(
      async (ctx) =>
        (await ctx.db
          .query('redemptionCodes')
          .withIndex('by_purchaser', (q) => q.eq('purchasedByUserId', userId))
          .first())!.codeHash,
    );
    await t.mutation(internal.membershipCodes.consumeAndGrant, { userId: recipientId, codeHash });

    list = await t.query(internal.membershipCodes.listPurchasedCodes, { userId });
    expect(list[0].status).toBe('redeemed');
    expect(list[0].redeemedAt).not.toBeNull();
  });
});

describe('billing donations', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api.nowpayments.example');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const invoiceMock = () =>
    vi.fn(
      async () =>
        new Response(JSON.stringify({ id: 'inv_d', invoice_url: 'https://pay.example/d' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );

  test('membership checkout carries an optional donation on the same charge', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await enableBilling(t);
    vi.stubGlobal('fetch', invoiceMock());

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      donationCents: 500,
    });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.amountCents).toBe(1400 + 500); // membership + donation, one charge
      expect(order?.donationCents).toBe(500);
      expect(order?.tierId).toBe(memberTierId);
      expect(order?.kind ?? 'self').toBe('self');
    });
  });

  test('standalone donation checkout creates a tier-less donation order', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await enableBilling(t);
    vi.stubGlobal('fetch', invoiceMock());

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      kind: 'donation',
      donationCents: 1000,
    });
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.kind).toBe('donation');
      expect(order?.tierId).toBeUndefined();
      expect(order?.amountCents).toBe(1000);
      expect(order?.donationCents).toBe(1000);
      expect(order?.durationDays).toBe(0);
    });
  });

  test('rejects a donation below the configured minimum', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await enableBilling(t); // donation.minAmountCents defaults to 200
    await expect(
      t.action(internal.billing.createCheckout, {
        userId,
        processor: 'nowpayments',
        kind: 'donation',
        donationCents: 50,
      }),
    ).rejects.toThrow();
  });

  test('a settled membership+donation grants membership, funds the pool, stamps the donor badge', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'ref-don-self',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1900,
        donationCents: 500,
        currency: 'USD',
        status: 'pending',
        kind: 'self',
        updatedAt: Date.now(),
      }),
    );
    const r = await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-don-self',
      status: 'paid',
      processorRef: 'inv',
    });
    expect(r).toEqual({ applied: true, granted: true });
    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u?.tierId).toBe(memberTierId); // membership granted
      expect(u?.firstDonatedAt != null && u.firstDonatedAt > 0).toBe(true); // donor badge marker
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).donatedCents).toBe(500); // pool funded
      const audit = (await ctx.db.query('auditLog').collect()).find(
        (a) => a.action === 'billing.order.paid',
      );
      expect(JSON.stringify(audit!.payload ?? {})).toContain('500'); // donationCents audited
    });
  });

  test('a settled donation-only order funds the pool without granting membership', async () => {
    const t = convexTest(schema, modules);
    const { userId, freeTierId } = await seedTiersAndUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'ref-don-only',
        userId,
        durationDays: 0,
        amountCents: 1000,
        donationCents: 1000,
        currency: 'USD',
        status: 'pending',
        kind: 'donation',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-don-only',
      status: 'paid',
      processorRef: 'inv',
    });
    await t.run(async (ctx) => {
      const u = await ctx.db.get(userId);
      expect(u?.tierId).toBe(freeTierId); // NO membership change
      expect(u?.membershipExpiresAt ?? null).toBeNull();
      expect(u?.firstDonatedAt != null && u.firstDonatedAt > 0).toBe(true);
      const st = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:freeBonus'))
        .unique();
      expect(JSON.parse(st!.value).donatedCents).toBe(1000);
      // The grant schedules BOTH the instant fleet re-cap and the targeted
      // freeActive recount — the donor must see a current "free accounts
      // reached" figure right away, not the last daily reconcile's.
      const scheduled = await ctx.db.system.query('_scheduled_functions').collect();
      expect(scheduled.some((f) => f.name.includes('applyFreeBonus'))).toBe(true);
      expect(scheduled.some((f) => f.name.includes('refreshFreeActive'))).toBe(true);
    });
  });

  test('a settled donation lands a per-month history ledger entry', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seedTiersAndUser(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'ref-don-hist',
        userId,
        durationDays: 0,
        amountCents: 1000,
        donationCents: 1000,
        currency: 'USD',
        status: 'pending',
        kind: 'donation',
        updatedAt: Date.now(),
      }),
    );
    await t.mutation(internal.billing.applyEvent, {
      processor: 'nowpayments',
      orderRef: 'ref-don-hist',
      status: 'paid',
      processorRef: 'inv',
    });
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('appState')
        .withIndex('by_key', (q) => q.eq('key', 'donation:history'))
        .unique();
      const entries = JSON.parse(row!.value) as {
        monthKey: string;
        donatedCents: number;
        bonusGb: number;
      }[];
      expect(entries).toHaveLength(1);
      const mk = new Date().toISOString().slice(0, 7);
      expect(entries[0]).toMatchObject({ monthKey: mk, donatedCents: 1000, bonusGb: 10 }); // $10 × 1 GB/USD
    });
  });
});

describe('billing.testProcessorConnection (live credential probe)', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('ok on a 200 from the processor; status-only error on failure; never the key', async () => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-live-key');
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api.nowpayments.example');
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      expect(headers['x-api-key']).toBe('np-live-key'); // stored secret is used…
      return new Response('{}', { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const t = convexTest(schema, modules);
    const res = await t.action(internal.billing.testProcessorConnection, {
      processor: 'nowpayments',
    });
    expect(res).toEqual({ ok: true, error: null });
    expect(JSON.stringify(res)).not.toContain('np-live-key'); // …but never echoed
  });

  test('a 401 surfaces as a status-only error', async () => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-bad-key');
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api.nowpayments.example');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('nope', { status: 401 })),
    );
    const t = convexTest(schema, modules);
    const res = await t.action(internal.billing.testProcessorConnection, {
      processor: 'nowpayments',
    });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/401/);
    expect(JSON.stringify(res)).not.toContain('np-bad-key');
  });

  test('an unconfigured rail fails without any network call', async () => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', '');
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const t = convexTest(schema, modules);
    const res = await t.action(internal.billing.testProcessorConnection, {
      processor: 'nowpayments',
    });
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/not configured/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('paypal probe validates via the OAuth token fetch', async () => {
    vi.stubEnv('PAYPAL_CLIENT_ID', 'cid');
    vi.stubEnv('PAYPAL_SECRET', 'sec');
    vi.stubEnv('PAYPAL_API_BASE', 'https://api-m.sandbox.example');
    const fetchMock = vi.fn(async (input: string | URL) => {
      expect(String(input)).toContain('/v1/oauth2/token');
      return new Response(JSON.stringify({ access_token: 'tok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const t = convexTest(schema, modules);
    const res = await t.action(internal.billing.testProcessorConnection, { processor: 'paypal' });
    expect(res).toEqual({ ok: true, error: null });
    expect(JSON.stringify(res)).not.toContain('sec');
  });
});
