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
    const payload = { payment_status: 'finished', payment_id: 7, order_id: 'ref-dup' };
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

    const payload = { payment_status: 'finished', payment_id: 77, order_id: 'ref-retry' };
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
    const payload = { payment_status: 'finished', payment_id: 55, order_id: 'ref-dbsecret' };
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
    const payload = { payment_status: 'finished', payment_id: 100, order_id: 'ref-gift' };
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
      expect(
        codes.every(
          (c) =>
            c.status === 'active' &&
            c.purchasedByOrderId === order!._id &&
            c.mintedByAdminId === undefined,
        ),
      ).toBe(true);
      const user = await ctx.db.get(userId);
      expect(user?.tierId).toBe(freeTierId); // membership NOT extended
      expect(user?.membershipExpiresAt).toBeUndefined();
    });
  });

  test('getOrderStatus reveals the codes once; ack clears the buffer', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seedTiersAndUser(t);
    await insertGiftOrder(t, userId, memberTierId, 'ref-gift2', 1);
    const payload = { payment_status: 'finished', payment_id: 101, order_id: 'ref-gift2' };
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
    const payload = { payment_status: 'finished', payment_id: 102, order_id: 'ref-gift3' };
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
    const payload = { payment_status: 'finished', payment_id: 103, order_id: 'ref-gift4' };
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
