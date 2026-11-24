/// <reference types="vite/client" />
/**
 * The billing core's Telegram gift-shop orders: userless Telegram Stars gift
 * orders (channel 'telegram'), the bot's read and ack by ref, and the privacy
 * rule that a bot order's codes are bound to nobody. The bot itself is tested in telegramBot.test.ts.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { hmacSha512Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');
const IPN_SECRET = 'test-ipn-secret';

async function seed(t: ReturnType<typeof convexTest>): Promise<{ memberTierId: Id<'tiers'> }> {
  return t.run(async (ctx) => {
    const base = {
      backend: 'remnawave' as const,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      isActive: true,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    };
    await ctx.db.insert('tiers', {
      ...base,
      slug: 'free',
      name: 'Free',
      monthlyTrafficGb: 50,
      trafficStrategy: 'MONTH',
      isDefaultFree: true,
      priority: 0,
    });
    const memberTierId = await ctx.db.insert('tiers', {
      ...base,
      slug: 'member',
      name: 'FreeSocks Membership',
      monthlyTrafficGb: 0,
      trafficStrategy: 'NO_RESET',
      isDefaultFree: false,
      priority: 10,
    });
    const put = (key: string, value: unknown) =>
      ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() });
    await put('billing.enabled', true);
    await put('billing.nowpayments.enabled', true);
    await put('billing.membership.durations', [
      { months: 3, amountCents: 1400 },
      { months: 12, amountCents: 5000 },
    ]);
    return { memberTierId };
  });
}

async function signIpn(payload: Record<string, unknown>): Promise<string> {
  const sorted = JSON.stringify(payload, Object.keys(payload).sort());
  return hmacSha512Hex(IPN_SECRET, sorted);
}

function invoiceFetch() {
  return vi.fn(
    async (_url: string | URL | Request, _init?: RequestInit) =>
      new Response(JSON.stringify({ id: 'inv_tg', invoice_url: 'https://pay.example/i/inv_tg' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
}

async function payIpn(t: ReturnType<typeof convexTest>, orderRef: string, paymentId = 777) {
  const payload = {
    payment_status: 'finished',
    payment_id: paymentId,
    order_id: orderRef,
    price_amount: 28,
    price_currency: 'usd',
    actually_paid: 1,
    pay_amount: 1,
  };
  return t.action(internal.billing.ingestEvent, {
    processor: 'nowpayments',
    rawBody: JSON.stringify(payload),
    signature: await signIpn(payload),
  });
}

async function starsBotOrder(t: ReturnType<typeof convexTest>, quantity = 2) {
  return t.mutation(internal.billing.createStarsOrder, {
    opaqueRef: randomRef(),
    months: 3,
    quantity,
    starsPerCode: 700,
  });
}
let refSeq = 0;
function randomRef(): string {
  return (refSeq++).toString(16).padStart(32, 'c');
}

describe('Telegram gift orders and the rest of billing', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', IPN_SECRET);
    vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api-sandbox.nowpayments.io');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('an anonymous web gift is still refused', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    vi.stubGlobal('fetch', invoiceFetch());
    await expect(
      t.action(internal.billing.createCheckout, {
        processor: 'nowpayments',
        months: 3,
        kind: 'gift',
        quantity: 1,
      }),
    ).rejects.toThrow(/Sign in/);
  });

  test('a paid Stars order mints codes bound to nobody; the bot reads them once', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef, totalStars } = await starsBotOrder(t);
    const before = await t.query(internal.billing.botOrderStatus, { orderRef });
    expect(before?.status).toBe('pending');
    expect(before?.giftCodes).toEqual([]);

    await t.action(internal.billing.ingestStarsPayment, {
      orderRef,
      chargeId: 'ch_nobody',
      totalAmount: totalStars,
      currency: 'XTR',
      event: 'paid',
    });
    const paid = await t.query(internal.billing.botOrderStatus, { orderRef });
    expect(paid?.status).toBe('paid');
    expect(paid?.months).toBe(3);
    expect(paid?.giftCodes).toHaveLength(2);
    for (const c of paid?.giftCodes ?? []) expect(c).toMatch(/^FSM-/);

    await t.run(async (ctx) => {
      const codes = await ctx.db.query('redemptionCodes').collect();
      expect(codes).toHaveLength(2);
      for (const c of codes) {
        // Privacy rule: nothing ties a bot gift's codes to a buyer or an order.
        expect(c.purchasedByUserId).toBeUndefined();
        expect(c.purchasedByOrderId).toBeUndefined();
        expect(c.status).toBe('active');
      }
    });

    expect(await t.mutation(internal.billing.ackBotGiftReveal, { orderRef })).toEqual({ ok: true });
    const acked = await t.query(internal.billing.botOrderStatus, { orderRef });
    expect(acked?.giftCodes).toEqual([]);
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
        .unique();
      expect(order?.giftReveal).toBeUndefined();
      expect(order?.giftRevealPending).toBeUndefined();
    });
  });

  test('a userless gift order NOT from the bot is still never granted', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seed(t);
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'webless',
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'pending',
        kind: 'gift',
        quantity: 1,
        updatedAt: Date.now(),
      }),
    );
    expect(await payIpn(t, 'webless')).toEqual({ ok: true, applied: false });
    await t.run(async (ctx) => {
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(0);
    });
  });

  test('the bot cannot read or ack a web order by its ref', async () => {
    const t = convexTest(schema, modules);
    const { memberTierId } = await seed(t);
    const userId = await t.run((ctx) =>
      ctx.db.insert('users', { tierId: memberTierId, status: 'active', updatedAt: Date.now() }),
    );
    await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'nowpayments',
        opaqueRef: 'web-gift',
        userId,
        tierId: memberTierId,
        durationDays: 91,
        amountCents: 1400,
        currency: 'USD',
        status: 'paid',
        kind: 'gift',
        quantity: 1,
        giftReveal: ['FSM-AAAA-BBBB-CCCC'],
        updatedAt: Date.now(),
      }),
    );
    expect(await t.query(internal.billing.botOrderStatus, { orderRef: 'web-gift' })).toBeNull();
    expect(await t.mutation(internal.billing.ackBotGiftReveal, { orderRef: 'web-gift' })).toEqual({
      ok: false,
    });
  });

  test('an operator cannot grant a bot order (its codes could never be delivered)', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef } = await starsBotOrder(t, 1);
    const orderId = await t.run(async (ctx) => {
      const o = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
        .unique();
      return o!._id as string;
    });
    await expect(t.action(internal.billing.adminGrantOrder, { orderId })).rejects.toThrow(
      /delivered in the chat/,
    );
    await expect(t.mutation(internal.billing.grantOrderByAdmin, { orderId })).rejects.toThrow(
      /delivered in the chat/,
    );
    await t.run(async (ctx) => {
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(0);
    });
  });
});

describe('Telegram Stars orders', () => {
  afterEach(() => vi.unstubAllEnvs());

  async function starsOrder(t: ReturnType<typeof convexTest>, ref = 'a'.repeat(32)) {
    return t.mutation(internal.billing.createStarsOrder, {
      opaqueRef: ref,
      months: 3,
      quantity: 2,
      starsPerCode: 700,
    });
  }

  test('creates a pending XTR order priced in whole Stars', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const res = await starsOrder(t);
    expect(res.totalStars).toBe(1400);
    await t.run(async (ctx) => {
      const order = await ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', res.orderRef))
        .unique();
      expect(order?.processor).toBe('telegram_stars');
      expect(order?.channel).toBe('telegram');
      expect(order?.currency).toBe('XTR');
      expect(order?.amountCents).toBe(1400);
      expect(order?.userId).toBeUndefined();
    });
  });

  test('refuses an unknown duration and a bad quantity', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const base = { opaqueRef: 'b'.repeat(32), starsPerCode: 700 };
    await expect(
      t.mutation(internal.billing.createStarsOrder, { ...base, months: 7, quantity: 1 }),
    ).rejects.toThrow(/duration/);
    await expect(
      t.mutation(internal.billing.createStarsOrder, { ...base, months: 3, quantity: 51 }),
    ).rejects.toThrow(/between 1 and 50/);
  });

  test('pre-checkout accepts only the exact pending amount in XTR', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef } = await starsOrder(t);
    const ask = (totalAmount: number, currency = 'XTR', ref = orderRef) =>
      t.query(internal.billing.starsPreCheckout, { orderRef: ref, totalAmount, currency });
    expect(await ask(1400)).toEqual({ ok: true });
    expect(await ask(1399)).toEqual({ ok: false, reason: 'amount' });
    expect(await ask(1400, 'USD')).toEqual({ ok: false, reason: 'amount' });
    expect(await ask(1400, 'XTR', 'nope')).toEqual({ ok: false, reason: 'not_found' });
    await t.action(internal.billing.ingestStarsPayment, {
      orderRef,
      chargeId: 'ch_1',
      totalAmount: 1400,
      currency: 'XTR',
      event: 'paid',
    });
    expect(await ask(1400)).toEqual({ ok: false, reason: 'not_pending' });
  });

  test('a successful payment grants exactly once, even when Telegram resends it', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef } = await starsOrder(t);
    const pay = () =>
      t.action(internal.billing.ingestStarsPayment, {
        orderRef,
        chargeId: 'ch_1',
        totalAmount: 1400,
        currency: 'XTR',
        event: 'paid',
      });
    expect(await pay()).toEqual({ duplicate: false, applied: true, granted: true });
    expect(await pay()).toEqual({ duplicate: true, applied: false, granted: false });
    const status = await t.query(internal.billing.botOrderStatus, { orderRef });
    expect(status?.status).toBe('paid');
    expect(status?.giftCodes).toHaveLength(2);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(2);
      const events = await ctx.db.query('webhookEvents').collect();
      expect(events).toHaveLength(1);
      // The stored payload is a short summary: no chat, no user.
      expect(JSON.parse(events[0]!.payload)).toEqual({
        event: 'paid',
        amount: 1400,
        currency: 'XTR',
      });
    });
  });

  test('a short Stars payment is refused, not granted', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef } = await starsOrder(t);
    const res = await t.action(internal.billing.ingestStarsPayment, {
      orderRef,
      chargeId: 'ch_short',
      totalAmount: 10,
      currency: 'XTR',
      event: 'paid',
    });
    expect(res.granted).toBe(false);
    expect((await t.query(internal.billing.botOrderStatus, { orderRef }))?.status).toBe('pending');
  });

  test('a refund of a paid Stars order is audited as refund_seen', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef } = await starsOrder(t);
    const send = (event: 'paid' | 'refunded') =>
      t.action(internal.billing.ingestStarsPayment, {
        orderRef,
        chargeId: 'ch_1',
        totalAmount: 1400,
        currency: 'XTR',
        event,
      });
    await send('paid');
    await send('refunded');
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      expect(audits.map((a) => a.action)).toContain('billing.refund_seen');
    });
  });
});

const newTest = () => convexTest(schema, modules);

describe('Stars orders in the billing currency', () => {
  afterEach(() => vi.unstubAllEnvs());

  const pay = (
    t: ReturnType<typeof convexTest>,
    orderRef: string,
    totalAmount: number,
    id: string,
  ) =>
    t.action(internal.billing.ingestStarsPayment, {
      orderRef,
      chargeId: id,
      totalAmount,
      currency: 'XTR',
      event: 'paid',
    });
  const orderOf = (t: ReturnType<typeof newTest>, orderRef: string) =>
    t.run((ctx) =>
      ctx.db
        .query('billingOrders')
        .withIndex('by_opaque_ref', (q) => q.eq('opaqueRef', orderRef))
        .unique(),
    );
  const revenue = (t: ReturnType<typeof convexTest>) =>
    t.query(internal.adminApi.billingRevenueSeries, {
      sinceMs: Date.now() - 3_600_000,
      untilMs: Date.now() + 3_600_000,
    });

  test('a paid Stars order records its USD value at the Stars rate then', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef, totalStars } = await starsBotOrder(t);
    expect((await orderOf(t, orderRef))?.valueMinor).toBeUndefined();
    await pay(t, orderRef, totalStars, 'ch_value');
    // 1,400 Stars at the default 13.00 USD per 1,000 Stars.
    let order = await orderOf(t, orderRef);
    expect(order?.valueMinor).toBe(1820);
    expect(order?.valueCurrency).toBe('USD');

    // A later rate edit never moves a recorded value.
    await t.mutation(internal.telegramAdmin.setConfig, { starsValuePer1000: 2000 });
    order = await orderOf(t, orderRef);
    expect(order?.valueMinor).toBe(1820);
  });

  test('the revenue chart sums Stars orders at their value; unvalued ones stay out until backfilled', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const a = await starsBotOrder(t);
    await pay(t, a.orderRef, a.totalStars, 'ch_a');
    // A Stars order paid before values were recorded.
    const old = await t.run((ctx) =>
      ctx.db.insert('billingOrders', {
        processor: 'telegram_stars',
        channel: 'telegram',
        opaqueRef: 'd'.repeat(32),
        processorRef: 'ch_old',
        durationDays: 90,
        amountCents: 700,
        donationCents: 0,
        currency: 'XTR',
        status: 'paid',
        paidAt: Date.now() - 60_000,
        kind: 'gift',
        quantity: 1,
        updatedAt: Date.now(),
      }),
    );

    let r = await revenue(t);
    expect(r.totals.giftCents).toBe(1820);
    expect(r.totals.donationCents).toBe(0);
    expect(r.convertedOrders).toBe(1);
    expect(r.otherCurrencyOrders).toBe(1);

    await t.mutation(internal.telegramAdmin.setConfig, { starsValuePer1000: 1500 });
    expect(await t.mutation(internal.billing.backfillStarsOrderValues, {})).toEqual({ valued: 1 });
    expect(await t.mutation(internal.billing.backfillStarsOrderValues, {})).toEqual({ valued: 0 });
    const valued = await t.run((ctx) => ctx.db.get(old));
    expect(valued?.valueMinor).toBe(1050);
    expect(valued?.valueCurrency).toBe('USD');

    r = await revenue(t);
    expect(r.totals.giftCents).toBe(1820 + 1050);
    expect(r.totals.totalCents).toBe(1820 + 1050);
    expect(r.convertedOrders).toBe(2);
    expect(r.otherCurrencyOrders).toBe(0);
  });

  test('the admin orders list carries the value', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { orderRef, totalStars } = await starsBotOrder(t, 1);
    await pay(t, orderRef, totalStars, 'ch_list');
    const overview = await t.query(internal.adminApi.billingOverview, {});
    const row = overview.orders.find((o) => o.processor === 'telegram_stars');
    expect(row).toMatchObject({
      amountCents: 700,
      currency: 'XTR',
      valueMinor: 910,
      valueCurrency: 'USD',
    });
  });

  test('the Stars rate must be a whole number of cents above zero', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    expect((await t.query(internal.telegramAdmin.view, {})).starsValuePer1000).toBe(1300);
    for (const bad of [0, -5, 12.5]) {
      await expect(
        t.mutation(internal.telegramAdmin.setConfig, { starsValuePer1000: bad }),
      ).rejects.toThrow(/starsValuePer1000/);
    }
    await t.mutation(internal.telegramAdmin.setConfig, { starsValuePer1000: 1450 });
    expect((await t.query(internal.telegramAdmin.view, {})).starsValuePer1000).toBe(1450);
  });
});
