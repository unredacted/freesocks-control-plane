/**
 * Direct checkout (a crypto rail set to `direct` in Admin -> Billing): the
 * checkout reads the payment details from the processor API and stores them on
 * the order for our own return page; the IPN / webhook and grant path stay the
 * hosted ones. See docs/billing.md "Direct checkout".
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { hmacSha512Hex } from './lib/crypto';
import { ConvexError } from 'convex/values';
import { linkMatches } from './lib/processors/btcpay';

const modules = import.meta.glob('./**/*.*s');
const IPN_SECRET = 'test-ipn-secret';
const HOUR = 3_600_000;

type T = ReturnType<typeof convexTest>;

async function seed(t: T): Promise<{ userId: Id<'users'>; memberTierId: Id<'tiers'> }> {
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
    return { userId, memberTierId };
  });
}

async function settings(t: T, rows: Record<string, unknown>) {
  await t.run(async (ctx) => {
    for (const [key, value] of Object.entries({
      'billing.enabled': true,
      'billing.membership.durations': [{ months: 3, amountCents: 1400 }],
      ...rows,
    })) {
      await ctx.db.insert('appSettings', {
        key,
        value: JSON.stringify(value),
        updatedAt: Date.now(),
      });
    }
  });
}

const readOrder = (t: T, ref: string) =>
  t.run(async (ctx) =>
    (await ctx.db.query('billingOrders').collect()).find((o) => o.opaqueRef === ref),
  ) as Promise<Doc<'billingOrders'> | undefined>;
const orderCount = (t: T) =>
  t.run(async (ctx) => (await ctx.db.query('billingOrders').collect()).length);

const jsonRes = (body: unknown, status = 200) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

/** The order_id the last stubbed /v1/invoice was created with (the payment inherits it). */
let invoiceOrderId: string | null = null;

/** A NOWPayments API stub: /v1/invoice as today, /v1/invoice-payment as given. */
function stubNowPayments(payment: (body: Record<string, unknown>) => Response) {
  const calls: Array<{ path: string; body: Record<string, unknown> | null }> = [];
  const fetchMock = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ path, body });
    if (path === '/v1/invoice') {
      invoiceOrderId = typeof body?.order_id === 'string' ? body.order_id : null;
      return jsonRes({ id: 'inv_9', invoice_url: 'https://nowpayments.io/payment/?iid=inv_9' });
    }
    if (path === '/v1/invoice-payment') return payment(body ?? {});
    return jsonRes({}, 404);
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}

/** A realistic invoice-payment reply, with the amount kept as raw JSON text. */
function paymentReply(over: Record<string, unknown> = {}, amountText = '14.03') {
  const base = {
    payment_id: '5745459419',
    payment_status: 'waiting',
    pay_address: 'TXYZabc123DepositAddress',
    price_amount: 14,
    price_currency: 'usd',
    pay_currency: 'usdttrc20',
    order_id: invoiceOrderId,
    payin_extra_id: null as string | null,
    network: 'trx',
    expiration_estimate_date: new Date(Date.now() + 24 * HOUR).toISOString(),
    ...over,
  };
  // Splice the amount in as raw text so a value like 0.00012000 keeps its zeros.
  return JSON.stringify(base).replace(/}$/, `,"pay_amount":${amountText}}`);
}

async function catchCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (err) {
    return err instanceof ConvexError ? (err.data as { code?: string }).code : String(err);
  }
}

describe('direct checkout: NOWPayments', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('NOWPAYMENTS_IPN_SECRET', IPN_SECRET);
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const direct = (t: T, extra: Record<string, unknown> = {}) =>
    settings(t, {
      'billing.nowpayments.enabled': true,
      'billing.nowpayments.checkoutStyle': 'direct',
      // These tests pin the hand-written list; the account source is below.
      'billing.nowpayments.coinSource': 'list',
      ...extra,
    });

  test('stores the payment details and keeps the invoice as the processorRef', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    const { calls } = stubNowPayments((b) =>
      jsonRes(paymentReply({ pay_currency: String(b.pay_currency) })),
    );

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'USDTTRC20',
    });
    expect(res.direct).toBe(true);
    // The hosted page for the SAME invoice stays available as a fallback.
    expect(res.redirectUrl).toBe('https://nowpayments.io/payment/?iid=inv_9');
    expect(calls.map((c) => c.path)).toEqual(['/v1/invoice', '/v1/invoice-payment']);
    expect(calls[1]?.body).toEqual({ iid: 'inv_9', pay_currency: 'usdttrc20' });

    const order = await readOrder(t, res.orderRef);
    expect(order?.processorRef).toBe('inv_9');
    expect(order?.directPayment?.methods).toEqual([
      {
        id: 'usdttrc20',
        unit: 'USDT',
        network: 'Tron (TRC-20)',
        address: 'TXYZabc123DepositAddress',
        amount: '14.03',
        qr: 'TXYZabc123DepositAddress',
      },
    ]);
    expect(order?.directPayment?.expiresAt).toBeGreaterThan(Date.now());

    const status = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: res.orderRef,
      userId,
    });
    expect(status?.payment?.processor).toBe('nowpayments');
    expect(status?.payment?.methods[0]?.amount).toBe('14.03');
    expect(status?.payment?.expiresAt).toMatch(/Z$/);
  });

  test('keeps the exact decimal text of a tiny amount', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply({ pay_currency: 'btc' }, '0.00012000')));
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'btc',
    });
    expect((await readOrder(t, res.orderRef))?.directPayment?.methods[0]?.amount).toBe(
      '0.00012000',
    );
  });

  test('the IPN grants exactly once through the unchanged path and wipes the details', async () => {
    const t = convexTest(schema, modules);
    const { userId, memberTierId } = await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply()));
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'usdttrc20',
    });

    const ipn = {
      payment_status: 'finished',
      payment_id: 5745459419,
      invoice_id: 'inv_9',
      order_id: res.orderRef,
      price_amount: 14,
      price_currency: 'usd',
      pay_amount: 14.03,
      actually_paid: 14.03,
    };
    const sig = await hmacSha512Hex(IPN_SECRET, JSON.stringify(ipn, Object.keys(ipn).sort()));
    for (let i = 0; i < 2; i++) {
      await t.action(internal.billing.ingestEvent, {
        processor: 'nowpayments',
        rawBody: JSON.stringify(ipn),
        signature: sig,
      });
    }
    const order = await readOrder(t, res.orderRef);
    expect(order?.status).toBe('paid');
    expect(order?.directPayment).toBeUndefined();
    const user = await t.run((ctx) => ctx.db.get(userId));
    expect(user?.tierId).toBe(memberTierId);
    const grants = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter((a) => a.action === 'billing.order.paid'),
    );
    expect(grants).toHaveLength(1);
    const status = await t.query(internal.billing.getOrderStatus, {
      opaqueRef: res.orderRef,
      userId,
    });
    expect(status?.payment).toBeNull();
  });

  test('an IPN carrying a different invoice id is still refused (ref cross-check unchanged)', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply()));
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'usdttrc20',
    });
    const ipn = {
      payment_status: 'finished',
      payment_id: 1,
      invoice_id: 'someone-elses-invoice',
      order_id: res.orderRef,
      price_amount: 14,
      price_currency: 'usd',
      pay_amount: 1,
      actually_paid: 1,
    };
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(ipn),
      signature: await hmacSha512Hex(IPN_SECRET, JSON.stringify(ipn, Object.keys(ipn).sort())),
    });
    expect((await readOrder(t, res.orderRef))?.status).toBe('pending');
  });

  test('an expired IPN wipes the details', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply()));
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'usdttrc20',
    });
    const ipn = {
      payment_status: 'expired',
      payment_id: 7,
      invoice_id: 'inv_9',
      order_id: res.orderRef,
    };
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(ipn),
      signature: await hmacSha512Hex(IPN_SECRET, JSON.stringify(ipn, Object.keys(ipn).sort())),
    });
    const order = await readOrder(t, res.orderRef);
    expect(order?.status).toBe('expired');
    expect(order?.directPayment).toBeUndefined();
  });

  test('a coin off the allowlist is refused before any invoice exists', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    const { fetchMock } = stubNowPayments(() => jsonRes(paymentReply()));
    const code = await catchCode(
      t.action(internal.billing.createCheckout, {
        userId,
        processor: 'nowpayments',
        months: 3,
        payCurrency: 'usdterc20',
      }),
    );
    expect(code).toBe('billing.invalid_coin');
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await orderCount(t)).toBe(0);
  });

  test("below the coin's minimum is a member-facing error and stores nothing", async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(() =>
      jsonRes(
        {
          statusCode: 400,
          code: 'AMOUNT_MINIMAL_ERROR',
          message: 'Crypto amount 0.02 is less than minimal',
        },
        400,
      ),
    );
    const code = await catchCode(
      t.action(internal.billing.createCheckout, {
        userId,
        processor: 'nowpayments',
        months: 3,
        payCurrency: 'xmr',
      }),
    );
    expect(code).toBe('billing.coin_minimum');
    expect(await orderCount(t)).toBe(0);
  });

  test('a memo the operator has not allowed is refused; an allowed one is stored', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t, {
      'billing.nowpayments.directCoins': [
        { ticker: 'xrp', label: 'XRP', network: 'XRP Ledger', allowMemo: false },
        { ticker: 'xlm', label: 'XLM', network: 'Stellar', allowMemo: true },
      ],
    });
    stubNowPayments((b) =>
      jsonRes(paymentReply({ pay_currency: b.pay_currency, payin_extra_id: '1234567' })),
    );
    expect(
      await catchCode(
        t.action(internal.billing.createCheckout, {
          userId,
          processor: 'nowpayments',
          months: 3,
          payCurrency: 'xrp',
        }),
      ),
    ).toBe('billing.invalid_coin');
    expect(await orderCount(t)).toBe(0);

    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'xlm',
    });
    expect((await readOrder(t, res.orderRef))?.directPayment?.methods[0]?.memo).toBe('1234567');
  });

  test.each([
    ['an API error', () => jsonRes({ message: 'boom' }, 500)],
    ['a different coin than asked', () => jsonRes(paymentReply({ pay_currency: 'usdterc20' }))],
    ['a payment for another order', () => jsonRes(paymentReply({ order_id: 'not-ours' }))],
    // Its IPNs find the order by order_id: without it the payment could never grant.
    ['a payment without our order id', () => jsonRes(paymentReply({ order_id: null }))],
    ['an address with spaces', () => jsonRes(paymentReply({ pay_address: 'T X Y' }))],
    [
      'an expiry in the past',
      () => jsonRes(paymentReply({ expiration_estimate_date: '2001-01-01T00:00:00Z' })),
    ],
  ])('%s falls back to the hosted page', async (_name, reply) => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(reply);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'usdttrc20',
    });
    expect(res.direct).toBe(false);
    const order = await readOrder(t, res.orderRef);
    expect(order?.status).toBe('pending');
    expect(order?.directPayment).toBeUndefined();
  });

  test('hosted style ignores a coin; direct without a coin (an older SPA) stays hosted', async () => {
    for (const style of ['hosted', 'direct']) {
      const t = convexTest(schema, modules);
      const { userId } = await seed(t);
      await settings(t, {
        'billing.nowpayments.enabled': true,
        'billing.nowpayments.checkoutStyle': style,
        'billing.nowpayments.coinSource': 'list',
      });
      const { calls } = stubNowPayments(() => jsonRes(paymentReply()));
      const res = await t.action(internal.billing.createCheckout, {
        userId,
        processor: 'nowpayments',
        months: 3,
        ...(style === 'hosted' ? { payCurrency: 'usdttrc20' } : {}),
      });
      expect(res.direct).toBe(false);
      expect(calls.map((c) => c.path)).toEqual(['/v1/invoice']);
    }
  });

  test('an anonymous donation poll carries the details', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply()));
    const res = await t.action(internal.billing.createCheckout, {
      processor: 'nowpayments',
      kind: 'donation',
      donationCents: 500,
      payCurrency: 'usdttrc20',
    });
    const status = await t.query(internal.billing.getAnonOrderStatus, { opaqueRef: res.orderRef });
    expect(status?.payment?.methods[0]?.address).toBe('TXYZabc123DepositAddress');
  });

  test('the stale-order sweep wipes the details', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await direct(t);
    stubNowPayments(() => jsonRes(paymentReply()));
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'usdttrc20',
    });
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(Date.now() + 72 * HOUR);
      await t.mutation(internal.retention.expireStalePendingOrders, {});
    } finally {
      vi.useRealTimers();
    }
    const order = await readOrder(t, res.orderRef);
    expect(order?.status).toBe('expired');
    expect(order?.directPayment).toBeUndefined();
  });
});

describe('direct checkout: coins from the NOWPayments account', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const account = (t: T, extra: Record<string, unknown> = {}) =>
    settings(t, {
      'billing.nowpayments.enabled': true,
      'billing.nowpayments.checkoutStyle': 'direct',
      ...extra,
    });

  /** /v1/merchant/coins + /v1/full-currencies (+ invoice / invoice-payment for checkout). */
  function stubAccount(merchantOk = true) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        const path = new URL(String(url)).pathname;
        const body = init?.body
          ? (JSON.parse(init.body as string) as Record<string, unknown>)
          : null;
        if (path === '/v1/merchant/coins') {
          return merchantOk
            ? jsonRes({ selectedCurrencies: ['BTC', 'usdttrc20', 'xrp', 'nonet', 'off'] })
            : jsonRes({}, 500);
        }
        if (path === '/v1/full-currencies') {
          return jsonRes({
            currencies: [
              { code: 'BTC', network: 'btc', extra_id_exists: false, enable: true },
              { code: 'USDTTRC20', network: 'trx', extra_id_exists: false, enable: true },
              { code: 'XRP', network: 'xrp', extra_id_exists: true, enable: true },
              { code: 'NONET', network: null, enable: true },
              { code: 'OFF', network: 'eth', enable: false },
            ],
          });
        }
        if (path === '/v1/invoice') {
          invoiceOrderId = typeof body?.order_id === 'string' ? body.order_id : null;
          return jsonRes({ id: 'inv_9', invoice_url: 'https://nowpayments.io/payment/?iid=inv_9' });
        }
        if (path === '/v1/invoice-payment') {
          return jsonRes(paymentReply({ pay_currency: 'xrp', payin_extra_id: '99' }));
        }
        return jsonRes({}, 404);
      }),
    );
  }

  test('the refresh caches enabled coins with a network; members see them in order', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    await account(t);
    stubAccount();
    await t.action(internal.billing.refreshAccountCoins, {});
    const { coins } = await t.query(internal.billing.publicDirectCoins, {});
    // No network → left out; disabled → left out; pinned btc first.
    expect(coins).toEqual([
      { ticker: 'btc', label: 'BTC', network: 'Bitcoin', memo: false, pinned: true },
      { ticker: 'usdttrc20', label: 'USDT', network: 'Tron (TRC-20)', memo: false, pinned: true },
      { ticker: 'xrp', label: 'XRP', network: 'XRP Ledger', memo: true, pinned: false },
    ]);
  });

  test('a memo coin from the account checks out with its memo', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await account(t);
    stubAccount();
    await t.action(internal.billing.refreshAccountCoins, {});
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'xrp',
    });
    expect(res.direct).toBe(true);
    const m = (await readOrder(t, res.orderRef))?.directPayment?.methods[0];
    expect(m).toMatchObject({ unit: 'XRP', network: 'XRP Ledger', memo: '99' });
  });

  test('an excluded coin is refused, and an unreadable refresh keeps the last list', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await account(t, { 'billing.nowpayments.coinExclude': ['xrp'] });
    stubAccount();
    await t.action(internal.billing.refreshAccountCoins, {});
    expect(
      await catchCode(
        t.action(internal.billing.createCheckout, {
          userId,
          processor: 'nowpayments',
          months: 3,
          payCurrency: 'xrp',
        }),
      ),
    ).toBe('billing.invalid_coin');

    stubAccount(false);
    await t.action(internal.billing.refreshAccountCoins, {});
    const { coins } = await t.query(internal.billing.publicDirectCoins, {});
    expect(coins.map((c) => c.ticker)).toEqual(['btc', 'usdttrc20']);
  });

  test('no cached list yet: nothing to offer, checkout stays hosted', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await account(t);
    stubAccount();
    expect((await t.query(internal.billing.publicDirectCoins, {})).coins).toEqual([]);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'nowpayments',
      months: 3,
      payCurrency: 'btc',
    });
    expect(res.direct).toBe(false);
  });

  test('the refresh does nothing while the rail is hosted', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    await settings(t, { 'billing.nowpayments.enabled': true });
    stubAccount();
    await t.action(internal.billing.refreshAccountCoins, {});
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('direct checkout: BTCPay', () => {
  beforeEach(() => {
    vi.stubEnv('BTCPAY_API_URL', 'https://btcpay.test');
    vi.stubEnv('BTCPAY_STORE_ID', 'store_1');
    vi.stubEnv('BTCPAY_API_KEY', 'k');
    vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  const expiry = () => Math.floor((Date.now() + 90 * 60_000) / 1000);
  function stubBtcpay(methods: unknown) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) =>
        String(url).endsWith('/payment-methods')
          ? jsonRes(methods)
          : jsonRes({
              id: 'bp_inv_1',
              checkoutLink: 'https://btcpay.test/i/bp_inv_1',
              expirationTime: expiry(),
            }),
      ),
    );
  }
  const onchain = {
    paymentMethodId: 'BTC-CHAIN',
    currency: 'BTC',
    destination: 'bc1qexampleaddress',
    paymentLink: 'bitcoin:bc1qexampleaddress?amount=0.00021',
    amount: '0.00020000',
    due: '0.00021000',
    activated: true,
  };
  const lightning = {
    paymentMethodId: 'BTC-LN',
    currency: 'BTC',
    destination: 'lnbc210n1pexampleinvoice',
    paymentLink: 'lightning:lnbc210n1pexampleinvoice',
    amount: '0.00020000',
    due: '0.00020000',
    activated: true,
  };

  test('shows the allowlisted, activated methods in the operator order', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await settings(t, {
      'billing.btcpay.enabled': true,
      'billing.btcpay.checkoutStyle': 'direct',
      'billing.btcpay.directMethods': ['BTC-LN', 'BTC-CHAIN'],
    });
    stubBtcpay([onchain, lightning, { ...onchain, paymentMethodId: 'LTC-CHAIN' }]);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'btcpay',
      months: 3,
    });
    expect(res.direct).toBe(true);
    const order = await readOrder(t, res.orderRef);
    expect(order?.processorRef).toBe('bp_inv_1');
    const methods = order?.directPayment?.methods ?? [];
    expect(methods.map((m) => m.id)).toEqual(['BTC-LN', 'BTC-CHAIN']);
    expect(methods[1]).toMatchObject({
      amount: '0.00021000',
      unit: 'BTC',
      qr: 'bitcoin:bc1qexampleaddress?amount=0.00021',
    });
    expect(order?.directPayment?.expiresAt).toBe(expiry() * 1000);
  });

  test('lazy (unactivated) methods fall back to the hosted page', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await settings(t, { 'billing.btcpay.enabled': true, 'billing.btcpay.checkoutStyle': 'direct' });
    stubBtcpay([{ ...onchain, activated: false }]);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'btcpay',
      months: 3,
    });
    expect(res.direct).toBe(false);
    expect(res.redirectUrl).toBe('https://btcpay.test/i/bp_inv_1');
  });

  test.each([
    ['another address', { paymentLink: 'bitcoin:bc1qsomeoneelse?amount=0.00021' }],
    ['another amount', { paymentLink: 'bitcoin:bc1qexampleaddress?amount=0.5' }],
  ])('a payment link with %s falls back to the hosted page', async (_name, over) => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await settings(t, { 'billing.btcpay.enabled': true, 'billing.btcpay.checkoutStyle': 'direct' });
    stubBtcpay([{ ...onchain, ...over }]);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'btcpay',
      months: 3,
    });
    expect(res.direct).toBe(false);
  });

  test('a payment link with another scheme is never encoded', async () => {
    const t = convexTest(schema, modules);
    const { userId } = await seed(t);
    await settings(t, { 'billing.btcpay.enabled': true, 'billing.btcpay.checkoutStyle': 'direct' });
    stubBtcpay([{ ...onchain, paymentLink: 'javascript:alert(1)' }]);
    const res = await t.action(internal.billing.createCheckout, {
      userId,
      processor: 'btcpay',
      months: 3,
    });
    expect(res.direct).toBe(false);
  });
});

describe('BTCPay QR link must pay what the page shows', () => {
  test.each([
    ['bc1qabc', 'bc1qabc', '0.1', true],
    ['bitcoin:bc1qabc?amount=0.10000', 'bc1qabc', '0.1', true],
    ['BITCOIN:BC1QABC?amount=0.1&lightning=lnbc1', 'bc1qabc', '0.1', true],
    ['bitcoin:bc1qabc', 'bc1qabc', '0.1', true],
    ['bitcoin:bc1qabc?amount=0.2', 'bc1qabc', '0.1', false],
    ['bitcoin:bc1qother?amount=0.1', 'bc1qabc', '0.1', false],
    ['lightning:LNBC1XYZ', 'lnbc1xyz', '0.1', true],
    ['lightning:lnbc1other', 'lnbc1xyz', '0.1', false],
  ])('%s vs %s / %s -> %s', (qr, address, amount, ok) => {
    expect(linkMatches(qr, address, amount)).toBe(ok);
  });
});

describe('admin coin check', () => {
  beforeEach(() => {
    vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  test('compares minimums with the cheapest PRICE and keeps an unreadable minimum null', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    await settings(t, {
      'billing.nowpayments.enabled': true,
      'billing.nowpayments.coinSource': 'list',
      // Prices don't rise with the term here: the 6-month term is the cheapest.
      'billing.membership.durations': [
        { months: 3, amountCents: 3000 },
        { months: 6, amountCents: 1000 },
      ],
      'billing.nowpayments.directCoins': [
        { ticker: 'btc', label: 'BTC', network: 'Bitcoin', allowMemo: false },
        { ticker: 'usdttrc20', label: 'USDT', network: 'Ethereum', allowMemo: false },
      ],
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        const u = new URL(String(url));
        if (u.pathname === '/v1/merchant/coins')
          return jsonRes({ selectedCurrencies: ['btc', 'usdttrc20'] });
        if (u.pathname === '/v1/full-currencies') {
          return jsonRes({
            currencies: [
              { code: 'BTC', network: 'btc', extra_id_exists: false },
              { code: 'USDTTRC20', network: 'trx', extra_id_exists: false },
            ],
          });
        }
        if (u.pathname === '/v1/min-amount') {
          return jsonRes({
            fiat_equivalent: u.searchParams.get('currency_from') === 'btc' ? 12.5 : null,
          });
        }
        return jsonRes({}, 404);
      }),
    );
    const res = await t.action(internal.billing.checkDirectCoins, {});
    expect(res.cheapestCryptoCents).toBe(1000);
    const btc = res.coins.find((c) => c.ticker === 'btc');
    const usdt = res.coins.find((c) => c.ticker === 'usdttrc20');
    expect(btc).toMatchObject({ minFiat: 12.5, network: 'btc', networkName: 'Bitcoin' });
    // null fiat_equivalent stays null (not a zero minimum); the network is
    // reported so the admin can see "Ethereum" is the wrong label for it.
    expect(usdt).toMatchObject({ minFiat: null, network: 'trx', networkName: 'Tron' });
  });
});
