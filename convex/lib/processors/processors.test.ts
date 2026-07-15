import { afterEach, describe, expect, test, vi } from 'vitest';
import * as stripe from './stripe';
import * as paypal from './paypal';
import * as btcpay from './btcpay';
import * as nowpayments from './nowpayments';
import { hmacSha256Hex } from '../crypto';

/**
 * Adapter-level coverage for the Stripe + PayPal + BTCPay payment rails
 * (NOWPayments is exercised at the billing-domain level). These exercise the
 * risky surfaces directly: webhook authenticity (signature / verify-API),
 * event→status mapping, order-ref extraction, dedupe ids, and hosted-checkout
 * request shaping. Stripe's + BTCPay's verify are pure HMAC (no network);
 * everything else runs against a stubbed `fetch`.
 */

/** Minimal stand-in for a fetch Response (only the fields the adapters read). */
function res(body: unknown, init: { ok?: boolean; status?: number } = {}): Response {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => (typeof body === 'string' ? JSON.parse(text) : body),
    text: async () => text,
  } as unknown as Response;
}

afterEach(() => vi.unstubAllGlobals());

// ===========================================================================
// Stripe
// ===========================================================================

describe('stripe.verifyAndParse', () => {
  const SECRET = 'whsec_test';
  const T = 1_700_000_000; // fixed; pass nowSec so the tolerance check is deterministic

  /** Sign a body the way Stripe does: v1 = HMAC-SHA256(secret, `${t}.${body}`). */
  async function signed(bodyObj: unknown, t = T, secret = SECRET) {
    const body = JSON.stringify(bodyObj);
    const sig = await hmacSha256Hex(secret, `${t}.${body}`);
    return { body, signature: `t=${t},v1=${sig}` };
  }

  test('rejects a missing signature header', async () => {
    const r = await stripe.verifyAndParse({
      rawBody: '{}',
      signature: null,
      secret: SECRET,
      nowSec: T,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/missing/i);
  });

  test('rejects a malformed signature header', async () => {
    const r = await stripe.verifyAndParse({
      rawBody: '{}',
      signature: 'garbage-no-scheme',
      secret: SECRET,
      nowSec: T,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/malformed/i);
  });

  test('rejects a stale timestamp (replay window)', async () => {
    const { body, signature } = await signed({ id: 'evt_1', type: 'checkout.session.completed' });
    const r = await stripe.verifyAndParse({
      rawBody: body,
      signature,
      secret: SECRET,
      nowSec: T + 10 * 60, // 10 min later — outside the 5 min tolerance
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/tolerance/i);
  });

  test('rejects a signature computed with the wrong secret', async () => {
    const { body, signature } = await signed(
      { id: 'evt_1', type: 'checkout.session.completed' },
      T,
      'wrong-secret',
    );
    const r = await stripe.verifyAndParse({ rawBody: body, signature, secret: SECRET, nowSec: T });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/mismatch/i);
  });

  test('accepts a valid signature and maps a paid checkout', async () => {
    const { body, signature } = await signed({
      id: 'evt_42',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_1', client_reference_id: 'order-abc', payment_status: 'paid' } },
    });
    const r = await stripe.verifyAndParse({ rawBody: body, signature, secret: SECRET, nowSec: T });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.status).toBe('paid');
      expect(r.orderRef).toBe('order-abc');
      expect(r.processorRef).toBe('cs_1');
      expect(r.dedupeId).toBe('stripe:evt_42');
    }
  });

  test('a completed session not yet paid maps to confirming', async () => {
    const { body, signature } = await signed({
      id: 'evt_43',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_2', client_reference_id: 'o2', payment_status: 'unpaid' } },
    });
    const r = await stripe.verifyAndParse({ rawBody: body, signature, secret: SECRET, nowSec: T });
    expect(r.ok && r.status).toBe('confirming');
  });

  test('expired / failed / unhandled event types map correctly', async () => {
    const cases: [string, string][] = [
      ['checkout.session.expired', 'expired'],
      ['checkout.session.async_payment_failed', 'failed'],
      ['invoice.whatever.unhandled', 'pending'],
    ];
    for (const [type, expected] of cases) {
      const { body, signature } = await signed({
        id: `e_${type}`,
        type,
        data: { object: { id: 'x' } },
      });
      const r = await stripe.verifyAndParse({
        rawBody: body,
        signature,
        secret: SECRET,
        nowSec: T,
      });
      expect(r.ok && r.status).toBe(expected);
    }
  });

  test('a valid signature over unparseable JSON fails closed', async () => {
    const body = 'not-json{';
    const sig = await hmacSha256Hex(SECRET, `${T}.${body}`);
    const r = await stripe.verifyAndParse({
      rawBody: body,
      signature: `t=${T},v1=${sig}`,
      secret: SECRET,
      nowSec: T,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/json/i);
  });
});

describe('stripe.createCheckout', () => {
  const cfg = { apiKey: 'sk_test' };
  const params = {
    orderRef: 'order-1',
    amountCents: 1500,
    currency: 'USD',
    description: 'FreeSocks Membership — 3 months',
    ipnUrl: 'https://x/ipn',
    successUrl: 'https://x/ok',
    cancelUrl: 'https://x/no',
  };

  test('posts a form-encoded session and returns the redirect url + id', async () => {
    let captured: { url: string; init?: RequestInit } | null = null;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        captured = { url: String(url), init };
        return res({ id: 'cs_123', url: 'https://checkout.stripe/cs_123' });
      }),
    );
    const out = await stripe.createCheckout(cfg, params);
    expect(out).toEqual({ redirectUrl: 'https://checkout.stripe/cs_123', processorRef: 'cs_123' });
    expect(captured!.url).toMatch(/\/v1\/checkout\/sessions$/);
    // Parse the form back (URLSearchParams decodes the bracketed keys).
    const form = new URLSearchParams(String(captured!.init!.body));
    expect(form.get('mode')).toBe('payment');
    expect(form.get('client_reference_id')).toBe('order-1');
    expect(form.get('success_url')).toBe(params.successUrl);
    expect(form.get('line_items[0][price_data][currency]')).toBe('usd'); // lowercased
    expect(form.get('line_items[0][price_data][unit_amount]')).toBe('1500'); // minor units
  });

  test('throws when Stripe returns a non-OK status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => res({ error: 'bad' }, { ok: false, status: 402 })),
    );
    await expect(stripe.createCheckout(cfg, params)).rejects.toThrow(/402|stripe/i);
  });

  test('throws when the session response is missing id/url', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => res({ id: 'cs_x' })),
    ); // no url
    await expect(stripe.createCheckout(cfg, params)).rejects.toThrow(/missing id\/url/i);
  });
});

// ===========================================================================
// PayPal
// ===========================================================================

const PP_CFG = {
  clientId: 'id',
  secret: 'sec',
  apiBase: 'https://api-m.sandbox.paypal.com',
  webhookId: 'wh_1',
};
const PP_HEADERS = {
  'paypal-auth-algo': 'SHA256withRSA',
  'paypal-cert-url': 'https://paypal/cert',
  'paypal-transmission-id': 'tx-1',
  'paypal-transmission-sig': 'sig-1',
  'paypal-transmission-time': '2026-01-01T00:00:00Z',
};

/** Route PayPal's multi-call flow (token → verify → capture / create-order). */
function ppFetch(opts: { verification?: string; capture?: 'ok' | 'already' | 'fail' } = {}) {
  return vi.fn(async (url: string | URL) => {
    const u = String(url);
    if (u.includes('/v1/oauth2/token')) return res({ access_token: 'tok' });
    if (u.includes('/verify-webhook-signature'))
      return res({ verification_status: opts.verification ?? 'SUCCESS' });
    if (u.includes('/capture')) {
      if (opts.capture === 'fail') return res({}, { ok: false, status: 500 });
      if (opts.capture === 'already')
        return res('{"details":[{"issue":"ORDER_ALREADY_CAPTURED"}]}', { ok: false, status: 422 });
      return res({ status: 'COMPLETED' });
    }
    if (u.includes('/v2/checkout/orders'))
      return res({ id: 'PP-1', links: [{ rel: 'approve', href: 'https://pp/approve' }] });
    return res({});
  });
}

describe('paypal.verifyAndParse', () => {
  test('rejects when the verify API does not return SUCCESS', async () => {
    vi.stubGlobal('fetch', ppFetch({ verification: 'FAILURE' }));
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({ id: 'evt', event_type: 'PAYMENT.CAPTURE.COMPLETED' }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/not SUCCESS/i);
  });

  test('rejects an unparseable body before any network call', async () => {
    const fetchMock = ppFetch();
    vi.stubGlobal('fetch', fetchMock);
    const r = await paypal.verifyAndParse({
      rawBody: 'not-json{',
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/json/i);
    expect(fetchMock).not.toHaveBeenCalled(); // failed closed before the token fetch
  });

  test('a completed capture maps to paid (order-ref from custom_id)', async () => {
    vi.stubGlobal('fetch', ppFetch());
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({
        id: 'evt_pc',
        event_type: 'PAYMENT.CAPTURE.COMPLETED',
        resource: { id: 'CAP-1', custom_id: 'order-xyz' },
      }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.status).toBe('paid');
      expect(r.orderRef).toBe('order-xyz');
      expect(r.dedupeId).toBe('paypal:evt_pc');
    }
  });

  test('an APPROVED order is captured server-side → paid; custom_id read from purchase_units', async () => {
    vi.stubGlobal('fetch', ppFetch({ capture: 'ok' }));
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({
        id: 'evt_ap',
        event_type: 'CHECKOUT.ORDER.APPROVED',
        resource: { id: 'PP-1', purchase_units: [{ custom_id: 'order-nested' }] },
      }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok && r.status).toBe('paid');
    if (r.ok) expect(r.orderRef).toBe('order-nested'); // nested extraction
  });

  test('an APPROVED order whose capture fails is REJECTED (retryable), not silently confirming', async () => {
    vi.stubGlobal('fetch', ppFetch({ capture: 'fail' }));
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({
        id: 'evt_af',
        event_type: 'CHECKOUT.ORDER.APPROVED',
        resource: { id: 'PP-2', purchase_units: [{ custom_id: 'o' }] },
      }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    // Must NOT 200-ack as 'confirming' (that marks the webhook processed → PayPal
    // never retries → the buyer is never charged). Fail so ingest 400s and PayPal
    // redelivers; the retry is idempotent via the 422 guard. (Review #1.)
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/capture failed/i);
  });

  test('an already-captured APPROVED redelivery still maps to paid (idempotent)', async () => {
    vi.stubGlobal('fetch', ppFetch({ capture: 'already' }));
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({
        id: 'evt_dup',
        event_type: 'CHECKOUT.ORDER.APPROVED',
        resource: { id: 'PP-3', purchase_units: [{ custom_id: 'o' }] },
      }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok && r.status).toBe('paid');
  });

  test('a denied capture maps to failed', async () => {
    vi.stubGlobal('fetch', ppFetch());
    const r = await paypal.verifyAndParse({
      rawBody: JSON.stringify({
        id: 'evt_dn',
        event_type: 'PAYMENT.CAPTURE.DENIED',
        resource: { id: 'CAP-9', custom_id: 'o' },
      }),
      headers: PP_HEADERS,
      cfg: PP_CFG,
    });
    expect(r.ok && r.status).toBe('failed');
  });
});

describe('paypal.createCheckout', () => {
  test('creates a CAPTURE order and returns the approval link + order id', async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        if (String(url).includes('/v1/oauth2/token')) return res({ access_token: 'tok' });
        return res({ id: 'PP-ORDER', links: [{ rel: 'approve', href: 'https://pp/approve' }] });
      }),
    );
    const out = await paypal.createCheckout(PP_CFG, {
      orderRef: 'order-1',
      amountCents: 1500,
      currency: 'usd',
      description: 'Membership',
      ipnUrl: 'https://x/ipn',
      successUrl: 'https://x/ok',
      cancelUrl: 'https://x/no',
    });
    expect(out).toEqual({ redirectUrl: 'https://pp/approve', processorRef: 'PP-ORDER' });
    const create = calls.find((c) => c.url.includes('/v2/checkout/orders'));
    const body = JSON.parse(String(create!.init!.body));
    expect(body.intent).toBe('CAPTURE');
    expect(body.purchase_units[0].custom_id).toBe('order-1');
    expect(body.purchase_units[0].amount.value).toBe('15.00'); // cents → decimal
    expect(body.purchase_units[0].amount.currency_code).toBe('USD'); // uppercased
  });

  test('falls back to the payer-action link when there is no approve rel', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL) => {
        if (String(url).includes('/v1/oauth2/token')) return res({ access_token: 'tok' });
        return res({ id: 'PP-2', links: [{ rel: 'payer-action', href: 'https://pp/payer' }] });
      }),
    );
    const out = await paypal.createCheckout(PP_CFG, {
      orderRef: 'o',
      amountCents: 500,
      currency: 'USD',
      description: 'm',
      ipnUrl: 'https://x/i',
      successUrl: 'https://x/ok',
      cancelUrl: 'https://x/no',
    });
    expect(out.redirectUrl).toBe('https://pp/payer');
  });
});

// ===========================================================================
// BTCPay Server
// ===========================================================================

describe('btcpay.verifyAndParse', () => {
  const SECRET = 'btcpay-webhook-secret';

  /** Sign a body the way BTCPay does: BTCPay-Sig = sha256=<HMAC-SHA256(secret, body)>. */
  async function signed(bodyObj: unknown, secret = SECRET) {
    const body = JSON.stringify(bodyObj);
    const sig = await hmacSha256Hex(secret, body);
    return { body, signature: `sha256=${sig}` };
  }

  test('rejects a missing signature header', async () => {
    const r = await btcpay.verifyAndParse({
      rawBody: '{}',
      signature: null,
      webhookSecret: SECRET,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/missing/i);
  });

  test('rejects a signature without the sha256= scheme', async () => {
    const r = await btcpay.verifyAndParse({
      rawBody: '{}',
      signature: 'deadbeef',
      webhookSecret: SECRET,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/malformed/i);
  });

  test('rejects a signature computed with the wrong secret', async () => {
    const { body, signature } = await signed({ type: 'InvoiceSettled' }, 'wrong-secret');
    const r = await btcpay.verifyAndParse({ rawBody: body, signature, webhookSecret: SECRET });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/mismatch/i);
  });

  test('accepts a valid signature and maps a settled invoice (order-ref from metadata)', async () => {
    const { body, signature } = await signed({
      type: 'InvoiceSettled',
      invoiceId: 'inv_42',
      storeId: 'store_1',
      metadata: { orderId: 'order-abc' },
    });
    const r = await btcpay.verifyAndParse({ rawBody: body, signature, webhookSecret: SECRET });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.status).toBe('paid');
      expect(r.orderRef).toBe('order-abc');
      expect(r.processorRef).toBe('inv_42');
      expect(r.dedupeId).toBe('btcpay:inv_42:InvoiceSettled');
    }
  });

  test('a redelivery of the same transition produces the same dedupe id', async () => {
    const event = {
      type: 'InvoiceProcessing',
      invoiceId: 'inv_7',
      metadata: { orderId: 'o7' },
    };
    const a = await signed({ ...event, isRedelivery: false });
    const b = await signed({ ...event, isRedelivery: true });
    const ra = await btcpay.verifyAndParse({ ...a, rawBody: a.body, webhookSecret: SECRET });
    const rb = await btcpay.verifyAndParse({ ...b, rawBody: b.body, webhookSecret: SECRET });
    expect(ra.ok && rb.ok && ra.dedupeId === rb.dedupeId).toBe(true);
  });

  test('invoice event types map correctly', async () => {
    const cases: [string, string][] = [
      ['InvoiceSettled', 'paid'],
      ['InvoiceProcessing', 'confirming'],
      ['InvoiceReceivedPayment', 'confirming'],
      ['InvoicePaymentSettled', 'confirming'],
      ['InvoiceCreated', 'pending'],
      ['InvoiceExpired', 'expired'],
      ['InvoiceInvalid', 'failed'],
    ];
    for (const [type, expected] of cases) {
      const { body, signature } = await signed({ type, invoiceId: 'i', metadata: {} });
      const r = await btcpay.verifyAndParse({ rawBody: body, signature, webhookSecret: SECRET });
      expect(r.ok && r.status).toBe(expected);
    }
  });

  test('a non-invoice store event parses with no orderRef (acked, no grant)', async () => {
    const { body, signature } = await signed({ type: 'PayoutCreated', payoutId: 'p1' });
    const r = await btcpay.verifyAndParse({ rawBody: body, signature, webhookSecret: SECRET });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.orderRef).toBeNull();
      expect(r.status).toBe('pending');
    }
  });

  test('a valid signature over unparseable JSON fails closed', async () => {
    const body = 'not-json{';
    const sig = await hmacSha256Hex(SECRET, body);
    const r = await btcpay.verifyAndParse({
      rawBody: body,
      signature: `sha256=${sig}`,
      webhookSecret: SECRET,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/json/i);
  });

  test('the persisted summary allowlists only non-PII fields', async () => {
    const { body, signature } = await signed({
      type: 'InvoiceSettled',
      invoiceId: 'inv_9',
      storeId: 'store_1',
      metadata: { orderId: 'o9', buyerEmail: 'leak@example.org' },
      deliveryId: 'd1',
    });
    const r = await btcpay.verifyAndParse({ rawBody: body, signature, webhookSecret: SECRET });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Object.keys(r.summary).sort()).toEqual(['invoice_id', 'order_id', 'store_id', 'type']);
      expect(JSON.stringify(r.summary)).not.toContain('leak@example.org');
    }
  });
});

describe('btcpay.createCheckout', () => {
  const cfg = { apiUrl: 'https://pay.example.org', storeId: 'store_1', apiKey: 'token-abc' };
  const params = {
    orderRef: 'order-1',
    amountCents: 1500,
    currency: 'usd',
    description: 'FreeSocks Membership — 3 months',
    ipnUrl: 'https://x/ipn',
    successUrl: 'https://x/ok',
    cancelUrl: 'https://x/no',
  };

  test('posts a Greenfield invoice and returns the checkout link + id', async () => {
    let captured: { url: string; init?: RequestInit } | null = null;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL, init?: RequestInit) => {
        captured = { url: String(url), init };
        return res({ id: 'inv_123', checkoutLink: 'https://pay.example.org/i/inv_123' });
      }),
    );
    const out = await btcpay.createCheckout(cfg, params);
    expect(out).toEqual({
      redirectUrl: 'https://pay.example.org/i/inv_123',
      processorRef: 'inv_123',
    });
    expect(captured!.url).toBe('https://pay.example.org/api/v1/stores/store_1/invoices');
    const headers = captured!.init!.headers as Record<string, string>;
    expect(headers.authorization).toBe('token token-abc');
    const body = JSON.parse(String(captured!.init!.body));
    expect(body.amount).toBe('15.00'); // cents → decimal string
    expect(body.currency).toBe('USD'); // uppercased
    expect(body.metadata.orderId).toBe('order-1'); // echoed back on webhooks
    expect(body.checkout.redirectURL).toBe(params.successUrl);
  });

  test('throws when BTCPay returns a non-OK status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => res({ message: 'nope' }, { ok: false, status: 403 })),
    );
    await expect(btcpay.createCheckout(cfg, params)).rejects.toThrow(/403|btcpay/i);
  });

  test('throws when the invoice response is missing id/checkoutLink', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => res({ id: 'inv_x' })),
    ); // no checkoutLink
    await expect(btcpay.createCheckout(cfg, params)).rejects.toThrow(/schema mismatch/i);
  });
});

describe('nowpayments.mapStatus', () => {
  test('partially_paid stays non-terminal (confirming) and never grants', () => {
    expect(nowpayments.mapStatus('partially_paid')).toBe('confirming');
  });

  test('the full status map: only finished pays; unknowns stay pending', () => {
    expect(nowpayments.mapStatus('finished')).toBe('paid');
    expect(nowpayments.mapStatus('waiting')).toBe('pending');
    expect(nowpayments.mapStatus('confirming')).toBe('confirming');
    expect(nowpayments.mapStatus('refunded')).toBe('failed');
    expect(nowpayments.mapStatus('expired')).toBe('expired');
    expect(nowpayments.mapStatus('some-new-status')).toBe('pending');
  });
});

describe('parsed-event grant cross-check fields', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('stripe: session events carry the session id + amount_total + currency', async () => {
    const secret = 'whsec_test';
    const body = JSON.stringify({
      id: 'evt_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_1',
          client_reference_id: 'order-1',
          payment_status: 'paid',
          amount_total: 1400,
          currency: 'usd',
        },
      },
    });
    const t = Math.floor(Date.now() / 1000);
    const sig = `t=${t},v1=${await hmacSha256Hex(secret, `${t}.${body}`)}`;
    const out = await stripe.verifyAndParse({ rawBody: body, signature: sig, secret });
    expect(out).toMatchObject({
      ok: true,
      status: 'paid',
      checkoutRef: 'cs_test_1',
      amountMinor: 1400,
      amountCurrency: 'USD',
    });
  });

  test('paypal: a capture-completed event maps amount + the related order id', async () => {
    const event = {
      id: 'WH-1',
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      resource: {
        id: 'cap_1',
        custom_id: 'order-1',
        amount: { currency_code: 'USD', value: '14.00' },
        supplementary_data: { related_ids: { order_id: 'pp_order_1' } },
      },
    };
    const fetchMock = vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.includes('/v1/oauth2/token')) return res({ access_token: 'tok' });
      if (url.includes('/verify-webhook-signature')) return res({ verification_status: 'SUCCESS' });
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    const out = await paypal.verifyAndParse({
      rawBody: JSON.stringify(event),
      headers: {},
      cfg: {
        clientId: 'id',
        secret: 's',
        apiBase: 'https://api.test',
        webhookId: 'wh',
      },
    });
    expect(out).toMatchObject({
      ok: true,
      status: 'paid',
      orderRef: 'order-1',
      checkoutRef: 'pp_order_1',
      amountMinor: 1400,
      amountCurrency: 'USD',
    });
  });

  test('paypal: refund/reversal events map to failed (the refund_seen signal)', async () => {
    const fetchMock = vi.fn(async (input: string | URL) => {
      const url = String(input);
      if (url.includes('/v1/oauth2/token')) return res({ access_token: 'tok' });
      if (url.includes('/verify-webhook-signature')) return res({ verification_status: 'SUCCESS' });
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    for (const event_type of ['PAYMENT.CAPTURE.REFUNDED', 'PAYMENT.CAPTURE.REVERSED']) {
      const out = await paypal.verifyAndParse({
        rawBody: JSON.stringify({
          id: 'WH-2',
          event_type,
          resource: { id: 'refund_1', custom_id: 'order-1' },
        }),
        headers: {},
        cfg: { clientId: 'id', secret: 's', apiBase: 'https://api.test', webhookId: 'wh' },
      });
      expect(out).toMatchObject({ ok: true, status: 'failed', orderRef: 'order-1' });
    }
  });

  test('btcpay: the settle event binds its own invoice id as checkoutRef', async () => {
    const secret = 'btcpay-secret';
    const body = JSON.stringify({
      type: 'InvoiceSettled',
      invoiceId: 'inv_1',
      storeId: 'store_1',
      metadata: { orderId: 'order-1' },
    });
    const sig = `sha256=${await hmacSha256Hex(secret, body)}`;
    const out = await btcpay.verifyAndParse({
      rawBody: body,
      signature: sig,
      webhookSecret: secret,
    });
    expect(out).toMatchObject({
      ok: true,
      status: 'paid',
      orderRef: 'order-1',
      checkoutRef: 'inv_1',
    });
  });
});
