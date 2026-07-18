/**
 * Stripe card rail: hosted Checkout Session (redirect) + webhook verification.
 * Pure HTTP via `fetch` + `crypto.subtle` — NO Stripe SDK, so it stays in the V8
 * action isolate and adds no dependency. One-time payments only (no
 * subscriptions in v1). Errors never capture the secret key.
 *
 * Docs: create = POST /v1/checkout/sessions (form-encoded, Bearer key) →
 * { id, url }. Webhook auth = the `Stripe-Signature` header (`t=…,v1=…`), where
 * v1 = HMAC-SHA256(secret, `${t}.${rawBody}`).
 */
import { hmacSha256Hex, timingSafeEqual } from '../crypto';
import type { CheckoutParams, CheckoutResult, OrderStatus, VerifyResult } from './types';

export interface StripeConfig {
  apiKey: string;
  apiBase?: string; // defaults to https://api.stripe.com
  timeoutMs?: number;
}

const DEFAULT_BASE = 'https://api.stripe.com';
const SIG_TOLERANCE_SEC = 5 * 60; // reject signatures older than 5 min (replay guard)

class StripeApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'StripeApiError';
    this.status = status;
  }
}

/** Create a hosted Checkout Session and return its redirect URL + session id. */
export async function createCheckout(
  cfg: StripeConfig,
  params: CheckoutParams,
): Promise<CheckoutResult> {
  const url = `${cfg.apiBase ?? DEFAULT_BASE}/v1/checkout/sessions`;
  // Stripe takes application/x-www-form-urlencoded with bracketed nested keys.
  const form = new URLSearchParams({
    mode: 'payment',
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    client_reference_id: params.orderRef,
    // Echo our ref on the PaymentIntent too: refund/dispute events carry the
    // CHARGE (no client_reference_id), so the verify path recovers the ref from
    // the PI's metadata (one API read, only for those event types).
    'payment_intent_data[metadata][fcp_ref]': params.orderRef,
    'line_items[0][quantity]': '1',
    'line_items[0][price_data][currency]': params.currency.toLowerCase(),
    'line_items[0][price_data][unit_amount]': String(params.amountCents),
    'line_items[0][price_data][product_data][name]': params.description,
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${cfg.apiKey}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
      signal: controller.signal,
    });
    if (!res.ok)
      throw new StripeApiError(`Stripe ${res.status} on /v1/checkout/sessions`, res.status);
    const json = (await res.json()) as { id?: string; url?: string };
    if (!json.id || !json.url) throw new StripeApiError('Stripe checkout session missing id/url');
    return { redirectUrl: json.url, processorRef: json.id };
  } finally {
    clearTimeout(timer);
  }
}

function parseSigHeader(header: string): { t: string | null; v1: string[] } {
  const v1: string[] = [];
  let t: string | null = null;
  for (const part of header.split(',')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === 't') t = val;
    else if (key === 'v1') v1.push(val);
  }
  return { t, v1 };
}

function mapEvent(type: string, paymentStatus: string | undefined): OrderStatus {
  switch (type) {
    case 'checkout.session.completed':
    case 'checkout.session.async_payment_succeeded':
      return paymentStatus === 'paid' ? 'paid' : 'confirming';
    case 'checkout.session.async_payment_failed':
      return 'failed';
    case 'checkout.session.expired':
      return 'expired';
    // Refund/chargeback class: never grants; when the order is ALREADY paid the
    // grant path audits it (billing.refund_seen) so the operator has a queue to
    // act on instead of a silently-live chargeback membership.
    case 'charge.refunded':
    case 'charge.dispute.created':
      return 'failed';
    default:
      return 'pending'; // an event we don't act on (acked, no grant)
  }
}

/** Recover our order ref from the PaymentIntent's metadata (set at checkout as
 *  `payment_intent_data[metadata][fcp_ref]`). Only called for refund/dispute
 *  events, whose charge object has no client_reference_id. Best-effort: any
 *  failure leaves the ref null (the event acks without applying, as before). */
async function orderRefFromPaymentIntent(
  apiKey: string,
  apiBase: string | undefined,
  paymentIntentId: string,
): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(
      `${apiBase ?? DEFAULT_BASE}/v1/payment_intents/${encodeURIComponent(paymentIntentId)}`,
      { headers: { authorization: `Bearer ${apiKey}` }, signal: controller.signal },
    );
    if (!res.ok) return null;
    const json = (await res.json()) as { metadata?: Record<string, unknown> };
    const ref = json.metadata?.fcp_ref;
    return typeof ref === 'string' && ref ? ref : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify a Stripe webhook (`Stripe-Signature`) and parse it. The signed payload
 * is `${t}.${rawBody}`; we recompute HMAC-SHA256 and timing-safe compare against
 * the header's v1 scheme(s), plus a 5-minute timestamp tolerance (replay guard).
 * The order is looked up by `client_reference_id` (our opaque ref); refund/
 * dispute events carry the charge instead, so their ref is recovered from the
 * PaymentIntent's `fcp_ref` metadata (needs `apiKey`; sessions created before
 * that metadata existed still ack unmapped).
 */
export async function verifyAndParse(args: {
  rawBody: string;
  signature: string | null;
  secret: string;
  apiKey?: string;
  apiBase?: string;
  nowSec?: number;
}): Promise<VerifyResult> {
  if (!args.signature) return { ok: false, reason: 'missing Stripe-Signature' };
  const { t, v1 } = parseSigHeader(args.signature);
  if (!t || v1.length === 0) return { ok: false, reason: 'malformed Stripe-Signature' };
  const now = args.nowSec ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(t)) > SIG_TOLERANCE_SEC) {
    return { ok: false, reason: 'signature timestamp outside tolerance' };
  }
  const expected = await hmacSha256Hex(args.secret, `${t}.${args.rawBody}`);
  if (!v1.some((sig) => timingSafeEqual(expected, sig))) {
    return { ok: false, reason: 'signature mismatch' };
  }

  let event: { id?: string; type?: string; data?: { object?: Record<string, unknown> } };
  try {
    event = JSON.parse(args.rawBody);
  } catch {
    return { ok: false, reason: 'invalid JSON body' };
  }
  const obj = event.data?.object ?? {};
  const type = typeof event.type === 'string' ? event.type : '';
  let orderRef =
    typeof obj.client_reference_id === 'string' && obj.client_reference_id
      ? obj.client_reference_id
      : null;
  // Refund/dispute events carry the charge: try its own metadata first, then
  // the PaymentIntent's (one API read, only when an apiKey is configured).
  if (!orderRef) {
    const md = obj.metadata;
    if (md && typeof md === 'object') {
      const ref = (md as Record<string, unknown>).fcp_ref;
      if (typeof ref === 'string' && ref) orderRef = ref;
    }
  }
  if (!orderRef && args.apiKey && typeof obj.payment_intent === 'string' && obj.payment_intent) {
    orderRef = await orderRefFromPaymentIntent(args.apiKey, args.apiBase, obj.payment_intent);
  }
  const processorRef = typeof obj.id === 'string' ? obj.id : (event.id ?? '');
  const paymentStatus = typeof obj.payment_status === 'string' ? obj.payment_status : undefined;
  // On checkout.session.* events the object IS the session minted at checkout,
  // so its id cross-checks against the order's stored processorRef, and
  // amount_total (minor units) against the order's cents. Charge-class events
  // carry `amount` (gross) instead — reported for the refund audit trail only,
  // never a grant cross-check (these events never grant).
  const isSessionEvent = type.startsWith('checkout.session.');
  const isChargeEvent = type.startsWith('charge.');
  return {
    ok: true,
    orderRef,
    processorRef,
    status: mapEvent(type, paymentStatus),
    checkoutRef: isSessionEvent && typeof obj.id === 'string' ? obj.id : null,
    amountMinor:
      isSessionEvent && typeof obj.amount_total === 'number'
        ? obj.amount_total
        : isChargeEvent && typeof obj.amount === 'number'
          ? obj.amount
          : null,
    amountCurrency:
      isSessionEvent && typeof obj.currency === 'string'
        ? obj.currency.toUpperCase()
        : isChargeEvent && typeof obj.currency === 'string'
          ? obj.currency.toUpperCase()
          : null,
    // Stripe guarantees idempotency by event id, so dedupe on it.
    dedupeId: `stripe:${event.id ?? processorRef}`,
    summary: {
      type,
      event_id: event.id ?? null,
      session_id: processorRef,
      payment_status: paymentStatus ?? null,
    },
  };
}
