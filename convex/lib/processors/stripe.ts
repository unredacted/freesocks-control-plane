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
    default:
      return 'pending'; // an event we don't act on (acked, no grant)
  }
}

/**
 * Verify a Stripe webhook (`Stripe-Signature`) and parse it. The signed payload
 * is `${t}.${rawBody}`; we recompute HMAC-SHA256 and timing-safe compare against
 * the header's v1 scheme(s), plus a 5-minute timestamp tolerance (replay guard).
 * The order is looked up by `client_reference_id` (our opaque ref).
 */
export async function verifyAndParse(args: {
  rawBody: string;
  signature: string | null;
  secret: string;
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
  const orderRef =
    typeof obj.client_reference_id === 'string' && obj.client_reference_id
      ? obj.client_reference_id
      : null;
  const processorRef = typeof obj.id === 'string' ? obj.id : (event.id ?? '');
  const paymentStatus = typeof obj.payment_status === 'string' ? obj.payment_status : undefined;
  return {
    ok: true,
    orderRef,
    processorRef,
    status: mapEvent(type, paymentStatus),
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
