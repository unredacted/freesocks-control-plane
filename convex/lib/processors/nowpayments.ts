/**
 * NOWPayments crypto rail (hosted invoice + IPN). Pure HTTP, callable from a
 * Convex action (V8: fetch + crypto.subtle, no Node). Mirrors the backend
 * adapters: a config object, a timeout, zod-validated responses, and errors that
 * NEVER capture the api key or full URL.
 *
 * Docs: invoice create = POST /v1/invoice (x-api-key) → { id, invoice_url }.
 * IPN auth = HMAC-SHA512 of the key-sorted JSON body with the IPN secret,
 * compared against the `x-nowpayments-sig` header.
 */
import { z } from 'zod';
import { hmacSha512Hex, timingSafeEqual } from '../crypto';
import type { CheckoutParams, CheckoutResult, OrderStatus, VerifyResult } from './types';

export interface NowPaymentsConfig {
  apiUrl: string;
  apiKey: string;
  timeoutMs?: number;
}

const InvoiceResponse = z.object({
  // NOWPayments returns the invoice id as a number; coerce to string.
  id: z.union([z.string(), z.number()]).transform(String),
  invoice_url: z.string().url(),
});

class NowPaymentsApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'NowPaymentsApiError';
    this.status = status;
  }
}

/** Map a NOWPayments payment_status to our normalized order status. */
export function mapStatus(s: string): OrderStatus {
  switch (s) {
    case 'finished':
      return 'paid';
    case 'confirming':
    case 'confirmed':
    case 'sending':
    case 'partially_paid':
      return 'confirming';
    case 'waiting':
      return 'pending';
    case 'failed':
    case 'refunded':
      return 'failed';
    case 'expired':
      return 'expired';
    default:
      // Unknown/new status: stay non-terminal so a later, recognized IPN can
      // still advance the order (and the stale-pending sweep eventually expires it).
      return 'pending';
  }
}

/** Recursively sort object keys (arrays keep order) — matches NOWPayments' ksort-then-encode. */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src).sort()) out[k] = sortKeysDeep(src[k]);
    return out;
  }
  return value;
}

/** Create a hosted invoice and return its redirect URL + invoice id. */
export async function createCheckout(
  cfg: NowPaymentsConfig,
  params: CheckoutParams,
): Promise<CheckoutResult> {
  const url = new URL('/v1/invoice', cfg.apiUrl).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'x-api-key': cfg.apiKey,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({
        price_amount: Number((params.amountCents / 100).toFixed(2)),
        price_currency: params.currency.toLowerCase(),
        order_id: params.orderRef,
        order_description: params.description,
        ipn_callback_url: params.ipnUrl,
        success_url: params.successUrl,
        cancel_url: params.cancelUrl,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Capture the error body (truncated) so the operator can see WHY — e.g.
      // "Invalid api key", a min-amount error, or "Invoice" not enabled on the
      // account. This is SERVER-LOG ONLY: createCheckout catches it and returns a
      // generic message to the member. NOWPayments error bodies describe the
      // rejected request fields, never the api key (that's a request header).
      const detail = (await res.text().catch(() => '')).slice(0, 300);
      throw new NowPaymentsApiError(
        `NOWPayments ${res.status} on /v1/invoice${detail ? `: ${detail}` : ''}`,
        res.status,
      );
    }
    const body: unknown = await res.json().catch(() => null);
    const parsed = InvoiceResponse.safeParse(body);
    if (!parsed.success) {
      throw new NowPaymentsApiError(
        `NOWPayments invoice schema mismatch: ${JSON.stringify(body).slice(0, 200)}`,
      );
    }
    return { redirectUrl: parsed.data.invoice_url, processorRef: parsed.data.id };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * PHP `json_encode` escaping applied on top of JSON.stringify: NOWPayments
 * signs its IPN from PHP, whose default flags escape `/` → `\/` and every
 * non-ASCII code unit → `\uXXXX`. JSON.stringify does neither, so an IPN
 * carrying non-ASCII (e.g. an em-dash in our own invoice description) or a
 * slash can produce a VALID signature over the PHP-canonical form that plain
 * JSON.stringify would reject. Both canonical forms of the SAME parsed payload
 * are accepted — dual-accept is safe: an attacker still needs a valid HMAC
 * over one deterministic canonicalization of the exact body.
 */
function phpEscapeJson(json: string): string {
  return json
    .replace(/\//g, '\\/')
    .replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * Verify an IPN's authenticity and parse it. The signature is HMAC-SHA512 of the
 * key-sorted JSON body (the EXACT bytes we received, re-serialized in sorted-key
 * order) using the IPN secret — checked against BOTH the JSON.stringify and the
 * PHP-escaped canonical forms (see phpEscapeJson). On success, the order is
 * looked up by `order_id` (our opaque ref). The persisted summary is REDACTED
 * (NOWPayments IPNs carry no payer PII, but we allowlist fields defensively).
 */
export async function verifyAndParse(args: {
  rawBody: string;
  signature: string | null;
  ipnSecret: string;
}): Promise<VerifyResult> {
  if (!args.signature) return { ok: false, reason: 'missing x-nowpayments-sig' };
  let payload: unknown;
  try {
    payload = JSON.parse(args.rawBody);
  } catch {
    return { ok: false, reason: 'invalid JSON body' };
  }
  if (!payload || typeof payload !== 'object') {
    return { ok: false, reason: 'IPN payload is not an object' };
  }
  const canonical = JSON.stringify(sortKeysDeep(payload));
  const expected = await hmacSha512Hex(args.ipnSecret, canonical);
  const expectedPhp =
    canonical === phpEscapeJson(canonical)
      ? expected
      : await hmacSha512Hex(args.ipnSecret, phpEscapeJson(canonical));
  const sig = args.signature.trim();
  if (!timingSafeEqual(expected, sig) && !timingSafeEqual(expectedPhp, sig)) {
    return { ok: false, reason: 'IPN signature mismatch' };
  }

  const p = payload as Record<string, unknown>;
  const rawStatus = typeof p.payment_status === 'string' ? p.payment_status : '';
  const orderRef = typeof p.order_id === 'string' && p.order_id ? p.order_id : null;
  const processorRef =
    p.payment_id != null ? String(p.payment_id) : p.invoice_id != null ? String(p.invoice_id) : '';
  let status = mapStatus(rawStatus);
  // Settle-tolerance guard: with partial-payment acceptance enabled on the
  // merchant account, NOWPayments can report `finished` for an invoice paid
  // only within a custom tolerance. Downgrade to `confirming` (never a grant)
  // and flag the underpayment for audit when the received amount is short —
  // OR when the amounts are absent/unparseable entirely (a `finished` we can't
  // verify fails safe, not open). Amounts may arrive as JSON strings on some
  // account configs, so coerce.
  const toAmount = (x: unknown): number | null => {
    const n = typeof x === 'number' ? x : typeof x === 'string' ? Number(x) : NaN;
    return Number.isFinite(n) ? n : null;
  };
  const actuallyPaid = toAmount(p.actually_paid);
  const payAmount = toAmount(p.pay_amount);
  const underpaid =
    status === 'paid' && (actuallyPaid == null || payAmount == null || actuallyPaid < payAmount);
  if (underpaid) status = 'confirming';
  return {
    ok: true,
    orderRef,
    processorRef,
    status,
    ...(underpaid ? { underpaid: true } : {}),
    // The invoice id minted at checkout (stored as the order's processorRef);
    // the grant path cross-checks it. Distinct from payment_id above.
    checkoutRef: p.invoice_id != null ? String(p.invoice_id) : null,
    // price_amount is the FIAT price we set on the invoice (not the crypto
    // amount), so it compares 1:1 against the order's cents.
    amountMinor: typeof p.price_amount === 'number' ? Math.round(p.price_amount * 100) : null,
    amountCurrency: typeof p.price_currency === 'string' ? p.price_currency.toUpperCase() : null,
    dedupeId: `nowpayments:${processorRef || orderRef || 'unknown'}:${rawStatus || 'unknown'}`,
    summary: {
      payment_status: rawStatus,
      payment_id: processorRef || null,
      order_id: orderRef,
      price_amount: typeof p.price_amount === 'number' ? p.price_amount : null,
      price_currency: typeof p.price_currency === 'string' ? p.price_currency : null,
      pay_currency: typeof p.pay_currency === 'string' ? p.pay_currency : null,
    },
  };
}
