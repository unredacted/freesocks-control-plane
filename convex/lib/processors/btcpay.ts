/**
 * BTCPay Server rail (self-hosted Bitcoin: on-chain + Lightning). Pure HTTP via
 * the Greenfield API, callable from a Convex action (V8: fetch + crypto.subtle,
 * no Node). Mirrors the other adapters: injected config, a timeout,
 * zod-validated responses, and errors that NEVER capture the API key.
 *
 * Docs: invoice create = POST /api/v1/stores/{storeId}/invoices
 * (`Authorization: token <apiKey>`) → { id, checkoutLink }. Our opaque order ref
 * rides in `metadata.orderId` and is echoed back on every webhook event.
 * Webhook auth = the `BTCPay-Sig` header (`sha256=<hex>`), where <hex> =
 * HMAC-SHA256(webhookSecret, rawBody). Unlike the hosted rails there is no
 * per-invoice IPN URL: the operator registers ONE store webhook pointing at
 * /api/webhooks/btcpay (see docs/billing.md), so `params.ipnUrl`/`cancelUrl`
 * are unused here.
 */
import { z } from 'zod';
import { hmacSha256Hex, timingSafeEqual } from '../crypto';
import type { CheckoutParams, CheckoutResult, OrderStatus, VerifyResult } from './types';

export interface BtcpayConfig {
  /** The operator's own BTCPay Server origin, e.g. https://pay.example.org. */
  apiUrl: string;
  storeId: string;
  apiKey: string;
  timeoutMs?: number;
}

const InvoiceResponse = z.object({
  id: z.string(),
  checkoutLink: z.string().url(),
});

class BtcpayApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'BtcpayApiError';
    this.status = status;
  }
}

/**
 * Map a Greenfield webhook event type to our normalized order status. Only
 * `InvoiceSettled` grants; the intermediate payment events are all `confirming`
 * (the SPA keeps polling). Non-invoice store events (payouts, payment requests)
 * fall through to `pending` with no orderRef, which applyEvent no-ops on — so
 * they're acked instead of 400-spamming BTCPay's redelivery queue.
 */
export function mapEventType(type: string): OrderStatus {
  switch (type) {
    case 'InvoiceSettled':
      return 'paid';
    case 'InvoiceProcessing':
    case 'InvoiceReceivedPayment':
    case 'InvoicePaymentSettled':
      return 'confirming';
    case 'InvoiceCreated':
      return 'pending';
    case 'InvoiceExpired':
      return 'expired';
    case 'InvoiceInvalid':
      return 'failed';
    default:
      return 'pending';
  }
}

/** Create a hosted invoice and return its checkout link + invoice id. */
export async function createCheckout(
  cfg: BtcpayConfig,
  params: CheckoutParams,
): Promise<CheckoutResult> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const path = `/api/v1/stores/${encodeURIComponent(cfg.storeId)}/invoices`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: {
        authorization: `token ${cfg.apiKey}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({
        amount: (params.amountCents / 100).toFixed(2),
        currency: params.currency.toUpperCase(),
        metadata: { orderId: params.orderRef, itemDesc: params.description },
        checkout: { redirectURL: params.successUrl },
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Truncated error body for the server log so the operator can see WHY
      // (bad store id, missing permission, malformed amount). BTCPay error
      // bodies describe the rejected request, never the API key (a header).
      const detail = (await res.text().catch(() => '')).slice(0, 300);
      throw new BtcpayApiError(
        `BTCPay ${res.status} on store invoice create${detail ? `: ${detail}` : ''}`,
        res.status,
      );
    }
    const body: unknown = await res.json().catch(() => null);
    const parsed = InvoiceResponse.safeParse(body);
    if (!parsed.success) {
      throw new BtcpayApiError(
        `BTCPay invoice schema mismatch: ${JSON.stringify(body).slice(0, 200)}`,
      );
    }
    return { redirectUrl: parsed.data.checkoutLink, processorRef: parsed.data.id };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch the invoice's billed amount AND settle state for the grant cross-check
 * (BTCPay's settle event carries neither). `additionalStatus === 'PaidPartial'`
 * is the settle-tolerance case: a store configured to settle at e.g. 90% paid
 * fires `InvoiceSettled` on a PARTIAL payment — the billed `amount` alone
 * can't see this (it equals the order's cents by construction), so the settle
 * state must. Best-effort: any failure leaves the detail null (the invoice-id
 * binding remains the guard).
 */
const InvoiceDetail = z
  .object({
    amount: z.string(),
    currency: z.string(),
    additionalStatus: z.string().optional(),
  })
  .passthrough();

async function invoiceDetail(
  cfg: BtcpayConfig,
  invoiceId: string,
): Promise<{ amountMinor: number; currency: string; paidPartial: boolean } | null> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const path = `/api/v1/stores/${encodeURIComponent(cfg.storeId)}/invoices/${encodeURIComponent(invoiceId)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(`${base}${path}`, {
      headers: { authorization: `token ${cfg.apiKey}`, accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const parsed = InvoiceDetail.safeParse(await res.json().catch(() => null));
    if (!parsed.success) return null;
    const value = Number.parseFloat(parsed.data.amount);
    if (!Number.isFinite(value)) return null;
    return {
      amountMinor: Math.round(value * 100),
      currency: parsed.data.currency.toUpperCase(),
      paidPartial: parsed.data.additionalStatus === 'PaidPartial',
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify a store webhook's authenticity and parse it. The `BTCPay-Sig` header is
 * `sha256=<hex HMAC-SHA256 of the raw body>` with the store webhook's secret.
 * The order is looked up by `metadata.orderId` (our opaque ref, set at invoice
 * creation and included on every invoice event). The persisted summary is
 * REDACTED (invoice events carry no payer PII, but we allowlist defensively).
 * When `cfg` is supplied, an `InvoiceSettled` event additionally fetches the
 * invoice amount so applyEvent can cross-check it (settle-tolerance guard).
 */
export async function verifyAndParse(args: {
  rawBody: string;
  signature: string | null;
  webhookSecret: string;
  cfg?: BtcpayConfig;
}): Promise<VerifyResult> {
  if (!args.signature) return { ok: false, reason: 'missing BTCPay-Sig' };
  const sig = args.signature.trim();
  if (!sig.toLowerCase().startsWith('sha256=')) {
    return { ok: false, reason: 'malformed BTCPay-Sig' };
  }
  const expected = await hmacSha256Hex(args.webhookSecret, args.rawBody);
  if (!timingSafeEqual(expected, sig.slice('sha256='.length))) {
    return { ok: false, reason: 'webhook signature mismatch' };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(args.rawBody);
  } catch {
    return { ok: false, reason: 'invalid JSON body' };
  }
  if (!payload || typeof payload !== 'object') {
    return { ok: false, reason: 'webhook payload is not an object' };
  }
  const p = payload as Record<string, unknown>;
  const type = typeof p.type === 'string' ? p.type : '';
  const invoiceId = typeof p.invoiceId === 'string' ? p.invoiceId : '';
  const metadata = (p.metadata ?? {}) as Record<string, unknown>;
  const orderRef =
    typeof metadata.orderId === 'string' && metadata.orderId ? metadata.orderId : null;
  // The settle event carries no amount/settle state — fetch them for the grant
  // cross-check (one API read, only on the granting transition, only when
  // configured). A Settled-at-partial invoice (store settle-tolerance) is NOT a
  // grant: downgrade to confirming + flag the underpayment for audit.
  const detail =
    type === 'InvoiceSettled' && invoiceId && args.cfg
      ? await invoiceDetail(args.cfg, invoiceId)
      : null;
  const underpaid = detail?.paidPartial === true;
  const status = underpaid ? 'confirming' : mapEventType(type);
  return {
    ok: true,
    orderRef,
    processorRef: invoiceId,
    status,
    ...(underpaid ? { underpaid: true } : {}),
    // The settle event carries no amount, so the invoice-id binding IS the
    // grant guard: applyEvent refuses when it differs from the invoice id FCP
    // itself minted at checkout — an attacker-created invoice on a shared
    // store (different id, forged metadata.orderId) can never grant.
    checkoutRef: invoiceId || null,
    amountMinor: detail?.amountMinor ?? null,
    amountCurrency: detail?.currency ?? null,
    // Distinct per (invoice, event type) — a redelivery of the same transition
    // dedupes; a later transition for the same invoice is a fresh event.
    dedupeId: `btcpay:${invoiceId || orderRef || 'unknown'}:${type || 'unknown'}`,
    summary: {
      type,
      invoice_id: invoiceId || null,
      order_id: orderRef,
      store_id: typeof p.storeId === 'string' ? p.storeId : null,
    },
  };
}

/**
 * Live credential probe (Admin → Billing): `GET /api/v1/stores/{storeId}` —
 * validates the API key AND the store id in one read. Never captures the key.
 */
export async function testConnection(
  cfg: BtcpayConfig,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(`${base}/api/v1/stores/${encodeURIComponent(cfg.storeId)}`, {
      headers: { authorization: `token ${cfg.apiKey}`, accept: 'application/json' },
      signal: controller.signal,
    });
    if (res.ok) return { ok: true };
    return { ok: false, error: `BTCPay returned HTTP ${res.status}` };
  } catch {
    return { ok: false, error: 'Connection failed' };
  } finally {
    clearTimeout(timer);
  }
}
