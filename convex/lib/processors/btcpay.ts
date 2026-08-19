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
  // --- per-invoice checkout overrides ---------------------------------------
  // All three go under the Greenfield request's `checkout` object (NOT top level —
  // only `amount`/`currency`/`metadata` live there). They're on the CONFIG rather
  // than on `CheckoutParams` because that struct is shared by all four rails and
  // none of these translate to the hosted ones. Each is omitted from the request
  // when unset, so BTCPay's own default applies.
  //
  // DELIBERATELY ABSENT: `checkout.paymentTolerance`. Setting it above 0 makes
  // BTCPay settle a short payment as Settled + additionalStatus PaidPartial —
  // which `verifyAndParse` below downgrades to `confirming` and never grants. So
  // a tolerance would be inert: the payer's money arrives, the order stays
  // non-terminal, and the operator believes they configured otherwise. Supporting
  // it means comparing the ACTUAL shortfall against the tolerance before
  // downgrading, which needs the paid amount (a second read of
  // `/invoices/{id}/payment-methods`, summed across methods via each one's rate)
  // plus currency + rounding care. That loosens a grant guard, so it belongs in
  // its own change — not smuggled in as a config default.
  /**
   * How long the payer has to pay. BTCPay's default is 15 minutes — far too
   * short for someone who has to go acquire crypto first, which is the common
   * case in censored regions.
   */
  expirationMinutes?: number;
  /**
   * How long after expiry BTCPay keeps watching for a late payment. A payment
   * that lands after expiry with no monitoring window is a stuck payment the
   * payer already made.
   */
  monitoringMinutes?: number;
  /**
   * Which payment method is preselected on the checkout page, e.g. `BTC-LN`.
   * Only meaningful once the store offers more than Bitcoin: Checkout v2 shows
   * one unified BIP21 QR for on-chain + Lightning, but any non-Bitcoin chain
   * reintroduces a payer-facing coin selector, and this decides where it lands.
   */
  defaultPaymentMethod?: string;
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
        checkout: {
          redirectURL: params.successUrl,
          // Each override is omitted when unset so BTCPay's own default stands.
          ...(cfg.expirationMinutes !== undefined
            ? { expirationMinutes: cfg.expirationMinutes }
            : {}),
          ...(cfg.monitoringMinutes !== undefined
            ? { monitoringMinutes: cfg.monitoringMinutes }
            : {}),
          ...(cfg.defaultPaymentMethod ? { defaultPaymentMethod: cfg.defaultPaymentMethod } : {}),
        },
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
  // Hoisted so TS narrows `cfg` for the call below AND so `detailUnavailable`
  // keys off the same value rather than re-deriving the condition (a cast here
  // would start lying the moment either half changed).
  const settleCfg = type === 'InvoiceSettled' && invoiceId ? args.cfg : undefined;
  const detail = settleCfg ? await invoiceDetail(settleCfg, invoiceId) : null;
  const underpaid = detail?.paidPartial === true;
  // We asked for the settle detail and didn't get it, so this grant proceeds
  // with the amount + PaidPartial cross-checks disabled. Almost always an
  // API key missing `btcpay.store.canviewinvoices`. Surfaced so it can be
  // fixed rather than quietly under-collecting.
  const detailUnavailable = !!settleCfg && detail === null;
  const status = underpaid ? 'confirming' : mapEventType(type);
  return {
    ok: true,
    orderRef,
    processorRef: invoiceId,
    status,
    ...(underpaid ? { underpaid: true } : {}),
    ...(detailUnavailable ? { detailUnavailable: true } : {}),
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
 * Live credential probe (Admin → Billing). TWO reads, because the rail needs two
 * distinct permissions and a probe that only proves one is worse than none — it
 * reports green on a key whose settle-time read-back will 403, leaving grants
 * running without the amount + PaidPartial cross-checks:
 *
 *  1. `GET /api/v1/stores/{storeId}` — the API key and the store id
 *     (`btcpay.store.canviewstoresettings`).
 *  2. `GET /api/v1/stores/{storeId}/invoices?take=1` — the invoice read-back
 *     `verifyAndParse` depends on (`btcpay.store.canviewinvoices`).
 *
 * Never captures the key. A 403 on the second read is called out by name so the
 * operator knows exactly which permission to add.
 */
export async function testConnection(
  cfg: BtcpayConfig,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const store = `/api/v1/stores/${encodeURIComponent(cfg.storeId)}`;
  const headers = { authorization: `token ${cfg.apiKey}`, accept: 'application/json' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const storeRes = await fetch(`${base}${store}`, { headers, signal: controller.signal });
    if (!storeRes.ok) {
      return { ok: false, error: `BTCPay returned HTTP ${storeRes.status}` };
    }
    // The permission the grant path actually depends on. `take=1` keeps this a
    // cheap read on a store with a long invoice history.
    const invRes = await fetch(`${base}${store}/invoices?take=1`, {
      headers,
      signal: controller.signal,
    });
    if (invRes.status === 403 || invRes.status === 401) {
      return {
        ok: false,
        error:
          'API key cannot read invoices — add the btcpay.store.canviewinvoices permission. ' +
          'Without it a settled invoice grants without the amount and partial-payment checks.',
      };
    }
    if (!invRes.ok) {
      return { ok: false, error: `BTCPay returned HTTP ${invRes.status} on invoice read` };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: 'Connection failed' };
  } finally {
    clearTimeout(timer);
  }
}
