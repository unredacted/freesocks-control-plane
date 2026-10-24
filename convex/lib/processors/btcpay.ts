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
  /**
   * `checkout.paymentTolerance`: the percent short BTCPay still settles. Set to
   * the billing `underpaymentTolerancePct`, so BTCPay settles exactly the
   * payments FCP would grant (and does the confirmation waiting). The settle
   * path still measures the real shortfall from the invoice's payment methods
   * and applyEvent re-checks it against the CURRENT tolerance, so a store-level
   * default or a since-lowered setting can't grant more than FCP allows.
   */
  paymentTolerancePct?: number;
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
          ...(cfg.paymentTolerancePct !== undefined
            ? { paymentTolerance: cfg.paymentTolerancePct }
            : {}),
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
 * marks an invoice that holds payments but is still short; it is the fallback
 * underpayment signal when the paid amount itself can't be read (a payment
 * settled within `paymentTolerance` comes through as plain Settled, so only
 * invoicePaidRatio sees that one). Best-effort: any failure leaves the detail
 * null (the invoice-id binding remains the guard).
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

const InvoicePaymentMethods = z.array(
  z
    .object({
      // "The invoice amount, converted to this payment method's currency."
      amount: z.string(),
      // "The total amount paid by all payment methods to the invoice,
      // converted to this payment method's currency."
      totalPaid: z.string(),
      paymentMethodPaid: z.string().optional(),
    })
    .passthrough(),
);

/**
 * The fraction of the invoice the payer actually delivered (1 = exact, above 1
 * = overpaid), read from `GET …/invoices/{id}/payment-methods` (same
 * `canviewinvoices` permission as invoiceDetail). Every entry's `totalPaid`
 * already sums ALL methods in that entry's currency, so one entry answers it;
 * the one the payer used (largest `paymentMethodPaid`) avoids conversion
 * rounding. Measured in the paid asset, so rate drift since the invoice was
 * created doesn't count. Best-effort: null on any failure.
 */
async function invoicePaidRatio(cfg: BtcpayConfig, invoiceId: string): Promise<number | null> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const path = `/api/v1/stores/${encodeURIComponent(cfg.storeId)}/invoices/${encodeURIComponent(invoiceId)}/payment-methods`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetch(`${base}${path}`, {
      headers: { authorization: `token ${cfg.apiKey}`, accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const parsed = InvoicePaymentMethods.safeParse(await res.json().catch(() => null));
    if (!parsed.success) return null;
    let best: { paid: number; ratio: number } | null = null;
    for (const m of parsed.data) {
      const amount = Number.parseFloat(m.amount);
      const totalPaid = Number.parseFloat(m.totalPaid);
      if (!Number.isFinite(amount) || amount <= 0 || !Number.isFinite(totalPaid)) continue;
      const paid = Number.parseFloat(m.paymentMethodPaid ?? '0');
      const used = Number.isFinite(paid) ? paid : 0;
      if (!best || used > best.paid) best = { paid: used, ratio: totalPaid / amount };
    }
    return best ? best.ratio : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// A float-safe "short of the invoice": decimal-string division can land a hair
// under 1 on an exact payment.
const SHORT_EPSILON = 1e-9;

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
  // cross-check (API reads only on the granting transition, only when
  // configured). A settle that is short of the invoice (within the invoice's
  // paymentTolerance, a store default, or marked settled by hand) is flagged
  // `underpaid` with the fraction delivered; applyEvent grants it only within
  // the underpayment tolerance.
  // Hoisted so TS narrows `cfg` for the call below AND so `detailUnavailable`
  // keys off the same value rather than re-deriving the condition (a cast here
  // would start lying the moment either half changed).
  const settleCfg = type === 'InvoiceSettled' && invoiceId ? args.cfg : undefined;
  const detail = settleCfg ? await invoiceDetail(settleCfg, invoiceId) : null;
  // An invoice that expired holding a partial payment: the money arrived but
  // BTCPay never accepted it (and it may be unconfirmed), so it is always held
  // for the operator as `underpaid`, never granted, and never just `expired`.
  const expiredPartial = type === 'InvoiceExpired' && p.partiallyPaid === true;
  const ratioCfg = (settleCfg || expiredPartial) && invoiceId ? args.cfg : undefined;
  const measured = ratioCfg ? await invoicePaidRatio(ratioCfg, invoiceId) : null;
  // Short by the measured amount when it could be read; otherwise BTCPay's own
  // PaidPartial flag (ratio unknown, so it never grants).
  const short = measured != null ? measured < 1 - SHORT_EPSILON : detail?.paidPartial === true;
  const underpaid = expiredPartial || (type === 'InvoiceSettled' && short);
  const paidRatio = measured != null && measured < 1 - SHORT_EPSILON ? measured : null;
  // We asked for the settle detail and didn't get it, so this grant proceeds
  // with the amount + PaidPartial cross-checks disabled. Almost always an
  // API key missing `btcpay.store.canviewinvoices`. Surfaced so it can be
  // fixed rather than quietly under-collecting.
  const detailUnavailable = !!settleCfg && detail === null;
  const status = expiredPartial ? 'underpaid' : mapEventType(type);
  return {
    ok: true,
    orderRef,
    processorRef: invoiceId,
    status,
    ...(underpaid ? { underpaid: true, paidRatio } : {}),
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
 * Live credential probe (Admin → Billing). Checks BOTH permissions the rail
 * needs — and only those two — without creating anything:
 *
 *  1. `GET /stores/{storeId}/invoices?take=1` — validates the API URL, the key,
 *     the store id, and `btcpay.store.canviewinvoices` (the permission
 *     `verifyAndParse` needs for the amount + PaidPartial cross-checks) in one
 *     call. `take=1` keeps it cheap on a long invoice history.
 *  2. `POST /stores/{storeId}/invoices` with a DELIBERATELY UNBINDABLE body —
 *     validates `btcpay.store.cancreateinvoice` without minting an invoice.
 *
 * Why (2) looks strange: there is no side-effect-free way to read a key's own
 * permissions. `GET /api/v1/api-keys/current` needs
 * `btcpay.server.canmanageusers` — a SERVER-level permission far beyond
 * anything the control plane should hold — and archiving a throwaway invoice
 * needs `canmodifyinvoices`, a fourth permission. Both would mean over-granting
 * the key that lives on the public host, which is what
 * docs/btcpay-server-runbook.md §4 exists to prevent.
 *
 * So instead we exploit ordering: ASP.NET Core runs authorization BEFORE model
 * binding, so a request whose body cannot bind still gets permission-checked
 * first. A key without the permission answers 403; a key with it answers 400
 * (the body is rejected as intended) and no invoice is created. `amount` is a
 * decimal string in the Greenfield schema, so a non-numeric value fails binding
 * outright — note it must NOT be an empty/None body, because an amount-less
 * invoice is a VALID top-up invoice and would really be created.
 *
 * Only 403 is treated as failure here. Anything else passes: 400 proves the
 * permission, and on an unexpected status we FAIL OPEN deliberately, because a
 * missing create permission fails loudly and harmlessly at checkout (the member
 * sees an error, nothing is granted) whereas a false red would block a
 * correctly-configured operator from going live.
 *
 * Never captures the key.
 */
export async function testConnection(
  cfg: BtcpayConfig,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const base = cfg.apiUrl.replace(/\/$/, '');
  const invoices = `/api/v1/stores/${encodeURIComponent(cfg.storeId)}/invoices`;
  const headers = { authorization: `token ${cfg.apiKey}`, accept: 'application/json' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    // (1) Read: URL + key + store id + canviewinvoices.
    const readRes = await fetch(`${base}${invoices}?take=1`, {
      headers,
      signal: controller.signal,
    });
    if (!readRes.ok) {
      if (readRes.status === 401) {
        return { ok: false, error: 'BTCPay rejected the API key (HTTP 401)' };
      }
      // BTCPay answers 403 both for a key lacking the permission and for a key
      // scoped to a DIFFERENT store, so name both rather than guess wrong.
      if (readRes.status === 403) {
        return {
          ok: false,
          error:
            'BTCPay refused the invoice read (HTTP 403) — either the API key lacks ' +
            'btcpay.store.canviewinvoices, or it is not scoped to this store id. ' +
            'Without that permission a settled invoice grants without the amount and ' +
            'partial-payment checks.',
        };
      }
      if (readRes.status === 404) {
        return { ok: false, error: 'BTCPay store not found (HTTP 404) — check the store id' };
      }
      return { ok: false, error: `BTCPay returned HTTP ${readRes.status}` };
    }

    // (2) Create permission, without creating an invoice. See the header comment
    // for why the body is intentionally unbindable and why only 403 fails.
    const createRes = await fetch(`${base}${invoices}`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({ amount: 'not-a-number', currency: 'USD' }),
      signal: controller.signal,
    });
    if (createRes.status === 403) {
      return {
        ok: false,
        error:
          'API key can read invoices but not create them — add the ' +
          'btcpay.store.cancreateinvoice permission. Checkout would fail for every member.',
      };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: 'Connection failed' };
  } finally {
    clearTimeout(timer);
  }
}
