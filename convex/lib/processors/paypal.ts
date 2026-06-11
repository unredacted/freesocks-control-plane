/**
 * PayPal rail (Orders v2, hosted approval redirect). The heaviest adapter:
 *  - createCheckout: OAuth2 client-credentials token → create a CAPTURE order →
 *    return the buyer-approval link.
 *  - verifyAndParse: PayPal has no HMAC header; authenticity is an async API call
 *    (`/v1/notifications/verify-webhook-signature`) over the `paypal-*` request
 *    headers + the webhook id. PayPal also does NOT auto-capture a redirect order,
 *    so on `CHECKOUT.ORDER.APPROVED` we capture server-side here; success (or an
 *    already-captured order) maps to `paid`. `PAYMENT.CAPTURE.COMPLETED` also maps
 *    to `paid` (idempotent — the single-grant guard collapses the duplicate).
 *
 * Pure HTTP via `fetch` (no PayPal SDK → stays in the V8 isolate). Errors never
 * capture the secret. Operationally PayPal is the freeze-prone rail — enable last
 * and sweep the balance often (see docs/billing.md).
 */
import type { CheckoutParams, CheckoutResult, OrderStatus, VerifyResult } from './types';

export interface PayPalConfig {
  clientId: string;
  secret: string;
  apiBase: string; // https://api-m.paypal.com (live) or the sandbox host
  webhookId: string;
  timeoutMs?: number;
}

class PayPalApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'PayPalApiError';
    this.status = status;
  }
}

function timed(timeoutMs = 10000): { signal: AbortSignal; done: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

async function accessToken(cfg: PayPalConfig): Promise<string> {
  const { signal, done } = timed(cfg.timeoutMs);
  try {
    const res = await fetch(`${cfg.apiBase}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${btoa(`${cfg.clientId}:${cfg.secret}`)}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
      signal,
    });
    if (!res.ok) throw new PayPalApiError(`PayPal ${res.status} on /v1/oauth2/token`, res.status);
    const json = (await res.json()) as { access_token?: string };
    if (!json.access_token) throw new PayPalApiError('PayPal token response missing access_token');
    return json.access_token;
  } finally {
    done();
  }
}

/** Create a CAPTURE order and return the buyer-approval link + the PayPal order id. */
export async function createCheckout(
  cfg: PayPalConfig,
  params: CheckoutParams,
): Promise<CheckoutResult> {
  const token = await accessToken(cfg);
  const { signal, done } = timed(cfg.timeoutMs);
  try {
    const res = await fetch(`${cfg.apiBase}/v2/checkout/orders`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [
          {
            custom_id: params.orderRef,
            description: params.description,
            amount: {
              currency_code: params.currency.toUpperCase(),
              value: (params.amountCents / 100).toFixed(2),
            },
          },
        ],
        application_context: {
          return_url: params.successUrl,
          cancel_url: params.cancelUrl,
          shipping_preference: 'NO_SHIPPING',
          user_action: 'PAY_NOW',
        },
      }),
      signal,
    });
    if (!res.ok)
      throw new PayPalApiError(`PayPal ${res.status} on /v2/checkout/orders`, res.status);
    const json = (await res.json()) as { id?: string; links?: { rel: string; href: string }[] };
    const approve = json.links?.find((l) => l.rel === 'approve' || l.rel === 'payer-action');
    if (!json.id || !approve?.href)
      throw new PayPalApiError('PayPal order missing id/approve link');
    return { redirectUrl: approve.href, processorRef: json.id };
  } finally {
    done();
  }
}

/** Capture an approved order. Treats an already-captured order as success (idempotent). */
async function captureOrder(cfg: PayPalConfig, token: string, orderId: string): Promise<boolean> {
  const { signal, done } = timed(cfg.timeoutMs);
  try {
    const res = await fetch(
      `${cfg.apiBase}/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`,
      {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        signal,
      },
    );
    if (res.ok) return true;
    // 422 ORDER_ALREADY_CAPTURED (re-delivered APPROVED) is success for our purpose.
    const body = await res.text().catch(() => '');
    if (res.status === 422 && body.includes('ORDER_ALREADY_CAPTURED')) return true;
    throw new PayPalApiError(`PayPal ${res.status} on capture`, res.status);
  } finally {
    done();
  }
}

function customIdFromResource(resource: Record<string, unknown> | undefined): string | null {
  if (!resource) return null;
  if (typeof resource.custom_id === 'string' && resource.custom_id) return resource.custom_id;
  // CHECKOUT.ORDER.* events nest custom_id under purchase_units[0].
  const pu = resource.purchase_units;
  if (Array.isArray(pu) && pu[0] && typeof pu[0] === 'object') {
    const cid = (pu[0] as Record<string, unknown>).custom_id;
    if (typeof cid === 'string' && cid) return cid;
  }
  return null;
}

/**
 * Verify a PayPal webhook via the verify-signature API, then parse + (for an
 * approved order) capture. `headers` carries the inbound `paypal-*` headers.
 */
export async function verifyAndParse(args: {
  rawBody: string;
  headers: Record<string, string>;
  cfg: PayPalConfig;
}): Promise<VerifyResult> {
  let event: { id?: string; event_type?: string; resource?: Record<string, unknown> };
  try {
    event = JSON.parse(args.rawBody);
  } catch {
    return { ok: false, reason: 'invalid JSON body' };
  }
  const h = (k: string) => args.headers[k] ?? args.headers[k.toLowerCase()] ?? '';
  const token = await accessToken(args.cfg);

  const { signal, done } = timed(args.cfg.timeoutMs);
  let verification: string;
  try {
    const res = await fetch(`${args.cfg.apiBase}/v1/notifications/verify-webhook-signature`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        auth_algo: h('paypal-auth-algo'),
        cert_url: h('paypal-cert-url'),
        transmission_id: h('paypal-transmission-id'),
        transmission_sig: h('paypal-transmission-sig'),
        transmission_time: h('paypal-transmission-time'),
        webhook_id: args.cfg.webhookId,
        webhook_event: event,
      }),
      signal,
    });
    if (!res.ok) return { ok: false, reason: `verify API ${res.status}` };
    verification =
      ((await res.json()) as { verification_status?: string }).verification_status ?? '';
  } finally {
    done();
  }
  if (verification !== 'SUCCESS') return { ok: false, reason: 'verification_status not SUCCESS' };

  const eventType = typeof event.event_type === 'string' ? event.event_type : '';
  const resource = event.resource;
  const orderRef = customIdFromResource(resource);
  const processorRef = typeof resource?.id === 'string' ? resource.id : (event.id ?? '');

  let status: OrderStatus = 'pending';
  if (eventType === 'CHECKOUT.ORDER.APPROVED') {
    // PayPal doesn't auto-capture a redirect order — capture it now.
    const captured = await captureOrder(args.cfg, token, processorRef).catch(() => false);
    status = captured ? 'paid' : 'confirming';
  } else if (eventType === 'PAYMENT.CAPTURE.COMPLETED') {
    status = 'paid';
  } else if (eventType === 'PAYMENT.CAPTURE.DENIED' || eventType === 'CHECKOUT.ORDER.DECLINED') {
    status = 'failed';
  }

  return {
    ok: true,
    orderRef,
    processorRef,
    status,
    dedupeId: `paypal:${event.id ?? processorRef}`,
    summary: { event_type: eventType, event_id: event.id ?? null, resource_id: processorRef },
  };
}
