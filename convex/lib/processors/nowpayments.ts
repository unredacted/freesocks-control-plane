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
import { readBoundedBody } from '../readBoundedBody';
import { fetchProcessorApi } from './apiFetch';
import {
  cleanAmount,
  cleanExpiry,
  cleanToken,
  DirectPaymentError,
  type DirectPayment,
} from '../directPayment';
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

/**
 * Map a NOWPayments payment_status to our normalized order status.
 * `partially_paid` is paid-class: NOWPayments sends it once the (short) funds
 * have arrived, so it is as final as `finished`. verifyAndParse flags every
 * paid-class event whose received amount is short as `underpaid`, and
 * applyEvent grants it only within the underpayment tolerance.
 */
export function mapStatus(s: string): OrderStatus {
  switch (s) {
    case 'finished':
    case 'partially_paid':
      return 'paid';
    case 'confirming':
    case 'confirmed':
    case 'sending':
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

// The Convex V8 runtime supports raw JSON primitives. The TypeScript lib used
// by this project does not yet declare these two standard JSON methods.
const numericJson = JSON as JSON & {
  rawJSON(text: string): object;
  isRawJSON(value: unknown): boolean;
};

/** Recursively sort object keys (arrays keep order) — matches NOWPayments' ksort-then-encode. */
function sortKeysDeep(value: unknown, depth = 0): unknown {
  if (depth > 32 || (typeof value === 'number' && !Number.isFinite(value))) {
    throw new Error('unsupported IPN value');
  }
  if (Array.isArray(value)) return value.map((item) => sortKeysDeep(item, depth + 1));
  if (value && typeof value === 'object') {
    if (numericJson.isRawJSON(value)) return value;
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = Object.create(null);
    for (const k of Object.keys(src).sort()) out[k] = sortKeysDeep(src[k], depth + 1);
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
    const res = await fetchProcessorApi(url, {
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

export const MAX_IPN_BYTES = 64 * 1024;

const amountFields = new Set([
  'price_amount',
  'pay_amount',
  'actually_paid',
  'actually_paid_at_fiat',
  'outcome_amount',
]);

/** At most three encodings, each at most MAX_IPN_BYTES. Only build the next on mismatch. */
function* signaturePayloads(sorted: Record<string, unknown>, rawBody: string) {
  const encoder = new TextEncoder();
  const canonical = JSON.stringify(sorted);
  if (canonical.length > MAX_IPN_BYTES) return;
  const plain = encoder.encode(canonical);
  if (plain.byteLength > MAX_IPN_BYTES) return;
  yield plain;

  // PHP's escaped form is ASCII. Size it before expanding any string.
  let phpBytes = canonical.length;
  for (let i = 0; i < canonical.length; i++) {
    const code = canonical.charCodeAt(i);
    if (code === 47) phpBytes++;
    else if (code >= 127) phpBytes += 5;
    if (phpBytes > MAX_IPN_BYTES) return;
  }
  if (phpBytes !== canonical.length) yield encoder.encode(phpEscapeJson(canonical));

  // When the wire retains whole-number decimals, preserve their exact positions.
  // The first parse already enforced the depth limit before using a reviver.
  let floats = 0;
  let monetary: unknown;
  if (rawBody.includes('.0')) {
    const typed = JSON.parse(rawBody, (_key, value, context?: { source?: string }) => {
      if (
        typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        /^-?\d+\.0+$/.test(context?.source ?? '')
      ) {
        floats++;
        return numericJson.rawJSON(`${value}.0`);
      }
      return value;
    });
    if (floats) monetary = sortKeysDeep(typed);
  }
  if (!floats) {
    // Some callbacks have already lost the decimal spelling on the wire.
    const amounts = { ...sorted };
    for (const key of amountFields) {
      if (Number.isSafeInteger(amounts[key])) {
        amounts[key] = numericJson.rawJSON(`${amounts[key]}.0`);
        floats++;
      }
    }
    monetary = amounts;
  }
  if (floats && phpBytes + 2 * floats <= MAX_IPN_BYTES) {
    yield encoder.encode(phpEscapeJson(JSON.stringify(monetary)));
  }
}

/**
 * Fetch a payment's authoritative state straight from NOWPayments
 * (`GET /v1/payment/{id}`, x-api-key) — the postback path for an IPN whose
 * HMAC we couldn't reproduce (see verifyAndParse). Returns the raw payment
 * record (same field names as the IPN body) or null on ANY failure; never
 * captures the api key or full URL in errors.
 */
async function fetchPayment(
  cfg: NowPaymentsConfig,
  paymentId: string,
): Promise<Record<string, unknown> | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetchProcessorApi(
      new URL(`/v1/payment/${paymentId}`, cfg.apiUrl).toString(),
      {
        headers: { 'x-api-key': cfg.apiKey, accept: 'application/json' },
        signal: controller.signal,
      },
    );
    if (!res.ok) return null;
    const text = await readBoundedBody(res, MAX_IPN_BYTES);
    if (!text) return null;
    const body: unknown = JSON.parse(text);
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
    const rec = body as Record<string, unknown>;
    // Must actually be the payment we asked about, with a status to map.
    if (String(rec.payment_id ?? '') !== paymentId) return null;
    if (typeof rec.payment_status !== 'string') return null;
    return rec;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Verify the sorted JSON or PHP forms, then optionally consult the authoritative payment record. */
export async function verifyAndParse(args: {
  rawBody: string;
  signature: string | null;
  ipnSecret: string;
  postback?: { cfg: NowPaymentsConfig; reserve: () => Promise<void> };
}): Promise<VerifyResult> {
  const sig = args.signature;
  if (!sig || sig.length !== 128 || !/^[0-9a-f]+$/i.test(sig)) {
    return { ok: false, reason: 'invalid x-nowpayments-sig' };
  }
  const encoder = new TextEncoder();
  if (args.rawBody.length > MAX_IPN_BYTES || encoder.encode(args.rawBody).length > MAX_IPN_BYTES) {
    return { ok: false, reason: 'IPN payload too large' };
  }

  let p: Record<string, unknown>;
  let sorted: Record<string, unknown>;
  try {
    p = JSON.parse(args.rawBody);
    if (!p || typeof p !== 'object' || Array.isArray(p)) {
      return { ok: false, reason: 'IPN payload is not an object' };
    }
    sorted = sortKeysDeep(p) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: 'invalid IPN payload' };
  }

  const signature = Uint8Array.from(sig.match(/../g)!, (byte) => parseInt(byte, 16));
  let key: CryptoKey | undefined;
  let matched = false;
  for (const candidate of signaturePayloads(sorted, args.rawBody)) {
    key ??= await crypto.subtle.importKey(
      'raw',
      encoder.encode(args.ipnSecret),
      { name: 'HMAC', hash: 'SHA-512' },
      false,
      ['verify'],
    );
    if (await crypto.subtle.verify('HMAC', key, signature, candidate)) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    const id = p.payment_id;
    const paymentId = typeof id === 'string' || Number.isSafeInteger(id) ? String(id) : '';
    if (!args.postback || !/^\d{1,20}$/.test(paymentId)) {
      return { ok: false, reason: 'IPN signature mismatch' };
    }
    await args.postback.reserve();
    const viaApi = await fetchPayment(args.postback.cfg, paymentId);
    if (!viaApi) return { ok: false, reason: 'IPN signature mismatch' };
    // Loud but secret-free: a recurring postback means the IPN secret is wrong
    // OR the canonicalization drifted — worth the operator's attention either way.
    console.warn(
      `[billing] nowpayments IPN HMAC mismatch for payment ${paymentId}; verified via API postback`,
    );
    p = viaApi;
  }
  const rawStatus = typeof p.payment_status === 'string' ? p.payment_status : '';
  const orderRef = typeof p.order_id === 'string' && p.order_id ? p.order_id : null;
  const processorRef =
    p.payment_id != null ? String(p.payment_id) : p.invoice_id != null ? String(p.invoice_id) : '';
  const status = mapStatus(rawStatus);
  // Underpayment check: a paid-class event (`partially_paid`, or `finished`
  // under the merchant's "Payment covering" setting) whose received amount is
  // short is flagged with the fraction delivered, in the PAID coin
  // (actually_paid / pay_amount), so rate drift doesn't count against the
  // payer. applyEvent compares it to the tolerance. Absent/unparseable amounts
  // flag it with a null ratio, which never grants (fails safe, not open).
  // Amounts may arrive as JSON strings on some account configs, so coerce.
  const toAmount = (x: unknown): number | null => {
    const n = typeof x === 'number' ? x : typeof x === 'string' ? Number(x) : NaN;
    return Number.isFinite(n) ? n : null;
  };
  const actuallyPaid = toAmount(p.actually_paid);
  const payAmount = toAmount(p.pay_amount);
  const underpaid =
    status === 'paid' && (actuallyPaid == null || payAmount == null || actuallyPaid < payAmount);
  const paidRatio =
    underpaid && actuallyPaid != null && payAmount != null && payAmount > 0
      ? actuallyPaid / payAmount
      : null;
  return {
    ok: true,
    orderRef,
    processorRef,
    status,
    ...(underpaid ? { underpaid: true, paidRatio } : {}),
    // The invoice id minted at checkout (stored as the order's processorRef);
    // the grant path cross-checks it. Distinct from payment_id above.
    checkoutRef: p.invoice_id != null ? String(p.invoice_id) : null,
    // price_amount is the FIAT price we set on the invoice (not the crypto
    // amount), so it compares 1:1 against the order's cents. Coerced with the
    // same toAmount helper as the crypto amounts: on account configs that
    // serialize amounts as JSON strings, a strict typeof check would null this
    // out and silently disable the grant-time amount_mismatch cross-check.
    // (Review C-F3.)
    amountMinor: (() => {
      const n = toAmount(p.price_amount);
      return n != null ? Math.round(n * 100) : null;
    })(),
    amountCurrency: typeof p.price_currency === 'string' ? p.price_currency.toUpperCase() : null,
    dedupeId: `nowpayments:${processorRef || orderRef || 'unknown'}:${rawStatus || 'unknown'}`,
    summary: {
      payment_status: rawStatus,
      payment_id: processorRef || null,
      order_id: orderRef,
      price_amount: typeof p.price_amount === 'number' ? p.price_amount : null,
      price_currency: typeof p.price_currency === 'string' ? p.price_currency : null,
      pay_currency: typeof p.pay_currency === 'string' ? p.pay_currency : null,
      // Crypto amounts (no payer PII): what the invoice asked vs what arrived,
      // so an underpayment can be read back from the webhook log.
      pay_amount: payAmount,
      actually_paid: actuallyPaid,
    },
  };
}

/**
 * Live credential probe for the Admin → Billing "test connection" button.
 * `GET /v1/currencies` is the cheapest authenticated read — a 401/403 means a
 * bad key, a 200 means the rail can actually transact. Never captures the key.
 */
export async function testConnection(
  cfg: NowPaymentsConfig,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetchProcessorApi(new URL('/v1/currencies', cfg.apiUrl).toString(), {
      headers: { 'x-api-key': cfg.apiKey, accept: 'application/json' },
      signal: controller.signal,
    });
    if (res.ok) return { ok: true };
    return { ok: false, error: `NOWPayments returned HTTP ${res.status}` };
  } catch {
    return { ok: false, error: 'Connection failed' };
  } finally {
    clearTimeout(timer);
  }
}

// --- direct checkout (Admin -> Billing: checkout style "direct") -------------

const MAX_API_BYTES = 64 * 1024;

/** A coin as the direct step needs it (see DirectCoin in lib/billingConfig.ts). */
export interface DirectCoinSpec {
  ticker: string;
  label: string;
  network: string;
  allowMemo: boolean;
}

/**
 * Parse a NOWPayments JSON body, keeping `pay_amount` as the exact decimal
 * text the API sent (a JS number would re-spell 1e-7-sized amounts). Uses the
 * same JSON.parse source-text reviver the IPN verifier relies on.
 */
function parseKeepingAmount(text: string): unknown {
  return JSON.parse(text, (key, value, context?: { source?: string }) =>
    key === 'pay_amount' && typeof value === 'number' && context?.source ? context.source : value,
  );
}

/**
 * Direct checkout: create the payment ON the invoice createCheckout already
 * minted (`POST /v1/invoice-payment` { iid, pay_currency }), so every IPN for
 * it still carries `invoice_id` = the order's stored processorRef and the
 * whole verify + grant path (checkoutRef, price_amount, paidRatio) is
 * unchanged. Returns the validated details for the payer, or throws a
 * DirectPaymentError; never captures the api key or full URL.
 */
export async function createInvoicePayment(
  cfg: NowPaymentsConfig,
  args: {
    invoiceId: string;
    orderRef: string;
    coin: DirectCoinSpec;
    hostedUrl: string;
    now: number;
  },
): Promise<DirectPayment> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  let body: Record<string, unknown>;
  try {
    const res = await fetchProcessorApi(new URL('/v1/invoice-payment', cfg.apiUrl).toString(), {
      method: 'POST',
      headers: {
        'x-api-key': cfg.apiKey,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({ iid: args.invoiceId, pay_currency: args.coin.ticker }),
      signal: controller.signal,
    });
    const text = await readBoundedBody(res, MAX_API_BYTES);
    if (!res.ok) {
      // Server-log detail (truncated); the member gets a generic or a
      // "coin minimum" message. Error bodies describe the request, never the key.
      const detail = (text ?? '').slice(0, 300);
      if (/minimal|AMOUNT_MINIMAL/i.test(detail)) {
        throw new DirectPaymentError(
          'below_minimum',
          `NOWPayments ${res.status} on /v1/invoice-payment: ${detail}`,
        );
      }
      throw new DirectPaymentError(
        'unavailable',
        `NOWPayments ${res.status} on /v1/invoice-payment${detail ? `: ${detail}` : ''}`,
      );
    }
    const parsed: unknown = text ? parseKeepingAmount(text) : null;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new DirectPaymentError('unavailable', 'NOWPayments invoice-payment: not an object');
    }
    body = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof DirectPaymentError) throw err;
    throw new DirectPaymentError('unavailable', 'NOWPayments invoice-payment request failed');
  } finally {
    clearTimeout(timer);
  }

  const fail = (what: string): never => {
    throw new DirectPaymentError('unavailable', `NOWPayments invoice-payment: ${what}`);
  };
  if (body.payment_id == null || body.payment_id === '') fail('no payment_id');
  const payCurrency = typeof body.pay_currency === 'string' ? body.pay_currency.toLowerCase() : '';
  if (payCurrency !== args.coin.ticker) fail(`pay_currency ${payCurrency || 'missing'}`);
  // The payment must belong to OUR order (it inherits the invoice's order_id).
  if (body.order_id != null && body.order_id !== args.orderRef) fail('order_id mismatch');
  const address = cleanToken(body.pay_address, 256) ?? fail('bad pay_address');
  const amount = cleanAmount(body.pay_amount) ?? fail('bad pay_amount');
  let memo: string | undefined;
  if (body.payin_extra_id != null && body.payin_extra_id !== '') {
    memo = cleanToken(body.payin_extra_id, 128) ?? fail('bad payin_extra_id');
    if (!args.coin.allowMemo) {
      throw new DirectPaymentError(
        'memo_refused',
        `NOWPayments ${args.coin.ticker} needs a memo; allow it on the coin to offer it`,
      );
    }
  }
  const expiresAt = cleanExpiry(body.expiration_estimate_date ?? body.valid_until, args.now);
  if (expiresAt === null) return fail('bad expiry');
  return {
    methods: [
      {
        id: args.coin.ticker,
        unit: args.coin.label,
        network: args.coin.network,
        address,
        amount,
        ...(memo ? { memo } : {}),
        // The address only: wallet URI schemes differ per coin and network, so
        // the payer pastes the amount (and memo) rather than trusting a QR for them.
        qr: address,
      },
    ],
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    hostedUrl: args.hostedUrl,
  };
}

/** One row of the Admin -> Billing "Check coins" report. Nulls = could not tell. */
export interface CoinCheck {
  ticker: string;
  /** Switched on in the NOWPayments dashboard's coin settings. */
  enabledOnAccount: boolean | null;
  /** NOWPayments' own network code for the ticker, e.g. `trx`. */
  network: string | null;
  /** NOWPayments uses a memo / destination tag for this coin. */
  needsMemo: boolean | null;
  /** The coin's minimum payment in the fiat currency (indicative: no conversion leg). */
  minFiat: number | null;
}

async function getJson(cfg: NowPaymentsConfig, path: string): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 10000);
  try {
    const res = await fetchProcessorApi(new URL(path, cfg.apiUrl).toString(), {
      headers: { 'x-api-key': cfg.apiKey, accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const text = await readBoundedBody(res, 4 * 1024 * 1024);
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function listOf(x: unknown, ...keys: string[]): unknown[] | null {
  if (!x || typeof x !== 'object') return null;
  for (const k of keys) {
    const v = (x as Record<string, unknown>)[k];
    if (Array.isArray(v)) return v;
  }
  return null;
}

/** `/v1/full-currencies` keyed by lower-cased code (empty map when unreadable). */
async function currencyDetails(
  cfg: NowPaymentsConfig,
): Promise<Map<string, Record<string, unknown>>> {
  const details = new Map<string, Record<string, unknown>>();
  for (const c of listOf(await getJson(cfg, '/v1/full-currencies'), 'currencies') ?? []) {
    if (c && typeof c === 'object' && typeof (c as { code?: unknown }).code === 'string') {
      details.set((c as { code: string }).code.toLowerCase(), c as Record<string, unknown>);
    }
  }
  return details;
}

/**
 * Every coin switched on in the NOWPayments dashboard's coin settings
 * (`/v1/merchant/coins`), with its network code and memo use from
 * `/v1/full-currencies`. A coin without a readable network is left out: the
 * member must be told the network, and we won't guess it. Null when either
 * call fails (the caller keeps its last good list).
 */
export async function accountCoins(
  cfg: NowPaymentsConfig,
): Promise<Array<{ ticker: string; network: string; memo: boolean }> | null> {
  const [merchant, details] = await Promise.all([
    getJson(cfg, '/v1/merchant/coins'),
    currencyDetails(cfg),
  ]);
  const enabled = listOf(merchant, 'selectedCurrencies', 'currencies');
  if (!enabled || details.size === 0) return null;
  const out: Array<{ ticker: string; network: string; memo: boolean }> = [];
  const seen = new Set<string>();
  for (const raw of enabled) {
    const ticker = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
    if (!/^[a-z0-9]{2,20}$/.test(ticker) || seen.has(ticker)) continue;
    const d = details.get(ticker);
    if (!d || d.enable === false) continue;
    const network = typeof d.network === 'string' ? d.network.trim().toLowerCase() : '';
    if (!/^[a-z0-9-]{1,20}$/.test(network)) continue;
    seen.add(ticker);
    out.push({ ticker, network, memo: d.extra_id_exists === true });
  }
  return out;
}

/**
 * Read-only check of the direct-coin allowlist against the account: which
 * tickers are switched on (`/v1/merchant/coins`), their network and memo use
 * (`/v1/full-currencies`), and each one's minimum (`/v1/min-amount` with a fiat
 * equivalent). Creates nothing. Best effort: an unreadable answer is a null.
 */
export async function checkCoins(
  cfg: NowPaymentsConfig,
  tickers: string[],
  fiat: string,
): Promise<CoinCheck[]> {
  const [merchant, details] = await Promise.all([
    getJson(cfg, '/v1/merchant/coins'),
    currencyDetails(cfg),
  ]);
  const enabled = listOf(merchant, 'selectedCurrencies', 'currencies');
  const enabledSet = enabled
    ? new Set(enabled.filter((c): c is string => typeof c === 'string').map((c) => c.toLowerCase()))
    : null;
  return Promise.all(
    tickers.map(async (ticker): Promise<CoinCheck> => {
      const d = details.get(ticker);
      const min = await getJson(
        cfg,
        `/v1/min-amount?currency_from=${encodeURIComponent(ticker)}&currency_to=${encodeURIComponent(ticker)}&fiat_equivalent=${encodeURIComponent(fiat.toLowerCase())}`,
      );
      const fiatMin =
        min && typeof min === 'object'
          ? Number((min as Record<string, unknown>).fiat_equivalent)
          : NaN;
      return {
        ticker,
        enabledOnAccount: enabledSet ? enabledSet.has(ticker) : null,
        network: d && typeof d.network === 'string' ? d.network : null,
        needsMemo: d && typeof d.extra_id_exists === 'boolean' ? d.extra_id_exists : null,
        minFiat: Number.isFinite(fiatMin) ? fiatMin : null,
      };
    }),
  );
}
