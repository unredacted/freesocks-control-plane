/**
 * Direct checkout (crypto rails set to `direct` in Admin -> Billing): the
 * payment details a payer needs, read server-side from the processor API at
 * checkout and shown on FreeSocks' own page, so a payer who can't reach the
 * processor's domain can still pay. Shared by the NOWPayments and BTCPay
 * adapters, the order schema and the order-status poll.
 *
 * Everything here is processor OUTPUT shown to a payer as "send your money
 * here", so it is validated strictly before it is stored: anything off fails
 * the checkout instead of showing a wrong address or amount.
 */
import { v, type Infer } from 'convex/values';

export const directMethodValidator = v.object({
  /** NOWPayments ticker (`usdttrc20`) or BTCPay payment method id (`BTC-LN`). */
  id: v.string(),
  /** Unit shown next to the amount, e.g. `USDT`, `BTC`. */
  unit: v.string(),
  /** Network label (operator text for NOWPayments; empty for BTCPay, whose id says it). */
  network: v.string(),
  /** Deposit address, or a BOLT11 invoice for Lightning. */
  address: v.string(),
  /** Exact amount to send, as the processor's own decimal string (never re-formatted). */
  amount: v.string(),
  /** Memo / destination tag the payment can't be matched without. */
  memo: v.optional(v.string()),
  /** What the QR encodes: the address, or a validated `bitcoin:` / `lightning:` link. */
  qr: v.string(),
});
export type DirectMethod = Infer<typeof directMethodValidator>;

export const directPaymentValidator = v.object({
  methods: v.array(directMethodValidator),
  /** When the processor stops accepting payment to these details (ms); absent = unknown. */
  expiresAt: v.optional(v.number()),
  /** The processor-hosted page for the SAME invoice, offered as a fallback. */
  hostedUrl: v.string(),
});
export type DirectPayment = Infer<typeof directPaymentValidator>;

/** The order statuses that still show the payment details (anything else wipes them). */
export function directPaymentLive(status: string): boolean {
  return status === 'pending' || status === 'confirming';
}

/**
 * A deposit address / memo / BOLT11: printable ASCII with no spaces, bounded.
 * Every real address format fits; anything else is not something to show a payer.
 */
export function cleanToken(raw: unknown, max = 1024): string | null {
  if (typeof raw !== 'string' && typeof raw !== 'number') return null;
  const s = String(raw).trim();
  if (s.length < 1 || s.length > max || !/^[\x21-\x7e]+$/.test(s)) return null;
  return s;
}

/**
 * A positive plain decimal string (`0.17070286`), at most 20 + 20 digits.
 * Numbers arrive as JSON numbers from some APIs; a number is accepted only when
 * its JS spelling is already plain decimal (no exponent), since re-formatting
 * an amount someone will copy into a wallet is exactly the bug to avoid.
 */
export function cleanAmount(raw: unknown): string | null {
  const s = typeof raw === 'number' ? String(raw) : typeof raw === 'string' ? raw.trim() : '';
  if (!/^\d{1,20}(\.\d{1,20})?$/.test(s)) return null;
  return Number(s) > 0 ? s : null;
}

const MAX_EXPIRY_MS = 30 * 86_400_000;

/**
 * A payment deadline from the processor: ISO string, or unix seconds / ms.
 * `undefined` = the processor gave none (no timer). `null` = it gave one that
 * is unparseable, already past, or absurdly far out (fails the checkout).
 */
export function cleanExpiry(raw: unknown, now: number): number | null | undefined {
  if (raw == null || raw === '') return undefined;
  let ms: number;
  if (typeof raw === 'number') ms = raw < 1e12 ? raw * 1000 : raw;
  else if (typeof raw === 'string') ms = Date.parse(raw);
  else return null;
  if (!Number.isFinite(ms) || ms <= now || ms > now + MAX_EXPIRY_MS) return null;
  return ms;
}

/** A BTCPay payment link we are willing to encode in a QR. */
export function cleanPaymentLink(raw: unknown): string | null {
  const s = cleanToken(raw, 2048);
  return s && /^(bitcoin|lightning):/i.test(s) ? s : null;
}

/** Thrown by the adapters when the direct step can't produce safe details. */
export class DirectPaymentError extends Error {
  /**
   * `below_minimum`: the processor refused the amount for this coin.
   * `memo_refused`: the coin needs a memo the operator hasn't allowed.
   * `unavailable`: anything else (API error, malformed or mismatched output).
   */
  kind: 'below_minimum' | 'memo_refused' | 'unavailable';
  constructor(kind: DirectPaymentError['kind'], message: string) {
    super(message);
    this.name = 'DirectPaymentError';
    this.kind = kind;
  }
}
