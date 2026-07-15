/**
 * Shared types for the self-service payment processors. Each processor is a pure
 * HTTP module (mirroring convex/lib/backends/*): it builds a hosted-checkout
 * redirect and verifies + parses inbound webhooks. The billing domain module
 * (convex/billing.ts) constructs the per-processor config from env, dispatches,
 * and maps the parsed event onto applyMembership. Keeping these pure (config
 * injected, no Convex/env access here) makes them unit-testable with stubbed
 * fetch + signing.
 */

export type ProcessorId = 'nowpayments' | 'btcpay' | 'stripe' | 'paypal';

/** Order lifecycle — kept in sync with the billingOrderStatus union in schema.ts. */
export type OrderStatus = 'pending' | 'confirming' | 'paid' | 'failed' | 'expired';

/** Inputs to create a hosted checkout. Amount is in minor units (cents). */
export interface CheckoutParams {
  /** Our opaque order ref; passed to the processor as its order id and echoed back. */
  orderRef: string;
  amountCents: number;
  /** ISO 4217, e.g. 'USD'. */
  currency: string;
  /** Human description shown on the hosted page, e.g. "FreeSocks Membership — 3 months". */
  description: string;
  /** Absolute URL the processor POSTs webhooks/IPNs to. */
  ipnUrl: string;
  /** Absolute URL the payer returns to on success (the SPA /account?order=<ref>). */
  successUrl: string;
  /** Absolute URL the payer returns to on cancel. */
  cancelUrl: string;
}

export interface CheckoutResult {
  /** The processor-hosted page to full-page redirect the payer to. */
  redirectUrl: string;
  /** The processor's invoice/session/order id (stored for reconciliation). */
  processorRef: string;
}

/** A verified + parsed webhook event. */
export interface ParsedEvent {
  ok: true;
  /** Our opaque order ref echoed by the processor (order_id / client_reference_id / custom_id). */
  orderRef: string | null;
  /** The processor's payment/session id (for reconciliation + dedupe). */
  processorRef: string;
  /** Normalized lifecycle status. Only `paid` grants membership. */
  status: OrderStatus;
  /** Stable id for webhookEvents dedupe — distinct per (payment, status) transition. */
  dedupeId: string;
  /** REDACTED summary safe to persist (no payer PII — no email/name/address). */
  summary: Record<string, unknown>;
  /**
   * Defense-in-depth grant cross-checks (applyEvent refuses + audits on
   * mismatch, so a processor-side anomaly — e.g. an attacker-minted 1-cent
   * invoice carrying a victim's orderRef on a shared store/account — fails
   * safe instead of granting):
   *  - `checkoutRef`: the processor id MINTED AT CHECKOUT (invoice / session /
   *    order id) when this event carries one; compared against the order's
   *    stored `processorRef`. Null/absent when the event only carries a
   *    different id kind (e.g. a PayPal capture id).
   *  - `amountMinor` + `amountCurrency`: the amount the event reports for a
   *    PAID transition, in minor units + ISO currency. Null/absent when the
   *    rail's settle event has no amount (BTCPay — its checkoutRef binding is
   *    the guard there).
   */
  checkoutRef?: string | null;
  amountMinor?: number | null;
  amountCurrency?: string | null;
}

export interface VerifyFailure {
  ok: false;
  /** Internal reason (logged, never echoed to the unauthenticated webhook caller). */
  reason: string;
}

export type VerifyResult = ParsedEvent | VerifyFailure;
