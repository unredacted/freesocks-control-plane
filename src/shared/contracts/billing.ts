import { z } from 'zod';

/**
 * Self-service membership purchase contracts (the declared shape of the
 * `/api/v1/billing/*` surface the SPA consumes). The server validates with
 * Convex `v.*`; these zod schemas are what `apiClient` parses responses against.
 *
 * Flow: POST /billing/checkout → { redirectUrl, orderRef }; the SPA full-page
 * navigates to the processor-hosted page, then returns to /account?order=<ref>
 * and polls GET /billing/order/<ref> until a terminal status.
 */

export const BillingProcessor = z.enum(['nowpayments', 'stripe', 'paypal']);
export type BillingProcessor = z.infer<typeof BillingProcessor>;

export const CheckoutRequest = z.object({
  processor: BillingProcessor,
  /** A duration offered in PublicConfig.billing.durations (validated server-side against the catalog). */
  months: z.number().int().positive(),
});
export type CheckoutRequest = z.infer<typeof CheckoutRequest>;

export const CheckoutResponse = z.object({
  /** The processor-hosted invoice/checkout page to full-page redirect to. */
  redirectUrl: z.string().url(),
  /** Our opaque order ref; echoed back as ?order=<ref> on return for polling. */
  orderRef: z.string().min(1),
});
export type CheckoutResponse = z.infer<typeof CheckoutResponse>;

export const BillingOrderStatus = z.enum(['pending', 'confirming', 'paid', 'failed', 'expired']);
export type BillingOrderStatus = z.infer<typeof BillingOrderStatus>;

export const OrderStatusResponse = z.object({
  status: BillingOrderStatus,
  /** The member's membership expiry once `paid` (ISO); null while pending/failed. */
  membershipExpiresAt: z.string().datetime().nullable(),
});
export type OrderStatusResponse = z.infer<typeof OrderStatusResponse>;
