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

// --- admin surface (the AdminBilling CMS page) ------------------------------

export const BillingDuration = z.object({
  months: z.number().int(),
  amountCents: z.number().int(),
});
export type BillingDuration = z.infer<typeof BillingDuration>;

/** The full (admin-editable) billing config — superset of PublicConfig.billing. */
export const BillingConfigView = z.object({
  enabled: z.boolean(),
  rails: z.object({
    nowpayments: z.boolean(),
    stripe: z.boolean(),
    paypal: z.boolean(),
  }),
  currency: z.string(),
  tierSlug: z.string(),
  durations: z.array(BillingDuration),
});
export type BillingConfigView = z.infer<typeof BillingConfigView>;

/** A partial config patch the admin PATCH accepts (validated/sanitized server-side). */
export const BillingConfigPatch = BillingConfigView.partial();
export type BillingConfigPatch = z.infer<typeof BillingConfigPatch>;

export const AdminBillingOrder = z.object({
  id: z.string(),
  processor: BillingProcessor,
  /** Only a prefix of the opaque ref (the full ref is the member's poll token). */
  refPrefix: z.string(),
  userId: z.string(),
  status: BillingOrderStatus,
  amountCents: z.number().int(),
  currency: z.string(),
  durationDays: z.number().int(),
  processorRef: z.string().nullable(),
  createdAt: z.string().datetime(),
  paidAt: z.string().datetime().nullable(),
});
export type AdminBillingOrder = z.infer<typeof AdminBillingOrder>;

/** GET /api/v1/admin/billing and PATCH /api/v1/admin/billing/config responses. */
export const AdminBillingOverview = z.object({
  config: BillingConfigView,
  orders: z.array(AdminBillingOrder),
  nextCursor: z.string().nullable(),
});
export type AdminBillingOverview = z.infer<typeof AdminBillingOverview>;

export const AdminBillingConfigResponse = z.object({
  config: BillingConfigView,
});
export type AdminBillingConfigResponse = z.infer<typeof AdminBillingConfigResponse>;
