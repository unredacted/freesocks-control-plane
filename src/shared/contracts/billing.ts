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
  /** 'gift' buys `quantity` shareable codes instead of extending your own membership. Default 'self'. */
  kind: z.enum(['self', 'gift']).optional(),
  /** Number of codes for a gift order (1..50). Ignored for 'self'. */
  quantity: z.number().int().positive().max(50).optional(),
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
  /** 'self' extends the buyer's membership; 'gift' mints shareable codes. */
  kind: z.enum(['self', 'gift']).default('self'),
  /** Gift orders only: the freshly-minted codes, revealed ONCE on return (empty
   *  once acknowledged / for self orders). Plaintext — show, let the buyer save, ack. */
  giftCodes: z.array(z.string()).default([]),
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
  /** Minimum term (months) purchasable with the crypto rail (per-coin minimums). */
  cryptoMinMonths: z.number().int(),
});
export type BillingConfigView = z.infer<typeof BillingConfigView>;

/**
 * Processor credential status: which secrets are set (booleans, never values) +
 * the non-secret URLs. Returned to the admin UI so it can show "set / not set".
 */
export const ProcessorSecretStatus = z.object({
  publicBaseUrl: z.string(),
  nowpayments: z.object({ apiKey: z.boolean(), ipnSecret: z.boolean(), apiUrl: z.string() }),
  stripe: z.object({ apiKey: z.boolean(), webhookSecret: z.boolean() }),
  paypal: z.object({
    clientId: z.boolean(),
    secret: z.boolean(),
    webhookId: z.boolean(),
    apiBase: z.string(),
  }),
});
export type ProcessorSecretStatus = z.infer<typeof ProcessorSecretStatus>;

/**
 * The admin billing-config PATCH body: a partial of the config view, plus the
 * non-secret `publicBaseUrl` and write-only `secrets` (blank fields are left
 * unchanged server-side). Not wire-validated; this is the client-side shape.
 */
export interface BillingConfigPatch extends Partial<BillingConfigView> {
  publicBaseUrl?: string;
  secrets?: {
    nowpayments?: { apiKey?: string; ipnSecret?: string; apiUrl?: string };
    stripe?: { apiKey?: string; webhookSecret?: string };
    paypal?: { clientId?: string; secret?: string; webhookId?: string; apiBase?: string };
  };
}

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
  secretStatus: ProcessorSecretStatus,
  orders: z.array(AdminBillingOrder),
  nextCursor: z.string().nullable(),
});
export type AdminBillingOverview = z.infer<typeof AdminBillingOverview>;

export const AdminBillingConfigResponse = z.object({
  config: BillingConfigView,
  secretStatus: ProcessorSecretStatus,
});
export type AdminBillingConfigResponse = z.infer<typeof AdminBillingConfigResponse>;
