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

export const BillingProcessor = z.enum(['nowpayments', 'btcpay', 'stripe', 'paypal']);
export type BillingProcessor = z.infer<typeof BillingProcessor>;

export const CheckoutRequest = z.object({
  processor: BillingProcessor,
  /** A duration offered in PublicConfig.billing.durations (validated server-side against
   *  the catalog). Optional — omitted for a standalone donation (kind 'donation'). */
  months: z.number().int().positive().optional(),
  /** 'gift' buys `quantity` shareable codes; 'donation' is a standalone donation (no
   *  membership); default 'self' extends your own membership. */
  kind: z.enum(['self', 'gift', 'donation']).optional(),
  /** Number of codes for a gift order (1..50). Ignored for 'self'/'donation'. */
  quantity: z.number().int().positive().max(50).optional(),
  /** Optional donation in cents — added on top of a membership (self/gift), or the
   *  entire charge for a standalone donation (kind 'donation'). */
  donationCents: z.number().int().nonnegative().optional(),
});
export type CheckoutRequest = z.infer<typeof CheckoutRequest>;

export const CheckoutResponse = z.object({
  /** The processor-hosted invoice/checkout page to full-page redirect to.
   *  https-only: it's built from admin-editable processor config, so the scheme
   *  is pinned here rather than trusted (an http:/javascript: value fails parse). */
  redirectUrl: z
    .string()
    .url()
    .refine((u) => u.startsWith('https://'), { message: 'redirect URL must be https' }),
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
  /** 'self' extends the buyer's membership; 'gift' mints shareable codes; 'donation' grants nothing. */
  kind: z.enum(['self', 'gift', 'donation']).default('self'),
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

/** Optional-donation config (add-on + standalone → free-user bandwidth pool). */
export const DonationConfigView = z.object({
  enabled: z.boolean(),
  suggestedAmountsCents: z.array(z.number().int()),
  minAmountCents: z.number().int(),
  bonusGbPerUsd: z.number(),
  monthlyBonusCapGb: z.number(),
});
export type DonationConfigView = z.infer<typeof DonationConfigView>;

const DONATION_VIEW_DEFAULT: DonationConfigView = {
  enabled: false,
  suggestedAmountsCents: [],
  minAmountCents: 0,
  bonusGbPerUsd: 0,
  monthlyBonusCapGb: 0,
};

/** The full (admin-editable) billing config — superset of PublicConfig.billing. */
export const BillingConfigView = z.object({
  enabled: z.boolean(),
  rails: z.object({
    nowpayments: z.boolean(),
    btcpay: z.boolean().default(false),
    stripe: z.boolean(),
    paypal: z.boolean(),
  }),
  currency: z.string(),
  tierSlug: z.string(),
  durations: z.array(BillingDuration),
  /** Minimum term (months) purchasable with the crypto rail (per-coin minimums). */
  cryptoMinMonths: z.number().int(),
  /** Minimum term (months) purchasable with the BTCPay rail (default 1). */
  btcpayMinMonths: z.number().int().default(1),
  /** Defaulted so a transient SPA-newer-than-backend deploy skew still parses. */
  donation: DonationConfigView.default(DONATION_VIEW_DEFAULT),
});
export type BillingConfigView = z.infer<typeof BillingConfigView>;

/**
 * Processor credential status: which secrets are set (booleans, never values) +
 * the non-secret URLs. Returned to the admin UI so it can show "set / not set".
 */
export const ProcessorSecretStatus = z.object({
  publicBaseUrl: z.string(),
  nowpayments: z.object({ apiKey: z.boolean(), ipnSecret: z.boolean(), apiUrl: z.string() }),
  btcpay: z
    .object({
      apiKey: z.boolean(),
      webhookSecret: z.boolean(),
      apiUrl: z.string(),
      storeId: z.string(),
    })
    .default({ apiKey: false, webhookSecret: false, apiUrl: '', storeId: '' }),
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
    btcpay?: { apiKey?: string; webhookSecret?: string; apiUrl?: string; storeId?: string };
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
  /** The buyer's non-secret support id (FS-XXXX-XXXX), for the "who donated" column. */
  userHandle: z.string().nullable().default(null),
  status: BillingOrderStatus,
  amountCents: z.number().int(),
  /** The donation portion of amountCents (0 for a pure membership order). */
  donationCents: z.number().int().nonnegative().default(0),
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
  /** Webhook claims stuck 'failed' (grant threw; sender's retries exhausted =
   *  a paid-but-ungranted order). Optional/defaulted for rolling-deploy compat. */
  failedWebhooks: z
    .object({
      count: z.number().int(),
      recent: z.array(z.object({ eventId: z.string(), source: z.string(), at: z.string() })),
    })
    .optional()
    .default({ count: 0, recent: [] }),
  nextCursor: z.string().nullable(),
});
export type AdminBillingOverview = z.infer<typeof AdminBillingOverview>;

export const AdminBillingConfigResponse = z.object({
  config: BillingConfigView,
  secretStatus: ProcessorSecretStatus,
});
export type AdminBillingConfigResponse = z.infer<typeof AdminBillingConfigResponse>;

/** `POST /api/v1/admin/billing/test-connection`: a LIVE credential probe —
 *  proves the stored key actually authenticates (status-only error text,
 *  never secret material). */
export const BillingTestConnectionResponse = z.object({
  ok: z.boolean(),
  error: z.string().nullable(),
});
export type BillingTestConnectionResponse = z.infer<typeof BillingTestConnectionResponse>;
