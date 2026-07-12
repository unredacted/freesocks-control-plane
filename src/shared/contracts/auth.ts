import { z } from 'zod';

export const AuthMeResponse = z.object({
  authenticated: z.boolean(),
  member: z
    .object({
      // Slug is admin-controlled free text; never the narrower TierSlug enum
      // (a renamed/custom slug must not make zod reject a valid response).
      tier: z.object({ slug: z.string().min(1), name: z.string() }),
    })
    .optional(),
});
export type AuthMeResponse = z.infer<typeof AuthMeResponse>;

export const LoginRedirectQuery = z.object({
  returnTo: z.string().optional(),
});
export type LoginRedirectQuery = z.infer<typeof LoginRedirectQuery>;

export const AdminAuthStatus = z.object({
  hasAdmins: z.boolean(),
  bootstrapAvailable: z.boolean(),
  /**
   * Whether the caller currently has a valid admin cookie session. Used by
   * AdminEntry to skip the login form and redirect to the admin app when an
   * already-signed-in admin lands on `/admin` directly.
   */
  signedIn: z.boolean(),
});
export type AdminAuthStatus = z.infer<typeof AdminAuthStatus>;

export const PublicConfig = z.object({
  membersJoinUrl: z.string().url().optional(),
  membersAccountUrl: z.string().url().optional(),
  /**
   * Where the renew/upgrade callouts point (P1-13). `donateUrl` is the primary
   * CTA for lapsed/expiring members (FreeSocks is donation-funded); `contactUrl`
   * is the secondary "contact us" link (e.g. to redeem a membership code). Both
   * optional; the UI omits a missing one rather than rendering a dead link.
   */
  donateUrl: z.string().url().optional(),
  contactUrl: z.string().url().optional(),
  /**
   * W1: self-hosted Cap captcha. `apiEndpoint` is the same-origin path the widget
   * hits (e.g. `/cap`); the widget's data-cap-api-endpoint is
   * `${apiEndpoint}/${siteKey}/`. `siteKey` empty => captcha not configured (the
   * UI can fall back / the dev bypass applies server-side).
   */
  captcha: z.object({
    apiEndpoint: z.string(),
    siteKey: z.string(),
  }),
  environment: z.enum(['production', 'development', 'test']),
  /**
   * Public-safe tier limits so the marketing/comparison UI renders the actual
   * enforced numbers (straight from the DB) instead of hardcoded copies that
   * silently drift from the seed. Active tiers only, ordered by `priority`
   * ascending (free → patron), deduped by slug. Deliberately excludes every
   * sensitive field: no backend/squad identifiers.
   */
  tiers: z.array(
    z.object({
      // Free-form: admins may define custom tier slugs (the admin contract
      // allows any string), so this must not be the narrower TierSlug enum;
      // an out-of-enum slug must never 500 this public endpoint.
      slug: z.string(),
      name: z.string(),
      // Admin-editable marketing line (Admin → Tiers). Surfaced on the
      // comparison cards so tier copy is DB-driven, not hardcoded in the SPA.
      description: z.string().nullable(),
      monthlyTrafficGb: z.number().int(), // 0 = unlimited
      deviceLimit: z.number().int(),
    }),
  ),
  /** Free-account lifetime in days (the admin-editable `freetier.expiryDays`
   *  setting). Lets the signup flow state the real validity instead of a
   *  hardcoded number that drifts from the server's actual expiry. */
  freeTierDays: z.number().int(),
  /**
   * Public subset of AppSettings the SPA needs to render the backend chooser
   * on `/get-key` and pick the right labels everywhere else. This is the only
   * way anonymous users learn about the backend toggle state; the full
   * `/api/v1/admin/settings` endpoint is admin-only.
   *
   * `userChoiceEnabled` gates whether the chooser is rendered at all; when
   * false, the server picks `defaultBackend` and the SPA shouldn't tease the
   * user with an option they can't use.
   */
  backends: z.object({
    remnawaveEnabled: z.boolean(),
    outlineEnabled: z.boolean(),
    defaultBackend: z.enum(['remnawave', 'outline']),
    userChoiceEnabled: z.boolean(),
    labels: z.object({
      remnawave: z.string(),
      outline: z.string(),
    }),
  }),
  /**
   * Public billing catalog for the self-service membership upgrade. Prices and
   * durations are public; the SPA renders the upgrade UI only when `enabled` is
   * true and shows a payment method only when its `rails.*` flag is true.
   * `amountCents` is in `currency` (ISO 4217). No secrets here (processor API
   * keys / IPN secrets are server-side env only).
   */
  billing: z.object({
    enabled: z.boolean(),
    rails: z.object({
      nowpayments: z.boolean(),
      // Additive rail — default keeps a newer SPA parsing an older backend's config.
      btcpay: z.boolean().default(false),
      stripe: z.boolean(),
      paypal: z.boolean(),
    }),
    currency: z.string(),
    tierSlug: z.string(),
    durations: z.array(
      z.object({
        months: z.number().int(),
        amountCents: z.number().int(),
      }),
    ),
    /** Minimum term (months) the crypto rail accepts (per-coin minimums; XMR's
     * is high). The SPA disables shorter terms when crypto is the chosen method. */
    cryptoMinMonths: z.number().int(),
    /** Minimum term (months) the BTCPay rail accepts (default 1; Lightning has
     * no per-coin floor — this is an operator-tunable hygiene knob). */
    btcpayMinMonths: z.number().int().default(1),
    /**
     * Optional donations. Public so the picker can render preset amounts and the
     * "adds ~N GB to every free user" copy. `currentBonusGb` is the bonus live on
     * every free user's monthly cap right now (this calendar month's pool).
     * Defaulted so a newer SPA still parses an older backend's config.
     */
    donation: z
      .object({
        enabled: z.boolean(),
        suggestedAmountsCents: z.array(z.number().int()),
        minAmountCents: z.number().int(),
        bonusGbPerUsd: z.number(),
        monthlyBonusCapGb: z.number(),
        currentBonusGb: z.number(),
        /** Active free users the shared bonus reaches (daily-reconciled count). */
        freeUsersHelped: z.number().default(0),
        /** Per-month bonus-GB ledger (last 12) for the impact graphs. GB only —
         *  dollar amounts are never projected publicly. */
        history: z.array(z.object({ month: z.string(), bonusGb: z.number() })).default([]),
      })
      .default({
        enabled: false,
        suggestedAmountsCents: [],
        minAmountCents: 0,
        bonusGbPerUsd: 0,
        monthlyBonusCapGb: 0,
        currentBonusGb: 0,
        freeUsersHelped: 0,
        history: [],
      }),
  }),
  /** Whether the opt-in "trouble connecting? try a mirror" affordance is available
   *  (≥1 active mirror provider). The SPA hides it entirely when false. */
  mirrorsEnabled: z.boolean().optional(),
  /** Device-limit (HWID) enforcement master switch. When false, device limits
   *  are off deployment-wide and the connect UI hides app-compatibility gating.
   *  Optional/defaulted for forward-compat. */
  devices: z
    .object({ enforcementEnabled: z.boolean() })
    .optional()
    .default({ enforcementEnabled: false }),
  /** Admin-selected brand theme (W3-3): a preset id + optional hue override,
   *  applied client-side over the baked default. Optional for forward-compat. */
  theme: z
    .object({
      preset: z.string(),
      hue: z.number().nullable(),
    })
    .optional(),
  /** Admin-configured E2EE verification channels (non-secret): the off-CDN
   *  channels the "Verify connection" panel shows (empty string = unset, omitted)
   *  and whether to surface the E2EE badge/panel at all. Optional for forward-compat. */
  verification: z
    .object({
      showPanel: z.boolean(),
      releaseUrl: z.string(),
      onionAddress: z.string(),
      sourceUrl: z.string(),
      extensionUrl: z.string(),
    })
    .optional(),
  /** Admin-configured site chrome (non-secret): the announcement banner (a
   *  toggle + operator-typed text, rendered as escaped text — never HTML) and the
   *  footer "View source" repo link (a toggle + an https-only URL; '' = unset).
   *  Both default off/empty until set. Optional for forward-compat. */
  site: z
    .object({
      bannerEnabled: z.boolean(),
      bannerText: z.string(),
      repoEnabled: z.boolean(),
      repoUrl: z.string(),
      tosUrl: z.string(),
      privacyUrl: z.string(),
    })
    .optional(),
  /** Member-facing connection-mode catalog (the transport chooser): id +
   *  `deliveryStyle` (url vs rawConfig — drives delivery behavior) + admin copy
   *  overrides + whether it's the default + `available` (its backend placement
   *  pool is bound). `label`/`description` are null unless the admin set them —
   *  a non-null value overrides the SPA's translated copy verbatim (all
   *  locales); null keeps the i18n defaults. NEVER a squad UUID. Data-driven
   *  (string ids). Optional/defaulted for forward-compat. */
  connectionModes: z
    .array(
      z.object({
        id: z.string(),
        deliveryStyle: z.enum(['url', 'rawConfig']),
        label: z.string().nullable(),
        description: z.string().nullable().optional().default(null),
        isDefault: z.boolean(),
        available: z.boolean(),
      }),
    )
    .optional()
    .default([]),
  /** CMS-managed recommended-client catalog for the single "set up your app"
   *  section. Public-safe (no secrets). `schemeId` maps to a client-side deep-link
   *  import builder (null = manual / QR only). Defaulted for forward-compat. */
  clients: z
    .array(
      z.object({
        name: z.string(),
        platforms: z.array(z.string()),
        backends: z.array(z.enum(['remnawave', 'outline'])),
        homepageUrl: z.string(),
        schemeId: z.string().nullable(),
        hwid: z.boolean(),
        openSource: z.boolean().optional().default(false),
        license: z.string().optional(),
        sourceUrl: z.string().optional(),
      }),
    )
    .optional()
    .default([]),
});
export type PublicConfig = z.infer<typeof PublicConfig>;
