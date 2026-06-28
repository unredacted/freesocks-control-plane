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
  }),
  /** Whether the opt-in "trouble connecting? try a mirror" affordance is available
   *  (≥1 active mirror provider). The SPA hides it entirely when false. */
  mirrorsEnabled: z.boolean().optional(),
  /** Admin-selected brand theme (W3-3): a preset id + optional hue override,
   *  applied client-side over the baked default. Optional for forward-compat. */
  theme: z
    .object({
      preset: z.string(),
      hue: z.number().nullable(),
    })
    .optional(),
});
export type PublicConfig = z.infer<typeof PublicConfig>;
