import { z } from 'zod';
import { SubscriptionFormat, TierSlug } from './common';
import { BackendId } from './admin';

export const SubscriptionRequest = z.object({
  turnstileToken: z.string().min(1).optional(),
  format: SubscriptionFormat.optional(),
  honeypot: z.string().max(0).optional(),
  /**
   * Optional backend preference for free-tier issuance. Honored only when
   * admins have set `subscription.user_choice_enabled = true` AND the
   * requested backend is itself enabled in app settings. Otherwise the
   * server falls back to `subscription.default_backend`.
   */
  backend: BackendId.optional(),
});
export type SubscriptionRequest = z.infer<typeof SubscriptionRequest>;

export const SubscriptionMirror = z.object({
  provider: z.string(),
  publicUrl: z.string().url(),
  latencyMs: z.number().int().nonnegative().optional(),
});
export type SubscriptionMirror = z.infer<typeof SubscriptionMirror>;

export const SubscriptionResponse = z.object({
  subscriptionUrl: z.string().url(),
  fallbackUrl: z.string().url().optional(),
  mirrors: z.array(SubscriptionMirror).default([]),
  tier: z.object({
    slug: TierSlug,
    name: z.string(),
    monthlyTrafficGb: z.number(),
    deviceLimit: z.number(),
  }),
  /**
   * Backend that actually issued the key. Echoed back so the SPA can label
   * the result ("Subscription URL" vs "Access key") and pick the right
   * filename for the download button without re-querying app settings.
   */
  backend: BackendId,
  expiresAt: z.string().datetime().nullable(),
  trafficLimitBytes: z.number().int().nonnegative().nullable(),
  trafficUsedBytes: z.number().int().nonnegative(),
  isReissued: z.boolean(),
  banner: z.string().optional(),
  /**
   * One-time plaintext account number, present ONLY on a fresh issuance when
   * the account-id feature is enabled. Shown once in the SubscriptionHero
   * reveal panel and never returned again (we store only a hash). Absent on
   * the reissue path and when the feature is off.
   */
  accountId: z.string().optional(),
  /**
   * Whether an account number is associated with this result. False on the
   * reissue path (the original number is still valid but can't be re-shown),
   * letting the SPA skip the reveal panel without implying the user has none.
   */
  accountIdAvailable: z.boolean().optional(),
});
export type SubscriptionResponse = z.infer<typeof SubscriptionResponse>;

/**
 * Body for `POST /api/v1/auth/account-login`. Turnstile is required on every
 * attempt (same widget that gates free-tier issuance) to stop headless
 * brute-force. The accountId is normalized server-side (strip spaces/hyphens).
 */
export const AccountLoginRequest = z.object({
  accountId: z.string().min(1),
  turnstileToken: z.string().min(1),
});
export type AccountLoginRequest = z.infer<typeof AccountLoginRequest>;

/**
 * One-time reveal of a freshly minted/rotated account number (user- or
 * admin-initiated rotation). The plaintext is returned exactly once.
 */
export const AccountIdRevealResponse = z.object({
  accountId: z.string(),
});
export type AccountIdRevealResponse = z.infer<typeof AccountIdRevealResponse>;
