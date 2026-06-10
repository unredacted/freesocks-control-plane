import { z } from 'zod';

export const SubscriptionMirror = z.object({
  provider: z.string(),
  publicUrl: z.string().url(),
  latencyMs: z.number().int().nonnegative().optional(),
});
export type SubscriptionMirror = z.infer<typeof SubscriptionMirror>;

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
