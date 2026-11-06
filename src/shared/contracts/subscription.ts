import { z } from 'zod';
import { MIRROR_FORMATS } from '../mirrorFormats';

export const SubscriptionMirror = z.object({
  provider: z.string(),
  /** The mirror's `links` object; each other format sits beside it (src/shared/mirrorFormats.ts). */
  publicUrl: z.string().url(),
  /** The formats this mirror holds now (a mirror from before formats: `links` only, until its next upload). */
  formats: z.array(z.enum(MIRROR_FORMATS)).optional().default(['links']),
  latencyMs: z.number().int().nonnegative().optional(),
});
export type SubscriptionMirror = z.infer<typeof SubscriptionMirror>;

/**
 * Body for `POST /api/v1/auth/account-login`. A captcha (self-hosted Cap) is
 * required on every attempt (same widget that gates free-tier issuance) to stop
 * headless brute-force. The accountId is normalized server-side (strip spaces).
 */
export const AccountLoginRequest = z.object({
  accountId: z.string().min(1),
  captchaToken: z.string().min(1),
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
