import { z } from 'zod';

/**
 * Opt-in subscription-mirror contracts (the `/api/v1/mirror` surface). A member
 * who can't reach the normal subscription URL provisions one mirror at a time
 * (country-tiered, capped). The country code is used transiently to pick a nearby
 * host and is never stored.
 */

export const MirrorRequest = z.object({
  /**
   * ISO-3166-1 alpha-2 (prefilled from the CDN geo, user-overridable). A 2-letter
   * code targets that country; `null` forces a global provider (don't geo-detect);
   * omitted lets the server fall back to the CDN header.
   */
  countryCode: z.string().length(2).nullable().optional(),
});
export type MirrorRequest = z.infer<typeof MirrorRequest>;

export const MirrorRequestResponse = z.object({
  /** ok = a mirror was added; capped = at the per-user cap; exhausted = no untried
   *  provider left for this country; no_subscription = no active key; error = transient. */
  status: z.enum(['ok', 'capped', 'exhausted', 'no_subscription', 'error']),
  /** The mirror URL to add as an additional subscription (present only on `ok`). */
  publicUrl: z.string().url().optional(),
  provider: z.string().optional(),
  /** Mirrors the member may still add before hitting the per-user cap. */
  remaining: z.number().int().nonnegative(),
});
export type MirrorRequestResponse = z.infer<typeof MirrorRequestResponse>;

export const MirrorClearResponse = z.object({
  removed: z.number().int().nonnegative(),
});
export type MirrorClearResponse = z.infer<typeof MirrorClearResponse>;
