import { z } from 'zod';
import { TierSlug, UserStatus } from './common';
import { SubscriptionMirror } from './subscription';
import { BackendId } from './admin';

export const AccountResponse = z.object({
  user: z.object({
    // Convex document id (string) since the P10 migration; was an integer PK.
    id: z.string(),
    status: UserStatus,
    tier: z.object({
      slug: TierSlug,
      name: z.string(),
      monthlyTrafficGb: z.number(),
      deviceLimit: z.number(),
      /**
       * Backend the tier itself is bound to. The SPA reads this on /account to
       * label "Your tier" with a "via Remnawave / via Outline" indicator, and
       * to decide whether to show the "Switch backend" CTA (it appears only
       * when a peer tier on the other backend exists for the same membership
       * type, server-side logic; client just gates on `peerBackend`).
       */
      backend: BackendId,
    }),
    membership: z
      .object({
        expiresAt: z.string().datetime().nullable(),
        isCurrent: z.boolean(),
      })
      .nullable(),
    createdAt: z.string().datetime(),
  }),
  subscription: z
    .object({
      url: z.string().url(),
      shortUuid: z.string(),
      mirrors: z.array(SubscriptionMirror),
      expiresAt: z.string().datetime().nullable(),
      trafficLimitBytes: z.number().int().nonnegative().nullable(),
      trafficUsedBytes: z.number().int().nonnegative(),
      /**
       * Backend that issued THIS specific subscription. May differ from the
       * tier's backend if the user just switched tiers/backends, since they keep
       * the old subscription for a 24h overlap so they can re-import on all
       * devices without immediate disruption.
       */
      backend: BackendId,
      devices: z.array(
        z.object({
          hwid: z.string(),
          firstSeenAt: z.string().datetime().optional(),
          lastSeenAt: z.string().datetime().optional(),
        }),
      ),
    })
    .nullable(),
});
export type AccountResponse = z.infer<typeof AccountResponse>;

export const RegenerateRequest = z.object({
  confirm: z.literal(true),
});
export type RegenerateRequest = z.infer<typeof RegenerateRequest>;

/**
 * Switch a member's subscription from one backend to the other. Free-tier users
 * land on the default-free tier of the target backend; the old subscription is
 * tombstoned with a 24h overlap so the user can re-import on all their devices
 * before the old key stops working, mirroring the regenerate UX.
 *
 * Caller must include `confirm: true` so accidental POSTs from the SPA can't
 * trigger a backend switch.
 */
export const SwitchBackendRequest = z.object({
  backend: BackendId,
  confirm: z.literal(true),
});
export type SwitchBackendRequest = z.infer<typeof SwitchBackendRequest>;

export const SwitchBackendResponse = z.object({
  subscriptionUrl: z.string().url(),
  shortUuid: z.string(),
  backend: BackendId,
  tier: z.object({
    slug: TierSlug,
    name: z.string(),
    monthlyTrafficGb: z.number(),
    deviceLimit: z.number(),
  }),
  /**
   * ISO timestamp at which the previous subscription stops working. Surface
   * this on the UI so the user knows how long they have to re-import on
   * existing devices.
   *
   * NULL when the user had no live previous subscription to tombstone
   * (e.g. they triggered switch-backend twice quickly and the second call
   * saw the row already in `state='disabled'` from the first). The SPA
   * suppresses the "old subscription works for 24 more hours" detail when
   * this is null. Fabricating a fake timestamp would be misleading.
   */
  oldSubscriptionDeletedAt: z.string().datetime().nullable(),
});
export type SwitchBackendResponse = z.infer<typeof SwitchBackendResponse>;

/**
 * Body for `POST /api/v1/account` (anonymous free-account creation). Turnstile
 * gates it (same widget as login). `backend` is an optional preference for which
 * default-free tier (and thus backend) the account lands on, honored only when
 * `subscription.user_choice_enabled` is set; no proxy server is provisioned here.
 */
export const CreateAccountRequest = z.object({
  turnstileToken: z.string().min(1),
  backend: BackendId.optional(),
});
export type CreateAccountRequest = z.infer<typeof CreateAccountRequest>;

/**
 * Result of creating a free account. The caller is auto-signed-in (the response
 * carries a `Set-Cookie`), so `authenticated` is always true. `accountId` is the
 * reveal-once 32-digit number (stored only as a hash; never returned again).
 * No subscription is created here: the member creates the proxy key separately
 * via `POST /api/v1/account/regenerate`.
 */
export const CreateAccountResponse = z.object({
  accountId: z.string(),
  tier: z.object({
    slug: TierSlug,
    name: z.string(),
    monthlyTrafficGb: z.number(),
    deviceLimit: z.number(),
    backend: BackendId,
  }),
  authenticated: z.literal(true),
});
export type CreateAccountResponse = z.infer<typeof CreateAccountResponse>;
