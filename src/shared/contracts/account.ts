import { z } from 'zod';
import { UserStatus } from './common';
import { SubscriptionMirror } from './subscription';
import { BackendId } from './admin';

// Tier slugs are admin-controlled free text (the admin tier validator accepts
// any string), so the member-facing contracts accept any non-empty string here
// rather than a fixed enum — a renamed/custom slug must not make zod reject an
// otherwise-valid response. Mirrors the same widening on PublicConfig.tiers[].slug.
const Slug = z.string().min(1);

export const AccountResponse = z.object({
  user: z.object({
    // Convex document id (string) since the P10 migration; was an integer PK.
    id: z.string(),
    status: UserStatus,
    // W3: non-secret `FS-XXXX-XXXX` support handle (null until backfilled).
    supportId: z.string().nullable(),
    tier: z.object({
      slug: Slug,
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
      // Live key state (additive/optional; absent or 'unknown' when the backend
      // was unreachable). `status` explains a stopped VPN (limited = over quota,
      // disabled = lapsed); resetStrategy + lastResetAt drive "resets in N days".
      status: z.enum(['active', 'disabled', 'limited', 'expired', 'unknown']).optional(),
      resetStrategy: z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']).optional(),
      lastResetAt: z.string().optional(),
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
          // Display-only device metadata (never IP or user-agent). Dates are
          // plain strings, not strict .datetime(), so a backend date-format
          // change can't reject the whole account response.
          platform: z.string().optional(),
          deviceModel: z.string().optional(),
          firstSeenAt: z.string().optional(),
          lastSeenAt: z.string().optional(),
        }),
      ),
    })
    .nullable(),
  /**
   * The visitor's country (ISO-3166-1 alpha-2) as seen by the CDN this request —
   * transient, NOT stored. Prefills the "trouble connecting? try a mirror" country
   * picker so the DB can hand out a host that's reachable where they are. Null when
   * not CDN-fronted or unknown.
   */
  geoCountry: z.string().nullable().optional(),
  /**
   * Server's country-based RECOMMENDATION for the delivery preference: 'privacy'
   * only for the admin-listed `delivery.privacyCountries`, else 'evade'. Just the
   * highlighted default in the picker — the member's actual choice is client-side.
   */
  suggestedDelivery: z.enum(['privacy', 'evade']).optional(),
});
export type AccountResponse = z.infer<typeof AccountResponse>;

export const RegenerateRequest = z.object({
  confirm: z.literal(true),
});
export type RegenerateRequest = z.infer<typeof RegenerateRequest>;

/**
 * Raw subscription content (the actual proxy config — vless/ss links or a
 * clash/sing-box doc) for the member to add manually. Delivered over the SEALED
 * reveal-leg channel (CDN sees ciphertext), so a member can get their config
 * WITHOUT their proxy client fetching the subscription URL through a CDN in
 * plaintext — the E2EE-preserving alternative to the public S3 mirror.
 */
export const SubscriptionContentResponse = z.object({
  content: z.string(),
  contentType: z.string(),
});
export type SubscriptionContentResponse = z.infer<typeof SubscriptionContentResponse>;

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
    slug: Slug,
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
 * Revoke one of the member's HWID devices (frees a slot under the tier's device
 * cap without a full key regenerate). The server verifies the hwid belongs to
 * the member's own current key before deleting it on the backend.
 */
export const RevokeDeviceRequest = z.object({
  hwid: z.string().min(1).max(256),
});
export type RevokeDeviceRequest = z.infer<typeof RevokeDeviceRequest>;

export const RevokeDeviceResponse = z.object({
  ok: z.literal(true),
});
export type RevokeDeviceResponse = z.infer<typeof RevokeDeviceResponse>;

/**
 * Body for `POST /api/v1/account` (anonymous free-account creation). Turnstile
 * gates it (same widget as login). `backend` is an optional preference for which
 * default-free tier (and thus backend) the account lands on, honored only when
 * `subscription.user_choice_enabled` is set; no proxy server is provisioned here.
 */
export const CreateAccountRequest = z.object({
  captchaToken: z.string().min(1),
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
    slug: Slug,
    name: z.string(),
    monthlyTrafficGb: z.number(),
    deviceLimit: z.number(),
    backend: BackendId,
  }),
  authenticated: z.literal(true),
  // PoP sid-binding: non-secret public per-session token the client persists +
  // signs into every request. Absent for clients without the signing worker.
  popSessionToken: z.string().optional(),
});
export type CreateAccountResponse = z.infer<typeof CreateAccountResponse>;
