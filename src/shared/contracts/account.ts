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
      /** True when this tier's device limit is actually enforced (tier opts in
       *  AND the global toggle is on). The SPA gates app-compatibility copy on
       *  it. Optional/defaulted for forward-compat. */
      deviceLimited: z.boolean().optional().default(false),
    }),
    membership: z
      .object({
        expiresAt: z.string().datetime().nullable(),
        isCurrent: z.boolean(),
      })
      .nullable(),
    /** The member's chosen connection mode (transport) id. The server sends the
     *  resolved catalog default when unset. A plain string (data-driven catalog).
     *  Optional for rolling-deploy compat. */
    connectionModeId: z.string().optional(),
    /** ISO timestamp of the member's first settled donation, or null if they've
     *  never donated. Drives the persistent account donor badge. Optional for
     *  rolling-deploy compat. */
    donorSince: z.string().datetime().nullable().optional(),
    /** Lifetime settled donation total (cents) + how many settled orders carried
     *  one — the member's own impact figures. Optional/defaulted for
     *  rolling-deploy compat. */
    donatedCentsTotal: z.number().optional().default(0),
    donationCount: z.number().int().optional().default(0),
    /** GB equivalent of the member's giving, computed server-side (the raw
     *  GB-per-dollar rate is never shipped to the client). Additive. */
    donatedGbTotal: z.number().optional().default(0),
    createdAt: z.string().datetime(),
  }),
  subscription: z
    .object({
      // The RAW backend subscription URL (fallback). The SPA prefers the
      // FCP-fronted URL it builds from `subToken` + its own origin (see
      // subscriptionDisplayUrl); `url` is only used for legacy subs with no token.
      // Plain string, NOT .url(): an Outline sub stores its ss:// accessUrl
      // (not a URL in zod's sense), and a stricter parse 500s the whole view.
      url: z.string(),
      // Opaque per-subscription capability for the FCP-fronted URL
      // (`<origin>/api/v1/sub/<subToken>`). Sealed in this reveal-leg response like
      // the rest of the subscription. Nullish for legacy subs / rolling deploys.
      subToken: z.string().nullish(),
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
      /** Node location this key is served from (the hosting instance's code +
       *  display label). Null when the instance has no location set; optional/
       *  defaulted for rolling-deploy compat. */
      location: z
        .object({ code: z.string(), label: z.string() })
        .nullable()
        .optional()
        .default(null),
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
   * Server's country-based RECOMMENDATION for the connection mode: the hardened
   * (rawConfig) mode id only for the admin-listed `delivery.privacyCountries`,
   * else the catalog default. Just the highlighted default in the picker — the
   * member's actual choice is client-side. A plain string (data-driven catalog).
   */
  suggestedModeId: z.string().nullable().optional(),
  /** The member's stored node-location preference (a PublicConfig.locations
   *  code; null = automatic). Optional for rolling-deploy compat. */
  preferredLocation: z.string().nullable().optional().default(null),
});
export type AccountResponse = z.infer<typeof AccountResponse>;

/**
 * Aggregate usage trend for the member's key (the usage-panel sparkline). Read
 * live from the backend, never persisted; `null` when the backend has no usage
 * history (e.g. Outline) or the read failed. Deliberately aggregate-only — no
 * per-node/per-country breakdown (metadata minimization).
 */
export const AccountUsageResponse = z.object({
  usage: z
    .object({
      points: z.array(z.number()),
      labels: z.array(z.string()),
      total: z.number(),
    })
    .nullable(),
});
export type AccountUsageResponse = z.infer<typeof AccountUsageResponse>;

export const RegenerateRequest = z.object({
  confirm: z.literal(true),
  /** Optional node-location pick for this issuance: a PublicConfig.locations
   *  code persists the preference, 'auto'/null clears it back to automatic,
   *  absent keeps the stored preference. */
  location: z.string().nullable().optional(),
});
export type RegenerateRequest = z.infer<typeof RegenerateRequest>;

/**
 * Response of `POST /api/v1/account/regenerate` (and the same shape for the
 * first-key create): the freshly-issued key. `subscriptionUrl` is the raw
 * backend URL — plain string, NOT .url() (an Outline sub is an ss:// link and
 * the server passes the backend's value through verbatim).
 */
export const RegenerateResponse = z.object({
  subscriptionUrl: z.string(),
  shortUuid: z.string(),
});
export type RegenerateResponse = z.infer<typeof RegenerateResponse>;

/** `POST /api/v1/account/connection-mode`: persist the picked mode. */
export const ConnectionModeResponse = z.object({ ok: z.boolean(), modeId: z.string() });
export type ConnectionModeResponse = z.infer<typeof ConnectionModeResponse>;

/** `POST /api/v1/account/refresh-membership`: the member's current entitlement
 *  snapshot after a refresh (post-payment return poll). */
export const RefreshMembershipResponse = z.object({
  tierSlug: z.string(),
  tierName: z.string(),
  membershipExpiresAt: z.string().nullable(),
  isCurrent: z.boolean(),
});
export type RefreshMembershipResponse = z.infer<typeof RefreshMembershipResponse>;

/**
 * Live-ish status of the node the member's config is homed to (the SPA polls
 * this while the account page is open). `online: null` = never observed.
 * Distinguishes "the node is up but your network filters it" from an outage.
 * `load` is the location's coarse public load band (quiet/busy/crowded),
 * null when the location has no load data (or no located instances).
 */
export const NodeStatusResponse = z.object({
  node: z
    .object({
      online: z.boolean().nullable(),
      label: z.string().nullable(),
      location: z.object({ code: z.string(), label: z.string() }).nullable(),
      load: z.enum(['quiet', 'busy', 'crowded', 'unknown']).nullable(),
      checkedAt: z.string().nullable(),
    })
    .nullable(),
});
export type NodeStatusResponse = z.infer<typeof NodeStatusResponse>;

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
  subscriptionUrl: z.string(),
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

export const SwitchModeRequest = z.object({
  modeId: z.string(),
  confirm: z.literal(true),
});
export type SwitchModeRequest = z.infer<typeof SwitchModeRequest>;

export const SwitchModeResponse = z.object({
  subscriptionUrl: z.string(),
  shortUuid: z.string(),
  mode: z.object({ id: z.string(), label: z.string().nullable() }),
  /** ISO timestamp the previous key stops working (24h grace); null when there
   *  was no live previous subscription to tombstone (see SwitchBackendResponse). */
  oldSubscriptionDeletedAt: z.string().datetime().nullable(),
});
export type SwitchModeResponse = z.infer<typeof SwitchModeResponse>;

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
 * `referralCode` optionally binds the new account to a referrer — an invalid
 * code never blocks creation (see `referralApplied`).
 */
export const CreateAccountRequest = z.object({
  captchaToken: z.string().min(1),
  backend: BackendId.optional(),
  referralCode: z.string().max(32).optional(),
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
  /** True when a referral code bound this account to its referrer (absent on
   *  older backends — treat as false). */
  referralApplied: z.boolean().optional(),
  // PoP sid-binding: non-secret public per-session token the client persists +
  // signs into every request. Absent for clients without the signing worker.
  popSessionToken: z.string().optional(),
});
export type CreateAccountResponse = z.infer<typeof CreateAccountResponse>;

/**
 * The member's referral card (`GET /api/v1/account/referrals`): their share
 * code + invite stats. `enabled: false` (program off) hides the whole surface;
 * `code: null` shouldn't happen (the route lazily mints) but parses.
 */
export const AccountReferralsResponse = z.object({
  enabled: z.boolean(),
  code: z.string().nullable(),
  stats: z
    .object({
      invited: z.number().int().nonnegative(),
      converted: z.number().int().nonnegative(),
      pending: z.number().int().nonnegative(),
      bonusDaysEarned: z.number().int().nonnegative(),
    })
    .nullable(),
});
export type AccountReferralsResponse = z.infer<typeof AccountReferralsResponse>;

/**
 * The member's enrolled passkeys (optional alternative login). Masked: only
 * non-secret display fields — never the public key or signature counter.
 */
export const PasskeyEntry = z.object({
  id: z.string(),
  deviceLabel: z.string().nullable(),
  aaguid: z.string().nullable(),
  lastUsedAt: z.string().nullable(),
  createdAt: z.string(),
});
export type PasskeyEntry = z.infer<typeof PasskeyEntry>;

export const PasskeyListResponse = z.object({ passkeys: z.array(PasskeyEntry) });
export type PasskeyListResponse = z.infer<typeof PasskeyListResponse>;
