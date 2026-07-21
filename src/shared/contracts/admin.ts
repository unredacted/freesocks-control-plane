import { z } from 'zod';
import { UserStatus } from './common';
import { BackendId } from './backends';

export const TrafficStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']);
export type TrafficStrategy = z.infer<typeof TrafficStrategy>;

// BackendId is defined once in ./backends (the BACKEND_IDS source of truth) and
// re-exported here for the admin/account/subscription contracts that use it.
export { BackendId };

export const TierAdmin = z.object({
  // Convex document ids are opaque strings (was an integer PK under SQLite).
  id: z.string(),
  slug: z.string().min(1).max(64),
  name: z.string().min(1).max(128),
  description: z.string().nullable(),
  backend: BackendId,
  monthlyTrafficGb: z.number().int().nonnegative(),
  deviceLimit: z.number().int().nonnegative(),
  hwidLimit: z.number().int().nonnegative(),
  hwidEnabled: z.boolean(),
  trafficStrategy: TrafficStrategy,
  /**
   * D-1: the cross-backend peer tier id (opaque), or null — the equivalent tier
   * on the OTHER backend used by account.switchBackend. Free tiers auto-peer via
   * the per-backend default-free row and leave this null.
   */
  peerTierId: z.string().nullable(),
  isDefaultFree: z.boolean(),
  isActive: z.boolean(),
  priority: z.number().int(),
  expirationDaysAfterMembershipLapse: z.number().int().nonnegative(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type TierAdmin = z.infer<typeof TierAdmin>;

export const TierUpsert = TierAdmin.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export type TierUpsert = z.infer<typeof TierUpsert>;

export const UserAdmin = z.object({
  id: z.string(),
  /**
   * First 4 digits of the member's account number. Non-secret and
   * admin-searchable (a full number is never exposed). Null until issuance
   * mints one. This is the only human-readable handle for an anonymous member.
   */
  accountIdPrefix: z.string().nullable(),
  /**
   * W3: the member's non-secret `FS-XXXX-XXXX` support handle (null until
   * backfilled). The primary human-readable id for support — collision-free,
   * unlike the 4-digit prefix.
   */
  supportId: z.string().nullable(),
  status: UserStatus,
  // Admin-controlled free text (see common.ts); not the narrower TierSlug enum.
  tierSlug: z.string(),
  membershipExpiresAt: z.string().datetime().nullable(),
  /** Backend-agnostic primary id of the user's current subscription. */
  backendUserId: z.string().nullable(),
  /** Which backend the subscription lives in, if any. */
  backend: BackendId.nullable(),
  /**
   * Set when the last backend push for this user failed and hasn't since
   * recovered (a tier propagation that never reached the panel, or a disable the
   * key ignored). Null = in sync. Surfaces as the "backend drift" badge.
   * Optional (additive): tolerated absent so a client built ahead of the backend
   * deploy still parses the response — it just shows no drift until both are live.
   */
  backendPushFailedAt: z.string().datetime().nullable().optional(),
  createdAt: z.string().datetime(),
});
export type UserAdmin = z.infer<typeof UserAdmin>;

export const UserSearchQuery = z.object({
  q: z.string().optional(),
  status: UserStatus.optional(),
  tier: z.string().optional(),
  // Restrict to users with unresolved backend push-drift.
  drift: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().optional(),
});
export type UserSearchQuery = z.infer<typeof UserSearchQuery>;

/**
 * Live backend state for one user (the admin per-user detail expander). `state`
 * is null when the user has no subscription or the backend was unreachable. The
 * live `status` here is compared against the user's LOCAL status to spot drift.
 */
export const AdminUserBackendState = z.object({
  state: z
    .object({
      status: z.enum(['active', 'disabled', 'limited', 'expired', 'unknown']),
      trafficLimitBytes: z.number().nullable(),
      usedTrafficBytes: z.number(),
      trafficLimitStrategy: z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']).nullable(),
      lastTrafficResetAt: z.string().nullable(),
      // Panel-side "last seen online" (nullish: additive field, so a client
      // built ahead of the server redeploy still parses).
      onlineAt: z.string().nullish(),
      devices: z.array(
        z.object({
          hwid: z.string(),
          platform: z.string().nullable(),
          deviceModel: z.string().nullable(),
          firstSeenAt: z.string().nullable(),
          lastSeenAt: z.string().nullable(),
        }),
      ),
    })
    .nullable(),
});
export type AdminUserBackendState = z.infer<typeof AdminUserBackendState>;

export const AuditEntry = z.object({
  id: z.string(),
  actorType: z.enum(['system', 'admin', 'member', 'anonymous', 'webhook']),
  actorId: z.string().nullable(),
  action: z.string(),
  targetType: z.string().nullable(),
  targetId: z.string().nullable(),
  payload: z.unknown().nullable(),
  requestId: z.string().nullable(),
  createdAt: z.string().datetime(),
});
export type AuditEntry = z.infer<typeof AuditEntry>;

/**
 * App settings exposed via the admin API. Server-side, each key has its own
 * Zod schema; see `src/server/services/app-settings.ts`. This contract is
 * intentionally loose so the SPA can render unknown future keys generically.
 */
export const AppSettingsRecord = z.record(z.string(), z.unknown());
export type AppSettingsRecord = z.infer<typeof AppSettingsRecord>;

/**
 * A backend instance (one deployed proxy server of any type) as exposed to the
 * admin CMS. Secrets are never round-tripped: the per-type config summary masks
 * them (Outline's apiUrl path is redacted; Remnawave's token is reported only as
 * `apiTokenSet`). Admins submit the full secret on create/edit and the server
 * stores it; they never read it back.
 */
const RemnawaveConfigSummary = z.object({
  type: z.literal('remnawave'),
  baseUrl: z.string(),
  apiTokenSet: z.boolean(),
});
const OutlineConfigSummary = z.object({
  type: z.literal('outline'),
  apiUrlMasked: z.string(),
  websocketEnabled: z.boolean(),
  websocketDomain: z.string().nullable(),
  prometheusUrl: z.string().nullable(),
});

export const BackendServerAdmin = z.object({
  id: z.string(),
  backend: BackendId,
  name: z.string().min(1).max(128),
  slug: z.string().min(1).max(64),
  // Member-facing node location: a short code ("MCI") + display label
  // ("Kansas City, MO"). null = not part of the member location picker.
  // Optional/defaulted for forward-compat with older servers.
  location: z.string().nullable().optional().default(null),
  locationLabel: z.string().nullable().optional().default(null),
  isActive: z.boolean(),
  priority: z.number().int(),
  keyCount: z.number().int().nonnegative(),
  // Hard capacity cap: at keyCount >= maxKeys the instance is skipped at
  // issuance. null = uncapped. Optional for forward-compat with older servers.
  maxKeys: z.number().int().positive().nullable().optional().default(null),
  lastHealthOkAt: z.string().datetime().nullable(),
  lastHealthRttMs: z.number().nonnegative().nullable(),
  config: z.discriminatedUnion('type', [RemnawaveConfigSummary, OutlineConfigSummary]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type BackendServerAdmin = z.infer<typeof BackendServerAdmin>;

/**
 * Create/edit input. Secret-bearing fields (apiToken, apiUrl) are required on
 * create and optional on edit (sent only to rotate the secret). The server
 * validates the required-per-type combination; `backend` is immutable on edit.
 */
export const BackendServerUpsert = z.object({
  backend: BackendId,
  name: z.string().min(1).max(128),
  slug: z.string().min(1).max(64),
  // Node location code + label; null/blank clears, absent keeps the current.
  location: z.string().max(16).nullable().optional(),
  locationLabel: z.string().max(64).nullable().optional(),
  isActive: z.boolean().default(true),
  priority: z.number().int().default(0),
  // Capacity cap: positive integer; null clears, absent keeps the current cap.
  maxKeys: z.number().int().positive().nullable().optional(),
  // Remnawave instance:
  baseUrl: z.string().url().optional(),
  apiToken: z.string().min(1).optional(),
  // Outline instance:
  apiUrl: z.string().url().optional(),
  websocketEnabled: z.boolean().optional(),
  websocketDomain: z.string().nullable().optional(),
  prometheusUrl: z.string().nullable().optional(),
});
export type BackendServerUpsert = z.infer<typeof BackendServerUpsert>;

// --- S3 mirror providers (subscription mirrors, Admin → Storage) ------------

/**
 * One mirror-provider row (GET /api/v1/admin/mirror-providers). The secret
 * (`secretAccessKey`) is NEVER returned — only `secretAccessKeySet`. `accessKeyId`
 * is the public half of the keypair (shown).
 */
export const MirrorProviderAdmin = z.object({
  id: z.string(),
  name: z.string().min(1).max(64),
  endpoint: z.string(),
  bucket: z.string(),
  publicUrl: z.string(),
  region: z.string(),
  accessKeyId: z.string(),
  secretAccessKeySet: z.boolean(),
  /** ISO-3166-1 alpha-2 codes this provider is preferred for (empty = global fallback). */
  countryCodes: z.array(z.string()),
  isActive: z.boolean(),
  priority: z.number().int(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type MirrorProviderAdmin = z.infer<typeof MirrorProviderAdmin>;

/**
 * Create/edit input. `secretAccessKey` is required on create, optional on edit
 * (sent only to rotate it — a blank field keeps the stored secret server-side).
 */
export const MirrorProviderUpsert = z.object({
  name: z.string().min(1).max(64),
  endpoint: z.string().min(1),
  bucket: z.string().min(1),
  publicUrl: z.string().min(1),
  region: z.string().optional(),
  accessKeyId: z.string().min(1).optional(),
  secretAccessKey: z.string().min(1).optional(),
  /** ISO-3166-1 alpha-2 codes this provider is preferred for (empty = global fallback). */
  countryCodes: z.array(z.string()).optional(),
  isActive: z.boolean().default(true),
  priority: z.number().int().default(0),
});
export type MirrorProviderUpsert = z.infer<typeof MirrorProviderUpsert>;

// --- recommended client apps (CMS-managed "set up your app" catalog) ---

/** One row in the clients list (GET /api/v1/admin/clients). No secrets. */
export const ClientAdmin = z.object({
  id: z.string(),
  name: z.string().min(1).max(64),
  platforms: z.array(z.string()),
  backends: z.array(z.enum(['remnawave', 'outline'])),
  homepageUrl: z.string(),
  /** An appLinks deep-link builder id, or null = manual / QR import only. */
  schemeId: z.string().nullable(),
  hwid: z.boolean(),
  /** Open-source signal: OSS apps get a badge + rank ahead of proprietary ones. */
  openSource: z.boolean(),
  license: z.string().nullable(),
  sourceUrl: z.string().nullable(),
  /** Ease-of-use rating: sorts within each OSS group (easier first) + drives a
   *  badge. null = unrated (treated as 'moderate'). */
  easeOfUse: z.enum(['easy', 'moderate', 'advanced']).nullable().optional().default(null),
  /** Admin-set member-facing blurb (verbatim in every locale); null = the SPA's
   *  built-in translated copy for known default apps. */
  description: z.string().nullable().optional().default(null),
  enabled: z.boolean(),
  priority: z.number().int(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type ClientAdmin = z.infer<typeof ClientAdmin>;

/** Create/edit input. `schemeId` null/absent = a manual / QR-only client. */
export const ClientUpsert = z.object({
  name: z.string().min(1).max(64),
  platforms: z.array(z.string()).default([]),
  backends: z.array(z.enum(['remnawave', 'outline'])).default(['remnawave']),
  homepageUrl: z.string().min(1),
  schemeId: z.string().nullable().optional(),
  hwid: z.boolean().default(false),
  openSource: z.boolean().default(false),
  license: z.string().nullable().optional(),
  sourceUrl: z.string().nullable().optional(),
  easeOfUse: z.enum(['easy', 'moderate', 'advanced']).nullable().optional(),
  description: z.string().max(280).nullable().optional(),
  enabled: z.boolean().default(true),
  priority: z.number().int().default(0),
});
export type ClientUpsert = z.infer<typeof ClientUpsert>;

// --- Remnawave: enforce the no-client-IP-logging posture on config profiles ---

/** Report from GET /logging-status (dry-run) or POST /harden-logging (apply):
 *  per Remnawave instance, per config profile, whether it's hardened / changed. */
export const RemnawaveLoggingReport = z.object({
  instances: z.array(
    z.object({
      serverId: z.string(),
      name: z.string(),
      ok: z.boolean(),
      error: z.string().optional(),
      profiles: z.array(
        z.object({
          uuid: z.string(),
          name: z.string(),
          hardened: z.boolean(),
          changed: z.boolean(),
          error: z.string().optional(),
        }),
      ),
    }),
  ),
});
export type RemnawaveLoggingReport = z.infer<typeof RemnawaveLoggingReport>;

// --- Remnawave: node placement (per-mode squad pools) ---

/** Per-mode bound-pool size. Pool SIZES only — the squad UUIDs are write-only
 *  and never round-trip to the client. */
export const RemnawavePlacementCount = z.object({
  modeId: z.string(),
  boundCount: z.number().int().nonnegative(),
});
export type RemnawavePlacementCount = z.infer<typeof RemnawavePlacementCount>;

/** Response of PATCH /api/v1/admin/remnawave/mode-placements: which modes now
 *  have a pool bound + the per-mode sizes. `placements` is defaulted for
 *  rolling-deploy compat (an older backend omits it). */
export const RemnawavePlacementUpdateResponse = z.object({
  bound: z.array(z.string()),
  placements: z.array(RemnawavePlacementCount).optional().default([]),
});
export type RemnawavePlacementUpdateResponse = z.infer<typeof RemnawavePlacementUpdateResponse>;

/** Response of GET /api/v1/admin/remnawave/node-stats: per-placement node-load
 *  snapshots (the node-placement picker's input, cached by the healthcheck
 *  cron) + the per-mode bound counts for the placement editor's badge. */
export const RemnawaveNodeStatsResponse = z.object({
  nodes: z.array(
    z.object({
      placement: z.string(),
      label: z.string().nullable(),
      usersOnline: z.number(),
      online: z.boolean(),
      nodeCount: z.number(),
      lastStatsAt: z.number(),
    }),
  ),
  placements: z.array(RemnawavePlacementCount).optional().default([]),
});
export type RemnawaveNodeStatsResponse = z.infer<typeof RemnawaveNodeStatsResponse>;

// --- admin management (multi-admin onboarding via invite links) ---

/** One row in the admins list (GET /api/v1/admin/admins). */
export const AdminListItem = z.object({
  id: z.string(),
  username: z.string(),
  displayName: z.string(),
  isActive: z.boolean(),
  // How many passkeys this admin has registered (0 = invited but not yet set up).
  passkeyCount: z.number().int().nonnegative(),
  // True when an unconsumed, unexpired invite is outstanding for this admin.
  pendingInvite: z.boolean(),
  lastLoginAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
});
export type AdminListItem = z.infer<typeof AdminListItem>;

export const AdminListResponse = z.object({ admins: z.array(AdminListItem) });

/** Mint an invite link for a NEW admin (POST /api/v1/admin/admins/invite). */
export const CreateInviteRequest = z.object({
  username: z.string().min(1).max(64),
  displayName: z.string().max(128).optional(),
});
export type CreateInviteRequest = z.infer<typeof CreateInviteRequest>;

/** The raw invite token is returned ONCE; the SPA builds the shareable URL. */
export const CreateInviteResponse = z.object({
  inviteToken: z.string(),
  username: z.string(),
  expiresAtMs: z.number(),
});
export type CreateInviteResponse = z.infer<typeof CreateInviteResponse>;

/** One of an admin's registered passkeys (masked — never the public key). */
export const AdminCredential = z.object({
  id: z.string(),
  deviceLabel: z.string().nullable(),
  aaguid: z.string().nullable(),
  lastUsedAt: z.string().datetime().nullable(),
  createdAt: z.string().datetime(),
});
export type AdminCredential = z.infer<typeof AdminCredential>;

/** GET /api/v1/admin/admins/credentials/{adminId}. */
export const AdminCredentialsResponse = z.object({ credentials: z.array(AdminCredential) });

/**
 * Operator status snapshot for the admin dashboard (`GET /api/v1/admin/status`).
 * Counts + health booleans only — never a backend secret. Also consumed by the
 * Ansible post-deploy health-gate.
 */
export const AdminStatusSummary = z.object({
  users: z.object({
    active: z.number().int().nonnegative(),
    grace: z.number().int().nonnegative(),
    disabled: z.number().int().nonnegative(),
    deleted: z.number().int().nonnegative(),
    // Idle free users (deactivated + retained). Additive: a pre-deploy backend
    // that omits it reads 0.
    inactive: z.number().int().nonnegative().default(0),
  }),
  /** Users whose last backend push failed and hasn't recovered (entitlement drift).
   *  Optional-with-default (additive): a pre-deploy backend that omits it reads 0. */
  backendDrift: z.number().int().nonnegative().default(0),
  totals: z.object({
    backends: z.number().int().nonnegative(),
    activeBackends: z.number().int().nonnegative(),
    healthyBackends: z.number().int().nonnegative(),
    keys: z.number().int().nonnegative(),
  }),
  backends: z.array(
    z.object({
      slug: z.string(),
      backend: BackendId,
      isActive: z.boolean(),
      keyCount: z.number().int().nonnegative(),
      healthy: z.boolean(),
      lastHealthOkAt: z.string().datetime().nullable(),
      lastHealthRttMs: z.number().nullable(),
      // Read-only fleet observability, cached by the healthcheck cron. Null for
      // backends without a fleet (Outline) or before the first fetch. Additive.
      fleetStats: z
        .object({
          onlineNow: z.number(),
          nodesOnline: z.number(),
          nodesTotal: z.number(),
          distinctCountries: z.number(),
          monthTrafficBytes: z.number(),
          lifetimeTrafficBytes: z.number(),
          panelVersion: z.string(),
        })
        .nullable()
        .optional(),
    }),
  ),
  healthcheck: z.object({
    ok: z.boolean(),
    lastOkAt: z.string().datetime().nullable(),
    staleSeconds: z.number().int().nonnegative().nullable(),
  }),
  // Per-cron liveness (W4-B4): one entry per scheduled job, from the heartbeat
  // each cron stamps at its run start vs the job's known cadence. Additive —
  // the default keeps a pre-deploy backend (which omits it) valid.
  crons: z
    .array(
      z.object({
        name: z.string(),
        description: z.string(),
        everyMs: z.number().int().positive(),
        state: z.enum(['ok', 'stale', 'pending']),
        lastRunAt: z.string().datetime().nullable(),
        ageSeconds: z.number().int().nonnegative().nullable(),
        runCount: z.number().int().nonnegative(),
        // Outcome tracking (additive — pre-deploy backends omit it): the last
        // successful completion, the latest failure message, and a rolled-up
        // "firing but failing" flag.
        lastOkAt: z.string().datetime().nullable().default(null),
        lastError: z.string().nullable().default(null),
        failing: z.boolean().default(false),
      }),
    )
    .default([]),
  /** Count of scheduled jobs overdue past their cadence. Additive default 0. */
  cronsStale: z.number().int().nonnegative().default(0),
  // PoP enrollment readiness for the POP_REQUIRED enforcement flip. Enabling the
  // flag rejects only cookie-only (unbound) sessions, so `readyToEnable` is true
  // once none remain. Additive — the default keeps a pre-deploy backend valid.
  pop: z
    .object({
      required: z.boolean(),
      activeSessions: z.number().int().nonnegative(),
      bound: z.number().int().nonnegative(),
      unbound: z.number().int().nonnegative(),
      unboundMember: z.number().int().nonnegative(),
      unboundAdmin: z.number().int().nonnegative(),
      readyToEnable: z.boolean(),
    })
    .default({
      required: false,
      activeSessions: 0,
      bound: 0,
      unbound: 0,
      unboundMember: 0,
      unboundAdmin: 0,
      readyToEnable: false,
    }),
  // CDN-blinding E2EE posture: FS_E2EE_REQUIRED rejects unsealed member
  // requests on seal/reveal routes. Additive default for a pre-deploy backend.
  e2ee: z.object({ required: z.boolean() }).default({ required: false }),
  generatedAt: z.string().datetime(),
});
export type AdminStatusSummary = z.infer<typeof AdminStatusSummary>;

/** Admin referral-program config (`/api/v1/admin/referrals/config`): the
 *  reward economics shown on the Admin → Billing "Referrals" card. */
export const AdminReferralConfig = z.object({
  enabled: z.boolean(),
  refereeBonusDays: z.number().int(),
  referrerBonusDays: z.number().int(),
  vestingDays: z.number().int(),
  maxRewardsPerMonth: z.number().int(),
});
export type AdminReferralConfig = z.infer<typeof AdminReferralConfig>;
