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
  remnawaveSquadUuid: z.string().uuid().nullable(),
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
  createdAt: z.string().datetime(),
});
export type UserAdmin = z.infer<typeof UserAdmin>;

export const UserSearchQuery = z.object({
  q: z.string().optional(),
  status: UserStatus.optional(),
  tier: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().optional(),
});
export type UserSearchQuery = z.infer<typeof UserSearchQuery>;

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
  isActive: z.boolean(),
  priority: z.number().int(),
  keyCount: z.number().int().nonnegative(),
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
  isActive: z.boolean().default(true),
  priority: z.number().int().default(0),
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
  isActive: z.boolean().default(true),
  priority: z.number().int().default(0),
});
export type MirrorProviderUpsert = z.infer<typeof MirrorProviderUpsert>;

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
