import { z } from 'zod';
import { TierSlug, UserStatus } from './common';

export const TrafficStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']);
export type TrafficStrategy = z.infer<typeof TrafficStrategy>;

export const BackendId = z.enum(['remnawave', 'outline']);
export type BackendId = z.infer<typeof BackendId>;

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
  status: UserStatus,
  tierSlug: TierSlug,
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
  tier: TierSlug.optional(),
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
 * Zod schema — see `src/server/services/app-settings.ts`. This contract is
 * intentionally loose so the SPA can render unknown future keys generically.
 */
export const AppSettingsRecord = z.record(z.string(), z.unknown());
export type AppSettingsRecord = z.infer<typeof AppSettingsRecord>;

/**
 * Outline server row as exposed to the admin CMS. `apiUrlMasked` redacts the
 * secret path segment of the upstream Outline Manager URL; the real value is
 * never round-tripped to the SPA. Admins submit the full URL on create/edit
 * and the server stores it — they never read it back.
 */
export const OutlineServerAdmin = z.object({
  id: z.string(),
  name: z.string().min(1).max(128),
  slug: z.string().min(1).max(64),
  apiUrlMasked: z.string(),
  websocketEnabled: z.boolean(),
  websocketDomain: z.string().nullable(),
  prometheusUrl: z.string().nullable(),
  isActive: z.boolean(),
  priority: z.number().int(),
  lastHealthOkAt: z.string().datetime().nullable(),
  accessKeyCount: z.number().int().nonnegative(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});
export type OutlineServerAdmin = z.infer<typeof OutlineServerAdmin>;

export const OutlineServerUpsert = z.object({
  name: z.string().min(1).max(128),
  slug: z.string().min(1).max(64),
  /** Full Outline Manager URL including the secret. Server-only — never echoed back. */
  apiUrl: z.string().url(),
  websocketEnabled: z.boolean().default(false),
  websocketDomain: z.string().nullable().optional(),
  prometheusUrl: z.string().nullable().optional(),
  isActive: z.boolean().default(true),
  priority: z.number().int().default(0),
});
export type OutlineServerUpsert = z.infer<typeof OutlineServerUpsert>;
