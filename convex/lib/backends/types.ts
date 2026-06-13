/**
 * Common proxy-backend types, ported from src/server/providers/backend.ts.
 * Backends ignore fields that don't apply to them. These are plain TS types;
 * the Convex action boundary (convex/backends.ts) validates with `v.*`. The
 * per-instance config types + the provider registry live in
 * convex/lib/backends/registry.ts.
 */

// Single source of truth for the backend-type set (the shared contract).
export type { BackendId } from '../../../src/shared/contracts/backends';
export type TrafficLimitStrategy = 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH';
export type BackendUserStatus = 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';

const DAY_MS = 86_400_000;

/**
 * Tier "GB" → bytes using BINARY GiB (1 GiB = 2^30), so the admin's number
 * matches what Remnawave shows: it renders limits in GiB, so a tier of `50`
 * displays as "50 GiB" (not "46.57 GiB", which `50 × 10^9` decimal produced).
 */
export function gbToBytes(gb: number): number {
  return gb * 1024 ** 3;
}

/**
 * The backend `expireAt` (ISO) for a user: a paid member's purchased term
 * (`membershipExpiresAt`), else the free-account window (now + `freeExpiryDays`).
 * Remnawave REQUIRES a date — FCP's lifecycle is still the source of truth for
 * disable/delete, this just keeps the key's own expiry honest + a backstop, and
 * a renewal re-pushes it. Call from an ACTION (uses Date.now()).
 */
export function computeExpireAtIso(
  membershipExpiresAtMs: number | null | undefined,
  freeExpiryDays: number,
): string {
  const ms = membershipExpiresAtMs ?? Date.now() + freeExpiryDays * DAY_MS;
  return new Date(ms).toISOString();
}

export interface IssueUserSpec {
  username: string;
  trafficLimitBytes: number | null;
  expireAt: string | null; // ISO 8601, null = no expiry
  tag: string;
  description?: string;
  // Remnawave-only:
  hwidDeviceLimit?: number | null;
  trafficLimitStrategy?: TrafficLimitStrategy;
  remnawaveSquadUuid?: string | null;
}

export interface IssuedUser {
  backendUserId: string;
  backendShortId: string;
  subscriptionUrl: string;
  raw: unknown;
}

export interface BackendDevice {
  hwid: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface UserState {
  trafficLimitBytes: number | null;
  usedTrafficBytes: number;
  expireAt: string | null;
  status: BackendUserStatus;
  devices: BackendDevice[];
}

export interface UpdateUserPatch {
  trafficLimitBytes?: number | null;
  expireAt?: string | null;
  tag?: string;
  description?: string;
  hwidDeviceLimit?: number | null;
  trafficLimitStrategy?: TrafficLimitStrategy;
  remnawaveSquadUuid?: string | null;
  status?: 'active' | 'disabled';
}

export interface SubscriptionContent {
  content: string;
  contentType: string;
}
