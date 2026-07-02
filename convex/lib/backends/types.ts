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
  // Display-only device metadata (never the IP or user-agent). firstSeenAt /
  // lastSeenAt map from the backend's created/updated timestamps.
  platform?: string;
  deviceModel?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface UserState {
  trafficLimitBytes: number | null;
  usedTrafficBytes: number;
  // Reset cadence for the member "resets in N days" hint (Remnawave-only;
  // undefined for backends without periodic resets, e.g. Outline).
  trafficLimitStrategy?: TrafficLimitStrategy;
  lastTrafficResetAt?: string;
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
  // Status changes go through the dedicated `setStatus` provider op
  // (Remnawave's /actions/{enable|disable}), not this field-update patch.
}

export interface SubscriptionContent {
  content: string;
  contentType: string;
}

/**
 * Aggregate per-bucket traffic usage for one user over a time range — the member
 * "usage trend" sparkline. Deliberately aggregate-only: the backend's per-node /
 * per-country breakdown is NOT surfaced (metadata minimization). Read live and
 * never persisted by FCP.
 */
export interface UsageSeries {
  points: number[]; // bytes per bucket (usually per day)
  labels: string[]; // bucket labels (dates), 1:1 with `points`
  total: number; // sum of `points`, bytes
}

/**
 * Fleet-wide observability for one backend panel (admin dashboard). Read-only,
 * cached by the healthcheck cron so the dashboard never makes a live panel call.
 * `panelVersion` surfaces version drift (relevant to the pinned API contract).
 */
export interface FleetStats {
  onlineNow: number;
  nodesOnline: number;
  nodesTotal: number;
  distinctCountries: number;
  monthTrafficBytes: number;
  lifetimeTrafficBytes: number;
  panelVersion: string;
}
