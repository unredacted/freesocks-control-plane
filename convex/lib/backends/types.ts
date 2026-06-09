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
