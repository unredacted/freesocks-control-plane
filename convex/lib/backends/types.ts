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
 * The per-user backend `trafficLimitBytes`: null (unlimited) when the tier has no
 * monthly cap (paid membership → `monthlyTrafficGb === 0`), else the tier's monthly
 * GB. For the default-free tier a shared donation bonus (GB) is folded in on top for
 * the current month (see lib/donationBonus.ts); the bonus never applies to a capped
 * non-free tier. Central so issuance / regenerate / switch / the event-driven tier
 * push all compute the free limit identically (pass `bonusGb: 0` for no bonus).
 */
export function resolveTrafficLimitBytes(
  tier: { monthlyTrafficGb: number; isDefaultFree: boolean },
  bonusGb: number,
): number | null {
  if (tier.monthlyTrafficGb <= 0) return null;
  const gb = tier.monthlyTrafficGb + (tier.isDefaultFree ? Math.max(0, bonusGb) : 0);
  return gbToBytes(gb);
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

/**
 * The per-user Remnawave `hwidDeviceLimit` to send: the tier's limit ONLY when
 * device-limit enforcement is globally enabled AND the tier opts in. When the
 * master toggle is off (the unlimited-by-default posture) this is null for every
 * user regardless of tier, so a client that doesn't send an x-hwid header is
 * never rejected. Panel-side enforcement additionally requires
 * HWID_DEVICE_LIMIT_ENABLED=true (outside FCP's control).
 */
export function resolveHwidLimit(
  enforcementEnabled: boolean,
  tier: { hwidEnabled: boolean; hwidLimit: number },
): number | null {
  return enforcementEnabled && tier.hwidEnabled ? tier.hwidLimit : null;
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
  // Opaque, backend-defined placement handle (where within the backend this key
  // is homed). The generic layer treats it as a black box; Remnawave maps it to
  // an internal-squad UUID (activeInternalSquads), Outline ignores it.
  placement?: string | null;
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
  // Opaque backend placement handle (see IssueUserSpec.placement). Present+null/''
  // clears it; Remnawave maps it to activeInternalSquads.
  placement?: string | null;
  // Status changes go through the dedicated `setStatus` provider op
  // (Remnawave's /actions/{enable|disable}), not this field-update patch.
}

export interface SubscriptionContent {
  content: string;
  contentType: string;
  // A small allowlist of subscription metadata headers to re-emit when FCP fronts
  // the subscription URL — traffic/expiry counters (`subscription-userinfo`) and
  // client update hints the proxy app displays. Undefined for backends that don't
  // emit them (Outline). Never carries a secret.
  headers?: Record<string, string>;
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

/**
 * Per-placement load snapshot for issuance-time node placement. A placement is
 * the opaque handle a key is homed to (Remnawave: an internal squad, which maps
 * to one or more nodes); the load is aggregated from that placement's node(s).
 * `usersOnline` is the primary signal (fewest wins). Read-only, refreshed by the
 * healthcheck cron. Squad-free by design — the generic layer never sees a squad.
 */
export interface NodeStats {
  placement: string; // opaque handle (Remnawave: internal-squad uuid)
  label: string; // display name (squad name)
  usersOnline: number; // summed over the placement's mapped nodes
  trafficBytesRealtime?: number; // summed realtime throughput, when available
  online: boolean; // ≥1 mapped node connected & not disabled
  nodeCount: number; // mapped nodes: 0 = unroutable, >1 = aggregated
}
