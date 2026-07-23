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
 * Rounded to a whole byte: the donation bonus can yield a fractional GB (e.g.
 * 2.01), and the Remnawave contract is INTEGER bytes — a float is rejected,
 * which previously wedged the fleet re-cap cron in a fail-retry loop.
 */
export function gbToBytes(gb: number): number {
  return Math.round(gb * 1024 ** 3);
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
 * The new key's traffic limit after carrying the superseded key's used bytes
 * forward (Review D-M3): a re-issue mints a FRESH backend counter while the old
 * key routes for the 24h tombstone grace, so without the carryover every
 * regenerate/switch multiplied the member's effective quota. 0 is NEVER
 * returned: it means UNLIMITED to Remnawave (and 'blocked' to Outline), so a
 * fully-spent quota carries as 1 byte — the only value that reads as "spent"
 * on both backends.
 */
export function applyUsageCarryover(limitBytes: number, usedBytes: number): number {
  return Math.max(1, limitBytes - Math.max(0, Math.floor(usedBytes)));
}

/** Panel-side "no expiry" sentinel horizon (~10 years). Remnawave requires a
 *  concrete date, so keys that must never expire on the panel's clock carry
 *  this instead of null. */
export const FAR_FUTURE_EXPIRY_DAYS = 3650;

export function farFutureExpiryIso(now = Date.now()): string {
  return new Date(now + FAR_FUTURE_EXPIRY_DAYS * DAY_MS).toISOString();
}

/** True when a panel `expireAt` is (a drifted copy of) the far-future sentinel —
 *  read-side, it maps back to "no expiry". The 5-year threshold sits far above
 *  any real membership term and comfortably below the 10-year sentinel. */
export function isFarFutureExpiry(iso: string, now = Date.now()): boolean {
  const t = Date.parse(iso);
  return Number.isFinite(t) && t - now > 1825 * DAY_MS;
}

/**
 * The backend `expireAt` (ISO) for a user: a paid member's purchased term
 * (`membershipExpiresAt`), else the far-future sentinel — a FREE key never
 * expires on the panel's clock. Free-account reclaim is usage-based instead:
 * the deactivate-idle-free sweep consults the panel's last-online stamp and
 * only reclaims genuinely idle accounts, so an actively-used free key keeps
 * the same config indefinitely. Call from an ACTION (uses Date.now()).
 */
export function computeExpireAtIso(membershipExpiresAtMs: number | null | undefined): string {
  const now = Date.now();
  if (membershipExpiresAtMs == null) return farFutureExpiryIso(now);
  let ms = membershipExpiresAtMs;
  // A LAPSED member's stored expiry is in the past — and Remnawave's create
  // DTO rejects past dates, which made self-serve regenerate fail permanently
  // for exactly the members most likely to need it. Clamp to a near-future
  // grace (the grace sweep owns actual disablement), mirroring the update
  // path's past-date clamp. (Review D-#7.)
  if (ms <= now) ms = now + 5 * 60_000;
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
  // Panel-side "last seen online" stamp (Remnawave-only; undefined for
  // backends that don't report liveness, e.g. Outline).
  onlineAt?: string;
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
  // The node this content was pinned to (Remnawave node pinning only) — the
  // serve paths persist it on the subscription row so the NEXT issuance can
  // exclude it (regenerate → a different node).
  pinnedNode?: string;
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
