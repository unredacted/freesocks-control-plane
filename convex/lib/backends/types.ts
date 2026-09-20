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

/** Backend-side "no expiry" sentinel horizon (~10 years). Remnawave requires a
 *  concrete date, so keys that must never expire on the backend's clock carry
 *  this instead of null. */
export const FAR_FUTURE_EXPIRY_DAYS = 3650;

export function farFutureExpiryIso(now = Date.now()): string {
  return new Date(now + FAR_FUTURE_EXPIRY_DAYS * DAY_MS).toISOString();
}

/** True when a backend `expireAt` is (a drifted copy of) the far-future sentinel —
 *  read-side, it maps back to "no expiry". The 5-year threshold sits far above
 *  any real membership term and comfortably below the 10-year sentinel. */
export function isFarFutureExpiry(iso: string, now = Date.now()): boolean {
  const t = Date.parse(iso);
  return Number.isFinite(t) && t - now > 1825 * DAY_MS;
}

/**
 * The backend `expireAt` (ISO) for a user: a paid member's purchased term
 * (`membershipExpiresAt`), else the far-future sentinel — a FREE key never
 * expires on the backend's clock. Free-account reclaim is usage-based instead:
 * the deactivate-idle-free sweep consults the backend's last-online stamp and
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
 * never rejected. Backend-side enforcement additionally requires
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
  // an internal-mode group UUID (activeInternalSquads), Outline ignores it.
  placement?: string | null;
}

export interface IssuedUser {
  backendUserId: string;
  backendShortId: string;
  subscriptionUrl: string;
  raw: unknown;
  /**
   * The UUID-class protocol credential the backend minted for the user (the VLESS
   * id), when the backend exposes one. The L7 front qualification authenticates
   * its test session with it; absent = this backend cannot back that check.
   */
  protocolUuid?: string;
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
  // Backend-side "last seen online" stamp (Remnawave-only; undefined for
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
 * Fleet-wide observability for one backend backend (admin dashboard). Read-only,
 * cached by the healthcheck cron so the dashboard never makes a live backend call.
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
 * the opaque handle a key is homed to (Remnawave: an internal mode group, which maps
 * to one or more nodes); the load is aggregated from that placement's node(s).
 * `usersOnline` is the primary signal (fewest wins). Read-only, refreshed by the
 * healthcheck cron. Mode group-free by design — the generic layer never sees a mode group.
 */
export interface NodeStats {
  placement: string; // opaque handle (Remnawave: internal-mode group uuid)
  label: string; // display name (mode group name)
  usersOnline: number; // summed over the placement's mapped nodes
  trafficBytesRealtime?: number; // summed realtime throughput, when available
  online: boolean; // ≥1 mapped node connected & not disabled
  nodeCount: number; // mapped nodes: 0 = unroutable, >1 = aggregated
}

/**
 * A client-facing connection entry the backend advertises in subscriptions
 * (Remnawave: a Host). Origin edges repoint the ADDRESS of the template Hosts
 * that belong to an origin slot; everything else is read-only here.
 */
export interface BackendHost {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  /** The HTTP Host header the client sends (`null`/`''` = the Host carries none). */
  host?: string | null;
  isDisabled: boolean;
  inbound?: { configProfileUuid: string; configProfileInboundUuid: string } | null;
}

/**
 * A Host repoint. `address`/`port` always move; `sni`/`host` are three-valued:
 * `undefined` = leave the field alone, a string = set it, `null` = CLEAR it.
 * An L4 → L7 transition must be able to clear a stale name, and an L7 → L4 one
 * must be able to clear a stale CDN hostname.
 */
export interface BackendHostPatch {
  uuid: string;
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
}

/** A NEW client-facing Host FCP creates for an origin listener (hostMode `fcp`). */
export interface BackendHostCreate {
  remark: string;
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
}

/**
 * One inbound a backend node serves, as the origin layer needs it for listener
 * discovery (Remnawave: an Xray inbound of the node's active config profile).
 * An ALLOWLIST projection: the protocol, port, stream/security kind and the
 * client-facing names/paths only. Credentials (`clients`), the REALITY private
 * key and short ids, and certificate material are never read into this shape.
 * `port` is null when the backend's value is not one plain port (a range/list).
 */
export interface PanelInbound {
  tag: string;
  configProfileUuid: string;
  configProfileInboundUuid: string;
  /** Xray protocol id as the backend reports it (`vless`, `trojan`, `vmess`, ...). */
  protocol: string;
  port: number | null;
  /** Xray `listen` when set (an inbound bound to loopback is reached only through something else on the node). */
  listen?: string | null;
  /** `streamSettings.network` (`tcp`, `raw`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `kcp`, ...); `tcp` when absent. */
  network: string;
  /** `streamSettings.security` (`none`, `tls`, `reality`); `none` when absent. */
  security: string;
  reality?: { target: string | null; serverNames: string[] };
  tls?: { serverName: string | null };
  ws?: { path: string | null; host: string | null };
  httpupgrade?: { path: string | null; host: string | null };
  grpc?: { serviceName: string | null };
  /** `xhttpSettings` (Xray 1.8.24+): path, host and the mode the inbound serves. */
  xhttp?: { path: string | null; host: string | null; mode: string | null };
  /** Whether the node currently serves this inbound (it is in the node's active inbound set). */
  active: boolean;
}

/**
 * Per-NODE load snapshot (Remnawave: one row per backend node). Distinct from
 * NodeStats, which aggregates per PLACEMENT (mode group): a shared origin mode group
 * spans several nodes, so the origin block detector needs the node grain.
 */
export interface NodeInventoryRow {
  nodeUuid: string;
  name: string;
  usersOnline: number;
  online: boolean;
  /** The node's public address / port / country as the backend knows them (for the origin picker). */
  address?: string;
  port?: number;
  countryCode?: string;
}

import type { PatchChange, PatchOp } from '../panel/patchOps';

// --- Backend observation (server management) -----------------------------------
//
// What FCP reads from a backend to show an operator the nodes, config profiles,
// Hosts and mode groups that already exist. Every shape is NON-SECRET by
// construction: an inbound is the same allowlist projection discovery uses,
// plus digests (convex/lib/backend/digest.ts) that say "this changed" without
// carrying what changed. Nothing here may ever hold a private key, a short id,
// a client, a certificate or a password.

/** The authentication identity of one REALITY inbound; the digest is keyed and value-free. */
export interface PanelRealityAuth {
  digest: string | null;
  /** Derived from the private key. Public by nature (it is in every share link). */
  publicKey: string | null;
  /** The profile stores a `publicKey` that does not belong to its private key. */
  publicKeyMismatch: boolean;
}

export type ObservedTransport = Omit<PanelInbound, 'active'> & {
  realityAuth?: PanelRealityAuth;
};

export interface PanelObservedProfile {
  profileUuid: string;
  name: string;
  /** SHA-256 over the redacted config: storable, drives diffs, blind to secret-only changes. */
  shapeHash: string;
  /** Keyed digest over the complete config: moves on ANY change, secrets included. */
  changeToken: string;
  inbounds: ObservedTransport[];
}

export interface PanelObservedNode {
  nodeUuid: string;
  name: string;
  address: string | null;
  port: number | null;
  countryCode: string | null;
  online: boolean;
  isDisabled: boolean;
  usersOnline: number;
  configProfileUuid: string | null;
  activeInboundUuids: string[];
  tags: string[];
}

export interface PanelObservedHost {
  hostUuid: string;
  remark: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  path: string | null;
  alpn: string | null;
  fingerprint: string | null;
  securityLayer: string | null;
  isDisabled: boolean;
  isHidden: boolean;
  tag: string | null;
  viewPosition: number | null;
  configProfileUuid: string | null;
  configProfileInboundUuid: string | null;
  /** Node uuids the Host is pinned to (empty = every node serving the inbound). */
  nodeUuids: string[];
}

export interface PanelObservedSquad {
  squadUuid: string;
  name: string;
  inboundUuids: string[];
  membersCount: number | null;
}

export interface PanelObservation {
  nodes: PanelObservedNode[];
  profiles: PanelObservedProfile[];
  hosts: PanelObservedHost[];
  squads: PanelObservedSquad[];
}

// --- Backend writes (server management) ------------------------------------------

export interface ProfilePatchPreview {
  profileName: string;
  baseToken: string;
  expectedToken: string;
  changed: boolean;
  changes: PatchChange[];
  touchedTags: string[];
  /** tag -> inbound uuid as read: a settled edit must leave every one of them as it was. */
  inboundUuids: Record<string, string>;
}

/** Every Host field an operator may set. Absent = leave; `null` = clear (sent as ''). */
export interface PanelHostFields {
  remark?: string;
  address?: string;
  port?: number;
  sni?: string | null;
  host?: string | null;
  path?: string | null;
  alpn?: string | null;
  fingerprint?: string | null;
  securityLayer?: string | null;
  isDisabled?: boolean;
  isHidden?: boolean;
  tag?: string | null;
  inbound?: { configProfileUuid: string; configProfileInboundUuid: string };
  /** Node uuids the Host is pinned to; empty = every node serving the inbound. */
  nodeUuids?: string[];
}

export type PanelHostCreate = PanelHostFields & {
  remark: string;
  address: string;
  port: number;
  inbound: { configProfileUuid: string; configProfileInboundUuid: string };
};

/** What the backend says about a node's application state; the only field read is its own clock. */
export interface PanelNodeStatus {
  nodeUuid: string;
  name: string;
  address: string | null;
  port: number | null;
  countryCode: string | null;
  lastStatusChange: string | null;
  isDisabled: boolean;
  configProfileUuid: string | null;
  activeInboundUuids: string[];
}

/** A node row FCP creates on the backend. The node's own secret is never FCP's to fetch. */
export interface PanelNodeCreate {
  name: string;
  address: string;
  port?: number;
  countryCode?: string;
  configProfileUuid: string;
  activeInboundUuids: string[];
}

/** Absent = leave. Profile and inbounds travel together (the backend takes them as one). */
export interface PanelNodeFields {
  name?: string;
  address?: string;
  port?: number;
  countryCode?: string;
  profile?: { configProfileUuid: string; activeInboundUuids: string[] };
}

/** A subscription template row as the backend lists it (type + uuid only). */
export interface PanelSubscriptionTemplateRef {
  uuid: string;
  templateType: string;
}

/** One subscription template in full: JSON body or the base64 YAML body, whichever the type uses. */
export interface PanelSubscriptionTemplate extends PanelSubscriptionTemplateRef {
  templateJson: unknown | null;
  encodedTemplateYaml: string | null;
}

/**
 * What an isolated test link of a REALITY inbound needs, read live and held in
 * memory only: the derived PUBLIC key, ONE short id, the names and the target,
 * plus the digests the resulting confirmation is bound to. The short id is the
 * one value here that is not public; it is never stored, logged or answered
 * over HTTP (docs/servers.md, "Node lifecycle").
 */
export interface PanelInboundTestParams {
  tag: string;
  inboundUuid: string;
  port: number | null;
  publicKey: string;
  shortId: string;
  serverNames: string[];
  /** `host:port` as the profile states it, or null. */
  target: string | null;
  authDigest: string | null;
  changeToken: string;
}

/**
 * The management writes of one backend type. Each is ONE outbound call, never
 * retried by the provider: whether it may be repeated is the ledger's decision.
 */
export interface PanelWrites<C> {
  /** Create a config profile from a complete Xray config. Key material passes through in memory only. */
  createProfile(
    config: C,
    spec: { name: string; config: unknown },
  ): Promise<{ profileUuid: string }>;
  /**
   * The backend-wide node secret (`SECRET_KEY`), for handing to a node the role
   * is bootstrapping. Returned to the caller and nowhere else: never persisted
   * by FCP, never logged, never audited.
   */
  nodeSecret(config: C): Promise<string>;
  listSubscriptionTemplates(config: C): Promise<PanelSubscriptionTemplateRef[]>;
  readSubscriptionTemplate(config: C, uuid: string): Promise<PanelSubscriptionTemplate>;
  updateSubscriptionTemplate(
    config: C,
    uuid: string,
    body: { templateJson?: unknown; encodedTemplateYaml?: string },
  ): Promise<void>;
  /** Live parameters of one REALITY inbound for an isolated test link; null when the tag is not REALITY. */
  readInboundForTest(
    config: C,
    profileUuid: string,
    tag: string,
    digestKey: string,
  ): Promise<PanelInboundTestParams | null>;
  /** The protocol credential (VLESS uuid) of a backend user FCP issued, in memory only. */
  userCredential(config: C, backendUserId: string): Promise<{ protocolUuid: string | null }>;
  createAddress(config: C, spec: PanelHostCreate): Promise<{ hostUuid: string }>;
  updateAddress(config: C, hostUuid: string, fields: PanelHostFields): Promise<void>;
  deleteAddress(config: C, hostUuid: string): Promise<void>;
  reorderAddresses(config: C, order: { hostUuid: string; viewPosition: number }[]): Promise<void>;
  createModeGroup(
    config: C,
    spec: { name: string; inboundUuids: string[] },
  ): Promise<{ squadUuid: string }>;
  updateModeGroup(
    config: C,
    squadUuid: string,
    fields: { name?: string; inboundUuids?: string[] },
  ): Promise<void>;
  deleteModeGroup(config: C, squadUuid: string): Promise<void>;
  createNode(config: C, spec: PanelNodeCreate): Promise<{ nodeUuid: string }>;
  updateNode(config: C, nodeUuid: string, fields: PanelNodeFields): Promise<void>;
  setNodeEnabled(config: C, nodeUuid: string, enabled: boolean): Promise<void>;
  /** Always a FORCED restart: a node otherwise skips it when its config hashes are unchanged. */
  restartNode(config: C, nodeUuid: string): Promise<void>;
  deleteNode(config: C, nodeUuid: string): Promise<void>;
  /**
   * What a typed profile edit WOULD do, from a fresh read: the token of the
   * config as it is, the token it would have afterwards, and the non-secret
   * before/after. Writes nothing.
   */
  previewProfilePatch(
    config: C,
    profileUuid: string,
    ops: readonly PatchOp[],
    digestKey: string,
  ): Promise<ProfilePatchPreview>;
  /**
   * Re-read, refuse unless the config still has `baseToken` (someone else
   * changed it: nothing is sent), apply the edit, send it ONCE. Key material
   * passes through this call in memory and nowhere else.
   */
  applyProfilePatch(
    config: C,
    profileUuid: string,
    ops: readonly PatchOp[],
    baseToken: string,
    digestKey: string,
  ): Promise<{ sent: true } | { sent: false; reason: 'profile_changed' | 'nothing_to_change' }>;
  readProfile(config: C, profileUuid: string, digestKey: string): Promise<PanelObservedProfile>;
  /** Targeted read-backs: the ledger settles an op by LOOKING, never by trusting a response. */
  readHosts(config: C): Promise<PanelObservedHost[]>;
  readSquads(config: C): Promise<PanelObservedSquad[]>;
  readNodeStatus(config: C): Promise<PanelNodeStatus[]>;
}
