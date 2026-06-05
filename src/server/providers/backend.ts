/**
 * Proxy backend abstraction. Every supported backend (currently Remnawave;
 * Outline is being added) implements `ProxyBackendProvider`. Higher-level
 * services (subscription-delivery, propagate-tier-change, account reads) call
 * the registry, not specific clients — backend choice is data-driven via the
 * `tiers.backend` and `subscriptions.backend` columns.
 *
 * Adding a third backend:
 *   1. Implement this interface in a new `providers/<name>/backend.ts`.
 *   2. Wire it into `BackendRegistry` in `services/container.ts`.
 *   3. Add the literal to the `BackendId` union below.
 *   4. Update the `tiers.backend` enum on the schema + any migration.
 */
import { z } from 'zod';

export const BackendId = z.enum(['remnawave', 'outline']);
export type BackendId = z.infer<typeof BackendId>;

export const TrafficLimitStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']);
export type TrafficLimitStrategy = z.infer<typeof TrafficLimitStrategy>;

/**
 * The superset of fields any backend might use to issue a new user. Backends
 * ignore the fields that don't apply (Outline has no concept of squads,
 * traffic strategy, or HWID limits; Remnawave has no concept of which Outline
 * server pool a key was issued from).
 */
export interface IssueUserSpec {
  username: string;
  trafficLimitBytes: number | null;
  expireAt: string | null; // ISO 8601, nullable for "no expiry"
  tag: string;
  description?: string;
  // Remnawave-only:
  hwidDeviceLimit?: number | null;
  trafficLimitStrategy?: TrafficLimitStrategy;
  remnawaveSquadUuid?: string | null;
  // Outline-only — admin-configured pool of outline servers this tier may issue from.
  // The pool picker (OutlineServerPool) chooses the best server; if a specific
  // server id is provided here, it's used as a hint.
  outlineServerId?: number;
  outlineServerPoolIds?: number[];
}

export interface IssuedUser {
  /** Remnawave: user uuid. Outline: access-key id. */
  backendUserId: string;
  /** Remnawave: shortUuid. Outline: a stable id we can use for subscription content lookup. */
  backendShortId: string;
  /** Final URL handed to the user — `ss://…` for Outline, the Remnawave sub URL for Remnawave. */
  subscriptionUrl: string;
  /**
   * Outline-only: the `outline_servers.id` row this key lives on. Persisted
   * to `subscriptions.outline_server_id` by SubscriptionDeliveryService so
   * subsequent reads/updates can resolve the right server without scanning.
   */
  outlineServerId?: number;
  /** Provider-native payload — opaque to callers that don't care about it. */
  raw: unknown;
}

export type BackendUserStatus = 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';

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

/**
 * Partial update — backends apply whatever fields they support and ignore
 * the rest. Returning success means "the patch was accepted to the extent
 * that the backend supports it" (not "every field landed").
 */
export type UpdateUserPatch = Partial<
  Pick<
    IssueUserSpec,
    | 'trafficLimitBytes'
    | 'expireAt'
    | 'tag'
    | 'description'
    | 'hwidDeviceLimit'
    | 'trafficLimitStrategy'
    | 'remnawaveSquadUuid'
  >
> & {
  status?: 'active' | 'disabled';
};

export interface SubscriptionContent {
  content: string;
  contentType: string;
}

export interface ProxyBackendProvider {
  readonly id: BackendId;
  issueUser(spec: IssueUserSpec): Promise<IssuedUser>;
  getUser(backendUserId: string): Promise<UserState>;
  updateUser(backendUserId: string, patch: UpdateUserPatch): Promise<void>;
  resetUserTraffic(backendUserId: string): Promise<void>;
  deleteUser(backendUserId: string): Promise<void>;
  fetchSubscriptionContent(backendShortId: string, ua?: string): Promise<SubscriptionContent>;
}
