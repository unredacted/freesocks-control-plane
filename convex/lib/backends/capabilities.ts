/**
 * Declarative per-backend capability record — the DB-side answer to "what can
 * this backend do?". Domain code (queries, mutations, actions) branches on
 * these flags instead of on backend-id literals, so adding a backend type is a
 * matter of declaring its row here rather than auditing every `if (backend ===
 * 'remnawave')` in the repo.
 *
 * Deliberately SEPARATE from registry.ts: the registry pulls the fetch-heavy
 * provider modules, and plenty of query/mutation code needs capabilities
 * without dragging HTTP provider code into its import graph. The two layers
 * are kept from drifting by capabilities.test.ts, which asserts each flag
 * against the presence of the matching optional provider method (and, once the
 * placement seam lands, against PLACEMENT_RESOLVERS).
 *
 * `Record<BackendId, ...>` makes a missing row a compile error when a new id
 * lands in BACKEND_IDS.
 */
import type { BackendId } from '../backendIds';

export interface BackendCapabilities {
  /** Mode→placement binding exists: placement is resolved at issue time,
   *  persisted on the subscription, re-sent on tier pushes, and a
   *  placement-less key is an auditable anomaly. */
  placement: boolean;
  /** Subscription content lists per-node endpoints that should be pinned to
   *  one node per key (pinSubscriptionToNode over the fetched content). */
  nodePinning: boolean;
  /** HWID device limits: device list, revoke, hwidDeviceLimit sends. */
  deviceManagement: boolean;
  /** Per-node load/online stats (the healthcheck cron's getNodeStats pull,
   *  the member node-status live path, load bands). */
  nodeStats: boolean;
  /** Instances contribute member-facing locations (location picker, status
   *  page location list). */
  locations: boolean;
  /** Fleet-wide traffic-limit updates in bulk; without it callers fall back
   *  to per-user updates. */
  bulkTrafficUpdate: boolean;
  /** Per-user usage history series (the member usage trend panel). */
  usageHistory: boolean;
  /** A 404 from fetchSubscriptionContent means the panel rejected the DEVICE
   *  (HWID enforcement), not that the key is gone. */
  fetch404IsDeviceRejection: boolean;
}

export const CAPABILITIES: Record<BackendId, BackendCapabilities> = {
  remnawave: {
    placement: true,
    nodePinning: true,
    deviceManagement: true,
    nodeStats: true,
    locations: true,
    bulkTrafficUpdate: true,
    usageHistory: true,
    fetch404IsDeviceRejection: true,
  },
  outline: {
    placement: false,
    nodePinning: false,
    deviceManagement: false,
    nodeStats: false,
    locations: false,
    bulkTrafficUpdate: false,
    usageHistory: false,
    fetch404IsDeviceRejection: false,
  },
};

export function capabilitiesOf(backend: BackendId): BackendCapabilities {
  return CAPABILITIES[backend];
}
