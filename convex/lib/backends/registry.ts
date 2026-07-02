/**
 * Backend provider registry: the per-type wire-protocol layer behind the generic
 * dispatch in convex/backends.ts. A "provider" is the set of pure HTTP functions
 * for one backend TYPE (Remnawave, Outline, ...); it takes a resolved instance
 * config (a variant of the schema's `backendServerConfig` union) and returns the
 * shared lib/backends/types.ts shapes. Instance selection + key->server
 * resolution are generic and live in convex/backendServers.ts, NOT here.
 *
 * Add a backend type: write its pure fns in convex/lib/backends/<id>.ts, add its
 * config variant below (mirroring the schema union), and register it in
 * PROVIDERS. Keying PROVIDERS by BackendId keeps it exhaustive: a new id with no
 * provider is a compile error.
 */
import type { BackendId } from '../../../src/shared/contracts/backends';
import type {
  IssueUserSpec,
  IssuedUser,
  SubscriptionContent,
  UpdateUserPatch,
  UserState,
} from './types';
import {
  remnawaveDeleteDevice,
  remnawaveDeleteUser,
  remnawaveFetchSubscription,
  remnawaveGetUser,
  remnawaveHealth,
  remnawaveIssueUser,
  remnawaveResetTraffic,
  remnawaveTestConnection,
  remnawaveUpdateUser,
} from './remnawave';
import {
  outlineDelete,
  outlineFetchContent,
  outlineGetState,
  outlineHealth,
  outlineIssue,
  outlineTestConnection,
  outlineUpdate,
} from './outline';

// Per-instance connection config. These mirror the `backendServerConfig` union
// in convex/schema.ts: a row's `config` is read back as exactly one variant.
export interface RemnawaveServerConfig {
  type: 'remnawave';
  baseUrl: string;
  apiToken: string;
}
export interface OutlineInstanceConfig {
  type: 'outline';
  apiUrl: string;
  websocketEnabled: boolean;
  websocketDomain?: string;
  prometheusUrl?: string;
}
export type BackendConfig = RemnawaveServerConfig | OutlineInstanceConfig;

export interface BackendHealth {
  // null = this backend doesn't expose a cheap instance key count (Remnawave),
  // so the healthcheck leaves the stored count alone instead of clobbering it.
  keyCount: number | null;
  rttMs: number;
}
export type TestConnectionResult = { ok: true; keyCount: number } | { ok: false; error: string };

/** The uniform operation set every backend type implements. */
export interface BackendProvider<C extends BackendConfig = BackendConfig> {
  issue(config: C, spec: IssueUserSpec): Promise<IssuedUser>;
  get(config: C, backendUserId: string): Promise<UserState>;
  update(config: C, backendUserId: string, patch: UpdateUserPatch): Promise<void>;
  resetTraffic(config: C, backendUserId: string): Promise<void>;
  remove(config: C, backendUserId: string): Promise<void>;
  // Optional: revoke one HWID device (frees a slot under the tier's device
  // cap). Absent for backends with no device concept (Outline).
  removeDevice?(config: C, backendUserId: string, hwid: string): Promise<void>;
  fetchContent(
    config: C,
    backendShortId: string,
    userAgent?: string,
    subscriptionUrl?: string,
  ): Promise<SubscriptionContent>;
  health(config: C): Promise<BackendHealth>;
  testConnection(config: C): Promise<TestConnectionResult>;
}

const remnawaveProvider: BackendProvider<RemnawaveServerConfig> = {
  issue: (c, spec) => remnawaveIssueUser(c, spec),
  get: (c, id) => remnawaveGetUser(c, id),
  update: (c, id, patch) => remnawaveUpdateUser(c, id, patch),
  resetTraffic: (c, id) => remnawaveResetTraffic(c, id),
  remove: (c, id) => remnawaveDeleteUser(c, id),
  removeDevice: (c, id, hwid) => remnawaveDeleteDevice(c, id, hwid),
  fetchContent: (c, shortId, ua, subUrl) => remnawaveFetchSubscription(c, shortId, ua, subUrl),
  health: (c) => remnawaveHealth(c),
  testConnection: (c) => remnawaveTestConnection(c),
};

const outlineProvider: BackendProvider<OutlineInstanceConfig> = {
  issue: (c, spec) =>
    outlineIssue(c, { username: spec.username, trafficLimitBytes: spec.trafficLimitBytes }),
  get: (c, id) => outlineGetState(c, id),
  update: (c, id, patch) => outlineUpdate(c, id, patch),
  // Outline exposes no per-key traffic reset; metrics roll on the server window.
  resetTraffic: async () => {},
  remove: (c, id) => outlineDelete(c, id),
  fetchContent: (c, shortId) => outlineFetchContent(c, shortId),
  health: async (c) => {
    const started = Date.now();
    const { keyCount } = await outlineHealth(c);
    return { keyCount, rttMs: Date.now() - started };
  },
  testConnection: (c) => outlineTestConnection(c),
};

/**
 * The provider for each backend type. The casts erase the per-provider config
 * generic (a registry can only be typed at the widened config); soundness is the
 * invariant that a row's `backend` always matches its `config.type`, enforced by
 * the create/update mutations, so dispatch always pairs the right config with
 * the right provider.
 */
export const PROVIDERS: Record<BackendId, BackendProvider> = {
  remnawave: remnawaveProvider as unknown as BackendProvider,
  outline: outlineProvider as unknown as BackendProvider,
};
