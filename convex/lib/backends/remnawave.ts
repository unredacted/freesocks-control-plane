/**
 * Remnawave proxy backend, ported from src/server/providers/remnawave/* into
 * config-based functions callable from a Convex action (V8 runtime: `fetch`
 * only, no Node deps). The native client + adapter were merged here; response
 * shapes are still validated with zod.
 */
import { z } from 'zod';
import type {
  BackendDevice,
  FleetStats,
  IssueUserSpec,
  IssuedUser,
  NodeStats,
  SubscriptionContent,
  UpdateUserPatch,
  UsageSeries,
  UserState,
} from './types';

export interface RemnawaveConfig {
  baseUrl: string;
  apiToken: string;
  timeoutMs?: number;
}

const TrafficLimitStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']);
const RemnawaveUserStatus = z.enum(['ACTIVE', 'DISABLED', 'LIMITED', 'EXPIRED']);

const RemnawaveUser = z.object({
  uuid: z.string().uuid(),
  shortUuid: z.string(),
  username: z.string(),
  status: RemnawaveUserStatus,
  trafficLimitBytes: z.number().int().nonnegative().nullable(),
  trafficLimitStrategy: TrafficLimitStrategy,
  // The reset anchor for the member's "resets in N days" hint. Display-only
  // string; nullish on NO_RESET tiers / older panels (kept lenient like the
  // device dates so a format change can't fail-parse the whole user).
  lastTrafficResetAt: z.string().nullish(),
  // Remnawave omits this on the CREATE response (a brand-new user has used
  // nothing); default to 0 so issuance parses. On GET it's present and kept.
  usedTrafficBytes: z
    .number()
    .int()
    .nonnegative()
    .nullish()
    .transform((v) => v ?? 0),
  expireAt: z.string().datetime().nullable(),
  hwidDeviceLimit: z.number().int().nonnegative().nullable(),
  subscriptionUrl: z.string().url(),
});
type RemnawaveUser = z.infer<typeof RemnawaveUser>;

// The device object Remnawave returns. Extra fields (userId/osVersion/
// userAgent/requestIp) are stripped by Zod — we deliberately do NOT surface the
// IP or user-agent (metadata minimization). Dates are kept as plain strings
// (display-only), so a panel date-format change can't fail-parse the whole list.
const HwidDevice = z.object({
  hwid: z.string(),
  platform: z.string().nullish(),
  deviceModel: z.string().nullish(),
  createdAt: z.string().nullish(),
  updatedAt: z.string().nullish(),
});
const HwidDevicesResponse = z.object({ devices: z.array(HwidDevice).default([]) });

class RemnawaveApiError extends Error {
  meta?: Record<string, unknown>;
  constructor(message: string, meta?: Record<string, unknown>) {
    super(message);
    this.name = 'RemnawaveApiError';
    this.meta = meta;
  }
  static async fromResponse(res: Response, path: string): Promise<RemnawaveApiError> {
    let body: string | undefined;
    try {
      body = await res.text();
    } catch {
      body = undefined;
    }
    // Deliberately do NOT capture the full URL (it carries the bearer token in
    // some misconfigurations); only the path + a short body slice. The body
    // slice goes in the MESSAGE too (not just meta) so it reaches the function
    // logs — it's Remnawave's own error text (e.g. validation / auth), not a
    // secret. The member still only ever sees a generic 502.
    const snippet = body?.slice(0, 200);
    return new RemnawaveApiError(
      `Remnawave ${res.status} on ${path}${snippet ? `: ${snippet}` : ''}`,
      { status: res.status, path, body: snippet },
    );
  }
}

/** True when the error is a Remnawave HTTP 404 (e.g. a HWID-gated subscription
 *  fetch made without a valid x-hwid header — the panel rejects it). Lets the
 *  fronted route pass the rejection through as 404 rather than a generic 502. */
export function isRemnawaveNotFound(err: unknown): boolean {
  return err instanceof RemnawaveApiError && err.meta?.status === 404;
}

/** Some endpoints wrap the payload in `{ response: {...} }`; tolerate both. */
function unwrap(json: unknown): unknown {
  if (json && typeof json === 'object' && 'response' in json) {
    return (json as { response: unknown }).response;
  }
  return json;
}

async function call<T>(
  cfg: RemnawaveConfig,
  args: {
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    path: string;
    body?: unknown;
    schema: z.ZodType<T>;
  },
): Promise<T> {
  const url = new URL(args.path, cfg.baseUrl).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 8000);
  try {
    const res = await fetch(url, {
      method: args.method,
      headers: {
        authorization: `Bearer ${cfg.apiToken}`,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: args.body !== undefined ? JSON.stringify(args.body) : undefined,
      signal: controller.signal,
    });
    if (!res.ok) throw await RemnawaveApiError.fromResponse(res, args.path);
    const parsed = args.schema.safeParse(unwrap(await res.json()));
    if (!parsed.success) {
      // Name the offending FIELDS (paths only, never values) so a Remnawave
      // version/shape difference is diagnosable from the logs — the most common
      // cause of a 2xx that still fails issuance.
      const issues = parsed.error.issues
        .slice(0, 6)
        .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
        .join('; ');
      throw new RemnawaveApiError(`Remnawave schema mismatch on ${args.path} (${issues})`, {
        path: args.path,
      });
    }
    return parsed.data;
  } finally {
    clearTimeout(timer);
  }
}

// --- Config-profile logging privacy (no client-IP logging) ------------------

/** The no-client-IP-logging Xray `log` block FCP enforces on every config profile
 *  (matches docs/privacy.md §5): no access log (the per-connection source-IP
 *  record), no error log, DNS logging off, and address masking as belt-and-
 *  suspenders if an operator later raises the level. */
export const PRIVACY_XRAY_LOG = {
  access: 'none',
  error: 'none',
  loglevel: 'none',
  dnsLog: false,
  maskAddress: 'full',
} as const;

export interface RemnawaveLoggingProfile {
  uuid: string;
  name: string;
  /** True once the profile carries the no-logging posture (already, or after apply). */
  hardened: boolean;
  /** True if this run changed it (apply) or WOULD change it (dry-run). */
  changed: boolean;
  /** Set when the profile was skipped (malformed / no inbounds) — never written. */
  error?: string;
}
export interface RemnawaveLoggingReport {
  profiles: RemnawaveLoggingProfile[];
}

/**
 * Deep-merge the no-client-IP-logging posture into an Xray config: set `log` to
 * PRIVACY_XRAY_LOG and `policy.levels."0".statsUserOnline` false, PRESERVING every
 * other key (inbounds, outbounds, routing, streamSettings/Reality, dns, ...).
 * Idempotent. THROWS if the config isn't a real Xray config (no non-empty
 * `inbounds`), so a read-modify-write can NEVER PATCH a degenerate config that
 * would wipe a node's inbounds. Exported for unit testing.
 */
export function hardenXrayLoggingConfig(config: unknown): {
  config: Record<string, unknown>;
  changed: boolean;
} {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new RemnawaveApiError('refusing to harden: config-profile config is not an object');
  }
  const c = { ...(config as Record<string, unknown>) };
  if (!Array.isArray(c.inbounds) || c.inbounds.length === 0) {
    throw new RemnawaveApiError('refusing to harden: config has no inbounds (would wipe the node)');
  }
  const obj = (val: unknown): Record<string, unknown> =>
    val && typeof val === 'object' && !Array.isArray(val)
      ? { ...(val as Record<string, unknown>) }
      : {};
  const logMatches = JSON.stringify(c.log ?? null) === JSON.stringify(PRIVACY_XRAY_LOG);
  const policy = obj(c.policy);
  const levels = obj(policy.levels);
  const level0 = obj(levels['0']);
  const statsOff = level0.statsUserOnline === false;
  if (logMatches && statsOff) return { config: c, changed: false };
  c.log = { ...PRIVACY_XRAY_LOG };
  level0.statsUserOnline = false;
  levels['0'] = level0;
  policy.levels = levels;
  c.policy = policy;
  return { config: c, changed: true };
}

const ConfigProfileRow = z.object({ uuid: z.string(), name: z.string(), config: z.unknown() });
// The list endpoint wraps in { response: ... }; after `call` unwraps, tolerate
// both { configProfiles: [...] } and a bare array.
const ConfigProfilesList = z.union([
  z.object({ configProfiles: z.array(ConfigProfileRow) }),
  z.array(ConfigProfileRow),
]);

/**
 * Enforce the no-client-IP-logging posture on EVERY Remnawave config profile
 * (docs/privacy.md §5) via a SAFE read-modify-write: GET the full config, merge
 * ONLY `log` + `policy.levels."0".statsUserOnline`, then PATCH the whole config
 * back — Remnawave replaces the config wholesale + re-derives inbounds, so the
 * complete object must be sent, and everything else is preserved verbatim.
 * Idempotent: an already-hardened profile is skipped (no needless node restart).
 * `dryRun` reports what WOULD change without writing. A malformed profile is
 * reported + skipped, never written. Remnawave 2.x only (Config Profiles API).
 */
export async function remnawaveHardenLogging(
  cfg: RemnawaveConfig,
  opts: { dryRun: boolean },
): Promise<RemnawaveLoggingReport> {
  const listed = await call(cfg, {
    method: 'GET',
    path: '/api/config-profiles',
    schema: ConfigProfilesList,
  });
  const rows = Array.isArray(listed) ? listed : listed.configProfiles;
  const report: RemnawaveLoggingReport = { profiles: [] };
  for (const p of rows) {
    try {
      const merged = hardenXrayLoggingConfig(p.config);
      if (merged.changed && !opts.dryRun) {
        await call(cfg, {
          method: 'PATCH',
          path: '/api/config-profiles',
          body: { uuid: p.uuid, config: merged.config },
          schema: z.unknown(),
        });
      }
      report.profiles.push({
        uuid: p.uuid,
        name: p.name,
        hardened: opts.dryRun ? !merged.changed : true,
        changed: merged.changed,
      });
    } catch (err) {
      report.profiles.push({
        uuid: p.uuid,
        name: p.name,
        hardened: false,
        changed: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return report;
}

function toState(user: RemnawaveUser, devices: BackendDevice[]): UserState {
  const status =
    user.status === 'ACTIVE'
      ? 'active'
      : user.status === 'DISABLED'
        ? 'disabled'
        : user.status === 'LIMITED'
          ? 'limited'
          : user.status === 'EXPIRED'
            ? 'expired'
            : 'unknown';
  return {
    trafficLimitBytes: user.trafficLimitBytes,
    usedTrafficBytes: user.usedTrafficBytes,
    trafficLimitStrategy: user.trafficLimitStrategy,
    lastTrafficResetAt: user.lastTrafficResetAt ?? undefined,
    expireAt: user.expireAt,
    status,
    devices,
  };
}

const DAY_MS = 86_400_000;

/**
 * Remnawave REQUIRES `expireAt` on create. Our model treats `expireAt: null` as
 * "no backend-enforced expiry — FCP's lifecycle (grace → disable → delete) is the
 * source of truth", so we send a far-future date as that sentinel rather than let
 * Remnawave expire the key on its own clock.
 */
function expiryOrFarFuture(expireAt: string | null): string {
  return expireAt ?? new Date(Date.now() + 3650 * DAY_MS).toISOString();
}

/**
 * Remnawave tags accept only `[A-Z0-9_]`. Coerce our slug-style tag (e.g.
 * "member" → "MEMBER"); return undefined when nothing usable remains, so the
 * field is omitted (Remnawave allows that) rather than sent invalid.
 */
function toRemnawaveTag(tag: string | undefined): string | undefined {
  if (!tag) return undefined;
  const t = tag
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, '_')
    .slice(0, 16);
  return t.length > 0 ? t : undefined;
}

export async function remnawaveIssueUser(
  cfg: RemnawaveConfig,
  spec: IssueUserSpec,
): Promise<IssuedUser> {
  const user = await call(cfg, {
    method: 'POST',
    path: '/api/users',
    body: {
      username: spec.username,
      trafficLimitBytes: spec.trafficLimitBytes ?? undefined,
      trafficLimitStrategy: spec.trafficLimitStrategy ?? 'MONTH',
      // Required by Remnawave; null spec => far-future sentinel (FCP owns expiry).
      expireAt: expiryOrFarFuture(spec.expireAt),
      hwidDeviceLimit: spec.hwidDeviceLimit ?? undefined,
      // Remnawave restricts tags to [A-Z0-9_]; coerce our lowercase slug.
      tag: toRemnawaveTag(spec.tag),
      description: spec.description,
      // The opaque placement handle IS the internal-squad UUID for Remnawave.
      activeInternalSquads: spec.placement ? [spec.placement] : undefined,
    },
    schema: RemnawaveUser,
  });
  return {
    backendUserId: user.uuid,
    backendShortId: user.shortUuid,
    subscriptionUrl: user.subscriptionUrl,
    raw: user,
  };
}

async function listDevices(cfg: RemnawaveConfig, userUuid: string): Promise<BackendDevice[]> {
  try {
    const result = await call(cfg, {
      method: 'GET',
      // Remnawave HWID controller is `/api/hwid`; a user's devices live at
      // `devices/{userUuid}` (path param, NOT a `?userUuid=` query). See the
      // contract table in docs/backends.md.
      path: `/api/hwid/devices/${encodeURIComponent(userUuid)}`,
      schema: HwidDevicesResponse,
    });
    return result.devices.map((d) => ({
      hwid: d.hwid,
      platform: d.platform ?? undefined,
      deviceModel: d.deviceModel ?? undefined,
      firstSeenAt: d.createdAt ?? undefined,
      lastSeenAt: d.updatedAt ?? undefined,
    }));
  } catch {
    // Some panel versions don't expose this endpoint; degrade to "no devices".
    return [];
  }
}

/**
 * Revoke one HWID device from a user, freeing a slot under the tier's device
 * cap without the nuclear full-key regenerate. Unlike listDevices (which
 * degrades to "no devices" on panels without the endpoint), a failed delete
 * THROWS — the member asked for a specific effect and must not be told it
 * succeeded when it didn't. The response body is version-dependent (some
 * panels echo the remaining device list), so it is deliberately not parsed.
 */
export async function remnawaveDeleteDevice(
  cfg: RemnawaveConfig,
  backendUserId: string,
  hwid: string,
): Promise<void> {
  await call(cfg, {
    method: 'POST',
    // `/api/hwid/devices/delete` (the HWID controller is `/api/hwid`); the body
    // carries the ids. Response echoes the remaining list, deliberately unparsed.
    path: '/api/hwid/devices/delete',
    body: { userUuid: backendUserId, hwid },
    schema: z.unknown(),
  });
}

export async function remnawaveGetUser(
  cfg: RemnawaveConfig,
  backendUserId: string,
): Promise<UserState> {
  const user = await call(cfg, {
    method: 'GET',
    path: `/api/users/${backendUserId}`,
    schema: RemnawaveUser,
  });
  return toState(user, await listDevices(cfg, backendUserId));
}

/**
 * Aggregate traffic-usage series for the member "usage trend" (last `days` days).
 * `GET /api/bandwidth-stats/users/{uuid}?start&end`. The response also carries a
 * per-node / per-country breakdown (`series` / `topNodes`) which we DELIBERATELY
 * DROP — only the aggregate sparkline reaches the member (metadata minimization).
 */
const UserUsageResponse = z.object({
  categories: z.array(z.string()).default([]),
  sparklineData: z.array(z.number()).default([]),
});

export async function remnawaveGetUserUsage(
  cfg: RemnawaveConfig,
  backendUserId: string,
  days: number,
): Promise<UsageSeries> {
  const end = new Date();
  const start = new Date(Date.now() - Math.max(1, days) * DAY_MS);
  const ymd = (d: Date) => d.toISOString().slice(0, 10);
  const result = await call(cfg, {
    method: 'GET',
    path: `/api/bandwidth-stats/users/${encodeURIComponent(backendUserId)}?start=${ymd(start)}&end=${ymd(end)}&topNodesLimit=1`,
    schema: UserUsageResponse,
  });
  return {
    points: result.sparklineData,
    labels: result.categories,
    total: result.sparklineData.reduce((a, b) => a + b, 0),
  };
}

// Fleet observability from two panel endpoints (both admin, read-only). Schemas
// pick only what the dashboard shows; unknown fields are stripped. Traffic totals
// arrive as bigint strings, so parse to Number for display (beta-scale safe).
const SystemStatsResponse = z.object({
  onlineStats: z.object({ onlineNow: z.number() }),
  nodes: z.object({ totalOnline: z.number(), totalBytesLifetime: z.string() }),
});
const RecapResponse = z.object({
  thisMonth: z.object({ traffic: z.string() }),
  total: z.object({ nodes: z.number(), traffic: z.string(), distinctCountries: z.number() }),
  version: z.string(),
});

export async function remnawaveFleetStats(cfg: RemnawaveConfig): Promise<FleetStats> {
  const [sys, recap] = await Promise.all([
    call(cfg, { method: 'GET', path: '/api/system/stats', schema: SystemStatsResponse }),
    call(cfg, { method: 'GET', path: '/api/system/stats/recap', schema: RecapResponse }),
  ]);
  const toNum = (s: string) => {
    const n = Number(s);
    return Number.isFinite(n) ? n : 0;
  };
  return {
    onlineNow: sys.onlineStats.onlineNow,
    nodesOnline: sys.nodes.totalOnline,
    nodesTotal: recap.total.nodes,
    distinctCountries: recap.total.distinctCountries,
    monthTrafficBytes: toNum(recap.thisMonth.traffic),
    lifetimeTrafficBytes: toNum(recap.total.traffic),
    panelVersion: recap.version,
  };
}

// --- Node-load placement telemetry ------------------------------------------
// FCP homes a new key to the least-loaded NODE. A key is assigned to an internal
// SQUAD (activeInternalSquads), and a squad maps to one or more nodes; the squad's
// load is aggregated from those nodes. We therefore fetch: the squad list, the
// per-squad node membership (accessible-nodes), and the per-node load (/api/nodes)
// + best-effort realtime bandwidth. All schemas are LENIENT (strip unknowns,
// nullish) so a panel-version field drift degrades gracefully rather than failing
// the whole cron. Field names verified against remnawave/backend `main` (nodes.schema,
// internal-squads accessible-nodes command) — re-confirm on a panel upgrade.

const InternalSquadsResponse = z.object({
  internalSquads: z.array(z.object({ uuid: z.string(), name: z.string() })),
});

// /api/nodes → (unwrapped) an array of nodes. Only the load-relevant fields.
const NodesResponse = z.array(
  z.object({
    uuid: z.string(),
    isConnected: z.boolean().nullish(),
    isDisabled: z.boolean().nullish(),
    usersOnline: z.number().nullish(),
    trafficUsedBytes: z.number().nullish(),
  }),
);

// /api/internal-squads/{uuid}/accessible-nodes → (unwrapped) { accessibleNodes: [{ uuid, … }] }.
const AccessibleNodesResponse = z.object({
  accessibleNodes: z.array(z.object({ uuid: z.string() })),
});

// /api/bandwidth-stats/nodes/realtime — best-effort; shape is version-sensitive,
// so parse VERY loosely: an array of { nodeUuid?/uuid?, ...bytes-ish }. We only
// use it as a secondary tiebreak and skip it silently if it doesn't parse.
const RealtimeNodesResponse = z
  .array(
    z
      .object({
        nodeUuid: z.string().nullish(),
        uuid: z.string().nullish(),
        totalBytes: z.number().nullish(),
        bytes: z.number().nullish(),
      })
      .passthrough(),
  )
  .nullish();

/**
 * Per-placement (per-squad) load snapshot for node placement. Aggregates each
 * squad's node load from /api/nodes over the squad's accessible-nodes. N+1
 * accessible-nodes calls (one per squad) — fine at beta squad counts; the cron
 * runs it every 10 min best-effort.
 */
export async function remnawaveGetNodeStats(cfg: RemnawaveConfig): Promise<NodeStats[]> {
  const squads = await call(cfg, {
    method: 'GET',
    path: '/api/internal-squads',
    schema: InternalSquadsResponse,
  });
  const nodes = await call(cfg, { method: 'GET', path: '/api/nodes', schema: NodesResponse });
  const nodeById = new Map(nodes.map((n) => [n.uuid, n]));

  // Secondary signal: realtime per-node bytes. Best-effort — never fail the pull.
  const realtimeById = new Map<string, number>();
  try {
    const rt = await call(cfg, {
      method: 'GET',
      path: '/api/bandwidth-stats/nodes/realtime',
      schema: RealtimeNodesResponse,
    });
    for (const r of rt ?? []) {
      const id = r.nodeUuid ?? r.uuid;
      const bytes = r.totalBytes ?? r.bytes;
      if (id && typeof bytes === 'number') realtimeById.set(id, bytes);
    }
  } catch {
    /* realtime unavailable this cycle → usersOnline-only scoring */
  }

  const out: NodeStats[] = [];
  for (const squad of squads.internalSquads) {
    let accessible: z.infer<typeof AccessibleNodesResponse>;
    try {
      accessible = await call(cfg, {
        method: 'GET',
        path: `/api/internal-squads/${encodeURIComponent(squad.uuid)}/accessible-nodes`,
        schema: AccessibleNodesResponse,
      });
    } catch {
      // A squad whose node membership can't be read is emitted as unroutable
      // (nodeCount 0 → the picker deprioritizes/skips it), never dropped silently.
      out.push({
        placement: squad.uuid,
        label: squad.name,
        usersOnline: 0,
        online: false,
        nodeCount: 0,
      });
      continue;
    }
    let usersOnline = 0;
    let realtime = 0;
    let online = false;
    let mapped = 0;
    for (const { uuid } of accessible.accessibleNodes) {
      const n = nodeById.get(uuid);
      if (!n) continue; // node not in /api/nodes (deleted mid-cycle) — skip
      mapped++;
      usersOnline += n.usersOnline ?? 0;
      realtime += realtimeById.get(uuid) ?? 0;
      if (n.isConnected && !n.isDisabled) online = true;
    }
    out.push({
      placement: squad.uuid,
      label: squad.name,
      usersOnline,
      ...(realtimeById.size > 0 ? { trafficBytesRealtime: realtime } : {}),
      online,
      nodeCount: mapped,
    });
  }
  return out;
}

export async function remnawaveUpdateUser(
  cfg: RemnawaveConfig,
  backendUserId: string,
  patch: UpdateUserPatch,
): Promise<void> {
  // Remnawave's update is `PATCH /api/users` with the target `uuid` IN THE BODY
  // (the route has no path param; the DTO requires uuid or username). Seed it here.
  const body: Record<string, unknown> = { uuid: backendUserId };
  if (patch.trafficLimitBytes !== undefined) body.trafficLimitBytes = patch.trafficLimitBytes;
  if (patch.trafficLimitStrategy !== undefined)
    body.trafficLimitStrategy = patch.trafficLimitStrategy;
  if (patch.expireAt !== undefined) body.expireAt = patch.expireAt;
  if (patch.hwidDeviceLimit !== undefined) body.hwidDeviceLimit = patch.hwidDeviceLimit;
  if (patch.description !== undefined) body.description = patch.description;
  if (patch.tag !== undefined) body.tag = toRemnawaveTag(patch.tag);
  if (patch.placement !== undefined) {
    // The placement handle IS the squad UUID; present+null/'' clears it, a value sets it.
    body.activeInternalSquads = patch.placement ? [patch.placement] : [];
  }
  await call(cfg, {
    method: 'PATCH',
    path: '/api/users',
    body,
    schema: RemnawaveUser,
  });
}

/**
 * Enable / disable a user via Remnawave's dedicated action endpoints
 * (`POST /api/users/{uuid}/actions/{enable|disable}`) rather than folding status
 * into the field-update PATCH. More faithful to the API and decoupled from the
 * (heavier) update call. Remnawave rejects setting LIMITED/EXPIRED here (it owns
 * those), which matches our two-state active|disabled model.
 */
export async function remnawaveSetStatus(
  cfg: RemnawaveConfig,
  backendUserId: string,
  active: boolean,
): Promise<void> {
  await call(cfg, {
    method: 'POST',
    path: `/api/users/${backendUserId}/actions/${active ? 'enable' : 'disable'}`,
    schema: z.unknown(),
  });
}

export async function remnawaveResetTraffic(
  cfg: RemnawaveConfig,
  backendUserId: string,
): Promise<void> {
  await call(cfg, {
    method: 'POST',
    path: `/api/users/${backendUserId}/actions/reset-traffic`,
    schema: z.unknown(),
  });
}

export async function remnawaveDeleteUser(
  cfg: RemnawaveConfig,
  backendUserId: string,
): Promise<void> {
  try {
    await call(cfg, {
      method: 'DELETE',
      path: `/api/users/${backendUserId}`,
      schema: z.unknown(),
    });
  } catch (err) {
    // Idempotent delete: an already-absent user (404) is success. This lets the
    // teardown sweep safely retry after a partial run (backend deleted, local
    // mark not yet committed) without looping forever on a 404.
    if (err instanceof RemnawaveApiError && err.meta?.status === 404) return;
    throw err;
  }
}

export async function remnawaveFetchSubscription(
  cfg: RemnawaveConfig,
  backendShortId: string,
  userAgent?: string,
  subscriptionUrl?: string,
  hwidHeaders?: Record<string, string>,
): Promise<SubscriptionContent> {
  // The raw content lives at the panel-provided PUBLIC subscription URL (the
  // shortUuid is the capability), NOT the admin API — `/api/subscriptions/...`
  // doesn't exist and 404s. Fetch that URL with NO admin Bearer (it's public).
  // Fall back to the conventional `/api/sub/<shortUuid>` only if we weren't
  // handed a URL (legacy callers); no UA → Remnawave serves the default base64
  // subscription rather than an HTML landing page.
  const url = subscriptionUrl ?? new URL(`/api/sub/${backendShortId}`, cfg.baseUrl).toString();
  const headers: Record<string, string> = {};
  if (userAgent) headers['user-agent'] = userAgent;
  // Forward the client's HWID identification headers so the panel registers the
  // device + enforces the limit (with HWID_DEVICE_LIMIT_ENABLED on, a fetch
  // without x-hwid is rejected 404 — the caller passes that through).
  if (hwidHeaders) for (const [k, val] of Object.entries(hwidHeaders)) headers[k] = val;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 8000);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) throw await RemnawaveApiError.fromResponse(res, 'subscription content');
    // Pass through the well-known subscription metadata headers (never a secret)
    // so the FCP-fronted URL is a faithful stand-in for the panel URL — the proxy
    // app still sees its traffic/expiry counters + update cadence.
    const passthrough: Record<string, string> = {};
    for (const h of [
      'subscription-userinfo',
      'profile-update-interval',
      'profile-title',
      'profile-web-page-url',
    ]) {
      const val = res.headers.get(h);
      if (val) passthrough[h] = val;
    }
    return {
      content: await res.text(),
      contentType: res.headers.get('content-type') ?? 'text/plain',
      headers: passthrough,
    };
  } finally {
    clearTimeout(timer);
  }
}

// A well-formed but absent user id: the panel answers 404 (reachable + token
// accepted) rather than 200, which is exactly what a health probe wants.
const HEALTH_PROBE_UUID = '00000000-0000-4000-8000-000000000000';

/**
 * Reachability + auth probe for the healthcheck cron + the admin
 * test-connection button. A 2xx or 404 means the panel is up and the token was
 * accepted; 401/403 means bad credentials; anything else (or a network error)
 * is unhealthy. `keyCount` is not cheaply available from Remnawave, so it is
 * `null` — the healthcheck then LEAVES the locally-bumped estimate alone instead
 * of clobbering it to 0 every cycle (P2: that reset broke multi-instance pool
 * load-scoring). Never leaks the token or URL (RemnawaveApiError scrubs them).
 */
export async function remnawaveHealth(
  cfg: RemnawaveConfig,
): Promise<{ keyCount: number | null; rttMs: number }> {
  const url = new URL(`/api/users/${HEALTH_PROBE_UUID}`, cfg.baseUrl).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 8000);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${cfg.apiToken}`, accept: 'application/json' },
      signal: controller.signal,
    });
    const rttMs = Date.now() - started;
    if (res.ok || res.status === 404) return { keyCount: null, rttMs };
    throw new RemnawaveApiError(`Remnawave ${res.status} on /api/users/{id}`, {
      status: res.status,
      path: '/api/users/{id}',
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Pre-save connectivity check; surfaces the HTTP status but never the secret. */
export async function remnawaveTestConnection(
  cfg: RemnawaveConfig,
): Promise<{ ok: true; keyCount: number } | { ok: false; error: string }> {
  try {
    const { keyCount } = await remnawaveHealth(cfg);
    return { ok: true, keyCount: keyCount ?? 0 };
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError')
      return { ok: false, error: 'Connection timed out' };
    const status = (err as { meta?: { status?: number } }).meta?.status;
    return { ok: false, error: status ? `Remnawave returned HTTP ${status}` : 'Connection failed' };
  }
}
