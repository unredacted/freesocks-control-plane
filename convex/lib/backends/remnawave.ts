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
  SquadStats,
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

// Per-squad load for the squad-pool balancer. `info.membersCount` is the
// panel's authoritative user count per internal squad. Lenient: a squad row
// missing `info` is skipped (never fails the whole fetch on shape drift).
const InternalSquadsResponse = z.object({
  internalSquads: z.array(
    z.object({
      uuid: z.string(),
      name: z.string(),
      info: z.object({ membersCount: z.number() }).optional(),
    }),
  ),
});

export async function remnawaveGetSquadStats(cfg: RemnawaveConfig): Promise<SquadStats[]> {
  const result = await call(cfg, {
    method: 'GET',
    path: '/api/internal-squads',
    schema: InternalSquadsResponse,
  });
  return result.internalSquads
    .filter((s) => s.info != null)
    .map((s) => ({ squadUuid: s.uuid, name: s.name, membersCount: s.info!.membersCount }));
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
