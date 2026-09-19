/**
 * Remnawave proxy backend, ported from src/server/providers/remnawave/* into
 * config-based functions callable from a Convex action (V8 runtime: `fetch`
 * only, no Node deps). The native client + adapter were merged here; response
 * shapes are still validated with zod.
 *
 * CONTRACT VERSIONS. Remnawave 2.x addresses a user by `uuid`; 3.0 dropped the
 * user uuid and addresses users by their per-panel numeric `id` (path params,
 * `PATCH /api/users` body `id`, hwid `userId`, bulk `userIds`). Everything else
 * FCP touches (shortUuid + the public subscription URL, internal squads, nodes,
 * config profiles, system stats) is unchanged. The provider speaks BOTH: the
 * contract is inferred from the shape of the RAW id it is handed (a UUID → 2.x,
 * an integer → 3.x), so a mixed fleet keeps working while panels are upgraded
 * one at a time, and a freshly issued key simply carries whichever id the panel
 * returned. Numeric ids are only unique per panel — the dispatch scopes them to
 * the instance before storing (convex/lib/backendUserId.ts); this module always
 * sees the bare id. See docs/backends.md "Remnawave API contract".
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
  BackendHost,
  BackendHostPatch,
  BackendHostCreate,
  NodeInventoryRow,
  PanelInbound,
  PanelHostCreate,
  PanelHostFields,
  PanelNodeCreate,
  PanelNodeFields,
  PanelNodeStatus,
  PanelObservation,
  PanelObservedHost,
  PanelObservedInbound,
  PanelObservedProfile,
  PanelObservedSquad,
  ProfilePatchPreview,
} from './types';
import { farFutureExpiryIso, isFarFutureExpiry } from './types';
import { changeToken, realityAuthDigest, shapeHash } from '../panel/digest';
import { applyPatchOps, type PatchOp } from '../panel/patchOps';

export interface RemnawaveConfig {
  baseUrl: string;
  apiToken: string;
  timeoutMs?: number;
}

// Tolerant at the boundary: an additive panel value (a new status / reset
// period in some future Remnawave release) must never fail-parse the whole
// user — that would break issuance and the account view outright. Unknown
// statuses map to 'unknown' in toState; an unknown strategy falls back to
// NO_RESET (it only feeds the "resets in N days" hint).
const TrafficLimitStrategy = z.enum(['NO_RESET', 'DAY', 'WEEK', 'MONTH']).catch('NO_RESET');
const RemnawaveUserStatus = z.string();

const RemnawaveUser = z
  .object({
    // Identity: 2.x panels return `uuid` (+ a numeric `id` nobody used); 3.x
    // panels return ONLY the numeric `id`. At least one must be present
    // (refined below) — `panelUserId()` picks the one the panel addresses by.
    uuid: z.string().uuid().optional(),
    id: z.number().int().nonnegative().optional(),
    shortUuid: z.string(),
    // The VLESS credential (present on create and get); the L7 front
    // qualification authenticates with it. Lenient: absent on exotic panels.
    vlessUuid: z.string().uuid().nullish(),
    username: z.string(),
    status: RemnawaveUserStatus,
    trafficLimitBytes: z.number().int().nonnegative().nullable(),
    trafficLimitStrategy: TrafficLimitStrategy,
    // The reset anchor for the member's "resets in N days" hint. Display-only
    // string; nullish on NO_RESET tiers / older panels (kept lenient like the
    // device dates so a format change can't fail-parse the whole user).
    lastTrafficResetAt: z.string().nullish(),
    // LEGACY / CREATE-response fallback. Remnawave omits used traffic on the CREATE
    // response (a brand-new user has used nothing) → default to 0 so issuance parses.
    // Older panels also carried it here on GET. Newer panels moved it under
    // `userTraffic` (below); toState prefers that and only falls back to this.
    usedTrafficBytes: z
      .number()
      .int()
      .nonnegative()
      .nullish()
      .transform((v) => v ?? 0),
    // Remnawave 2.x nests per-user used traffic here on GET /api/users/{uuid}
    // (the flat top-level `usedTrafficBytes` no longer exists on GET). Kept lenient
    // like the device dates — a panel shape change must never fail-parse the whole
    // user (that silent-0 masking is exactly what broke the account traffic counter).
    // Extra siblings (lifetimeUsedTrafficBytes/…) are stripped by z.object.
    // `onlineAt` lives here too (2.x and 3.x both nest it under userTraffic);
    // the flat top-level `onlineAt` below is the legacy location.
    userTraffic: z
      .object({
        usedTrafficBytes: z.number().int().nonnegative().nullish(),
        onlineAt: z.string().nullish(),
      })
      .nullish(),
    // Panel-side "last seen online" stamp — the closest per-user liveness signal
    // Remnawave exposes (there is no live-connection list). Display-only string,
    // kept lenient like the device dates; surfaced on the admin Live-details
    // expander. Legacy flat location; toState prefers `userTraffic.onlineAt`.
    onlineAt: z.string().nullish(),
    expireAt: z.string().datetime().nullable(),
    hwidDeviceLimit: z.number().int().nonnegative().nullable(),
    // Plain string, matching the panel contract (z.string(), not .url()) — a
    // relative or scheme-odd subscription URL must not fail-parse the user.
    subscriptionUrl: z.string(),
  })
  .refine((u) => u.uuid != null || u.id != null, {
    message: 'user carries neither uuid (Remnawave 2.x) nor id (Remnawave 3.x)',
  });
type RemnawaveUser = z.infer<typeof RemnawaveUser>;

/**
 * The id this panel addresses the user by: the 2.x `uuid` when present, else
 * the 3.x numeric `id` as a decimal string. This is the RAW provider id (the
 * dispatch scopes numeric ones to the instance before persisting).
 */
function panelUserId(user: { uuid?: string | null; id?: number | null }): string {
  if (user.uuid) return user.uuid;
  if (user.id != null) return String(user.id);
  // Unreachable after the schema refine; kept as a hard failure, never a guess.
  throw new RemnawaveApiError('Remnawave user carries no id');
}

/**
 * Contract inference from the raw id: an INTEGER is a 3.x numeric id; anything
 * else (a 2.x uuid) goes out on the 2.x shapes verbatim — the panel validates
 * it, so a malformed value fails loudly there rather than being guessed here.
 */
function isNumericId(rawId: string): boolean {
  return /^\d+$/.test(rawId);
}
/** The 3.x numeric id as a JSON number (the DTOs take `z.number()`, not a string). */
function numericId(rawId: string): number {
  return Number(rawId);
}

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
  static async fromResponse(
    res: Response,
    path: string,
    sensitive = false,
  ): Promise<RemnawaveApiError> {
    // A SENSITIVE call carries key material in its request or response (a
    // config profile holds the REALITY private key, short ids and the client
    // list), and a panel rejection can echo fragments of what was submitted.
    // Such an error names the status and the path and nothing else: the body is
    // not even read, so it cannot reach the message, the meta or the logs.
    if (sensitive) {
      return new RemnawaveApiError(`Remnawave ${res.status} on ${path}`, {
        status: res.status,
        path,
      });
    }
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

/**
 * Join an API path onto the instance baseUrl WITHOUT dropping a base path
 * prefix: `new URL('/api/x', 'https://host/panel/')` yields `https://host/api/x`
 * (the leading slash replaces the whole path), silently breaking panels hosted
 * under a subpath. (Review D-#11.)
 */
function joinUrl(baseUrl: string, path: string): string {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return new URL(path.replace(/^\/+/, ''), base).toString();
}

async function call<T>(
  cfg: RemnawaveConfig,
  args: {
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    path: string;
    body?: unknown;
    schema: z.ZodType<T>;
    /**
     * The exchange carries key material (every config-profile call). Errors
     * then name status + path only: no response-body slice, and a schema
     * mismatch lists the failing PATHS without zod's messages (an enum or
     * literal mismatch message quotes the received value).
     */
    sensitive?: boolean;
  },
): Promise<T> {
  const url = joinUrl(cfg.baseUrl, args.path);
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
    if (!res.ok) throw await RemnawaveApiError.fromResponse(res, args.path, args.sensitive);
    // 3.x answers some writes with NO body (bulk/update → 202, DELETE → 204;
    // 2.x returned `{ response: {...} }` for both). An empty 2xx parses as
    // `undefined` — the callers of those routes use `z.unknown()` — while a
    // non-empty body that is not JSON is still a hard error, never a guess.
    const text = await res.text();
    let json: unknown = undefined;
    if (text.trim().length > 0) {
      try {
        json = JSON.parse(text);
      } catch {
        throw new RemnawaveApiError(`Remnawave non-JSON ${res.status} body on ${args.path}`, {
          status: res.status,
          path: args.path,
        });
      }
    }
    const parsed = args.schema.safeParse(unwrap(json));
    if (!parsed.success) {
      // Name the offending FIELDS (paths only, never values) so a Remnawave
      // version/shape difference is diagnosable from the logs — the most common
      // cause of a 2xx that still fails issuance.
      const issues = parsed.error.issues
        .slice(0, 6)
        .map((i) => {
          const at = i.path.join('.') || '(root)';
          return args.sensitive ? at : `${at}: ${i.message}`;
        })
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
  // Field-by-field, NOT JSON.stringify: Remnawave stores the config in a
  // Postgres jsonb column, which rewrites object key order canonically — a
  // stringify comparison of the read-back `log` block false-negatives forever
  // (the check reported "logs IPs" right after a successful apply, and every
  // apply re-wrote the profile + restarted its nodes for nothing).
  const logBlock = obj(c.log);
  const logMatches = Object.entries(PRIVACY_XRAY_LOG).every(([k, v]) => logBlock[k] === v);
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
    sensitive: true,
  });
  const rows = Array.isArray(listed) ? listed : listed.configProfiles;
  const report: RemnawaveLoggingReport = { profiles: [] };
  for (const p of rows) {
    try {
      // Read the FULL config per profile before writing: the PATCH replaces
      // the config WHOLESALE, so writing from a possibly-partial LIST row
      // would wipe any keys the list omits (a future panel version). Never
      // PATCH from the list representation. (Review D-#14.)
      const full = await call(cfg, {
        method: 'GET',
        path: `/api/config-profiles/${p.uuid}`,
        schema: ConfigProfileRow,
        sensitive: true,
      });
      const merged = hardenXrayLoggingConfig(full.config);
      if (merged.changed && !opts.dryRun) {
        await call(cfg, {
          method: 'PATCH',
          path: '/api/config-profiles',
          body: { uuid: p.uuid, config: merged.config },
          schema: z.unknown(),
          sensitive: true,
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
    // 0 is the panel's UNLIMITED sentinel (the update path coerces FCP's null →
    // 0 on send); map it back to null on read so member/admin surfaces render
    // "Unlimited" instead of "… / 0 B".
    trafficLimitBytes: user.trafficLimitBytes || null,
    // Prefer the nested (2.x) location; fall back to the flat legacy field (a real
    // value on older panels, 0 on the CREATE response). Fixes the counter that sat
    // at "0 B" once the panel moved this under `userTraffic`.
    usedTrafficBytes: user.userTraffic?.usedTrafficBytes ?? user.usedTrafficBytes,
    trafficLimitStrategy: user.trafficLimitStrategy,
    lastTrafficResetAt: user.lastTrafficResetAt ?? undefined,
    onlineAt: user.userTraffic?.onlineAt ?? user.onlineAt ?? undefined,
    // The far-future write sentinel reads back as "no expiry" — free keys carry
    // it (they never expire on the panel's clock), and members shouldn't see a
    // 10-year countdown.
    expireAt: user.expireAt && !isFarFutureExpiry(user.expireAt) ? user.expireAt : null,
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
  return expireAt ?? farFutureExpiryIso();
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

/**
 * Best-effort cleanup of a just-created panel user after an AMBIGUOUS create
 * failure (schema mismatch / timeout / 5xx): the panel may have persisted the
 * user while we lost the response, and the issuance saga never learns the uuid.
 * Issuance usernames are unique per attempt (`freesocks-<slug>-<16hex>`), so a
 * username match can only be the user this attempt created. A definitive 4xx
 * (validation/auth/conflict) means nothing was created by us — no cleanup.
 */
async function cleanupAmbiguousCreate(cfg: RemnawaveConfig, username: string): Promise<void> {
  try {
    const found = await call(cfg, {
      method: 'GET',
      path: `/api/users/by-username/${encodeURIComponent(username)}`,
      schema: z.object({ uuid: z.string().uuid().optional(), id: z.number().int().optional() }),
    });
    await remnawaveDeleteUser(cfg, panelUserId(found));
    console.warn(`[remnawave] cleaned up user after ambiguous create failure (${username})`);
  } catch (cleanupErr) {
    console.warn(
      `[remnawave] orphan-cleanup failed after ambiguous create failure (${username}): ${
        cleanupErr instanceof Error ? cleanupErr.message : 'unknown'
      }`,
    );
  }
}

/**
 * The panel-reported `subscriptionUrl` is trusted ONLY on the panel's own
 * origin. FCP later fetches it (unauthenticated) and re-serves the body
 * publicly at /api/v1/sub/<token> + uploads it to S3 mirrors — an off-origin
 * URL would, after a panel-token compromise, make the control plane fetch and
 * republish an attacker-chosen internal address (confused deputy, Review
 * D-#4). Off-origin or malformed → the conventional /api/sub/<shortUuid> on
 * the panel origin.
 */
function pinnedSubscriptionUrl(cfg: RemnawaveConfig, url: string, shortUuid: string): string {
  try {
    if (new URL(url).origin === new URL(cfg.baseUrl).origin) return url;
  } catch {
    /* malformed — fall through */
  }
  return joinUrl(cfg.baseUrl, `/api/sub/${shortUuid}`);
}

export async function remnawaveIssueUser(
  cfg: RemnawaveConfig,
  spec: IssueUserSpec,
): Promise<IssuedUser> {
  let user: RemnawaveUser;
  try {
    user = await call(cfg, {
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
  } catch (err) {
    const status = err instanceof RemnawaveApiError ? err.meta?.status : undefined;
    if (typeof status !== 'number' || status >= 500)
      await cleanupAmbiguousCreate(cfg, spec.username);
    throw err;
  }
  return {
    // uuid on a 2.x panel, the numeric id on 3.x — see the header note.
    backendUserId: panelUserId(user),
    backendShortId: user.shortUuid,
    subscriptionUrl: pinnedSubscriptionUrl(cfg, user.subscriptionUrl, user.shortUuid),
    raw: user,
    protocolUuid: user.vlessUuid ?? undefined,
  };
}

/**
 * Re-find a user FCP created, by username (`GET /api/users/by-username/{u}`:
 * the same path on 2.x and 3.x, the one the health probe already relies on).
 * Returns the issued shape (the raw provider id, the short uuid, the pinned
 * subscription URL, the VLESS uuid) or null on a 404. Anything else throws:
 * an unreachable panel is not "no such user".
 */
export async function remnawaveFindUserByUsername(
  cfg: RemnawaveConfig,
  username: string,
): Promise<IssuedUser | null> {
  let user: RemnawaveUser;
  try {
    user = await call(cfg, {
      method: 'GET',
      path: `/api/users/by-username/${encodeURIComponent(username)}`,
      schema: RemnawaveUser,
    });
  } catch (err) {
    if (isRemnawaveNotFound(err)) return null;
    throw err;
  }
  return {
    backendUserId: panelUserId(user),
    backendShortId: user.shortUuid,
    subscriptionUrl: pinnedSubscriptionUrl(cfg, user.subscriptionUrl, user.shortUuid),
    raw: user,
    protocolUuid: user.vlessUuid ?? undefined,
  };
}

async function listDevices(cfg: RemnawaveConfig, backendUserId: string): Promise<BackendDevice[]> {
  try {
    const result = await call(cfg, {
      method: 'GET',
      // Remnawave HWID controller is `/api/hwid`; a user's devices live at
      // `devices/{user}` (path param, NOT a query) — the uuid on 2.x, the
      // numeric id on 3.x; the path template is the same. See docs/backends.md.
      path: `/api/hwid/devices/${encodeURIComponent(backendUserId)}`,
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
    // carries the ids — `userUuid` on 2.x, numeric `userId` on 3.x. Response
    // echoes the remaining list, deliberately unparsed.
    path: '/api/hwid/devices/delete',
    body: isNumericId(backendUserId)
      ? { userId: numericId(backendUserId), hwid }
      : { userUuid: backendUserId, hwid },
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

// --- Hosts (client-facing connection entries) --------------------------------
// The relay-edge flip repoints the ADDRESS of a slot's template Host. Hosts are
// uuid-addressed on 2.x and 3.x alike (the 3.x numeric-id change touched users
// only). Lenient schema: only the fields the relay layer reads.
const HostRow = z.object({
  uuid: z.string(),
  remark: z.string(),
  address: z.string(),
  port: z.number().int(),
  sni: z.string().nullish(),
  host: z.string().nullish(),
  isDisabled: z.boolean().nullish(),
  inbound: z
    .object({ configProfileUuid: z.string(), configProfileInboundUuid: z.string() })
    .nullish(),
});
// (unwrapped) either a bare array or { hosts: [...] } depending on panel version.
const HostsResponse = z.union([z.array(HostRow), z.object({ hosts: z.array(HostRow) })]);

function toBackendHost(h: z.infer<typeof HostRow>): BackendHost {
  return {
    uuid: h.uuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    // The panel returns an unset field as `null` on some versions and `''` on
    // others; both mean "the Host carries none", so they read back the same.
    sni: h.sni ? h.sni : null,
    host: h.host ? h.host : null,
    isDisabled: h.isDisabled ?? false,
    inbound: h.inbound ?? null,
  };
}

/** GET /api/hosts — every Host on the panel (small, operator-managed list). */
export async function remnawaveListHosts(cfg: RemnawaveConfig): Promise<BackendHost[]> {
  const res = await call(cfg, { method: 'GET', path: '/api/hosts', schema: HostsResponse });
  const rows = Array.isArray(res) ? res : res.hosts;
  return rows.map(toBackendHost);
}

/**
 * PATCH /api/hosts { uuid, address, port, sni?, host? } repoints one Host. The
 * uuid travels in the BODY (the panel's update contract). Fields the patch
 * leaves `undefined` are OMITTED, so the Host's inbound/fingerprint/path and any
 * name the caller did not ask about are untouched. The caller confirms by
 * re-listing (observe-then-write); the echoed row is not trusted as proof.
 *
 * Clearing sends `''`, not `null`: the panel's update DTO validates these
 * fields as optional STRINGS (the same shape as the user DTO documented at
 * `remnawaveUpdateUser`), so a null would 400 and reject the whole PATCH,
 * losing the address move with it. `''` and `null` read back alike
 * (`toBackendHost`), so a cleared field compares equal either way.
 */
export async function remnawaveUpdateHost(
  cfg: RemnawaveConfig,
  patch: BackendHostPatch,
): Promise<void> {
  const body: Record<string, unknown> = {
    uuid: patch.uuid,
    address: patch.address,
    port: patch.port,
  };
  if (patch.sni !== undefined) body.sni = patch.sni ?? '';
  if (patch.host !== undefined) body.host = patch.host ?? '';
  await call(cfg, { method: 'PATCH', path: '/api/hosts', body, schema: z.unknown() });
}

/**
 * POST /api/hosts creates one client-facing Host. Body fields verified against
 * remnawave/backend `CreateHostRequestDto` (3.x): `inbound {configProfileUuid,
 * configProfileInboundUuid}`, `remark`, `address`, `port`, optional `sni`,
 * `host`, `isDisabled`. The response echoes the row; only its uuid is read, and
 * the caller confirms by re-listing (observe-then-write). `''` clears like the
 * update contract.
 */
export async function remnawaveCreateHost(
  cfg: RemnawaveConfig,
  h: BackendHostCreate,
): Promise<{ uuid: string }> {
  const body: Record<string, unknown> = {
    inbound: {
      configProfileUuid: h.inbound.configProfileUuid,
      configProfileInboundUuid: h.inbound.configProfileInboundUuid,
    },
    remark: h.remark,
    address: h.address,
    port: h.port,
    isDisabled: false,
  };
  if (h.sni !== undefined) body.sni = h.sni ?? '';
  if (h.host !== undefined) body.host = h.host ?? '';
  const res = await call(cfg, {
    method: 'POST',
    path: '/api/hosts',
    body,
    schema: z.union([
      z.object({ uuid: z.string() }),
      z.object({ response: z.object({ uuid: z.string() }) }),
    ]),
  });
  return { uuid: 'uuid' in res ? res.uuid : res.response.uuid };
}

/**
 * PATCH /api/hosts { uuid, isDisabled } flips ONE Host's disabled bit and
 * nothing else: the panel's update DTO omits every field the body leaves out
 * (see `remnawaveUpdateHost`), so the address, port, names, inbound and
 * fingerprint are untouched. The caller confirms by re-listing and reading
 * `isDisabled` back (observe-then-write); the echoed row is not trusted.
 */
export async function remnawaveSetHostDisabled(
  cfg: RemnawaveConfig,
  uuid: string,
  disabled: boolean,
): Promise<void> {
  await call(cfg, {
    method: 'PATCH',
    path: '/api/hosts',
    body: { uuid, isDisabled: disabled },
    schema: z.unknown(),
  });
}

/** DELETE /api/hosts/{uuid}; a 404 is success (idempotent). The caller confirms by re-listing. */
export async function remnawaveDeleteHost(cfg: RemnawaveConfig, uuid: string): Promise<void> {
  try {
    await call(cfg, {
      method: 'DELETE',
      path: `/api/hosts/${encodeURIComponent(uuid)}`,
      schema: z.unknown(),
    });
  } catch (err) {
    if (
      err instanceof RemnawaveApiError &&
      (err.meta as { status?: number } | undefined)?.status === 404
    )
      return;
    throw err;
  }
}

/** GET /api/nodes → one row per panel node (name, users online, connected). */
export async function remnawaveGetNodeInventory(cfg: RemnawaveConfig): Promise<NodeInventoryRow[]> {
  const nodes = await call(cfg, { method: 'GET', path: '/api/nodes', schema: NodesResponse });
  return nodes.map((n) => ({
    nodeUuid: n.uuid,
    name: n.name ?? n.uuid,
    usersOnline: n.usersOnline ?? 0,
    online: (n.isConnected ?? false) && !(n.isDisabled ?? false),
    address: n.address ?? undefined,
    port: n.port ?? undefined,
    countryCode: n.countryCode ?? undefined,
  }));
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

// A config-profile inbound row as the panel derives it from the profile's
// Xray config (`ConfigProfileInboundsSchema` in remnawave/backend): the same
// shape appears under a node's `configProfile.activeInbounds` and under a
// profile's `inbounds`. Only `uuid` + `tag` are read; the row's `rawInbound`
// (the complete inbound JSON, private key included) is DELIBERATELY not in
// the schema, so zod strips it at the boundary.
const ConfigProfileInboundRef = z.object({ uuid: z.string(), tag: z.string() });

// /api/nodes → (unwrapped) an array of nodes. The load-relevant fields, plus
// the node's active config profile for inbound discovery. Verified against
// remnawave/backend `libs/contract/models/nodes.schema.ts`
// (`configProfile.activeConfigProfileUuid` + `activeInbounds[]`); the
// `configProfileUuid` spelling is accepted as a tolerance for older panels.
const NodesResponse = z.array(
  z.object({
    uuid: z.string(),
    name: z.string().nullish(),
    address: z.string().nullish(),
    port: z.number().nullish(),
    countryCode: z.string().nullish(),
    isConnected: z.boolean().nullish(),
    isDisabled: z.boolean().nullish(),
    usersOnline: z.number().nullish(),
    trafficUsedBytes: z.number().nullish(),
    configProfile: z
      .object({
        activeConfigProfileUuid: z.string().nullish(),
        configProfileUuid: z.string().nullish(),
        activeInbounds: z.array(ConfigProfileInboundRef).nullish(),
      })
      .nullish(),
  }),
);

// --- Node inbound discovery --------------------------------------------------

/** A config profile with its derived inbound rows (`GET /api/config-profiles/{uuid}`). */
const ConfigProfileWithInbounds = z.object({
  uuid: z.string(),
  name: z.string(),
  config: z.unknown(),
  inbounds: z.array(ConfigProfileInboundRef).nullish(),
});

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}
function obj(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** One plain port (`443`, `"443"`); a range or list (`"1000-2000"`, `"443,8443"`) is null. */
function plainPort(v: unknown): number | null {
  if (typeof v === 'number') return Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null;
  if (typeof v === 'string' && /^\d{1,5}$/.test(v.trim())) return plainPort(Number(v.trim()));
  return null;
}

/**
 * Project one raw Xray inbound (a `config.inbounds[]` entry) onto the
 * allowlisted `PanelInbound` shape. ONLY these paths are read: `tag`,
 * `protocol`, `port`, `streamSettings.network`, `.security`,
 * `.realitySettings.{dest,target,serverNames}`, `.tlsSettings.serverName`,
 * `.wsSettings.{path,host,headers.Host}`, `.httpupgradeSettings.{path,host}`
 * and `.grpcSettings.serviceName`. `settings` (the clients), the REALITY
 * `privateKey` / `shortIds`, `tlsSettings.certificates` and every other key
 * are never touched. Pure; exported for the redaction test. Returns null when
 * the entry has no usable tag.
 */
export function projectXrayInbound(
  raw: unknown,
  binding: { configProfileUuid: string; configProfileInboundUuid: string; active: boolean },
): PanelInbound | null {
  const ib = obj(raw);
  if (!ib) return null;
  const tag = str(ib.tag);
  if (!tag) return null;
  const stream = obj(ib.streamSettings) ?? {};
  const network = (str(stream.network) ?? 'tcp').toLowerCase();
  const security = (str(stream.security) ?? 'none').toLowerCase();
  const out: PanelInbound = {
    tag,
    configProfileUuid: binding.configProfileUuid,
    configProfileInboundUuid: binding.configProfileInboundUuid,
    protocol: (str(ib.protocol) ?? '').toLowerCase(),
    port: plainPort(ib.port),
    network,
    security,
    active: binding.active,
  };
  const listen = str(ib.listen);
  if (listen) out.listen = listen;
  if (security === 'reality') {
    const rs = obj(stream.realitySettings) ?? {};
    const names = Array.isArray(rs.serverNames)
      ? rs.serverNames.map(str).filter((n): n is string => n !== null)
      : [];
    // Xray renamed `dest` to `target` (both still accepted by the core).
    out.reality = { target: str(rs.target) ?? str(rs.dest), serverNames: names };
  } else if (security === 'tls') {
    const ts = obj(stream.tlsSettings) ?? {};
    out.tls = { serverName: str(ts.serverName) };
  }
  if (network === 'ws' || network === 'websocket') {
    const ws = obj(stream.wsSettings) ?? {};
    const headers = obj(ws.headers) ?? {};
    out.ws = { path: str(ws.path), host: str(ws.host) ?? str(headers.Host) ?? str(headers.host) };
  } else if (network === 'httpupgrade') {
    const hu = obj(stream.httpupgradeSettings) ?? {};
    out.httpupgrade = { path: str(hu.path), host: str(hu.host) };
  } else if (network === 'grpc' || network === 'gun') {
    const g = obj(stream.grpcSettings) ?? {};
    out.grpc = { serviceName: str(g.serviceName) };
  } else if (network === 'xhttp' || network === 'splithttp') {
    // `splithttp` was XHTTP's name before Xray 1.8.24; the settings key follows.
    const x = obj(stream.xhttpSettings) ?? obj(stream.splithttpSettings) ?? {};
    out.xhttp = { path: str(x.path), host: str(x.host), mode: str(x.mode) };
  }
  return out;
}

/**
 * The inbounds one panel node serves, for relay listener discovery:
 * `GET /api/nodes` finds the node's active config profile (+ which of its
 * inbounds the node has active), `GET /api/config-profiles/{uuid}` supplies
 * the profile's Xray `config.inbounds[]` and the derived inbound rows; the two
 * are joined BY TAG (the inbound uuid a Host binds to lives only on the derived
 * row; the stream settings only in the raw config). Every entry goes through
 * `projectXrayInbound`, so nothing beyond the allowlist leaves this function.
 * A node without an active profile answers `[]`; an unknown node uuid throws.
 */
export async function remnawaveListNodeInbounds(
  cfg: RemnawaveConfig,
  nodeUuid: string,
): Promise<PanelInbound[]> {
  const nodes = await call(cfg, { method: 'GET', path: '/api/nodes', schema: NodesResponse });
  const node = nodes.find((n) => n.uuid === nodeUuid);
  if (!node) throw new RemnawaveApiError('Remnawave node not found on /api/nodes', { status: 404 });
  const profileUuid =
    node.configProfile?.activeConfigProfileUuid ?? node.configProfile?.configProfileUuid ?? null;
  if (!profileUuid) return [];
  const activeUuids = new Set((node.configProfile?.activeInbounds ?? []).map((i) => i.uuid));
  const activeTags = new Set((node.configProfile?.activeInbounds ?? []).map((i) => i.tag));
  const profile = await call(cfg, {
    method: 'GET',
    path: `/api/config-profiles/${encodeURIComponent(profileUuid)}`,
    schema: ConfigProfileWithInbounds,
    sensitive: true,
  });
  const uuidByTag = new Map((profile.inbounds ?? []).map((i) => [i.tag, i.uuid]));
  const config = obj(profile.config);
  const rawInbounds = Array.isArray(config?.inbounds) ? config.inbounds : [];
  const out: PanelInbound[] = [];
  for (const raw of rawInbounds) {
    const tag = str(obj(raw)?.tag);
    if (!tag) continue;
    const inboundUuid = uuidByTag.get(tag);
    // No derived row = the panel has not indexed this inbound; a Host cannot
    // bind to it, so there is nothing a listener could map to.
    if (!inboundUuid) continue;
    const projected = projectXrayInbound(raw, {
      configProfileUuid: profile.uuid,
      configProfileInboundUuid: inboundUuid,
      active: activeUuids.has(inboundUuid) || activeTags.has(tag),
    });
    if (projected) out.push(projected);
  }
  return out;
}

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
 * squad's node load from /api/nodes over the squad's accessible-nodes. The
 * per-squad accessible-nodes calls fan out IN PARALLEL (was N+1 sequential 8s
 * timeouts — slow at fleet squad counts); the cron runs it every 10 min
 * best-effort.
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

  const out = await Promise.all(
    squads.internalSquads.map(async (squad): Promise<NodeStats> => {
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
        return {
          placement: squad.uuid,
          label: squad.name,
          usersOnline: 0,
          online: false,
          nodeCount: 0,
        };
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
      return {
        placement: squad.uuid,
        label: squad.name,
        usersOnline,
        ...(realtimeById.size > 0 ? { trafficBytesRealtime: realtime } : {}),
        online,
        nodeCount: mapped,
      };
    }),
  );
  return out;
}

export async function remnawaveUpdateUser(
  cfg: RemnawaveConfig,
  backendUserId: string,
  patch: UpdateUserPatch,
): Promise<void> {
  // Remnawave's update is `PATCH /api/users` with the target IN THE BODY (the
  // route has no path param; the DTO requires an id or username): `uuid` on a
  // 2.x panel, the numeric `id` on 3.x. Seed it here.
  const body: Record<string, unknown> = isNumericId(backendUserId)
    ? { id: numericId(backendUserId) }
    : { uuid: backendUserId };
  // The panel's UPDATE DTO takes `.optional()` NOT `.nullable()` here: a null
  // 400s and the WHOLE PATCH is rejected (re-enable + expiry + placement +
  // limits all lost). null means unlimited in FCP (resolveTrafficLimitBytes),
  // and 0 is Remnawave's documented unlimited sentinel — coerce. (CREATE
  // already omits via `?? undefined`.)
  if (patch.trafficLimitBytes !== undefined) body.trafficLimitBytes = patch.trafficLimitBytes ?? 0;
  if (patch.trafficLimitStrategy !== undefined)
    body.trafficLimitStrategy = patch.trafficLimitStrategy;
  if (patch.expireAt != null) {
    // Same DTO refuses null AND past dates ("cannot be in the past") — either
    // rejects the whole PATCH. A past entitlement expiry (e.g. an admin
    // re-tiering a lapsed member) is clamped to a near-future floor: FCP's
    // grace sweep, not the panel's date, governs actual disablement. A null
    // expireAt is simply omitted (Remnawave requires a date; there is no
    // "clear" semantics on update).
    const t = Date.parse(patch.expireAt);
    body.expireAt =
      Number.isFinite(t) && t <= Date.now()
        ? new Date(Date.now() + 5 * 60_000).toISOString()
        : patch.expireAt;
  }
  // The DTO is `.optional()` NOT `.nullable()` here too: a null 400s the WHOLE
  // PATCH (the same failure class as trafficLimitBytes/expireAt above). There
  // is no documented clear sentinel, so a null (FCP enforcement toggled off)
  // OMITS the field — pushes simply stop managing it rather than 400ing every
  // tier push on the fleet.
  if (patch.hwidDeviceLimit !== undefined && patch.hwidDeviceLimit !== null)
    body.hwidDeviceLimit = patch.hwidDeviceLimit;
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
 * Bulk-set `trafficLimitBytes` on many users in ONE call — Remnawave
 * `POST /api/users/bulk/update` (`{ uuids, fields }` on 2.x, `{ userIds, fields }`
 * with JSON numbers on 3.x; 500 ids per call max, panel-side). Used by the
 * donation free-bandwidth bonus to re-cap the whole free fleet efficiently
 * instead of a PATCH per user. The caller chunks to ≤500 Remnawave ids of ONE
 * instance; mid-migration a chunk can still mix uuid- and id-shaped keys, so the
 * two shapes go out as two calls (each ≤ the chunk size).
 */
export async function remnawaveBulkUpdateTrafficLimit(
  cfg: RemnawaveConfig,
  backendUserIds: string[],
  trafficLimitBytes: number,
): Promise<void> {
  const uuids = backendUserIds.filter((id) => !isNumericId(id));
  const userIds = backendUserIds.filter((id) => isNumericId(id)).map(numericId);
  for (const body of [
    uuids.length > 0 ? { uuids, fields: { trafficLimitBytes } } : null,
    userIds.length > 0 ? { userIds, fields: { trafficLimitBytes } } : null,
  ]) {
    if (!body) continue;
    await call(cfg, { method: 'POST', path: '/api/users/bulk/update', body, schema: z.unknown() });
  }
}

/**
 * Resolve the id a panel CURRENTLY addresses a user by, from the key's stable
 * `shortUuid` (`GET /api/users/by-short-uuid/{shortUuid}` — same route on 2.x
 * and 3.x). Returns the 2.x uuid on a 2.x panel and the numeric id (as a decimal
 * string) on 3.x; null when the panel no longer knows the user. This is the
 * remap primitive for the 2.x→3.x key migration (backendServers.migrateRemnawaveUserIds):
 * a 2.x-era key's uuid is GONE from the panel after the upgrade, but its
 * shortUuid survives.
 */
export async function remnawaveResolveUserIdByShortUuid(
  cfg: RemnawaveConfig,
  shortUuid: string,
): Promise<string | null> {
  try {
    const found = await call(cfg, {
      method: 'GET',
      path: `/api/users/by-short-uuid/${encodeURIComponent(shortUuid)}`,
      schema: z.object({ uuid: z.string().uuid().optional(), id: z.number().int().optional() }),
    });
    return panelUserId(found);
  } catch (err) {
    if (err instanceof RemnawaveApiError && err.meta?.status === 404) return null;
    throw err;
  }
}

/** Major version of the panel's reported semver (`3.4.2` → 3); null if unparseable. */
export function remnawaveMajorVersion(panelVersion: string): number | null {
  const m = /^v?(\d+)\./.exec(panelVersion.trim());
  return m ? Number(m[1]) : null;
}

/**
 * True when the panel rejected a status action because the user is ALREADY in
 * the requested state: the enable/disable actions are NOT idempotent panel-side
 * — enable on an ACTIVE user 400s with `A030 "User already enabled"` (disable
 * on a disabled user: `A029 "User already disabled"`). FCP wants set-semantics
 * ("make it active"), so the caller treats the no-op transition as success —
 * without this, EVERY tier push to an enabled key (e.g. a free→member upgrade)
 * threw on its unconditional re-enable and the membership never reached the
 * panel.
 */
function isAlreadyInRequestedStatus(err: unknown, active: boolean): boolean {
  if (!(err instanceof RemnawaveApiError) || err.meta?.status !== 400) return false;
  const body = typeof err.meta?.body === 'string' ? err.meta.body.toLowerCase() : '';
  return active
    ? body.includes('a030') || body.includes('already enabled')
    : body.includes('a029') || body.includes('already disabled');
}

/**
 * Enable / disable a user via Remnawave's dedicated action endpoints
 * (`POST /api/users/{uuid}/actions/{enable|disable}`) rather than folding status
 * into the field-update PATCH. More faithful to the API and decoupled from the
 * (heavier) update call. Remnawave rejects setting LIMITED/EXPIRED here (it owns
 * those), which matches our two-state active|disabled model. A400 "already
 * enabled/disabled" is swallowed: the user is in the requested state.
 */
export async function remnawaveSetStatus(
  cfg: RemnawaveConfig,
  backendUserId: string,
  active: boolean,
): Promise<void> {
  try {
    await call(cfg, {
      method: 'POST',
      path: `/api/users/${backendUserId}/actions/${active ? 'enable' : 'disable'}`,
      schema: z.unknown(),
    });
  } catch (err) {
    if (isAlreadyInRequestedStatus(err, active)) return;
    throw err;
  }
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

/**
 * Remnawave picks the subscription FORMAT by User-Agent, keying on the client
 * app's UA prefix. Probed live against the production panel (2026-08-30):
 * "SFA/…" → sing-box JSON, but the newer official sing-box shells fall through
 * to the base64 default — which sing-box then fails to import ("decode config:
 * invalid character 'd'…", base64 of vless://). Until the panel recognizes
 * them, rewrite a UA that IS sing-box but lacks a recognized prefix to a
 * canonical SFA one, carrying the core version through (the panel may pick the
 * legacy vs modern template by it). Deliberately narrow — only UAs that START
 * with "SFL/" / "SFW/", the official desktop shells' "SFL (sing-box ..." /
 * "SFW (sing-box ..." form (sing-box-for-desktop `src/main/userAgent.ts`: the
 * app name is SFL on Linux, SFW elsewhere), or "sing-box" — so sing-box-CORED
 * third-party apps with their own panel templates (Karing, Happ, …) are never
 * touched. `lib/edges/clientFamilies.ts` keeps the same shell list.
 */
const SINGBOX_RECOGNIZED_UA_RE = /^SF[AIMT]\//;
const SINGBOX_UNRECOGNIZED_UA_RE = /^(?:SF[LW](?:\/|\s+\(sing-box\s)|sing-?box)/i;
export function normalizeSubscriptionUserAgent(ua: string | undefined): string | undefined {
  if (!ua || SINGBOX_RECOGNIZED_UA_RE.test(ua) || !SINGBOX_UNRECOGNIZED_UA_RE.test(ua)) return ua;
  const ver =
    /sing-?box[/ ]v?(\d+(?:\.\d+){1,2})/i.exec(ua)?.[1] ??
    /^SF[LW]\/v?(\d+(?:\.\d+){1,2})/i.exec(ua)?.[1] ??
    '1.12.0';
  return `SFA/${ver} (sing-box ${ver})`;
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
  // subscription rather than an HTML landing page. A stored URL is re-pinned
  // to the panel origin (rows stored before the pinning fix, Review D-#4).
  const url = subscriptionUrl
    ? pinnedSubscriptionUrl(cfg, subscriptionUrl, backendShortId)
    : joinUrl(cfg.baseUrl, `/api/sub/${backendShortId}`);
  const headers: Record<string, string> = {};
  const ua = normalizeSubscriptionUserAgent(userAgent);
  if (ua) headers['user-agent'] = ua;
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

// A well-formed but absent username: the panel answers 404 (reachable + token
// accepted) rather than 200, which is exactly what a health probe wants. The
// by-username route is the same on 2.x and 3.x, whereas `/api/users/{id}` wants
// a uuid on 2.x and an integer on 3.x (the other shape 400s — and a 400 is NOT
// "healthy"). Issuance usernames are `freesocks-<slug>-<hex>`, so this can never
// collide with a real key.
const HEALTH_PROBE_USERNAME = 'fcp-health-probe-absent';

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
  const url = joinUrl(cfg.baseUrl, `/api/users/by-username/${HEALTH_PROBE_USERNAME}`);
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
    throw new RemnawaveApiError(`Remnawave ${res.status} on /api/users/by-username/{probe}`, {
      status: res.status,
      path: '/api/users/by-username/{probe}',
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

// --- Panel observation (server management) -----------------------------------

// The observation schemas are SEPARATE from the ones above on purpose: those
// parse exactly what their feature reads, and widening them would widen what
// every existing caller accepts. All extra fields are nullish (a panel that
// lacks one degrades to "unknown", never to a parse failure).
const ObservedHostRow = z.object({
  uuid: z.string(),
  remark: z.string(),
  address: z.string(),
  port: z.number().int(),
  sni: z.string().nullish(),
  host: z.string().nullish(),
  path: z.string().nullish(),
  alpn: z.string().nullish(),
  fingerprint: z.string().nullish(),
  securityLayer: z.string().nullish(),
  isDisabled: z.boolean().nullish(),
  isHidden: z.boolean().nullish(),
  tag: z.string().nullish(),
  viewPosition: z.number().nullish(),
  inbound: z
    .object({
      configProfileUuid: z.string().nullish(),
      configProfileInboundUuid: z.string().nullish(),
    })
    .nullish(),
  nodes: z.array(z.string()).nullish(),
});
const ObservedHostsResponse = z.union([
  z.array(ObservedHostRow),
  z.object({ hosts: z.array(ObservedHostRow) }),
]);

const ObservedSquadsResponse = z.object({
  internalSquads: z.array(
    z.object({
      uuid: z.string(),
      name: z.string(),
      inbounds: z.array(ConfigProfileInboundRef).nullish(),
      info: z.object({ membersCount: z.number().nullish() }).nullish(),
    }),
  ),
});

const ObservedNodesResponse = z.array(
  z.object({
    uuid: z.string(),
    name: z.string().nullish(),
    address: z.string().nullish(),
    port: z.number().nullish(),
    countryCode: z.string().nullish(),
    isConnected: z.boolean().nullish(),
    isDisabled: z.boolean().nullish(),
    usersOnline: z.number().nullish(),
    tags: z.array(z.string()).nullish(),
    configProfile: z
      .object({
        activeConfigProfileUuid: z.string().nullish(),
        configProfileUuid: z.string().nullish(),
        activeInbounds: z.array(ConfigProfileInboundRef).nullish(),
      })
      .nullish(),
  }),
);

/**
 * One config profile reduced to what may be stored: the allowlisted inbound
 * projection plus the three digests. The raw config (private keys, short ids)
 * exists only inside this function's scope. Pure apart from WebCrypto;
 * exported for the redaction test.
 */
export async function observeConfigProfile(
  profile: {
    uuid: string;
    name: string;
    config: unknown;
    inbounds?: { uuid: string; tag: string }[] | null;
  },
  digestKey: string,
): Promise<PanelObservedProfile> {
  const uuidByTag = new Map((profile.inbounds ?? []).map((i) => [i.tag, i.uuid]));
  const config = obj(profile.config);
  const rawInbounds = Array.isArray(config?.inbounds) ? config.inbounds : [];
  const inbounds: PanelObservedInbound[] = [];
  for (const raw of rawInbounds) {
    const tag = str(obj(raw)?.tag);
    if (!tag) continue;
    const projected = projectXrayInbound(raw, {
      configProfileUuid: profile.uuid,
      configProfileInboundUuid: uuidByTag.get(tag) ?? '',
      active: false,
    });
    if (!projected) continue;
    const { active: _active, ...inbound } = projected;
    const out: PanelObservedInbound = inbound;
    if (inbound.security === 'reality') {
      const rs = obj(obj(obj(raw)?.streamSettings)?.realitySettings);
      out.realityAuth = await realityAuthDigest(rs, digestKey);
    }
    inbounds.push(out);
  }
  return {
    profileUuid: profile.uuid,
    name: profile.name,
    shapeHash: await shapeHash(profile.config),
    changeToken: await changeToken(profile.config, digestKey),
    inbounds,
  };
}

/**
 * Read everything server management shows: nodes, config profiles, Hosts and
 * internal squads. READ-ONLY. Each profile is fetched by uuid (the list row is
 * never trusted to be complete) and reduced by `observeConfigProfile` before
 * anything leaves this function. `digestKey` keys the digests; it is the
 * caller's to supply so this module stays free of environment access.
 */
export async function remnawaveObservePanel(
  cfg: RemnawaveConfig,
  digestKey: string,
): Promise<PanelObservation> {
  const [nodeRows, hostRows, squadRows, listed] = await Promise.all([
    call(cfg, { method: 'GET', path: '/api/nodes', schema: ObservedNodesResponse }),
    call(cfg, { method: 'GET', path: '/api/hosts', schema: ObservedHostsResponse }),
    call(cfg, { method: 'GET', path: '/api/internal-squads', schema: ObservedSquadsResponse }),
    call(cfg, {
      method: 'GET',
      path: '/api/config-profiles',
      schema: ConfigProfilesList,
      sensitive: true,
    }),
  ]);
  const profiles: PanelObservedProfile[] = [];
  for (const p of Array.isArray(listed) ? listed : listed.configProfiles) {
    const full = await call(cfg, {
      method: 'GET',
      path: `/api/config-profiles/${encodeURIComponent(p.uuid)}`,
      schema: ConfigProfileWithInbounds,
      sensitive: true,
    });
    profiles.push(await observeConfigProfile(full, digestKey));
  }
  return {
    nodes: nodeRows.map((n) => ({
      nodeUuid: n.uuid,
      name: n.name ?? n.uuid,
      address: n.address ?? null,
      port: n.port ?? null,
      countryCode: n.countryCode ?? null,
      online: n.isConnected === true && n.isDisabled !== true,
      isDisabled: n.isDisabled === true,
      usersOnline: n.usersOnline ?? 0,
      configProfileUuid:
        n.configProfile?.activeConfigProfileUuid ?? n.configProfile?.configProfileUuid ?? null,
      activeInboundUuids: (n.configProfile?.activeInbounds ?? []).map((i) => i.uuid),
      tags: n.tags ?? [],
    })),
    profiles,
    hosts: mapObservedHosts(hostRows),
    squads: mapObservedSquads(squadRows),
  };
}

function mapObservedHosts(rows: z.infer<typeof ObservedHostsResponse>): PanelObservedHost[] {
  return (Array.isArray(rows) ? rows : rows.hosts).map((h) => ({
    hostUuid: h.uuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni || null,
    host: h.host || null,
    path: h.path || null,
    alpn: h.alpn || null,
    fingerprint: h.fingerprint || null,
    securityLayer: h.securityLayer || null,
    isDisabled: h.isDisabled === true,
    isHidden: h.isHidden === true,
    tag: h.tag || null,
    viewPosition: h.viewPosition ?? null,
    configProfileUuid: h.inbound?.configProfileUuid ?? null,
    configProfileInboundUuid: h.inbound?.configProfileInboundUuid ?? null,
    nodeUuids: h.nodes ?? [],
  }));
}

function mapObservedSquads(rows: z.infer<typeof ObservedSquadsResponse>): PanelObservedSquad[] {
  return rows.internalSquads.map((sq) => ({
    squadUuid: sq.uuid,
    name: sq.name,
    inboundUuids: (sq.inbounds ?? []).map((i) => i.uuid),
    membersCount: sq.info?.membersCount ?? null,
  }));
}

// --- Panel writes (server management) ------------------------------------------
//
// ONE outbound call each, no retry: a write whose answer is lost must be settled
// by the operations ledger LOOKING at the panel, never by sending it again (an
// identical Host create is a second Host, measured). Shapes are the ones the
// management contract probe pins against a live panel.

/** `null` clears a text field (the panel takes ''), absent leaves it. */
function hostBody(f: PanelHostFields): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const text = (k: 'sni' | 'host' | 'path' | 'tag') => {
    if (f[k] !== undefined) body[k] = f[k] ?? '';
  };
  if (f.remark !== undefined) body.remark = f.remark;
  if (f.address !== undefined) body.address = f.address;
  if (f.port !== undefined) body.port = f.port;
  text('sni');
  text('host');
  text('path');
  text('tag');
  // Enumerations: null is the panel's own "unset".
  if (f.alpn !== undefined) body.alpn = f.alpn;
  if (f.fingerprint !== undefined) body.fingerprint = f.fingerprint;
  if (f.securityLayer !== undefined) body.securityLayer = f.securityLayer ?? 'DEFAULT';
  if (f.isDisabled !== undefined) body.isDisabled = f.isDisabled;
  if (f.isHidden !== undefined) body.isHidden = f.isHidden;
  if (f.inbound !== undefined) body.inbound = f.inbound;
  if (f.nodeUuids !== undefined) body.nodes = f.nodeUuids;
  return body;
}

const CreatedUuid = z.object({ uuid: z.string() });

export async function remnawaveManageCreateHost(
  cfg: RemnawaveConfig,
  spec: PanelHostCreate,
): Promise<{ hostUuid: string }> {
  const made = await call(cfg, {
    method: 'POST',
    path: '/api/hosts',
    body: hostBody(spec),
    schema: CreatedUuid,
  });
  return { hostUuid: made.uuid };
}

export async function remnawaveManageUpdateHost(
  cfg: RemnawaveConfig,
  hostUuid: string,
  fields: PanelHostFields,
): Promise<void> {
  await call(cfg, {
    method: 'PATCH',
    path: '/api/hosts',
    body: { uuid: hostUuid, ...hostBody(fields) },
    schema: z.unknown(),
  });
}

export async function remnawaveReorderHosts(
  cfg: RemnawaveConfig,
  order: { hostUuid: string; viewPosition: number }[],
): Promise<void> {
  await call(cfg, {
    method: 'POST',
    path: '/api/hosts/actions/reorder',
    body: { hosts: order.map((o) => ({ uuid: o.hostUuid, viewPosition: o.viewPosition })) },
    schema: z.unknown(),
  });
}

export async function remnawaveCreateSquad(
  cfg: RemnawaveConfig,
  spec: { name: string; inboundUuids: string[] },
): Promise<{ squadUuid: string }> {
  const made = await call(cfg, {
    method: 'POST',
    path: '/api/internal-squads',
    body: { name: spec.name, inbounds: spec.inboundUuids },
    schema: CreatedUuid,
  });
  return { squadUuid: made.uuid };
}

export async function remnawaveUpdateSquad(
  cfg: RemnawaveConfig,
  squadUuid: string,
  fields: { name?: string; inboundUuids?: string[] },
): Promise<void> {
  const body: Record<string, unknown> = { uuid: squadUuid };
  if (fields.name !== undefined) body.name = fields.name;
  if (fields.inboundUuids !== undefined) body.inbounds = fields.inboundUuids;
  await call(cfg, { method: 'PATCH', path: '/api/internal-squads', body, schema: z.unknown() });
}

export async function remnawaveDeleteSquad(cfg: RemnawaveConfig, squadUuid: string): Promise<void> {
  await call(cfg, {
    method: 'DELETE',
    path: `/api/internal-squads/${encodeURIComponent(squadUuid)}`,
    schema: z.unknown(),
  });
}

export async function remnawaveReadHosts(cfg: RemnawaveConfig): Promise<PanelObservedHost[]> {
  return mapObservedHosts(
    await call(cfg, { method: 'GET', path: '/api/hosts', schema: ObservedHostsResponse }),
  );
}

export async function remnawaveReadSquads(cfg: RemnawaveConfig): Promise<PanelObservedSquad[]> {
  return mapObservedSquads(
    await call(cfg, {
      method: 'GET',
      path: '/api/internal-squads',
      schema: ObservedSquadsResponse,
    }),
  );
}

const NodeStatusResponse = z.array(
  z.object({
    uuid: z.string(),
    name: z.string().nullish(),
    address: z.string().nullish(),
    port: z.number().nullish(),
    countryCode: z.string().nullish(),
    isDisabled: z.boolean().nullish(),
    lastStatusChange: z.string().nullish(),
    configProfile: z
      .object({
        activeConfigProfileUuid: z.string().nullish(),
        configProfileUuid: z.string().nullish(),
        activeInbounds: z.array(ConfigProfileInboundRef).nullish(),
      })
      .nullish(),
  }),
);

export async function remnawaveReadNodeStatus(cfg: RemnawaveConfig): Promise<PanelNodeStatus[]> {
  const rows = await call(cfg, { method: 'GET', path: '/api/nodes', schema: NodeStatusResponse });
  return rows.map((n) => ({
    nodeUuid: n.uuid,
    name: n.name ?? n.uuid,
    address: n.address ?? null,
    port: n.port ?? null,
    countryCode: n.countryCode ?? null,
    lastStatusChange: n.lastStatusChange ?? null,
    isDisabled: n.isDisabled === true,
    configProfileUuid:
      n.configProfile?.activeConfigProfileUuid ?? n.configProfile?.configProfileUuid ?? null,
    activeInboundUuids: (n.configProfile?.activeInbounds ?? []).map((i) => i.uuid),
  }));
}

// --- node writes ---------------------------------------------------------------------------------
//
// FCP creates and changes the PANEL ROW of a node. It never asks the panel for
// the node's own secret (`/api/keygen`): installing a node and giving it that
// secret is the node role's job, done against the panel directly.

function nodeBody(f: PanelNodeFields): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (f.name !== undefined) body.name = f.name;
  if (f.address !== undefined) body.address = f.address;
  if (f.port !== undefined) body.port = f.port;
  if (f.countryCode !== undefined) body.countryCode = f.countryCode;
  if (f.profile !== undefined)
    body.configProfile = {
      activeConfigProfileUuid: f.profile.configProfileUuid,
      activeInbounds: f.profile.activeInboundUuids,
    };
  return body;
}

export async function remnawaveCreateNode(
  cfg: RemnawaveConfig,
  spec: PanelNodeCreate,
): Promise<{ nodeUuid: string }> {
  const made = await call(cfg, {
    method: 'POST',
    path: '/api/nodes',
    body: nodeBody({
      name: spec.name,
      address: spec.address,
      port: spec.port,
      countryCode: spec.countryCode,
      profile: {
        configProfileUuid: spec.configProfileUuid,
        activeInboundUuids: spec.activeInboundUuids,
      },
    }),
    schema: CreatedUuid,
  });
  return { nodeUuid: made.uuid };
}

export async function remnawaveUpdateNode(
  cfg: RemnawaveConfig,
  nodeUuid: string,
  fields: PanelNodeFields,
): Promise<void> {
  await call(cfg, {
    method: 'PATCH',
    path: '/api/nodes',
    body: { uuid: nodeUuid, ...nodeBody(fields) },
    schema: z.unknown(),
  });
}

export async function remnawaveSetNodeEnabled(
  cfg: RemnawaveConfig,
  nodeUuid: string,
  enabled: boolean,
): Promise<void> {
  await call(cfg, {
    method: 'POST',
    path: `/api/nodes/${encodeURIComponent(nodeUuid)}/actions/${enabled ? 'enable' : 'disable'}`,
    schema: z.unknown(),
  });
}

export async function remnawaveRestartNode(cfg: RemnawaveConfig, nodeUuid: string): Promise<void> {
  await call(cfg, {
    method: 'POST',
    path: `/api/nodes/${encodeURIComponent(nodeUuid)}/actions/restart`,
    // A node skips the restart when its config hashes are unchanged; an
    // operator who pressed Restart means it.
    body: { forceRestart: true },
    schema: z.unknown(),
  });
}

export async function remnawaveDeleteNode(cfg: RemnawaveConfig, nodeUuid: string): Promise<void> {
  await call(cfg, {
    method: 'DELETE',
    path: `/api/nodes/${encodeURIComponent(nodeUuid)}`,
    schema: z.unknown(),
  });
}

// --- Guarded config-profile edit (server management) ---------------------------------------
//
// The panel replaces a profile's config WHOLESALE and offers no conditional
// update (measured: stale preconditions are ignored). So: read the full config,
// refuse unless it is still the one the operator previewed, apply a CLOSED set
// of typed edits (lib/panel/patchOps.ts), send once. The config, key material
// included, exists only inside these functions; what leaves them is digests and
// the non-secret before/after.

async function readFullProfile(cfg: RemnawaveConfig, profileUuid: string) {
  return call(cfg, {
    method: 'GET',
    path: `/api/config-profiles/${encodeURIComponent(profileUuid)}`,
    schema: ConfigProfileWithInbounds,
    sensitive: true,
  });
}

export async function remnawavePreviewProfilePatch(
  cfg: RemnawaveConfig,
  profileUuid: string,
  ops: readonly PatchOp[],
  digestKey: string,
): Promise<ProfilePatchPreview> {
  const full = await readFullProfile(cfg, profileUuid);
  const out = applyPatchOps(full.config, ops);
  const baseToken = await changeToken(full.config, digestKey);
  return {
    profileName: full.name,
    baseToken,
    expectedToken: out.changed ? await changeToken(out.config, digestKey) : baseToken,
    changed: out.changed,
    changes: out.changes,
    touchedTags: out.touchedTags,
    inboundUuids: Object.fromEntries((full.inbounds ?? []).map((i) => [i.tag, i.uuid])),
  };
}

export async function remnawaveApplyProfilePatch(
  cfg: RemnawaveConfig,
  profileUuid: string,
  ops: readonly PatchOp[],
  baseToken: string,
  digestKey: string,
): Promise<{ sent: true } | { sent: false; reason: 'profile_changed' | 'nothing_to_change' }> {
  // Read again, as late as possible: the window in which another writer can
  // slip in is this function, and nothing the panel offers can close it.
  const full = await readFullProfile(cfg, profileUuid);
  if ((await changeToken(full.config, digestKey)) !== baseToken)
    return { sent: false, reason: 'profile_changed' };
  const out = applyPatchOps(full.config, ops);
  if (!out.changed) return { sent: false, reason: 'nothing_to_change' };
  await call(cfg, {
    method: 'PATCH',
    path: '/api/config-profiles',
    body: { uuid: profileUuid, config: out.config },
    schema: z.unknown(),
    sensitive: true,
    // A profile with hundreds of names and several nodes answers in tens of
    // milliseconds (measured), but the write must not be cut short by the
    // default read timeout.
  });
  return { sent: true };
}

export async function remnawaveReadProfile(
  cfg: RemnawaveConfig,
  profileUuid: string,
  digestKey: string,
): Promise<PanelObservedProfile> {
  return observeConfigProfile(await readFullProfile(cfg, profileUuid), digestKey);
}
