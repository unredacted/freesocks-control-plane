/**
 * Remnawave proxy backend, ported from src/server/providers/remnawave/* into
 * config-based functions callable from a Convex action (V8 runtime: `fetch`
 * only, no Node deps). The native client + adapter were merged here; response
 * shapes are still validated with zod.
 */
import { z } from 'zod';
import type {
  BackendDevice,
  IssueUserSpec,
  IssuedUser,
  SubscriptionContent,
  UpdateUserPatch,
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
  usedTrafficBytes: z.number().int().nonnegative(),
  expireAt: z.string().datetime().nullable(),
  hwidDeviceLimit: z.number().int().nonnegative().nullable(),
  subscriptionUrl: z.string().url(),
});
type RemnawaveUser = z.infer<typeof RemnawaveUser>;

const HwidDevice = z.object({
  hwid: z.string(),
  firstSeenAt: z.string().datetime().nullable().optional(),
  lastSeenAt: z.string().datetime().nullable().optional(),
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
    // some misconfigurations); only the path + a short body slice.
    return new RemnawaveApiError(`Remnawave ${res.status} on ${path}`, {
      status: res.status,
      path,
      body: body?.slice(0, 200),
    });
  }
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
      throw new RemnawaveApiError('Remnawave schema mismatch', { path: args.path });
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
    expireAt: user.expireAt,
    status,
    devices,
  };
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
      expireAt: spec.expireAt ?? undefined,
      hwidDeviceLimit: spec.hwidDeviceLimit ?? undefined,
      tag: spec.tag,
      description: spec.description,
      activeInternalSquads: spec.remnawaveSquadUuid ? [spec.remnawaveSquadUuid] : undefined,
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
      path: `/api/hwid-devices?userUuid=${encodeURIComponent(userUuid)}`,
      schema: HwidDevicesResponse,
    });
    return result.devices.map((d) => ({
      hwid: d.hwid,
      firstSeenAt: d.firstSeenAt ?? undefined,
      lastSeenAt: d.lastSeenAt ?? undefined,
    }));
  } catch {
    // Some panel versions don't expose this endpoint — degrade to "no devices".
    return [];
  }
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

export async function remnawaveUpdateUser(
  cfg: RemnawaveConfig,
  backendUserId: string,
  patch: UpdateUserPatch,
): Promise<void> {
  const body: Record<string, unknown> = {};
  if (patch.trafficLimitBytes !== undefined) body.trafficLimitBytes = patch.trafficLimitBytes;
  if (patch.trafficLimitStrategy !== undefined)
    body.trafficLimitStrategy = patch.trafficLimitStrategy;
  if (patch.expireAt !== undefined) body.expireAt = patch.expireAt;
  if (patch.hwidDeviceLimit !== undefined) body.hwidDeviceLimit = patch.hwidDeviceLimit;
  if (patch.description !== undefined) body.description = patch.description;
  if (patch.tag !== undefined) body.tag = patch.tag;
  if (patch.remnawaveSquadUuid !== undefined) {
    // present+null/'' clears the squad; a value sets it.
    body.activeInternalSquads = patch.remnawaveSquadUuid ? [patch.remnawaveSquadUuid] : [];
  }
  if (patch.status !== undefined) body.status = patch.status === 'active' ? 'ACTIVE' : 'DISABLED';
  await call(cfg, {
    method: 'PATCH',
    path: `/api/users/${backendUserId}`,
    body,
    schema: RemnawaveUser,
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
  await call(cfg, {
    method: 'DELETE',
    path: `/api/users/${backendUserId}`,
    schema: z.unknown(),
  });
}

export async function remnawaveFetchSubscription(
  cfg: RemnawaveConfig,
  backendShortId: string,
  userAgent?: string,
): Promise<SubscriptionContent> {
  const url = new URL(`/api/subscriptions/${backendShortId}`, cfg.baseUrl).toString();
  const headers: Record<string, string> = { authorization: `Bearer ${cfg.apiToken}` };
  if (userAgent) headers['user-agent'] = userAgent;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 8000);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) throw await RemnawaveApiError.fromResponse(res, `/api/subscriptions/${backendShortId}`);
    return {
      content: await res.text(),
      contentType: res.headers.get('content-type') ?? 'text/plain',
    };
  } finally {
    clearTimeout(timer);
  }
}
