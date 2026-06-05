/**
 * Outline Manager backend, ported from src/server/providers/outline/* into
 * config-based functions (V8 fetch). The DB-touching parts (server-pool
 * selection, key→server resolution, access-key-count bump) are NOT here — they
 * live in convex/outlineServers.ts as internal queries/mutations that the
 * dispatch action (convex/backends.ts) calls. These functions take a resolved
 * server config.
 *
 * `apiUrl` carries the Outline Manager secret path segment — treat as a
 * credential: never logged, never put in an error.
 */
import { z } from 'zod';
import type { IssuedUser, SubscriptionContent, UpdateUserPatch, UserState } from './types';

export interface OutlineServerConfig {
  apiUrl: string;
  websocketEnabled?: boolean;
  websocketDomain?: string | null;
  timeoutMs?: number;
}

const OutlineAccessKey = z
  .object({
    id: z.string(),
    name: z.string().nullable().optional(),
    accessUrl: z.string(),
    dataLimit: z.object({ bytes: z.number().int().nonnegative() }).optional(),
  })
  .passthrough();
type OutlineAccessKey = z.infer<typeof OutlineAccessKey>;

const OutlineTransferMetrics = z.object({
  bytesTransferredByUserId: z.record(z.string(), z.number().nonnegative()),
});

class OutlineApiError extends Error {
  meta: { status?: number; path?: string };
  constructor(message: string, meta: { status?: number; path?: string } = {}) {
    super(message);
    this.name = 'OutlineApiError';
    this.meta = meta;
  }
}

async function call<T>(
  cfg: OutlineServerConfig,
  args: { method: 'GET' | 'POST' | 'PUT' | 'DELETE'; path: string; body?: unknown; schema: z.ZodType<T> },
): Promise<T> {
  // apiUrl already includes the secret path segment; append to its trailing slash.
  const base = cfg.apiUrl.endsWith('/') ? cfg.apiUrl : `${cfg.apiUrl}/`;
  const url = new URL(args.path.replace(/^\//, ''), base).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs ?? 8000);
  try {
    const res = await fetch(url, {
      method: args.method,
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: args.body !== undefined ? JSON.stringify(args.body) : undefined,
      signal: controller.signal,
    });
    if (!res.ok) {
      // NEVER include the url/apiUrl in the error — only the path + status.
      throw new OutlineApiError(`Outline ${res.status} on ${args.path}`, {
        status: res.status,
        path: args.path,
      });
    }
    if (res.status === 204) return args.schema.parse(undefined);
    const json: unknown = await res.json().catch(() => undefined);
    const parsed = args.schema.safeParse(json);
    if (!parsed.success) throw new OutlineApiError('Outline schema mismatch', { path: args.path });
    return parsed.data;
  } finally {
    clearTimeout(timer);
  }
}

async function setDataLimit(cfg: OutlineServerConfig, id: string, bytes: number | null): Promise<void> {
  if (bytes === null) {
    await call(cfg, {
      method: 'DELETE',
      path: `/access-keys/${encodeURIComponent(id)}/data-limit`,
      schema: z.unknown(),
    });
    return;
  }
  await call(cfg, {
    method: 'PUT',
    path: `/access-keys/${encodeURIComponent(id)}/data-limit`,
    body: { limit: { bytes } },
    schema: z.unknown(),
  });
}

/** Create a key (+ apply a data limit if the tier sets one). Returns the access key. */
export async function outlineIssue(
  cfg: OutlineServerConfig,
  spec: { username: string; trafficLimitBytes: number | null },
): Promise<Omit<IssuedUser, 'outlineServerId'>> {
  const body: Record<string, unknown> = {};
  if (spec.username) body.name = spec.username;
  if (cfg.websocketEnabled) {
    body.websocket = {
      enabled: true,
      tcpPath: '/tcp',
      udpPath: '/udp',
      domain: cfg.websocketDomain ?? '',
      tls: true,
    };
  }
  const key = await call(cfg, {
    method: 'POST',
    path: '/access-keys',
    body: Object.keys(body).length > 0 ? body : undefined,
    schema: OutlineAccessKey,
  });
  if (spec.trafficLimitBytes !== null && spec.trafficLimitBytes > 0) {
    // A failed limit doesn't void a usable key — leave it; tier propagation / the
    // healthcheck cron will reconcile. (We swallow here, matching the original.)
    try {
      await setDataLimit(cfg, key.id, spec.trafficLimitBytes);
    } catch {
      /* noop — key is still usable */
    }
  }
  return {
    backendUserId: key.id,
    backendShortId: key.id, // Outline has no separate short form.
    subscriptionUrl: key.accessUrl,
    raw: key,
  };
}

export async function outlineGetState(
  cfg: OutlineServerConfig,
  backendUserId: string,
): Promise<UserState> {
  const key = await call(cfg, {
    method: 'GET',
    path: `/access-keys/${encodeURIComponent(backendUserId)}`,
    schema: OutlineAccessKey,
  });
  let usedTrafficBytes = 0;
  try {
    const metrics = await call(cfg, {
      method: 'GET',
      path: '/metrics/transfer',
      schema: OutlineTransferMetrics,
    });
    usedTrafficBytes = metrics.bytesTransferredByUserId[backendUserId] ?? 0;
  } catch {
    /* metrics best-effort */
  }
  return {
    trafficLimitBytes: key.dataLimit?.bytes ?? null,
    usedTrafficBytes,
    expireAt: null, // Outline has no per-key expiry; enforced by the local state machine.
    status: 'active', // Outline exposes no status enum; existing key = active.
    devices: [],
  };
}

export async function outlineUpdate(
  cfg: OutlineServerConfig,
  backendUserId: string,
  patch: UpdateUserPatch,
): Promise<void> {
  if (patch.trafficLimitBytes !== undefined) await setDataLimit(cfg, backendUserId, patch.trafficLimitBytes);
  // No native disable: 0-byte limit is the closest soft cutoff (use delete for hard).
  if (patch.status === 'disabled') await setDataLimit(cfg, backendUserId, 0);
  if (patch.status === 'active' && patch.trafficLimitBytes === undefined) {
    await setDataLimit(cfg, backendUserId, null);
  }
  // hwid / strategy / squad / tag / description / expireAt: not applicable to Outline.
}

export async function outlineDelete(cfg: OutlineServerConfig, backendUserId: string): Promise<void> {
  await call(cfg, {
    method: 'DELETE',
    path: `/access-keys/${encodeURIComponent(backendUserId)}`,
    schema: z.unknown(),
  });
}

export async function outlineFetchContent(
  cfg: OutlineServerConfig,
  backendUserId: string,
): Promise<SubscriptionContent> {
  const key = await call(cfg, {
    method: 'GET',
    path: `/access-keys/${encodeURIComponent(backendUserId)}`,
    schema: OutlineAccessKey,
  });
  // An Outline key IS its content — the ss:// URL is everything the client needs.
  // Returned as text so the S3 mirror flow has something to upload.
  return { content: `${key.accessUrl}\n`, contentType: 'text/plain' };
}
