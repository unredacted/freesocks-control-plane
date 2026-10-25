/**
 * FCP's side of the client-check wire (docs/edges.md § "FCP's own client
 * check"): where the service is, and the two signed calls. Runs in Convex's
 * default runtime (fetch + WebCrypto); `fetchImpl` is the test seam.
 *
 * Configuration (deployment env): `EDGE_CLIENT_CHECK_SECRET` turns it on (the
 * same secret the service holds); `EDGE_CLIENT_CHECK_URL` says where the service
 * listens, `http://edge-client-check:8080` (its compose name) when unset. The
 * address is the operator's own setting, so no SSRF check applies to it.
 */
import type {
  ClientCheckEngine,
  ClientCheckUncheckedCode,
} from '../../../../src/shared/contracts/edgeCodes';
import {
  CLIENT_CHECK_CALL_MS,
  CLIENT_CHECK_PATHS,
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
  type ClientCheckHealth,
  type ClientCheckResponse,
} from './protocol';
import { signRequest } from './signing';

export const DEFAULT_CLIENT_CHECK_URL = 'http://edge-client-check:8080';

export interface ClientCheckService {
  url: string;
  secret: string;
}

/** The configured service, or null when the deployment has no secret for it. */
export function clientCheckService(
  env: Record<string, string | undefined>,
): ClientCheckService | null {
  const secret = env.EDGE_CLIENT_CHECK_SECRET?.trim();
  if (!secret) return null;
  const url = (env.EDGE_CLIENT_CHECK_URL?.trim() || DEFAULT_CLIENT_CHECK_URL).replace(/\/+$/, '');
  return { url, secret };
}

export type ServiceAnswer<T> =
  | { ok: true; value: T }
  | { ok: false; code: ClientCheckUncheckedCode };

type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

async function signedCall(
  svc: ClientCheckService,
  method: 'GET' | 'POST',
  path: string,
  body: string,
  fetchImpl: FetchLike,
): Promise<ServiceAnswer<unknown>> {
  const time = String(Date.now());
  const signature = await signRequest(svc.secret, method, path, time, body);
  let res: Response;
  try {
    res = await fetchImpl(`${svc.url}${path}`, {
      method,
      ...(method === 'POST' ? { body } : {}),
      headers: {
        ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        [CLIENT_CHECK_TIME_HEADER]: time,
        [CLIENT_CHECK_SIGNATURE_HEADER]: signature,
      },
      redirect: 'error',
      signal: AbortSignal.timeout(CLIENT_CHECK_CALL_MS),
    });
  } catch {
    return { ok: false, code: 'unavailable' };
  }
  if (res.status === 401) return { ok: false, code: 'unauthorized' };
  if (res.status === 429) return { ok: false, code: 'busy' };
  if (res.status === 503) return { ok: false, code: 'not_configured' };
  if (!res.ok) return { ok: false, code: 'unavailable' };
  try {
    return { ok: true, value: await res.json() };
  } catch {
    return { ok: false, code: 'unavailable' };
  }
}

/** One engine's session through one outbound. */
export async function runEngineCheck(
  svc: ClientCheckService,
  req: { engine: ClientCheckEngine; outbound: Record<string, unknown>; reality: boolean },
  fetchImpl: FetchLike = fetch,
): Promise<ServiceAnswer<ClientCheckResponse>> {
  const a = await signedCall(svc, 'POST', CLIENT_CHECK_PATHS.check, JSON.stringify(req), fetchImpl);
  if (!a.ok) return a;
  const v = a.value as Partial<ClientCheckResponse> | null;
  if (!v || typeof v.ok !== 'boolean' || typeof v.code !== 'string')
    return { ok: false, code: 'unavailable' };
  return { ok: true, value: v as ClientCheckResponse };
}

export async function fetchHealth(
  svc: ClientCheckService,
  fetchImpl: FetchLike = fetch,
): Promise<ServiceAnswer<ClientCheckHealth>> {
  const a = await signedCall(svc, 'GET', CLIENT_CHECK_PATHS.health, '', fetchImpl);
  if (!a.ok) return a;
  const v = a.value as Partial<ClientCheckHealth> | null;
  if (!v || v.ok !== true || !Array.isArray(v.engines)) return { ok: false, code: 'unavailable' };
  return { ok: true, value: v as ClientCheckHealth };
}
