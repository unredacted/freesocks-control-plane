/**
 * Shared pieces of the admin HTTP dispatchers (one prefix route per verb feeding
 * a small dispatcher: `httpEdges.ts`, and the sections that follow its shape).
 * Each section keeps its own route table, scope map and code-to-status map;
 * what is identical between them lives here so the rules cannot drift:
 *
 *  - `makeFail`: turn a thrown error into a response WITHOUT ever logging a
 *    non-ConvexError message (Convex's ArgumentValidationError text embeds the
 *    offending argument VALUES: addresses, credentials, ids the caller typed).
 *  - `actorSubject` / `throttle`: the per-actor rate-limit subject, which is
 *    never the token plaintext (bucket names land in the DB).
 */
import { ConvexError } from 'convex/values';
import type { ActionCtx } from '../_generated/server';
import { internal } from '../_generated/api';
import { sha256Hex } from './crypto';
import { errorJson, ipHashSubject, newRequestId, resolveClientIp, type AdminAuth } from './http';
import type { RateLimitPolicyKey } from './rateLimitPolicy';

export const notFound = () => errorJson('not_found', 'Not found', 404);
export const unauth = () => errorJson('auth.unauthenticated', 'Authentication required', 401);

/**
 * Build a section's error responder. `tag` names the section in the one log
 * line an unhandled error produces (class name + request id, nothing else);
 * `statusFromCode` is the section's own mapping of `ConvexError.data.code`.
 */
export function makeFail(
  tag: string,
  statusFromCode: (code: string) => number,
): (err: unknown) => Response {
  return (err) => {
    if (err instanceof ConvexError) {
      const data = err.data as { code?: string; message?: string };
      const code = data.code ?? 'error';
      return errorJson(code, data.message ?? 'Request failed', statusFromCode(code));
    }
    const requestId = newRequestId();
    const kind = err instanceof Error ? err.constructor.name || err.name : typeof err;
    console.error(`[${tag}] unhandled error kind=${kind} requestId=${requestId}`);
    return errorJson('admin.error', 'The request could not be completed.', 400, { requestId });
  };
}

/**
 * Per-actor rate-limit subject: the admin id for a cookie session, a hash of
 * the bearer token for an `fsv1_` caller, else the (hashed) client IP. The
 * token plaintext is never the subject (bucket names land in the DB).
 */
export async function actorSubject(req: Request, admin: AdminAuth): Promise<string> {
  if (admin.adminUserId) return `admin:${admin.adminUserId}`;
  const m = /^Bearer\s+(\S+)$/i.exec((req.headers.get('authorization') ?? '').trim());
  if (m) return `tok:${(await sha256Hex(m[1])).slice(0, 32)}`;
  const ip = resolveClientIp(req);
  return ip ? `ip:${await ipHashSubject(ip)}` : 'unknown';
}

/** Enforce one rate-limit policy for this actor; a Response when refused, else null. */
export async function throttle(
  ctx: ActionCtx,
  req: Request,
  admin: AdminAuth,
  policyKey: RateLimitPolicyKey,
): Promise<Response | null> {
  const rl = await ctx.runMutation(internal.rateLimits.enforce, {
    policyKey,
    subject: await actorSubject(req, admin),
  });
  if (rl.allowed) return null;
  return errorJson('rate_limit.exceeded', 'Too many requests. Please slow down.', 429, {
    retryAfterMs: rl.retryAfterMs,
  });
}
