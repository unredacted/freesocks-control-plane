/**
 * HTTP-action helpers (P7): the small replacements for the Hono middleware
 * chain + lib/errors + middleware/services.resolveClientIp. Every public route
 * in convex/http.ts is a bare httpAction; these give it the request-id, the
 * `{ error: { code, message } }` envelope the SPA already parses, cookie-based
 * session resolution, and the fail-closed client-IP trust rules.
 *
 * Auth model: the member + admin sessions are httpOnly signed cookies (no JWT,
 * no Convex ctx.auth). Authenticated data flows through these HTTP actions, not
 * the reactive query channel, so the cookie never has to be readable by JS.
 */
import type { ActionCtx } from '../_generated/server';
import { httpAction } from '../_generated/server';
import { internal } from '../_generated/api';
import type { Id } from '../_generated/dataModel';
import { parseCookies, verifySignedValue } from './cookies';
import { hmacSha256Hex, randomHex } from './crypto';
import { allowedPopHosts, evaluatePop, extractPopFields, REPLAY_TTL_MS } from './pop';
import { POP_HOST_HEADER } from '../../src/shared/crypto/pop';

export const MEMBER_COOKIE = 'fs_session';
export const ADMIN_COOKIE = 'fs_admin_session';

export function newRequestId(): string {
  return randomHex(16);
}

/** Secure cookies everywhere except a local `development` deploy (http://localhost). */
export function secureCookies(): boolean {
  return process.env.ENVIRONMENT !== 'development';
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export function errorJson(
  code: string,
  message: string,
  status: number,
  details?: Record<string, unknown>,
): Response {
  return json({ error: { code, message, ...(details ? { details } : {}) } }, status);
}

// Read the request body text at most once and cache it (a real Request body is
// single-use). The PoP bodyHash and the handler's readJson share this cache so
// that, on a plaintext route, reading one does not starve the other.
const bodyTextCache = new WeakMap<object, Promise<string>>();
function cachedText(req: Request): Promise<string> {
  let p = bodyTextCache.get(req);
  if (!p) {
    p = Promise.resolve()
      .then(() => req.text())
      .catch(() => '');
    bodyTextCache.set(req, p);
  }
  return p;
}

/** Default request-body cap — far above any real payload on this API. */
export const MAX_BODY_BYTES = 64 * 1024;

/** Thrown by readBodyTextCapped; guard()/sealed() map it to a 413 envelope. */
export class PayloadTooLargeError extends Error {
  constructor() {
    super('request body too large');
  }
}

/**
 * Capped wire-body read: rejects on the declared content-length AND the actual
 * length. Convex has already buffered the request by the time an httpAction
 * runs, so the cap saves the downstream JSON.parse / HMAC / HPKE / runAction
 * work, not network ingress. `.length` is UTF-16 units (≤3x byte slack) —
 * fine for a DoS guard, and it matches the webhook route's existing check.
 */
export async function readBodyTextCapped(req: Request, maxBytes = MAX_BODY_BYTES): Promise<string> {
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) throw new PayloadTooLargeError();
  const text = await cachedText(req);
  if (text.length > maxBytes) throw new PayloadTooLargeError();
  return text;
}

export async function readJson<T = Record<string, unknown>>(
  req: Request,
  opts?: { maxBytes?: number },
): Promise<T> {
  const ct = req.headers.get('content-type') ?? '';
  const len = req.headers.get('content-length');
  if (len === '0' || !ct.toLowerCase().includes('json')) return {} as T;
  const text = await readBodyTextCapped(req, opts?.maxBytes);
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    return {} as T;
  }
}

/**
 * Plaintext-route wrapper that converts a PayloadTooLargeError (thrown by
 * readJson/readBodyTextCapped) into the 413 envelope. Sealed routes get the
 * same mapping inside lib/e2ee.sealed(), which reads the wire body itself.
 */
export function guard(handler: (ctx: ActionCtx, req: Request) => Promise<Response>) {
  return httpAction(async (ctx, req) => {
    try {
      return await handler(ctx, req);
    } catch (e) {
      if (e instanceof PayloadTooLargeError) {
        return errorJson('request.too_large', 'Request body too large', 413);
      }
      throw e;
    }
  });
}

/**
 * The EXACT wire body bytes for the PoP bodyHash. On a sealed route the wrapper
 * stashes the original wire body on the proxy request (the handler sees the
 * transformed body via .text(), but PoP must hash what the client actually
 * signed); on a plaintext route this is the cached real-body read, shared with
 * readJson so the single-use body is consumed once.
 */
export async function wireBodyText(req: Request): Promise<string> {
  const stashed = (req as { __fsWireBody?: string }).__fsWireBody;
  if (typeof stashed === 'string') return stashed;
  return cachedText(req);
}

/**
 * Decide whether a cookie session's proof-of-possession requirement is satisfied
 * for this request (CDN-blinding Phase 2). True -> proceed; false -> treat as
 * unauthenticated.
 *
 *  - Bound session (popPublicKey set): a fresh, in-window, non-replayed
 *    signature from the bound key is REQUIRED. Missing/invalid/replayed -> false
 *    (the re-bind rule: never silently accept a new key on an old sid, which a
 *    captured cookie could abuse).
 *  - Legacy/unbound session (predates Phase 2): cookie alone is accepted until
 *    POP_REQUIRED is enabled, then rejected so the client re-logs-in and binds.
 */
async function sessionPopOk(
  ctx: ActionCtx,
  req: Request,
  sid: string,
  popPublicKey: string | undefined,
): Promise<boolean> {
  if (!popPublicKey) return process.env.POP_REQUIRED !== 'true';
  const fields = extractPopFields(req);
  if (!fields) return false;
  const url = new URL(req.url);
  // v2 binds host + the reveal-leg ephemeral; both come from request headers (the
  // signature authenticates them). v1 ignores them (back-compat during rollout).
  const host = req.headers.get(POP_HOST_HEADER) ?? undefined;
  const respEph = req.headers.get('x-fs-resp-eph') ?? undefined;
  const { verdict, nonceHash } = await evaluatePop({
    popPublicKey,
    method: req.method,
    path: url.pathname,
    query: url.search.startsWith('?') ? url.search.slice(1) : url.search,
    host,
    respEph,
    wireBody: await wireBodyText(req),
    fields,
    nowMs: Date.now(),
  });
  if (verdict !== 'ok' || !nonceHash) return false;
  // v2 cross-vhost check: the now-authenticated declared host must be in the
  // allowlist when one is configured (else the bind is tamper-evident but not
  // enforced, so a deployment without POP_EXPECTED_HOST/WEBAUTHN_ORIGIN cannot
  // lock itself out).
  if (fields.version !== 'v1') {
    const allowed = allowedPopHosts();
    if (allowed.length > 0 && (!host || !allowed.includes(host.toLowerCase()))) return false;
  }
  const consumed = await ctx.runMutation(internal.replayGuard.consumeNonce, {
    sid,
    nonceHash,
    ttlMs: REPLAY_TTL_MS,
  });
  return consumed.ok;
}

/**
 * Hash a client IP into a stable rate-limit bucket subject. Never store or bucket
 * on a raw IP (consistent with the audit-log posture); the salted HMAC keeps the
 * counter keyed without persisting the address. Throws if IP_HASH_SALT is unset
 * (fail closed, like every other IP-hash site).
 */
export async function ipHashSubject(ip: string): Promise<string> {
  const salt = process.env.IP_HASH_SALT;
  if (!salt) throw new Error('IP_HASH_SALT must be set (bunx convex env set ...)');
  return hmacSha256Hex(salt, ip);
}

export function bearerToken(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (!h || !h.toLowerCase().startsWith('bearer ')) return null;
  const t = h.slice(7).trim();
  return t || null;
}

/**
 * Resolve the client IP with fail-closed trust rules. A header is only
 * trustworthy if the immediate upstream is KNOWN to set/overwrite it, so both
 * trust sources are opt-in and deployment-dependent:
 *
 *   - `CF_FRONTED=true`: a real Cloudflare edge sits in front and overwrites
 *     `cf-connecting-ip` with the true client IP for every request entering
 *     THROUGH Cloudflare. Enable this ONLY when the origin also rejects direct
 *     (non-CF) traffic (firewall / authenticated origin pulls); otherwise an
 *     attacker hits the origin directly and spoofs the header. Off by default.
 *   - `TRUSTED_PROXY=true`: a normalizing reverse proxy (e.g. Caddy with no
 *     `trusted_proxies`) overwrites `x-forwarded-for` with the immediate peer,
 *     so XFF[0] is the real client and cannot be spoofed.
 *
 * A client-supplied `cf-connecting-ip` is IGNORED unless CF_FRONTED is set:
 * Caddy and most proxies forward that header untouched, so trusting it
 * unconditionally lets any client choose its own rate-limit bucket. With
 * neither flag set we return null rather than a shared fallback (which would
 * itself be one giant rate-limit-bypass bucket).
 */
export function resolveClientIp(req: Request): string | null {
  if (process.env.CF_FRONTED === 'true') {
    const cf = req.headers.get('cf-connecting-ip')?.trim();
    if (cf) return cf;
  }
  if (process.env.TRUSTED_PROXY === 'true') {
    const first = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
    if (first) return first;
  }
  return null;
}

export interface MemberAuth {
  userId: Id<'users'>;
  source: 'cookie' | 'token';
  scopes?: string[];
}

/**
 * Member identity: the fs_session cookie, OR an fsv1_ token with subjectType:user.
 *
 * `required` (P1-1): when the caller is a TOKEN, it must carry this scope or the
 * call resolves to null (unauthenticated). Cookie sessions are the full-privilege
 * member and bypass the scope gate by design. Routes that don't pass a scope
 * accept any valid user token (used for minimal identity reads like /me).
 */
export async function resolveMember(
  ctx: ActionCtx,
  req: Request,
  required?: string,
): Promise<MemberAuth | null> {
  const raw = parseCookies(req.headers.get('cookie'))[MEMBER_COOKIE];
  const key = process.env.SESSION_SIGNING_KEY;
  if (raw && key) {
    const sid = await verifySignedValue(raw, key);
    if (sid) {
      const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
      if (sess && sess.kind === 'member' && sess.userId) {
        if (await sessionPopOk(ctx, req, sid, sess.popPublicKey)) {
          return { userId: sess.userId, source: 'cookie' };
        }
        // Bound session without a valid PoP signature: fall through (no bearer
        // present -> unauthenticated, which forces re-auth per the re-bind rule).
      }
    }
  }
  const bearer = bearerToken(req);
  if (bearer) {
    const tok = await ctx.runAction(internal.apiTokens.resolveToken, { plaintext: bearer });
    if (tok && tok.subjectType === 'user' && tok.subjectUserId) {
      if (required && !hasScope(tok.scopes, required)) return null;
      return { userId: tok.subjectUserId, source: 'token', scopes: tok.scopes };
    }
  }
  return null;
}

/** fsv1_ bearer resolution (service or user token). */
export async function resolveBearer(ctx: ActionCtx, req: Request) {
  const t = bearerToken(req);
  if (!t) return null;
  return ctx.runAction(internal.apiTokens.resolveToken, { plaintext: t });
}

export interface AdminAuth {
  adminUserId?: Id<'adminUsers'>;
  sid?: string;
  tokenScopes?: string[];
}

/**
 * Admin identity: the fs_admin_session cookie, OR an fsv1_ token.
 *
 * `required` (P1-1): when the caller is a TOKEN, it must carry this exact scope
 * (e.g. `admin:tiers:write`) or the call resolves to null. The cookie admin
 * session is the full-privilege admin and bypasses the scope gate. A token with
 * only `admin:*` scopes but not the specific one required is rejected — this is
 * what makes a read-only token actually read-only. (Routes still without a
 * `required` arg fall back to "any admin:* scope", used only by the unauth-
 * tolerant bootstrap-status endpoint.)
 */
export async function resolveAdmin(
  ctx: ActionCtx,
  req: Request,
  required?: string,
): Promise<AdminAuth | null> {
  const raw = parseCookies(req.headers.get('cookie'))[ADMIN_COOKIE];
  const key = process.env.ADMIN_SESSION_SIGNING_KEY;
  if (raw && key) {
    const sid = await verifySignedValue(raw, key);
    if (sid) {
      const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
      if (sess && sess.kind === 'admin' && sess.adminUserId) {
        if (await sessionPopOk(ctx, req, sid, sess.popPublicKey)) {
          return { adminUserId: sess.adminUserId, sid };
        }
        // Bound admin session without valid PoP: fall through to the token path
        // (no admin token present -> unauthenticated -> re-auth).
      }
    }
  }
  const tok = await resolveBearer(ctx, req);
  if (!tok) return null;
  if (required) {
    if (!hasScope(tok.scopes, required)) return null;
  } else if (!tok.scopes.some((s) => s.startsWith('admin:'))) {
    return null;
  }
  return { tokenScopes: tok.scopes };
}

export function hasScope(scopes: string[] | undefined, required: string): boolean {
  return Boolean(scopes?.includes(required));
}
