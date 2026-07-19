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
  // no-store by default: several responses carry secrets (the subscription URL
  // IS the proxy key; /account is the credential surface) and must never land
  // in a shared/intermediary cache if the fronting topology ever changes.
  // Routes that are genuinely cacheable override via `headers` (the spread
  // wins — e.g. /api/v1/e2ee/keys sets 'cache-control: public, max-age=60').
  return new Response(JSON.stringify(data), {
    status,
    // nosniff everywhere (the shipped Caddyfile sets hardening headers at the
    // edge, but a generic reverse-proxy deploy per docs serves API responses
    // without them — the invariant belongs to the origin, not the edge).
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers,
    },
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
 *    signature from the bound key is REQUIRED, AND it must bind the session's own
 *    public per-session token (so a signature cannot be lifted onto another
 *    session that reuses the same persisted key). Missing/invalid/replayed/
 *    wrong-token -> false (the re-bind rule: never silently accept a new key on
 *    an old sid, which a captured cookie could abuse).
 *  - Legacy/unbound session (predates Phase 2): cookie alone is accepted until
 *    POP_REQUIRED is enabled, then rejected so the client re-logs-in and binds.
 */
async function sessionPopOk(
  ctx: ActionCtx,
  req: Request,
  sid: string,
  popPublicKey: string | undefined,
  sessionToken: string | undefined,
  popAlg: string | undefined,
): Promise<boolean> {
  if (!popPublicKey) return process.env.POP_REQUIRED !== 'true';
  // A PoP-bound session must also carry its public per-session token (minted at
  // login + bound into the signature). A bound session without one predates this
  // change → force re-auth. Beta-only breakage; no inter-release compat is kept.
  if (!sessionToken) return false;
  const fields = extractPopFields(req);
  if (!fields) return false;
  const url = new URL(req.url);
  // host + reveal-leg ephemeral are client-declared headers (the signature
  // authenticates them); the session token is the server's OWN stored pst.
  const host = req.headers.get(POP_HOST_HEADER) ?? undefined;
  const respEph = req.headers.get('x-fs-resp-eph') ?? undefined;
  const { verdict, nonceHash } = await evaluatePop({
    popPublicKey,
    popAlg,
    method: req.method,
    path: url.pathname,
    query: url.search.startsWith('?') ? url.search.slice(1) : url.search,
    host,
    respEph,
    sessionToken,
    wireBody: await wireBodyText(req),
    fields,
    nowMs: Date.now(),
  });
  if (verdict !== 'ok' || !nonceHash) return false;
  // Cross-vhost check: the now-authenticated declared host must be in the
  // allowlist when one is configured (else the bind is tamper-evident but not
  // enforced, so a deployment without POP_EXPECTED_HOST/WEBAUTHN_ORIGIN cannot
  // lock itself out). The host is always bound now (single v1 message).
  const allowed = allowedPopHosts();
  if (allowed.length > 0 && (!host || !allowed.includes(host.toLowerCase()))) return false;
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

export type ClientIpRule = 'cf' | 'xff-hops' | 'xff-legacy' | 'none';

export interface ClientIpResolution {
  ip: string | null;
  rule: ClientIpRule;
  /** Effective number of trusted appending hops off the RIGHT of the XFF chain (0 when no XFF trust). */
  hops: number;
  /** The parsed, trimmed, non-empty X-Forwarded-For chain (left→right), for diagnosis. */
  chain: string[];
}

/**
 * Effective trusted-proxy hop count. `TRUSTED_PROXY_HOPS` (an integer ≥1) is the
 * generic knob and WINS when set — a garbage or <1 value pins to 0 (fail closed)
 * rather than silently falling back, so a typo can't quietly widen trust.
 * `TRUSTED_PROXY=true` remains a legacy alias for hops=1 (single-Caddy edge).
 */
function trustedProxyHops(): { hops: number; legacy: boolean } {
  const raw = process.env.TRUSTED_PROXY_HOPS;
  if (raw !== undefined && raw.trim() !== '') {
    const n = Number(raw.trim());
    return { hops: Number.isInteger(n) && n >= 1 ? n : 0, legacy: false };
  }
  return process.env.TRUSTED_PROXY === 'true'
    ? { hops: 1, legacy: true }
    : { hops: 0, legacy: false };
}

/**
 * Resolve the client IP with fail-closed, RIGHT-ANCHORED trust rules. A header is
 * only trustworthy if the immediate upstream is KNOWN to set it, so trust is
 * opt-in and deployment-dependent:
 *
 *   - `CF_FRONTED=true`: a real Cloudflare edge sits in front and overwrites
 *     `cf-connecting-ip` with the true client IP for every request entering
 *     THROUGH Cloudflare. Enable ONLY when the origin also rejects direct
 *     (non-CF) traffic; otherwise an attacker hits the origin directly and
 *     spoofs the header. Off by default. CF wins when set.
 *   - `TRUSTED_PROXY_HOPS=N` (or the legacy `TRUSTED_PROXY=true` ≡ N=1): trust N
 *     appending reverse-proxy hops. We take `chain[len - N]` — counting from the
 *     RIGHT, because the rightmost entries are appended by our own trusted infra
 *     and cannot be client-forged, while leftmost entries can be prepended by a
 *     malicious client if any hop appends rather than overwrites. A single Caddy
 *     edge overwrites XFF to one entry (N=1 → that entry); a fronting proxy
 *     (Pangolin / CF Tunnel / ngrok / LB) in front of Caddy appends one more
 *     (N=2 → the real client, second-from-right). See docs/beta-deploy.md.
 *
 * A chain shorter than `hops` → null (fail closed — the same semantics an
 * unresolvable IP already has on every route; a direct-to-origin request can't
 * then pick its own rate-limit bucket). With no trust configured we return null
 * rather than a shared fallback (which would be one giant rate-limit-bypass
 * bucket). `resolveClientIpDetailed` exposes the rule/hops/chain for the admin
 * self-diagnostic endpoint; `resolveClientIp` is the string-or-null hot path.
 */
export function resolveClientIpDetailed(req: Request): ClientIpResolution {
  const { hops, legacy } = trustedProxyHops();
  const chain = (req.headers.get('x-forwarded-for') ?? '')
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0);

  if (process.env.CF_FRONTED === 'true') {
    const cf = req.headers.get('cf-connecting-ip')?.trim();
    if (cf) return { ip: cf, rule: 'cf', hops, chain };
  }
  if (hops >= 1 && chain.length >= hops) {
    return {
      ip: chain[chain.length - hops]!,
      rule: legacy ? 'xff-legacy' : 'xff-hops',
      hops,
      chain,
    };
  }
  return { ip: null, rule: 'none', hops, chain };
}

export function resolveClientIp(req: Request): string | null {
  return resolveClientIpDetailed(req).ip;
}

/**
 * The visitor's country (ISO-3166-1 alpha-2, uppercase) for country-tiered mirror
 * selection — read from the CDN's `CF-IPCountry` header, and ONLY when CF_FRONTED
 * (otherwise it is a spoofable client header). Returns null for unknown / anonymizer
 * values (`XX`, `T1`, `T2`). Used transiently to pick a nearby mirror host; it is
 * NEVER stored and never bound to the user.
 */
export function resolveCountry(req: Request): string | null {
  if (process.env.CF_FRONTED !== 'true') return null;
  const cc = req.headers.get('cf-ipcountry')?.trim().toUpperCase();
  if (!cc || !/^[A-Z]{2}$/.test(cc) || cc === 'XX' || cc === 'T1' || cc === 'T2') return null;
  return cc;
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
 *
 * Member W3-8a: the resolved member's STATUS is re-checked on every request
 * (the same admission set as users.byAccountIdHash), so an admin disable or a
 * delete stops authorizing immediately instead of waiting out the 30-day
 * session TTL — and a pre-existing session can't be used to mint a fresh key
 * past an admin ban. LAPSED (membership_lapsed) and INACTIVE members KEEP
 * access: their renewal / reactivation flows run through these endpoints.
 */
export async function resolveMember(
  ctx: ActionCtx,
  req: Request,
  required?: string,
): Promise<MemberAuth | null> {
  let member: MemberAuth | null = null;
  const raw = parseCookies(req.headers.get('cookie'))[MEMBER_COOKIE];
  const key = process.env.SESSION_SIGNING_KEY;
  if (raw && key) {
    const sid = await verifySignedValue(raw, key);
    if (sid) {
      const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
      if (sess && sess.kind === 'member' && sess.userId) {
        if (
          await sessionPopOk(ctx, req, sid, sess.popPublicKey, sess.popSessionToken, sess.popAlg)
        ) {
          member = { userId: sess.userId, source: 'cookie' };
        }
        // Bound session without a valid PoP signature: fall through (no bearer
        // present -> unauthenticated, which forces re-auth per the re-bind rule).
      }
    }
  }
  if (!member) {
    const bearer = bearerToken(req);
    if (bearer) {
      const tok = await ctx.runAction(internal.apiTokens.resolveToken, { plaintext: bearer });
      if (tok && tok.subjectType === 'user' && tok.subjectUserId) {
        if (required && !hasScope(tok.scopes, required)) return null;
        member = { userId: tok.subjectUserId, source: 'token', scopes: tok.scopes };
      }
    }
  }
  if (!member) return null;
  const user = await ctx.runQuery(internal.users.get, { id: member.userId });
  if (!user || user.status === 'deleted') return null;
  if (user.status === 'disabled' && user.disabledReason !== 'membership_lapsed') return null;
  return member;
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
        // A deactivated admin's session must stop authorizing immediately
        // (W3-8a): re-check isActive on every request, so revoking access does
        // not wait for the session TTL.
        const adminRow = await ctx.runQuery(internal.admins.getById, {
          adminUserId: sess.adminUserId,
        });
        if (
          adminRow?.isActive &&
          (await sessionPopOk(ctx, req, sid, sess.popPublicKey, sess.popSessionToken, sess.popAlg))
        ) {
          return { adminUserId: sess.adminUserId, sid };
        }
        // Inactive admin, or a bound session without valid PoP: fall through to
        // the token path (no admin token present -> unauthenticated -> re-auth).
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

/**
 * Cookie-only admin-session probe for the unauthenticated `/api/admin/auth/status`
 * endpoint. Returns the bound adminUserId when the fs_admin_session cookie maps
 * to a live admin session — deliberately WITHOUT a proof-of-possession check.
 *
 * This is *detection*, not authorization: the status route returns only booleans
 * (signed-in? / bootstrap state) and performs no privileged action, so skipping
 * PoP here leaks nothing a cookie-holder didn't already have. Every privileged
 * admin route still goes through `resolveAdmin` (full PoP). Using `resolveAdmin`
 * here was the /admin re-prompt bug: a PoP-bound session's status GET is unsigned
 * (the admin auth surface can't be signed), so `sessionPopOk` failed and the
 * landing page reported signed-out and re-prompted an already-authenticated admin.
 */
export async function adminSessionProbe(
  ctx: ActionCtx,
  req: Request,
): Promise<Id<'adminUsers'> | null> {
  const raw = parseCookies(req.headers.get('cookie'))[ADMIN_COOKIE];
  const key = process.env.ADMIN_SESSION_SIGNING_KEY;
  if (!raw || !key) return null;
  const sid = await verifySignedValue(raw, key);
  if (!sid) return null;
  const sess = await ctx.runQuery(internal.sessions.bySid, { sid });
  if (!(sess && sess.kind === 'admin' && sess.adminUserId)) return null;
  // A deactivated admin reads as signed-out (so the SPA shows login, not an
  // admin shell whose every call 401s).
  const adminRow = await ctx.runQuery(internal.admins.getById, { adminUserId: sess.adminUserId });
  return adminRow?.isActive ? sess.adminUserId : null;
}

export function hasScope(scopes: string[] | undefined, required: string): boolean {
  return Boolean(scopes?.includes(required));
}
