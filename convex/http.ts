/**
 * Public HTTP surface (P7): the httpRouter that replaces the Hono app +
 * @hono/zod-openapi routes. Served on the Convex HTTP-actions port (:3211; in
 * dev the SPA's vite proxy forwards /api → here, so it's same-origin and needs
 * no CORS). Each handler is a bare httpAction; auth + the {error:{code,message}}
 * envelope + client-IP trust come from lib/http, cookie signing from lib/cookies.
 *
 * Member identity = the fs_session cookie OR an fsv1_ user token; admin identity
 * = the fs_admin_session cookie OR an fsv1_ admin-scoped token. No OIDC.
 */
import { httpRouter } from 'convex/server';
import { httpAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { ConvexError } from 'convex/values';
import { SETTINGS_DEFAULTS } from './appSettings';
import {
  CONNECTION_MODES,
  DEFAULT_CONNECTION_MODE,
  isConnectionModeId,
} from './lib/connectionModes';
import { buildSetCookie, parseCookies, verifySignedValue } from './lib/cookies';
import { verifyCaptcha } from './lib/captcha';
import { sealed } from './lib/e2ee';
import { POP_ALG_FIELD, POP_PUBKEY_FIELD } from '../src/shared/crypto/pop';
import {
  ADMIN_COOKIE,
  MEMBER_COOKIE,
  adminSessionProbe,
  errorJson,
  guard,
  ipHashSubject,
  json,
  newRequestId,
  readJson,
  resolveAdmin,
  resolveClientIp,
  resolveClientIpDetailed,
  resolveCountry,
  resolveMember,
  secureCookies,
} from './lib/http';

const http = httpRouter();

function statusFromCode(code: string): number {
  switch (code) {
    case 'auth.forbidden':
      return 403;
    case 'auth.unauthenticated':
      return 401;
    case 'rate_limit.exceeded':
      return 429;
    case 'not_found':
      return 404;
    default:
      return 400;
  }
}

/** Map a ConvexError({code,message}) thrown by an internalAction to an envelope. */
function convexError(err: unknown): Response {
  if (err instanceof ConvexError) {
    const data = err.data as { code?: string; message?: string };
    const code = data.code ?? 'error';
    return errorJson(code, data.message ?? 'Request failed', statusFromCode(code));
  }
  throw err;
}

/**
 * Map a subscription-issuance failure (account.regenerate / switch-backend) to a
 * clean envelope. A missing/empty proxy backend ("No active <backend> instances")
 * becomes a 503 the user can act on; anything else is logged server-side (the
 * backend error types already scrub URLs/secrets) and returned as a generic 502,
 * never a bare 500. Pairs with src/client/lib/api.ts's non-envelope fallback.
 */
function issuanceErrorResponse(err: unknown, requestId: string): Response {
  // A missing/empty proxy backend surfaces as a typed
  // ConvexError({code:'backend.unavailable'}) from backends.issueUser → a 503 the
  // user can act on. Match on the CODE (the message regex is only a legacy fallback
  // for any pre-typed error). (Review P3.)
  const code =
    err instanceof ConvexError && typeof (err.data as { code?: unknown })?.code === 'string'
      ? (err.data as { code: string }).code
      : null;
  const msg = err instanceof Error ? err.message : String(err);
  if (code === 'backend.unavailable' || /No active .* instances/i.test(msg)) {
    return errorJson(
      'backend.unavailable',
      'No proxy server is available right now. Please try again later or contact support.',
      503,
    );
  }
  console.error(`[subscription] issuance failed (req ${requestId}): ${msg}`);
  return errorJson(
    'issuance.failed',
    'Could not create a subscription right now. Please try again later.',
    502,
  );
}

/**
 * The shared member issuance-saga scaffold (regenerate / switch-backend /
 * switch-profile): rate-limit → acquire the per-user issuance lock → run → map
 * issuance errors → ALWAYS release the lock (owner-nonce checked, Review #7).
 * Centralizes three near-identical copies and removes the risk of a route
 * forgetting the `finally` release (a lock leak). The caller's `run` performs the
 * action call and shapes the success Response. (Review P3.)
 */
async function withIssuanceSaga(
  ctx: ActionCtx,
  userId: Id<'users'>,
  policyKey: string,
  run: (requestId: string) => Promise<Response>,
): Promise<Response> {
  const rl = await ctx.runMutation(internal.rateLimits.enforce, { policyKey, subject: userId });
  if (!rl.allowed) {
    return errorJson('rate_limit.exceeded', 'Too many changes. Please wait and try again.', 429, {
      retryAfterMs: rl.retryAfterMs,
    });
  }
  const lock = await ctx.runMutation(internal.account.acquireIssuanceLock, { userId });
  if (!lock.acquired) {
    return errorJson('issuance.in_progress', 'Another change is already in progress.', 409);
  }
  const requestId = newRequestId();
  try {
    return await run(requestId);
  } catch (err) {
    return issuanceErrorResponse(err, requestId);
  } finally {
    await ctx.runMutation(internal.account.releaseIssuanceLock, { userId, token: lock.token });
  }
}

/**
 * Shape a saga action's discriminated result into a Response: the error envelope on
 * failure, else the payload with the envelope fields (ok/status/code/message)
 * stripped. Used by switch-backend / switch-profile (regenerate returns raw).
 */
function sagaResult(result: {
  ok: boolean;
  status?: number;
  code?: string;
  message?: string;
}): Response {
  if (!result.ok) {
    return errorJson(
      result.code ?? 'issuance.failed',
      result.message ?? 'Request failed',
      result.status ?? 400,
    );
  }
  const {
    ok: _ok,
    status: _status,
    code: _code,
    message: _message,
    ...payload
  } = result as Record<string, unknown> & { ok: boolean };
  return json(payload);
}

const ADMIN_UNAUTH = () => errorJson('auth.unauthenticated', 'Authentication required', 401);

/**
 * Last path segment of a request URL, used to parse `:id` / `:op` out of the
 * pathPrefix-registered admin routes (Convex's httpRouter has no path params).
 * Trailing slashes are tolerated.
 */
function lastPathSegment(req: Request): string {
  const parts = new URL(req.url).pathname.split('/').filter(Boolean);
  return parts[parts.length - 1] ?? '';
}

// In-front cache TTL for the FCP-fronted subscription route (GET /api/v1/sub/*):
// short, so a proxy app re-poll sees near-fresh config while bursts/re-loads are
// absorbed and we don't hit the backend every time.
const SUBSCRIPTION_CACHE_TTL_MS = 30_000;

// One entry in the serialized `subscriptions.subCache` blob (a bounded per-UA
// list — see subscriptions.writeContentCache). Keyed by UA because Remnawave
// formats the subscription by User-Agent — we must never serve one client's
// format to another, on BOTH the fresh-hit and the stale-fallback paths. (Review #11.)
interface SubCacheEntry {
  content: string;
  contentType: string;
  headers?: Record<string, string>;
  ua: string;
  at: number;
}

/** The RAW subscription Response a proxy app consumes (not the JSON envelope):
 *  the backend content-type + cache-control + the passed-through metadata headers
 *  (traffic/expiry counters, update cadence).
 *
 *  Caching (this route can sit behind a shared cache/CDN): the body is formatted
 *  per User-Agent, so the public path MUST send `Vary: User-Agent` or a shared
 *  cache cross-serves the first fetcher's format (Clash vs v2ray) to everyone on
 *  the token. An HWID (device-specific) request is `private, no-store` — each
 *  device must reach the panel to register + get its own body. */
function subscriptionResponse(
  entry: { content: string; contentType: string; headers?: Record<string, string> },
  opts?: { hwid?: boolean },
): Response {
  const headers: Record<string, string> = {
    'content-type': entry.contentType || 'text/plain',
    ...(entry.headers ?? {}),
  };
  if (opts?.hwid) {
    headers['cache-control'] = 'private, no-store';
  } else {
    headers['cache-control'] = `public, max-age=${Math.floor(SUBSCRIPTION_CACHE_TTL_MS / 1000)}`;
    headers['vary'] = 'User-Agent';
  }
  return new Response(entry.content, { status: 200, headers });
}

/** Parse the bounded per-UA subCache blob; tolerates a legacy single-entry blob. */
function parseSubCache(blob: string | null | undefined): SubCacheEntry[] {
  if (!blob) return [];
  try {
    const parsed = JSON.parse(blob) as unknown;
    if (Array.isArray(parsed)) return parsed as SubCacheEntry[];
    if (parsed && typeof parsed === 'object') return [parsed as SubCacheEntry];
    return [];
  } catch {
    return [];
  }
}

/**
 * For `POST /api/v1/admin/users/{id}/{op}`: returns the id + op. Path shape is
 * `.../users/<id>/<op>`; both are the last two non-empty segments.
 */
function userIdAndOp(req: Request): { id: string; op: string } {
  const parts = new URL(req.url).pathname.split('/').filter(Boolean);
  const op = parts[parts.length - 1] ?? '';
  const id = parts[parts.length - 2] ?? '';
  return { id, op };
}

/** Turn an admin-resource handler error into a 400 envelope (uniqueness, etc.). */
function adminError(err: unknown): Response {
  if (err instanceof ConvexError) return convexError(err);
  const msg = err instanceof Error ? err.message : String(err);
  return errorJson('admin.error', msg, 400);
}

// --- operational ------------------------------------------------------------

// Liveness: the process is up and routing. Cheap, no datastore touch.
http.route({
  path: '/healthz',
  method: 'GET',
  handler: httpAction(async () =>
    json({ ok: true, timestamp: new Date().toISOString(), requestId: newRequestId() }),
  ),
});

// A3: readiness — a real datastore round-trip, so an uptime monitor can tell a
// wedged Postgres / exhausted pool apart from a merely-live process. 503 on
// failure so the monitor pages. Point external monitoring at /readyz.
http.route({
  path: '/readyz',
  method: 'GET',
  handler: httpAction(async (ctx) => {
    try {
      await ctx.runQuery(internal.health.dbPing, {});
      return json({ ok: true, db: 'ok', timestamp: new Date().toISOString() });
    } catch {
      return json({ ok: false, db: 'error', timestamp: new Date().toISOString() }, 503);
    }
  }),
});

/** Best-effort per-IP throttle for an unauthenticated public GET (origin-DoS
 *  hygiene, not access control). Skips silently when the client IP can't be
 *  resolved (no trusted proxy configured) so a misconfigured proxy never bricks a
 *  public read. Returns a 429 Response when limited, else null. */
async function throttlePublicGet(
  ctx: ActionCtx,
  req: Request,
  policyKey: 'config.fetch' | 'e2ee.keys.fetch',
): Promise<Response | null> {
  const ip = resolveClientIp(req);
  if (!ip) return null;
  const rl = await ctx.runMutation(internal.rateLimits.enforce, {
    policyKey,
    subject: await ipHashSubject(ip),
  });
  if (rl.allowed) return null;
  return errorJson('rate_limit.exceeded', 'Too many requests. Please slow down.', 429, {
    retryAfterMs: rl.retryAfterMs,
  });
}

http.route({
  path: '/api/v1/config',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const limited = await throttlePublicGet(ctx, req, 'config.fetch');
    if (limited) return limited;
    return json(await ctx.runQuery(api.publicConfig.get, {}));
  }),
});

// CDN-blinding Phase 3: the current manifest-signed epoch KEM public key (and,
// from P3c, the revoked-kid list). Public + unauthenticated: the key is public
// and the client verifies the manifest signature against its baked manifest
// public key before sealing the login to it, so a CDN that tampers is caught.
// Briefly cacheable (the epoch is valid for ~30 min and carries its own notAfter).
http.route({
  path: '/api/v1/e2ee/keys',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const limited = await throttlePublicGet(ctx, req, 'e2ee.keys.fetch');
    if (limited) return limited;
    const [epoch, revocation] = await Promise.all([
      ctx.runQuery(internal.keyEpochs.current, {}),
      ctx.runQuery(internal.keyRevocations.current, {}),
    ]);
    return json(
      {
        epoch: epoch
          ? {
              kid: epoch.kid,
              publicKey: epoch.publicKey,
              notAfter: epoch.notAfter,
              sig: epoch.manifestSig,
              sigPq: epoch.manifestSigPq,
            }
          : null,
        revocation: revocation
          ? {
              version: revocation.version,
              revokedKids: revocation.revokedKids,
              notAfter: revocation.notAfter,
              sig: revocation.manifestSig,
              sigPq: revocation.manifestSigPq,
            }
          : null,
      },
      200,
      { 'cache-control': 'public, max-age=60' },
    );
  }),
});

// --- account creation -------------------------------------------------------
// Anonymous sign-up: Cap captcha -> mint a user + account number + member session.
// NO proxy backend is touched here (the proxy key is created separately, once
// signed in, via POST /api/v1/account/regenerate), so a missing/empty backend
// can never block account creation. The account-number reveal is sealed (the
// '/api/v1/account' reveal policy in src/shared/crypto/envelope.ts).

http.route({
  path: '/api/v1/account',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const requestId = newRequestId();

    // Already signed in? They already have an account.
    if (await resolveMember(ctx, req)) {
      return errorJson(
        'account.exists',
        'You are already signed in. Sign out before creating another account.',
        409,
      );
    }

    const body = await readJson<{
      captchaToken?: string;
      turnstileToken?: string;
      backend?: 'remnawave' | 'outline';
    }>(req);
    // Accept the new `captchaToken` and the legacy `turnstileToken` (skew window).
    const captchaToken = body.captchaToken ?? body.turnstileToken;
    if (!captchaToken) {
      return errorJson('validation', 'Captcha token required', 400);
    }
    const ip = resolveClientIp(req);
    if (!ip) {
      return errorJson(
        'freetier.ip_unresolved',
        'Unable to establish your network address. Try again later or contact support.',
        503,
      );
    }
    // P1-2: per-IP throttle BEFORE the outbound captcha verify, so a flood can't
    // drive verify QPS (the per-day cap is enforced later in claimFreeSlot).
    const createRl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account.create.ip',
      subject: await ipHashSubject(ip),
    });
    if (!createRl.allowed) {
      return errorJson(
        'rate_limit.exceeded',
        'Too many attempts from your network. Please wait a bit and try again.',
        429,
        { retryAfterMs: createRl.retryAfterMs },
      );
    }
    const cap = await verifyCaptcha(captchaToken);
    if (!cap.configured) return errorJson('config', 'Captcha not configured', 503);
    if (!cap.success) return errorJson('auth.captcha_failed', 'Captcha verification failed', 403);

    // Resolve which default-free tier (backend) the new account lands on. This
    // reads only the admin enabled/default toggles, never proxy availability.
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    let backend = settings['subscription.default_backend'] as 'remnawave' | 'outline';
    if (body.backend && settings['subscription.user_choice_enabled']) backend = body.backend;
    if (!settings[`${backend}.enabled`]) {
      return errorJson(
        'backend.disabled',
        `Backend "${backend}" is currently disabled. Try again later or contact support.`,
        503,
      );
    }

    // PoP (Phase 2): account creation establishes a member session, so the client
    // folds its session public key into the (sealed) body to bind it (like login).
    const popRaw = (body as Record<string, unknown>)[POP_PUBKEY_FIELD];
    const popAlgRaw = (body as Record<string, unknown>)[POP_ALG_FIELD];

    let result;
    try {
      result = await ctx.runAction(internal.freeTier.createFreeAccount, {
        ip,
        ipCountry: req.headers.get('cf-ipcountry') ?? undefined,
        userAgent: req.headers.get('user-agent') ?? undefined,
        requestId,
        backend,
        popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
        popAlg: typeof popAlgRaw === 'string' ? popAlgRaw : undefined,
      });
    } catch (err) {
      // Account creation has no backend dependency, so a throw here is a config
      // or infra error. Log the detail server-side; return a clean envelope.
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[account] create failed (req ${requestId}): ${msg}`);
      return errorJson(
        'account.create_failed',
        'Could not create an account right now. Please try again later.',
        502,
      );
    }

    if (!result.ok) {
      // The per-(IP,day) cap is reached. There is no key to hand back (issuance
      // is a separate flow now), so the visitor signs in with their number.
      return errorJson(
        'freetier.cap_reached',
        'You have already created an account from this network today. Sign in with your account number instead.',
        429,
      );
    }

    const cookie = buildSetCookie(MEMBER_COOKIE, result.signedCookieValue, {
      maxAge: result.maxAgeSec,
      sameSite: 'Lax',
      secure: secureCookies(),
    });
    return json(
      {
        accountId: result.accountId,
        tier: result.tier,
        authenticated: true,
        // Public per-session token (PoP sid-binding): the client persists it and
        // signs it into every PoP message. Non-secret. Absent for unbound clients.
        popSessionToken: result.popSessionToken,
      },
      200,
      { 'set-cookie': cookie },
    );
  }),
});

// --- member auth ------------------------------------------------------------

http.route({
  path: '/api/v1/auth/account-login',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const body = await readJson<{
      accountId?: string;
      captchaToken?: string;
      turnstileToken?: string;
    }>(req);
    const captchaToken = body.captchaToken ?? body.turnstileToken;
    if (!body.accountId || !captchaToken) {
      return errorJson('validation', 'accountId and captchaToken are required', 400);
    }
    const ip = resolveClientIp(req) ?? undefined;
    // Per-IP throttle BEFORE the outbound captcha verify (mirrors account-create,
    // P1-2): without it, a login flood drives one Cap siteverify call per request.
    // Same policy key + subject the action used before, so counters carry over.
    // Not an oracle — the 429 depends only on the requester's own IP, never on
    // account validity (those failures stay folded into the generic 'invalid').
    // Unresolvable IP -> skip (matches the webhook route; a proxy misconfig must
    // not take login down, and the per-(prefix,IP) backstop still applies).
    if (ip) {
      const rl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'account-login.ip',
        subject: await ipHashSubject(ip),
      });
      if (!rl.allowed) {
        return errorJson(
          'rate_limit.exceeded',
          'Too many attempts from your network. Please wait a bit and try again.',
          429,
          { retryAfterMs: rl.retryAfterMs },
        );
      }
    }
    // PoP (Phase 2): the client folds its session public key into the (sealed)
    // login body to bind the session to it.
    const popRaw = (body as Record<string, unknown>)[POP_PUBKEY_FIELD];
    const popAlgRaw = (body as Record<string, unknown>)[POP_ALG_FIELD];
    const res = await ctx.runAction(internal.auth.accountLogin, {
      accountId: body.accountId,
      captchaToken,
      ip,
      popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
      popAlg: typeof popAlgRaw === 'string' ? popAlgRaw : undefined,
    });
    if (!res.ok) {
      if (res.reason === 'config') {
        // Cap unconfigured (CAP_* unset) — a loud misconfig signal, not a generic
        // captcha failure, matching the account-create route. (Review #12.)
        return errorJson('config', 'Captcha not configured', 503);
      }
      if (res.reason === 'captcha') {
        return errorJson('auth.captcha_failed', 'Captcha verification failed', 403);
      }
      return errorJson('auth.invalid_account_id', 'The submitted credential is not valid', 401);
    }
    const cookie = buildSetCookie(MEMBER_COOKIE, res.signedCookieValue, {
      maxAge: res.maxAgeSec,
      sameSite: 'Lax',
      secure: secureCookies(),
    });
    return json(
      { ok: true, popSessionToken: res.popSessionToken, lapsedDowngrade: res.lapsedDowngrade },
      200,
      { 'set-cookie': cookie },
    );
  }),
});

http.route({
  path: '/api/v1/auth/logout',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const raw = parseCookies(req.headers.get('cookie'))[MEMBER_COOKIE];
    const key = process.env.SESSION_SIGNING_KEY;
    if (raw && key) {
      const sid = await verifySignedValue(raw, key);
      if (sid) await ctx.runMutation(internal.sessions.deleteBySid, { sid });
    }
    const cookie = buildSetCookie(MEMBER_COOKIE, '', {
      maxAge: 0,
      sameSite: 'Lax',
      secure: secureCookies(),
    });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }),
});

http.route({
  path: '/api/v1/me',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const member = await resolveMember(ctx, req);
    if (!member) return json({ authenticated: false });
    const user = await ctx.runQuery(internal.users.get, { id: member.userId });
    const tier = user ? await ctx.runQuery(internal.tiers.get, { id: user.tierId }) : null;
    if (!user || !tier) return json({ authenticated: false });
    return json({
      authenticated: true,
      member: {
        tier: { slug: tier.slug, name: tier.name },
      },
    });
  }),
});

// --- account ----------------------------------------------------------------

http.route({
  path: '/api/v1/account',
  method: 'GET',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const view = await ctx.runAction(internal.account.getAccountView, { userId: member.userId });
    if (!view) return errorJson('not_found', 'user not found', 404);
    // geoCountry (transient, from the CDN header) prefills the "try a mirror"
    // picker AND drives the delivery suggestion. Inside the sealed body; never
    // stored on the user. The suggestion = "privacy" only for the admin-listed
    // countries (delivery.privacyCountries), else "evade"; the choice itself is
    // client-side. The country list stays server-side — only the verdict ships.
    const geoCountry = resolveCountry(req);
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const privacyCountries = (settings['delivery.privacyCountries'] as string[] | undefined) ?? [];
    // Suggest the hardened (rawConfig) mode for the admin-listed countries, else
    // the catalog default. Data-driven off the mode catalog; the choice itself
    // stays client-side and the country list never leaves the server.
    const hardenedModeId =
      CONNECTION_MODES.find((m) => m.deliveryStyle === 'rawConfig')?.id ?? DEFAULT_CONNECTION_MODE;
    const suggestedModeId =
      geoCountry && privacyCountries.includes(geoCountry)
        ? hardenedModeId
        : DEFAULT_CONNECTION_MODE;
    return json({ ...view, geoCountry, suggestedModeId });
  }),
});

// Aggregate usage trend for the member's key (last ~30 days). Non-secret member
// stats, read live from the backend and NEVER persisted; unsealed (TLS + PoP).
// Lazy — the SPA calls this only when the member opens the usage panel, so it
// doesn't add a second live backend call to the main /account load. Degrades to
// `{ usage: null }` for backends without usage history (Outline) or on any error.
http.route({
  path: '/api/v1/account/usage',
  method: 'GET',
  handler: guard(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const { usage } = await ctx.runAction(internal.account.getUsage, { userId: member.userId });
    return json({ usage });
  }),
});

// Raw subscription content (the actual proxy config) for manual setup. Fetched
// server-side from the backend and returned over the SEALED reveal-leg channel,
// so a privacy-minded member can copy their config by hand WITHOUT their proxy
// client pulling the subscription URL through a CDN in plaintext — the
// E2EE-preserving alternative to the public S3 mirror.
http.route({
  path: '/api/v1/subscription/content',
  method: 'GET',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const sub = await ctx.runQuery(internal.subscriptions.mirrorContextForUser, {
      userId: member.userId,
    });
    if (!sub) return errorJson('not_found', 'No active subscription', 404);
    try {
      const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: sub.backend,
        backendServerId: sub.backendServerId ?? undefined,
        backendShortId: sub.backendShortId,
        subscriptionUrl: sub.subscriptionUrl,
      });
      return json({ content: fetched.content, contentType: fetched.contentType ?? 'text/plain' });
    } catch (err) {
      console.error(
        `[subscription] content fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return errorJson('content.unavailable', 'Could not load the configuration right now.', 502);
    }
  }),
});

// FCP-fronted subscription URL (the evade delivery path): the member's proxy app
// fetches its config from THIS origin instead of the backend panel, so the backend
// origin is never exposed and we gain a cache/control point. PUBLIC + unauthenticated
// — possession of the 128-bit `subToken` IS the capability, exactly like the backend
// subscription URL it replaces (a proxy app can't do the E2EE reveal-leg). A small
// per-subscription TTL cache (keyed by User-Agent, since Remnawave formats config by
// UA) absorbs the app's periodic re-polls. NOTE: this necessarily serves data-plane
// config over the FCP edge in plaintext for evade users; privacy users never receive
// this URL (the client hides it) and use the sealed /subscription/content copy path.
http.route({
  pathPrefix: '/api/v1/sub/',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const token = lastPathSegment(req);
    if (!token) return errorJson('not_found', 'Not found', 404);
    // DoS hygiene: a lenient per-IP throttle (the cache absorbs normal polling; the
    // token is the real access control). Skip when the IP can't be resolved.
    const ip = resolveClientIp(req);
    if (ip) {
      const rl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'subscription.fetch',
        subject: await ipHashSubject(ip),
      });
      if (!rl.allowed) {
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'retry-after': String(Math.ceil((rl.retryAfterMs ?? 1000) / 1000)) },
        });
      }
    }
    const sub = await ctx.runQuery(internal.subscriptions.bySubToken, { subToken: token });
    if (!sub) return errorJson('not_found', 'Not found', 404);

    const now = Date.now();
    const ua = req.headers.get('user-agent') ?? '';
    // Forward the client's HWID identification headers so the panel registers
    // the device + enforces the limit (device-limited tiers). When present we
    // BYPASS the UA cache: registration is per-device and two devices can share
    // a UA, so a cached body would both hide the second device from the panel
    // and mask an over-limit rejection.
    const hwidHeaders: Record<string, string> = {};
    for (const h of ['x-hwid', 'x-device-os', 'x-ver-os', 'x-device-model']) {
      const val = req.headers.get(h);
      if (val) hwidHeaders[h] = val;
    }
    const hasHwid = 'x-hwid' in hwidHeaders;
    const cached = hasHwid ? [] : parseSubCache(sub.subCache);
    const fresh = cached.find((e) => e.ua === ua && now - e.at < SUBSCRIPTION_CACHE_TTL_MS);
    if (fresh) return subscriptionResponse(fresh); // fresh + same format → cache hit
    // Last-resort fallback MUST match this UA — never serve another client's
    // format (the same invariant the fresh path enforces). (Review #11.)
    const stale = cached.find((e) => e.ua === ua) ?? null;
    try {
      const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
        backend: sub.backend,
        backendServerId: sub.backendServerId ?? undefined,
        backendShortId: sub.backendShortId,
        subscriptionUrl: sub.subscriptionUrl,
        userAgent: ua || undefined,
        ...(hasHwid ? { hwidHeaders } : {}),
      });
      const entry: SubCacheEntry = {
        content: fetched.content,
        contentType: fetched.contentType ?? 'text/plain',
        headers: fetched.headers,
        ua,
        at: now,
      };
      // Don't cache an hwid'd response — the next device (different hwid, same
      // UA) must reach the panel too, for its own registration + enforcement.
      if (!hasHwid) {
        await ctx.runMutation(internal.subscriptions.writeContentCache, {
          subscriptionId: sub._id,
          entry: JSON.stringify(entry),
        });
      }
      // hwid'd → `private, no-store` (device-specific); otherwise public + Vary: UA.
      return subscriptionResponse(entry, { hwid: hasHwid });
    } catch (err) {
      // A HWID rejection (panel 404 for a device-limited key fetched without a
      // valid x-hwid) is authoritative — pass 404 through, and never serve a
      // stale body for it (that would defeat the device limit).
      if (
        err instanceof ConvexError &&
        (err.data as { code?: string })?.code === 'subscription.device_rejected'
      ) {
        return new Response(
          'Device limit reached, or your app must send a device identifier (HWID).',
          { status: 404 },
        );
      }
      // Backend blip: serve the last-known content FOR THIS UA rather than break
      // the member's client; only fail hard when nothing is cached for it.
      if (stale) return subscriptionResponse(stale);
      console.error(
        `[subscription] fronted fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return new Response('Subscription temporarily unavailable', { status: 502 });
    }
  }),
});

http.route({
  path: '/api/v1/account/regenerate',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    return withIssuanceSaga(ctx, member.userId, 'account.regenerate', async (requestId) => {
      const result = await ctx.runAction(internal.account.regenerate, {
        userId: member.userId,
        requestId,
      });
      return json(result);
    });
  }),
});

http.route({
  path: '/api/v1/account/switch-backend',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ backend?: 'remnawave' | 'outline'; confirm?: boolean }>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return errorJson('validation', 'backend must be "remnawave" or "outline"', 400);
    }
    if (body.confirm !== true) return errorJson('validation', 'confirm:true required', 400);
    const target = body.backend;
    return withIssuanceSaga(ctx, member.userId, 'account.switch-backend', async (requestId) => {
      const result = await ctx.runAction(internal.account.switchBackend, {
        userId: member.userId,
        target,
        requestId,
      });
      return sagaResult(result);
    });
  }),
});

// Set the member's connection mode WITHOUT re-issuing — used at sign-up, before
// the first key exists, so that first key is issued into the chosen mode's
// placement. A member who already HAS a key changes it via /switch-mode (which
// re-issues); this plain set only records the preference. Not sealed (the mode
// id is not a secret). The id is validated against the live mode catalog.
http.route({
  path: '/api/v1/account/connection-mode',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ modeId?: string }>(req);
    if (!isConnectionModeId(body.modeId)) {
      return errorJson('validation', 'unknown connection mode', 400);
    }
    // Defense-in-depth (the picker already disables unbound modes, and issuance
    // falls back so a stored unbound preference can't mint a dead key): refuse to
    // persist an unbound mode when a bound alternative exists. Allowed on an
    // all-unbound (bring-up) deploy so signup can still record the default. (WS1.)
    const modes = await ctx.runQuery(internal.connectionModes.list, {});
    const chosen = modes.find((m) => m.id === body.modeId);
    if (chosen && !chosen.bound && modes.some((m) => m.bound)) {
      return errorJson('validation', 'This connection mode is not available yet.', 400);
    }
    await ctx.runMutation(internal.users.setConnectionMode, {
      userId: member.userId,
      modeId: body.modeId,
    });
    return json({ ok: true, modeId: body.modeId });
  }),
});

// Switch the member's connection mode (transport) within the same backend. Same
// saga shape as switch-backend (re-issue + tombstone); the reveal leg is sealed
// (SEALED_ROUTES) since the response carries the new subscription URL.
http.route({
  path: '/api/v1/account/switch-mode',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ modeId?: string; confirm?: boolean }>(req);
    if (!isConnectionModeId(body.modeId)) {
      return errorJson('validation', 'unknown connection mode', 400);
    }
    if (body.confirm !== true) return errorJson('validation', 'confirm:true required', 400);
    const target = body.modeId;
    return withIssuanceSaga(ctx, member.userId, 'account.switch-mode', async (requestId) => {
      const result = await ctx.runAction(internal.account.switchMode, {
        userId: member.userId,
        target,
        requestId,
      });
      return sagaResult(result);
    });
  }),
});

http.route({
  path: '/api/v1/account/account-id/rotate',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account.rotate',
      subject: member.userId,
    });
    if (!rl.allowed) {
      return errorJson(
        'rate_limit.exceeded',
        'Too many rotations. Please wait and try again.',
        429,
        { retryAfterMs: rl.retryAfterMs },
      );
    }
    const result = await ctx.runAction(internal.auth.rotateAccountId, {
      userId: member.userId,
      requestId: newRequestId(),
    });
    return json(result);
  }),
});

http.route({
  path: '/api/v1/account/refresh-membership',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account.refresh-membership',
      subject: member.userId,
    });
    if (!rl.allowed) {
      return errorJson('rate_limit.exceeded', 'Refresh too soon. Try again in 30 seconds.', 429, {
        retryAfterMs: rl.retryAfterMs,
      });
    }
    return json(await ctx.runAction(internal.account.refreshMembership, { userId: member.userId }));
  }),
});

// Revoke one of the member's HWID devices, freeing a slot under the tier's
// device cap without the nuclear full-key regenerate. Ownership of the hwid is
// verified server-side against the member's own key.
http.route({
  path: '/api/v1/account/devices/revoke',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'subscription:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ hwid?: string }>(req);
    if (typeof body.hwid !== 'string' || body.hwid.length === 0 || body.hwid.length > 256) {
      return errorJson('validation', 'hwid required', 400);
    }
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'account.device-revoke',
      subject: member.userId,
    });
    if (!rl.allowed) {
      return errorJson('rate_limit.exceeded', 'Too many changes. Please wait and try again.', 429, {
        retryAfterMs: rl.retryAfterMs,
      });
    }
    const result = await ctx.runAction(internal.account.revokeDevice, {
      userId: member.userId,
      hwid: body.hwid,
      requestId: newRequestId(),
    });
    if (!result.ok) return errorJson(result.code, result.message, result.status);
    return json({ ok: true });
  }),
});

// Redeem a membership code (W4). Member-authenticated; the code is a bearer
// secret so the route is sealed like the other member actions. Every failure
// (unknown / revoked / used / rate-limited / malformed) returns one generic
// envelope — no oracle.
http.route({
  path: '/api/v1/account/redeem-code',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ code?: string }>(req);
    if (typeof body.code !== 'string' || !body.code.trim()) {
      return errorJson('validation', 'code is required', 400);
    }
    const result = await ctx.runAction(internal.membershipCodes.redeemCode, {
      userId: member.userId,
      code: body.code,
    });
    if (!result.ok) {
      return errorJson('code.invalid', 'That code is not valid, or has already been used.', 400);
    }
    return json(result);
  }),
});

// --- opt-in S3 subscription mirrors -----------------------------------------
// A member who can't reach the normal subscription URL provisions one mirror at a
// time (country-tiered, capped). `sealed` because the response carries the mirror
// URL (the config's location). The country code (from the body, else the CDN
// header) is used transiently to pick a nearby host and is never stored.
http.route({
  path: '/api/v1/mirror/request',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'mirror.request',
      subject: member.userId,
    });
    if (!rl.allowed) {
      return errorJson(
        'rate_limit.exceeded',
        'Too many attempts. Please wait and try again.',
        429,
        {
          retryAfterMs: rl.retryAfterMs,
        },
      );
    }
    // A valid 2-letter code → use it; explicit null → "global" (don't geo-detect);
    // absent → fall back to the CDN header. So picking "Global" can't be silently
    // overridden by the detected country.
    const body = await readJson<{ countryCode?: string | null }>(req);
    let countryCode: string | null;
    if (typeof body.countryCode === 'string' && /^[A-Za-z]{2}$/.test(body.countryCode.trim())) {
      countryCode = body.countryCode.trim().toUpperCase();
    } else if (body.countryCode === null) {
      countryCode = null;
    } else {
      countryCode = resolveCountry(req);
    }
    const result = await ctx.runAction(internal.storage.provisionMirror, {
      userId: member.userId,
      countryCode,
    });
    return json(result);
  }),
});

http.route({
  path: '/api/v1/mirror',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const result = await ctx.runAction(internal.storage.clearMirrorsForUser, {
      userId: member.userId,
    });
    return json(result);
  }),
});

// --- self-service membership billing ----------------------------------------

// Start a checkout: member picks a rail + duration, we mint an opaque order
// bound to their userId and return the processor-hosted redirect URL. Not
// `sealed` (no account-number/key material crosses — just processor+months → a
// public URL); `guard` caps the body. The member identity is NEVER sent to the
// processor; only the opaque ref is.
http.route({
  path: '/api/v1/billing/checkout',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'billing.checkout',
      subject: member.userId,
    });
    if (!rl.allowed) {
      return errorJson(
        'rate_limit.exceeded',
        'Too many checkout attempts. Please wait and try again.',
        429,
        { retryAfterMs: rl.retryAfterMs },
      );
    }
    const body = await readJson<{
      processor?: string;
      months?: number;
      kind?: string;
      quantity?: number;
    }>(req);
    if (
      body.processor !== 'nowpayments' &&
      body.processor !== 'stripe' &&
      body.processor !== 'paypal'
    ) {
      return errorJson('validation', 'processor must be nowpayments, stripe, or paypal', 400);
    }
    if (typeof body.months !== 'number' || !Number.isInteger(body.months) || body.months < 1) {
      return errorJson('validation', 'months must be a positive integer', 400);
    }
    const kind = body.kind === 'gift' ? 'gift' : 'self';
    if (
      kind === 'gift' &&
      (typeof body.quantity !== 'number' ||
        !Number.isInteger(body.quantity) ||
        body.quantity < 1 ||
        body.quantity > 50)
    ) {
      return errorJson('validation', 'quantity must be an integer between 1 and 50', 400);
    }
    try {
      const result = await ctx.runAction(internal.billing.createCheckout, {
        userId: member.userId,
        processor: body.processor,
        months: body.months,
        kind,
        quantity: kind === 'gift' ? body.quantity : 1,
      });
      return json(result);
    } catch (err) {
      if (err instanceof ConvexError) {
        const data = err.data as { code?: string; message?: string };
        const code = data.code ?? 'billing.error';
        const status =
          code === 'billing.unavailable' || code === 'billing.not_configured'
            ? 503
            : code === 'billing.disabled'
              ? 409
              : 400;
        return errorJson(code, data.message ?? 'Checkout could not be started', status);
      }
      console.error('[billing] checkout error', err);
      return errorJson('billing.error', 'Checkout could not be started', 500);
    }
  }),
});

// Poll an order's status (the return page). Scoped to the requesting member —
// a ref that isn't theirs (or doesn't exist) is a 404.
http.route({
  pathPrefix: '/api/v1/billing/order/',
  method: 'GET',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const opaqueRef = lastPathSegment(req);
    if (!opaqueRef) return errorJson('validation', 'order ref required', 400);
    const status = await ctx.runQuery(internal.billing.getOrderStatus, {
      opaqueRef,
      userId: member.userId,
    });
    if (!status) return errorJson('not_found', 'order not found', 404);
    return json(status);
  }),
});

// Acknowledge the one-time gift-code reveal → clear the transient plaintext
// buffer on the order. Member-scoped; idempotent.
http.route({
  path: '/api/v1/account/gift-codes/ack',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:write');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ orderRef?: string }>(req);
    if (typeof body.orderRef !== 'string' || !body.orderRef) {
      return errorJson('validation', 'orderRef is required', 400);
    }
    const result = await ctx.runMutation(internal.billing.ackGiftReveal, {
      opaqueRef: body.orderRef,
      userId: member.userId,
    });
    return json(result);
  }),
});

// List the gift codes this member has purchased (masked: prefix + tier + status
// + redeemed timestamp — never the full code or the recipient). Not sealed: the
// payload carries no bearer secret, only prefixes.
http.route({
  path: '/api/v1/account/codes',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const member = await resolveMember(ctx, req, 'account:read');
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const codes = await ctx.runQuery(internal.membershipCodes.listPurchasedCodes, {
      userId: member.userId,
    });
    return json({ codes });
  }),
});

// --- admin passkey auth -----------------------------------------------------

http.route({
  path: '/api/admin/auth/status',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    // Cookie-only probe (no PoP): this is signed-in *detection* that drives a
    // redirect, not a privileged action, and the admin auth surface is unsigned.
    // Gating it on a PoP signature re-prompted already-signed-in admins. See
    // adminSessionProbe.
    const adminUserId = await adminSessionProbe(ctx, req);
    const status = await ctx.runQuery(internal.admins.bootstrapStatus, {});
    return json({ ...status, signedIn: adminUserId !== null });
  }),
});

http.route({
  path: '/api/admin/auth/register-bootstrap/options',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const body = await readJson<{ username?: string; displayName?: string }>(req);
    if (!body.username) return errorJson('validation', 'username required', 400);
    try {
      const out = await ctx.runAction(internal.webauthn.registerBootstrapOptions, {
        bootstrapSecret: req.headers.get('x-admin-bootstrap-token') ?? '',
        username: body.username,
        displayName: body.displayName,
      });
      return json(out);
    } catch (err) {
      return convexError(err);
    }
  }),
});

http.route({
  path: '/api/admin/auth/register-bootstrap/verify',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const body = await readJson<{ adminId?: string; response?: unknown; deviceLabel?: string }>(
      req,
    );
    if (!body.adminId || !body.response)
      return errorJson('validation', 'adminId and response required', 400);
    try {
      const out = await ctx.runAction(internal.webauthn.registerBootstrapVerify, {
        adminId: body.adminId as never,
        response: body.response,
        deviceLabel: body.deviceLabel,
      });
      return json(out);
    } catch (err) {
      return convexError(err);
    }
  }),
});

http.route({
  path: '/api/admin/auth/authenticate/options',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    // Username is optional: omitted for the usernameless / discoverable flow,
    // present only as a fallback. An empty string is normalized to undefined so
    // it doesn't get treated as a (never-matching) username lookup.
    const body = await readJson<{ username?: string }>(req);
    const username = body.username?.trim() || undefined;
    try {
      const out = await ctx.runAction(internal.webauthn.authenticateOptions, {
        username,
        ip: resolveClientIp(req) ?? undefined,
      });
      return json(out);
    } catch (err) {
      return convexError(err);
    }
  }),
});

http.route({
  path: '/api/admin/auth/authenticate/verify',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const body = await readJson<{ challengeId?: string; response?: unknown }>(req);
    if (!body.challengeId || !body.response) {
      return errorJson('validation', 'challengeId and response required', 400);
    }
    const popRaw = (body as Record<string, unknown>)[POP_PUBKEY_FIELD];
    const popAlgRaw = (body as Record<string, unknown>)[POP_ALG_FIELD];
    try {
      const out = await ctx.runAction(internal.webauthn.authenticateVerify, {
        challengeId: body.challengeId,
        response: body.response,
        requestId: newRequestId(),
        popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
        popAlg: typeof popAlgRaw === 'string' ? popAlgRaw : undefined,
      });
      const cookie = buildSetCookie(ADMIN_COOKIE, out.signedCookieValue, {
        maxAge: out.maxAgeSec,
        sameSite: 'Strict',
        secure: secureCookies(),
      });
      return json({ ok: true, username: out.username, popSessionToken: out.popSessionToken }, 200, {
        'set-cookie': cookie,
      });
    } catch (err) {
      return convexError(err);
    }
  }),
});

http.route({
  path: '/api/admin/auth/logout',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const raw = parseCookies(req.headers.get('cookie'))[ADMIN_COOKIE];
    const key = process.env.ADMIN_SESSION_SIGNING_KEY;
    if (raw && key) {
      const sid = await verifySignedValue(raw, key);
      if (sid) await ctx.runMutation(internal.sessions.deleteBySid, { sid });
    }
    const cookie = buildSetCookie(ADMIN_COOKIE, '', {
      maxAge: 0,
      sameSite: 'Strict',
      secure: secureCookies(),
    });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }),
});

// --- admin invite registration (multi-admin onboarding) ---------------------
// Public + invite-gated: the invitee has no session yet, so the single-use
// invite token (in the body) is the authorization. Under /api/admin/auth/, so
// the client leaves these unsigned (no PoP key to sign with).

http.route({
  path: '/api/admin/auth/register/options',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const body = await readJson<{ invite?: string }>(req);
    if (!body.invite) return errorJson('validation', 'invite required', 400);
    try {
      const out = await ctx.runAction(internal.webauthn.registerInviteOptions, {
        invite: body.invite,
        ip: resolveClientIp(req) ?? undefined,
      });
      return json(out);
    } catch (err) {
      return convexError(err);
    }
  }),
});

http.route({
  path: '/api/admin/auth/register/verify',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const body = await readJson<{ invite?: string; response?: unknown; deviceLabel?: string }>(req);
    if (!body.invite || !body.response) {
      return errorJson('validation', 'invite and response required', 400);
    }
    try {
      const out = await ctx.runAction(internal.webauthn.registerInviteVerify, {
        invite: body.invite,
        response: body.response,
        deviceLabel: body.deviceLabel,
        requestId: newRequestId(),
      });
      return json({ ok: true, username: out.username });
    } catch (err) {
      return convexError(err);
    }
  }),
});

// --- billing webhook seam ---------------------------------------------------

http.route({
  path: '/api/webhooks/billing',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    // Loud, distinct config failure: while no billing portal exists, this env
    // var is legitimately unset (membership codes are the day-1 paid path) and
    // every post must say "not configured", NOT "invalid signature" — otherwise
    // a real portal integration is undebuggable from the caller's side.
    if (!process.env.WEBHOOK_SIGNING_SECRET) {
      console.error('[webhook] rejected: WEBHOOK_SIGNING_SECRET unset (webhook.not_configured)');
      return errorJson(
        'webhook.not_configured',
        'Billing webhooks are not configured on this deployment',
        503,
      );
    }
    // P1-2: reject an oversized body BEFORE hashing it (the HMAC over an
    // unbounded body is otherwise a cheap CPU-amplification vector for an
    // unauthenticated caller). 64 KiB is far above any real billing payload.
    const declaredLen = Number(req.headers.get('content-length') ?? '0');
    if (Number.isFinite(declaredLen) && declaredLen > 64 * 1024) {
      return errorJson('webhook.too_large', 'Payload too large', 413);
    }
    // Per-IP throttle when the IP resolves (defense in depth on top of the HMAC;
    // skipped when the IP is unresolvable so a misconfig can't block a real portal).
    const ip = resolveClientIp(req);
    if (ip) {
      const rl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: 'webhook.billing.ip',
        subject: await ipHashSubject(ip),
      });
      if (!rl.allowed) return errorJson('rate_limit.exceeded', 'Too many requests', 429);
    }
    const rawBody = await req.text();
    if (rawBody.length > 64 * 1024) {
      return errorJson('webhook.too_large', 'Payload too large', 413);
    }
    try {
      const result = await ctx.runAction(internal.webhooks.ingest, {
        rawBody,
        signature: req.headers.get('x-signature') ?? undefined,
      });
      return json(result);
    } catch (err) {
      // Defense in depth for the config case (the action also throws it when
      // called outside this route); keep it distinguishable from a bad HMAC.
      if (err instanceof ConvexError) {
        const data = err.data as { code?: string };
        if (data.code === 'webhook.not_configured') {
          return errorJson(
            'webhook.not_configured',
            'Billing webhooks are not configured on this deployment',
            503,
          );
        }
      }
      // Generic: never echo the internal error (leaks paths) to an
      // unauthenticated endpoint. Detail is in the function logs.
      return errorJson('webhook.rejected', 'Webhook rejected (invalid signature or payload)', 400);
    }
  }),
});

// --- self-service billing webhooks (one route per processor) ----------------
// Same template as the generic billing webhook: 503 when the rail's secret is
// unset (distinct from a bad signature), 64 KiB cap BEFORE verifying, per-IP
// throttle, raw-body read, then per-processor verify + parse in
// billing.ingestEvent. Factored because the three rails differ only in their
// secret env var, signature header, and IP policy key.
type BillingProcessorId = 'nowpayments' | 'stripe' | 'paypal';
function processorWebhook(opts: {
  processor: BillingProcessorId;
  /** Single signature header (NOWPayments/Stripe). Omit for PayPal (uses headerNames). */
  sigHeader?: string;
  /** Header set PayPal verifies over (its API call needs all of them). */
  headerNames?: string[];
  policyKey: 'webhook.nowpayments.ip' | 'webhook.stripe.ip' | 'webhook.paypal.ip';
}) {
  const notConfigured = () =>
    errorJson(
      'billing.not_configured',
      `${opts.processor} webhooks are not configured on this deployment`,
      503,
    );
  // The "not configured" 503 comes from billing.ingestEvent (it resolves the
  // rail's credentials from the DB or env and throws billing.not_configured when
  // unset) — caught below. No env pre-check here, since secrets may be DB-only.
  return httpAction(async (ctx, req) => {
    const declaredLen = Number(req.headers.get('content-length') ?? '0');
    if (Number.isFinite(declaredLen) && declaredLen > 64 * 1024) {
      return errorJson('webhook.too_large', 'Payload too large', 413);
    }
    const ip = resolveClientIp(req);
    if (ip) {
      const rl = await ctx.runMutation(internal.rateLimits.enforce, {
        policyKey: opts.policyKey,
        subject: await ipHashSubject(ip),
      });
      if (!rl.allowed) return errorJson('rate_limit.exceeded', 'Too many requests', 429);
    }
    const rawBody = await req.text();
    if (rawBody.length > 64 * 1024) {
      return errorJson('webhook.too_large', 'Payload too large', 413);
    }
    let headers: Record<string, string> | undefined;
    if (opts.headerNames) {
      headers = {};
      for (const name of opts.headerNames) {
        const v = req.headers.get(name);
        if (v != null) headers[name] = v;
      }
    }
    try {
      const result = await ctx.runAction(internal.billing.ingestEvent, {
        processor: opts.processor,
        rawBody,
        signature: opts.sigHeader ? (req.headers.get(opts.sigHeader) ?? undefined) : undefined,
        headers,
      });
      return json(result);
    } catch (err) {
      if (
        err instanceof ConvexError &&
        (err.data as { code?: string }).code === 'billing.not_configured'
      ) {
        return notConfigured();
      }
      return errorJson('webhook.rejected', 'Webhook rejected (invalid signature or payload)', 400);
    }
  });
}

http.route({
  path: '/api/webhooks/nowpayments',
  method: 'POST',
  handler: processorWebhook({
    processor: 'nowpayments',
    sigHeader: 'x-nowpayments-sig',
    policyKey: 'webhook.nowpayments.ip',
  }),
});

http.route({
  path: '/api/webhooks/stripe',
  method: 'POST',
  handler: processorWebhook({
    processor: 'stripe',
    sigHeader: 'stripe-signature',
    policyKey: 'webhook.stripe.ip',
  }),
});

http.route({
  path: '/api/webhooks/paypal',
  method: 'POST',
  handler: processorWebhook({
    processor: 'paypal',
    headerNames: [
      'paypal-auth-algo',
      'paypal-cert-url',
      'paypal-transmission-id',
      'paypal-transmission-sig',
      'paypal-transmission-time',
    ],
    policyKey: 'webhook.paypal.ip',
  }),
});

// --- admin: admins (multi-admin management + invites) -----------------------

http.route({
  path: '/api/v1/admin/admins',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:admins:read'))) return ADMIN_UNAUTH();
    return json({ admins: await ctx.runQuery(internal.admins.listAdminsWithCounts, {}) });
  }),
});

http.route({
  path: '/api/v1/admin/admins/invite',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:admins:write');
    if (!admin) return ADMIN_UNAUTH();
    // Inviting a new admin is a human-admin action, so require a cookie session
    // (which carries adminUserId) over a service token — the invite needs a real
    // creator for the audit trail.
    if (!admin.adminUserId) {
      return errorJson('auth.forbidden', 'Inviting requires an admin session', 403);
    }
    const body = await readJson<{ username?: string; displayName?: string }>(req);
    if (!body.username) return errorJson('validation', 'username required', 400);
    try {
      const out = await ctx.runAction(internal.webauthn.createInvite, {
        username: body.username,
        displayName: body.displayName,
        createdByAdminId: admin.adminUserId,
        requestId: newRequestId(),
      });
      return json(out);
    } catch (err) {
      return convexError(err);
    }
  }),
});

// GET /api/v1/admin/admins/credentials/{adminId}: an admin's passkeys (masked).
// Longer prefix than /admins/, so it wins for GET/DELETE on this path.
http.route({
  pathPrefix: '/api/v1/admin/admins/credentials/',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:admins:read'))) return ADMIN_UNAUTH();
    const adminId = lastPathSegment(req) as Id<'adminUsers'>;
    return json({
      credentials: await ctx.runQuery(internal.admins.listCredentials, { adminUserId: adminId }),
    });
  }),
});

// DELETE /api/v1/admin/admins/credentials/{credentialId}: revoke one passkey
// (last-admin guarded). Requires a cookie session for the audit actor.
http.route({
  pathPrefix: '/api/v1/admin/admins/credentials/',
  method: 'DELETE',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:admins:write');
    if (!admin) return ADMIN_UNAUTH();
    if (!admin.adminUserId)
      return errorJson('auth.forbidden', 'Managing admins requires an admin session', 403);
    const credentialId = lastPathSegment(req) as Id<'passkeyCredentials'>;
    try {
      return json(
        await ctx.runMutation(internal.admins.revokeCredential, {
          credentialId,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// PATCH /api/v1/admin/admins/{id}: activate / deactivate an admin (last-admin
// guarded). Requires a cookie session (real actor for audit + self-lockout).
http.route({
  pathPrefix: '/api/v1/admin/admins/',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:admins:write');
    if (!admin) return ADMIN_UNAUTH();
    if (!admin.adminUserId)
      return errorJson('auth.forbidden', 'Managing admins requires an admin session', 403);
    const id = lastPathSegment(req) as Id<'adminUsers'>;
    const body = await readJson<{ isActive?: boolean }>(req);
    if (typeof body.isActive !== 'boolean')
      return errorJson('validation', 'isActive (boolean) required', 400);
    try {
      return json(
        await ctx.runMutation(internal.admins.setAdminActive, {
          adminUserId: id,
          isActive: body.isActive,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: tiers -----------------------------------------------------------

http.route({
  path: '/api/v1/admin/tiers',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tiers:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.tiersList, {}));
  }),
});

http.route({
  path: '/api/v1/admin/tiers',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tiers:write'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, never>>(req);
    try {
      return json(await ctx.runMutation(internal.adminApi.createTier, body as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/tiers/',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tiers:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'tiers'>;
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.adminApi.updateTier, { id, ...body } as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/tiers/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tiers:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'tiers'>;
    try {
      return json(await ctx.runMutation(internal.adminApi.deleteTier, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// PUT /api/v1/admin/tiers/by-slug/{slug}: idempotent upsert (Ansible / IaC +
// declarative squad↔tier binding). A distinct METHOD (PUT) from the by-id
// PATCH/DELETE prefix routes above, so the two never collide; the slug comes
// from the path (authoritative).
http.route({
  pathPrefix: '/api/v1/admin/tiers/by-slug/',
  method: 'PUT',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:tiers:write');
    if (!admin) return ADMIN_UNAUTH();
    const slug = decodeURIComponent(lastPathSegment(req));
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.upsertTierBySlug, {
          ...body,
          slug,
          actorAdminId: admin.adminUserId,
        } as never),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- recommended client apps (the CMS-managed "set up your app" catalog) ------
http.route({
  path: '/api/v1/admin/clients',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.clients.listForAdmin, {}));
  }),
});

http.route({
  path: '/api/v1/admin/clients',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.clients.create, body as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/clients/by-name/',
  method: 'PUT',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const name = decodeURIComponent(lastPathSegment(req));
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.clients.upsertByName, { ...body, name } as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/clients/',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'clients'>;
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.clients.update, { id, ...body } as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/clients/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'clients'>;
    try {
      return json(await ctx.runMutation(internal.clients.remove, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: users -----------------------------------------------------------

http.route({
  path: '/api/v1/admin/users',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:users:read'))) return ADMIN_UNAUTH();
    const u = new URL(req.url);
    const limitRaw = u.searchParams.get('limit');
    const limit = limitRaw ? Number(limitRaw) : undefined;
    try {
      return json(
        await ctx.runQuery(internal.adminApi.usersSearch, {
          q: u.searchParams.get('q') ?? undefined,
          status: (u.searchParams.get('status') as never) ?? undefined,
          tier: u.searchParams.get('tier') ?? undefined,
          drift: u.searchParams.get('drift') === 'true' ? true : undefined,
          cursor: u.searchParams.get('cursor') ?? undefined,
          limit: Number.isFinite(limit) ? limit : undefined,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// GET /api/v1/admin/users/{id}/backend-state — live backend state for ONE user
// (status + used/limit + reset cadence + devices). A separate lazy call, NOT part
// of the users list (which is a pure DB query and can't do backend HTTP); the CMS
// fetches it on-demand when an admin expands a row. Surfaces LIVE backend status
// vs FCP's local status, complementing the backend-drift badge.
http.route({
  pathPrefix: '/api/v1/admin/users/',
  method: 'GET',
  handler: guard(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:users:read'))) return ADMIN_UNAUTH();
    const { id, op } = userIdAndOp(req);
    if (op !== 'backend-state') return errorJson('not_found', `Unknown user route "${op}"`, 404);
    try {
      const state = await ctx.runAction(internal.adminApi.userBackendState, {
        userId: id as Id<'users'>,
      });
      return json({ state });
    } catch (err) {
      return adminError(err);
    }
  }),
});

// POST /api/v1/admin/users/{id}/{op}
//   op ∈ disable | re-enable | reset-traffic | resync   (no body)
//   op = grant-membership                               (body: { tierId, durationDays })
http.route({
  pathPrefix: '/api/v1/admin/users/',
  method: 'POST',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:users:write');
    if (!admin) return ADMIN_UNAUTH();
    const { id, op } = userIdAndOp(req);
    const userId = id as Id<'users'>;

    if (op === 'grant-membership') {
      const body = await readJson<{ tierId?: string; durationDays?: number }>(req);
      if (!body.tierId || typeof body.durationDays !== 'number') {
        return errorJson('validation', 'grant-membership requires tierId and durationDays', 400);
      }
      try {
        return json(
          await ctx.runMutation(internal.adminApi.grantMembership, {
            userId,
            tierId: body.tierId as Id<'tiers'>,
            durationDays: body.durationDays,
            actorAdminId: admin.adminUserId,
          }),
        );
      } catch (err) {
        return adminError(err);
      }
    }

    if (op !== 'disable' && op !== 're-enable' && op !== 'reset-traffic' && op !== 'resync') {
      return errorJson('not_found', `Unknown user op "${op}"`, 404);
    }
    try {
      const result = await ctx.runAction(internal.adminApi.runUserOp, {
        userId,
        op,
        actorAdminId: admin.adminUserId,
      });
      return json(result);
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: tokens ----------------------------------------------------------

http.route({
  path: '/api/v1/admin/tokens',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tokens:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.tokensList, {}));
  }),
});

http.route({
  path: '/api/v1/admin/tokens',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:tokens:write');
    if (!admin) return ADMIN_UNAUTH();
    // Token creation must be attributed to a concrete admin row. A pure
    // admin-scoped service token has no adminUserId, so it can't mint tokens.
    if (!admin.adminUserId) {
      return errorJson('auth.forbidden', 'Token creation requires an admin session', 403);
    }
    const body = await readJson<{
      name?: string;
      scopes?: string[];
      subjectType?: 'service' | 'user';
      subjectUserId?: string | null;
      expiresInDays?: number | null;
    }>(req);
    if (!body.name || !Array.isArray(body.scopes) || body.scopes.length === 0) {
      return errorJson('validation', 'name and at least one scope are required', 400);
    }
    try {
      const minted = await ctx.runAction(internal.apiTokens.createToken, {
        name: body.name,
        scopes: body.scopes,
        subjectType: body.subjectType ?? 'service',
        subjectUserId: body.subjectUserId ? (body.subjectUserId as Id<'users'>) : undefined,
        expiresInDays: body.expiresInDays ?? undefined,
        createdByAdminId: admin.adminUserId,
      });
      const token = await ctx.runQuery(internal.adminApi.tokenById, {
        id: minted.id,
      });
      if (!token) return errorJson('admin.error', 'Token created but could not be read back', 500);
      return json({ token, plaintext: minted.plaintext });
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/tokens/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:tokens:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'apiTokens'>;
    try {
      return json(await ctx.runMutation(internal.adminApi.revokeToken, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: audit -----------------------------------------------------------

http.route({
  path: '/api/v1/admin/audit',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:audit:read'))) return ADMIN_UNAUTH();
    const sp = new URL(req.url).searchParams;
    const sinceRaw = sp.get('since');
    const since = sinceRaw && Number.isFinite(Number(sinceRaw)) ? Number(sinceRaw) : undefined;
    return json(
      await ctx.runQuery(internal.adminApi.auditList, {
        cursor: sp.get('cursor') ?? undefined,
        action: sp.get('action') ?? undefined,
        actorType: sp.get('actorType') ?? undefined,
        since,
      }),
    );
  }),
});

// --- admin: status (operator dashboard + Ansible health-gate) ---------------

http.route({
  path: '/api/v1/admin/status',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:status:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.statusSummary, {}));
  }),
});

// --- admin: client-IP self-diagnostic (verify TRUSTED_PROXY_HOPS / fronting) --
// Returns how THIS request's client IP resolved, for the caller's own request
// only — computed transiently, never stored/logged/audited (json() is no-store),
// consistent with the no-raw-IPs-at-rest posture. `chain`'s rightmost entry is
// the peer Caddy saw: if it shows the compose gateway (172.18.0.1) instead of the
// expected fronting peer, Docker's userland proxy masked the source → add the
// gateway to CADDY_TRUSTED_PROXIES and bump TRUSTED_PROXY_HOPS. See docs.
http.route({
  path: '/api/v1/admin/client-ip',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:status:read'))) return ADMIN_UNAUTH();
    const d = resolveClientIpDetailed(req);
    return json({ resolvedIp: d.ip, rule: d.rule, hops: d.hops, chain: d.chain });
  }),
});

// --- admin: theme (brand palette; shares the admin:settings:write scope) ----

http.route({
  path: '/api/v1/admin/theme',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<{ preset?: string; hue?: number | null }>(req);
    if (typeof body.preset !== 'string') {
      return errorJson('validation', 'preset is required', 400);
    }
    try {
      return json(
        await ctx.runMutation(internal.adminApi.setTheme, {
          preset: body.preset,
          hue: typeof body.hue === 'number' ? body.hue : null,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  path: '/api/v1/admin/verification',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<{
      showPanel?: boolean;
      releaseUrl?: string;
      onionAddress?: string;
      sourceUrl?: string;
      extensionUrl?: string;
    }>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.setVerification, {
          showPanel: body.showPanel !== false, // default on
          releaseUrl: typeof body.releaseUrl === 'string' ? body.releaseUrl : '',
          onionAddress: typeof body.onionAddress === 'string' ? body.onionAddress : '',
          sourceUrl: typeof body.sourceUrl === 'string' ? body.sourceUrl : '',
          extensionUrl: typeof body.extensionUrl === 'string' ? body.extensionUrl : '',
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  path: '/api/v1/admin/site',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<{
      bannerEnabled?: boolean;
      bannerText?: string;
      repoEnabled?: boolean;
      repoUrl?: string;
    }>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.setSiteConfig, {
          bannerEnabled: body.bannerEnabled === true,
          bannerText: typeof body.bannerText === 'string' ? body.bannerText : '',
          repoEnabled: body.repoEnabled === true,
          repoUrl: typeof body.repoUrl === 'string' ? body.repoUrl : '',
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: settings --------------------------------------------------------

http.route({
  path: '/api/v1/admin/settings',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    return json({ settings });
  }),
});

http.route({
  path: '/api/v1/admin/settings',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    const validKeys = new Set(Object.keys(SETTINGS_DEFAULTS));
    for (const key of Object.keys(body)) {
      if (!validKeys.has(key)) {
        return errorJson('validation', `Unknown setting "${key}"`, 400);
      }
    }
    // One transaction (Review P3): the whole patch applies or none, so a mid-way
    // failure can't leave settings half-updated with no indication which half.
    await ctx.runMutation(internal.appSettings.setMany, {
      entries: Object.entries(body).map(([key, value]) => ({
        key,
        value: JSON.stringify(value),
      })),
      updatedByAdminId: admin.adminUserId,
    });
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    return json({ settings });
  }),
});

// --- admin: rate-limit policies (W2) ----------------------------------------

http.route({
  path: '/api/v1/admin/rate-limits',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    return json({ policies: await ctx.runQuery(internal.rateLimits.listPolicies, {}) });
  }),
});

http.route({
  path: '/api/v1/admin/rate-limits',
  method: 'PATCH',
  handler: guard(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<{
      policyKey?: string;
      max?: number;
      windowMs?: number;
      enabled?: boolean;
      // `reset: true` reverts the policy to its compiled default (deletes the
      // stored override); the tuning fields are then ignored.
      reset?: boolean;
    }>(req);
    if (typeof body.policyKey !== 'string') {
      return errorJson('validation', 'policyKey is required', 400);
    }
    try {
      if (body.reset === true) {
        await ctx.runMutation(internal.rateLimits.resetPolicy, {
          policyKey: body.policyKey,
          actorAdminId: admin.adminUserId,
        });
        return json({ policies: await ctx.runQuery(internal.rateLimits.listPolicies, {}) });
      }
      if (
        typeof body.max !== 'number' ||
        typeof body.windowMs !== 'number' ||
        typeof body.enabled !== 'boolean'
      ) {
        return errorJson('validation', 'policyKey, max, windowMs, enabled are required', 400);
      }
      await ctx.runMutation(internal.rateLimits.setPolicy, {
        policyKey: body.policyKey,
        max: body.max,
        windowMs: body.windowMs,
        enabled: body.enabled,
        actorAdminId: admin.adminUserId,
      });
      return json({ policies: await ctx.runQuery(internal.rateLimits.listPolicies, {}) });
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: billing (self-service membership) -------------------------------

http.route({
  path: '/api/v1/admin/billing',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    const u = new URL(req.url);
    const limitRaw = u.searchParams.get('limit');
    const limit = limitRaw ? Number(limitRaw) : undefined;
    return json(
      await ctx.runQuery(internal.adminApi.billingOverview, {
        cursor: u.searchParams.get('cursor') ?? undefined,
        status: u.searchParams.get('status') ?? undefined,
        limit: Number.isFinite(limit) ? limit : undefined,
      }),
    );
  }),
});

http.route({
  path: '/api/v1/admin/billing/config',
  method: 'PATCH',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.setBillingConfig, {
          patch: body,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// Set the connection-mode catalog (per-mode label/description + the default) and
// the per-mode Remnawave placement pool. The Ansible panel-bootstrap PATCHes this
// to bind the squads it creates (dual-mode: an fsv1_ token with
// admin:settings:write works); also editable in the admin CMS. Squad UUIDs are
// write-only (never read back). (The placement pool moves to the namespaced
// /admin/remnawave/* endpoint in a later phase.)
http.route({
  path: '/api/v1/admin/connection-modes',
  method: 'PATCH',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:settings:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.setConnectionModes, {
          patch: body,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: membership codes (W4) -------------------------------------------

http.route({
  path: '/api/v1/admin/membership-codes',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:users:read'))) return ADMIN_UNAUTH();
    const sp = new URL(req.url).searchParams;
    return json(
      await ctx.runQuery(internal.membershipCodes.listCodes, {
        status: sp.get('status') ?? undefined,
        cursor: sp.get('cursor') ?? undefined,
      }),
    );
  }),
});

http.route({
  path: '/api/v1/admin/membership-codes',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:users:write');
    if (!admin) return ADMIN_UNAUTH();
    // Minting must be attributed to a concrete admin row (like token creation).
    if (!admin.adminUserId) {
      return errorJson('auth.forbidden', 'Code minting requires an admin session', 403);
    }
    const body = await readJson<{
      tierId?: string;
      durationDays?: number;
      count?: number;
      note?: string;
    }>(req);
    if (!body.tierId || typeof body.durationDays !== 'number' || typeof body.count !== 'number') {
      return errorJson('validation', 'tierId, durationDays, count are required', 400);
    }
    try {
      const minted = await ctx.runAction(internal.membershipCodes.mintCodes, {
        tierId: body.tierId as Id<'tiers'>,
        durationDays: body.durationDays,
        count: body.count,
        note: body.note,
        actorAdminId: admin.adminUserId,
      });
      return json(minted);
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/membership-codes/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:users:write');
    if (!admin) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'redemptionCodes'>;
    try {
      return json(
        await ctx.runMutation(internal.membershipCodes.revokeCode, {
          id,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: backend servers (instances) -------------------------------------

http.route({
  path: '/api/v1/admin/backend-servers',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.backendServersList, {}));
  }),
});

// --- admin: Remnawave-specific config (namespaced /admin/remnawave/*) --------
// Backend-specific surface, kept OFF the generic admin API so FCP stays
// backend-agnostic. Reuses the admin:servers:* scopes (same class as
// backend-servers). Squad UUIDs are write-only; node load is read-only.

// GET /api/v1/admin/remnawave/node-stats: per-placement node-load snapshots (the
// node-placement picker's input), read-only for the admin CMS. Placement handles
// (squad UUIDs) are shown — the admin set them; they never reach public config.
http.route({
  path: '/api/v1/admin/remnawave/node-stats',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:read'))) return ADMIN_UNAUTH();
    return json({ nodes: await ctx.runQuery(internal.remnawaveNodes.listNodeStats, {}) });
  }),
});

// PATCH /api/v1/admin/remnawave/mode-placements: bind each mode's squad pool (the
// nodes its keys are issued across). Write-only squad UUIDs; dual-mode (an fsv1_
// token with admin:servers:write works — the Ansible panel-bootstrap PATCHes this
// after it creates the per-node squads).
http.route({
  path: '/api/v1/admin/remnawave/mode-placements',
  method: 'PATCH',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:servers:write');
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.remnawaveNodes.setModePlacements, {
          patch: body,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  path: '/api/v1/admin/backend-servers',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:write'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return errorJson('validation', 'backend must be "remnawave" or "outline"', 400);
    }
    try {
      return json(await ctx.runMutation(internal.adminApi.createBackendServer, body as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// POST /api/v1/admin/backend-servers/test-connection: exact path, so it wins
// over the pathPrefix below (which only handles PATCH/DELETE anyway).
http.route({
  path: '/api/v1/admin/backend-servers/test-connection',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:read'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return json({ ok: false, error: 'Pick a backend type first' });
    }
    // Forward ONLY the connection fields the action declares. Convex arg
    // validators are strict, so a caller that reuses the fuller upsert body
    // (which carries name/slug/isActive/… — e.g. the Ansible role, or a future
    // client) would otherwise be rejected here and 500 instead of getting an
    // {ok} verdict. Be liberal in what this read-only probe accepts.
    const result = await ctx.runAction(internal.adminApi.testBackendConnection, {
      backend: body.backend,
      baseUrl: body.baseUrl,
      apiToken: body.apiToken,
      apiUrl: body.apiUrl,
      websocketEnabled: body.websocketEnabled,
      websocketDomain: body.websocketDomain,
    } as never);
    return json(result);
  }),
});

// PUT /api/v1/admin/backend-servers/by-slug/{slug}: idempotent upsert (for the
// Ansible role / IaC). A different METHOD than the PATCH/DELETE pathPrefix below,
// so the two never collide; the slug comes from the path (authoritative).
http.route({
  pathPrefix: '/api/v1/admin/backend-servers/by-slug/',
  method: 'PUT',
  handler: sealed(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:servers:write');
    if (!admin) return ADMIN_UNAUTH();
    const slug = decodeURIComponent(lastPathSegment(req));
    const body = await readJson<Record<string, unknown>>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return errorJson('validation', 'backend must be "remnawave" or "outline"', 400);
    }
    try {
      return json(
        await ctx.runMutation(internal.adminApi.upsertBackendServerBySlug, {
          ...body,
          slug,
          actorAdminId: admin.adminUserId,
        } as never),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// DELETE /api/v1/admin/backend-servers/by-slug/{slug}: idempotent slug-addressed
// delete (migrate / IaC). The longer prefix wins over the by-id DELETE below.
http.route({
  pathPrefix: '/api/v1/admin/backend-servers/by-slug/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req, 'admin:servers:write');
    if (!admin) return ADMIN_UNAUTH();
    const slug = decodeURIComponent(lastPathSegment(req));
    try {
      return json(
        await ctx.runMutation(internal.adminApi.deleteBackendServerBySlug, {
          slug,
          actorAdminId: admin.adminUserId,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/backend-servers/',
  method: 'PATCH',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'backendServers'>;
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.adminApi.updateBackendServer, { id, ...body } as never),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/backend-servers/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:servers:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'backendServers'>;
    try {
      return json(await ctx.runMutation(internal.adminApi.deleteBackendServer, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// --- admin: S3 mirror providers (subscription mirrors) ----------------------
// Storage config, so it shares the `admin:settings:*` scope with billing config.
// The secret (secretAccessKey) is never returned (set/not-set boolean) or logged.

http.route({
  path: '/api/v1/admin/mirror-providers',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.mirrorProviders.listForAdmin, {}));
  }),
});

http.route({
  path: '/api/v1/admin/mirror-providers',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.mirrorProviders.create, body as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// Exact path wins over the pathPrefix PATCH/DELETE below.
http.route({
  path: '/api/v1/admin/mirror-providers/test-connection',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:read'))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    // Same strict-validator hygiene as backend-servers/test-connection: forward
    // only the fields testProviderConnection declares, so a caller that reuses a
    // fuller provider body (name/publicUrl/…) gets an {ok} verdict, not a 500.
    const result = await ctx.runAction(internal.storage.testProviderConnection, {
      endpoint: body.endpoint,
      bucket: body.bucket,
      region: body.region,
      accessKeyId: body.accessKeyId,
      secretAccessKey: body.secretAccessKey,
    } as never);
    return json(result);
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/mirror-providers/',
  method: 'PATCH',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'mirrorProviders'>;
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(await ctx.runMutation(internal.mirrorProviders.update, { id, ...body } as never));
    } catch (err) {
      return adminError(err);
    }
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/mirror-providers/',
  method: 'DELETE',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'mirrorProviders'>;
    try {
      return json(await ctx.runMutation(internal.mirrorProviders.remove, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

// PUT /api/v1/admin/mirror-providers/by-name/{name}: idempotent upsert (IaC).
// PUT, so it never collides with the by-id PATCH/DELETE prefix routes above.
http.route({
  pathPrefix: '/api/v1/admin/mirror-providers/by-name/',
  method: 'PUT',
  handler: sealed(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req, 'admin:settings:write'))) return ADMIN_UNAUTH();
    const name = decodeURIComponent(lastPathSegment(req));
    const body = await readJson<Record<string, unknown>>(req);
    try {
      return json(
        await ctx.runMutation(internal.mirrorProviders.upsertByName, { ...body, name } as never),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

export default http;
