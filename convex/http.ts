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
import { buildSetCookie, parseCookies, verifySignedValue } from './lib/cookies';
import { verifyTurnstile } from './lib/turnstile';
import { sealed } from './lib/e2ee';
import { POP_PUBKEY_FIELD } from '../src/shared/crypto/pop';
import {
  ADMIN_COOKIE,
  MEMBER_COOKIE,
  errorJson,
  json,
  newRequestId,
  readJson,
  resolveAdmin,
  resolveClientIp,
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
  const msg = err instanceof Error ? err.message : String(err);
  if (/No active .* instances/i.test(msg)) {
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

http.route({
  path: '/healthz',
  method: 'GET',
  handler: httpAction(async () =>
    json({ ok: true, timestamp: new Date().toISOString(), requestId: newRequestId() }),
  ),
});

http.route({
  path: '/api/v1/config',
  method: 'GET',
  handler: httpAction(async (ctx) => json(await ctx.runQuery(api.publicConfig.get, {}))),
});

// CDN-blinding Phase 3: the current manifest-signed epoch KEM public key (and,
// from P3c, the revoked-kid list). Public + unauthenticated: the key is public
// and the client verifies the manifest signature against its baked manifest
// public key before sealing the login to it, so a CDN that tampers is caught.
// Briefly cacheable (the epoch is valid for ~30 min and carries its own notAfter).
http.route({
  path: '/api/v1/e2ee/keys',
  method: 'GET',
  handler: httpAction(async (ctx) => {
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
// Anonymous sign-up: Turnstile -> mint a user + account number + member session.
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

    const body = await readJson<{ turnstileToken?: string; backend?: 'remnawave' | 'outline' }>(
      req,
    );
    if (!body.turnstileToken) {
      return errorJson('validation', 'Turnstile token required', 400);
    }
    const ip = resolveClientIp(req);
    if (!ip) {
      return errorJson(
        'freetier.ip_unresolved',
        'Unable to establish your network address. Try again later or contact support.',
        503,
      );
    }
    const secret = process.env.TURNSTILE_SECRET_KEY;
    if (!secret) return errorJson('config', 'Turnstile not configured', 503);
    const ts = await verifyTurnstile(secret, body.turnstileToken, ip);
    if (!ts.success)
      return errorJson('auth.turnstile_failed', 'Turnstile verification failed', 403);

    // Resolve which default-free tier (backend) the new account lands on. This
    // reads only the admin enabled/default toggles, never proxy availability.
    const settings = await ctx.runQuery(api.appSettings.resolved, {});
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

    let result;
    try {
      result = await ctx.runAction(internal.freeTier.createFreeAccount, {
        ip,
        ipCountry: req.headers.get('cf-ipcountry') ?? undefined,
        userAgent: req.headers.get('user-agent') ?? undefined,
        turnstileAction: ts.action,
        turnstileCdata: ts.cdata,
        requestId,
        backend,
        popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
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
    return json({ accountId: result.accountId, tier: result.tier, authenticated: true }, 200, {
      'set-cookie': cookie,
    });
  }),
});

// --- member auth ------------------------------------------------------------

http.route({
  path: '/api/v1/auth/account-login',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const body = await readJson<{ accountId?: string; turnstileToken?: string }>(req);
    if (!body.accountId || !body.turnstileToken) {
      return errorJson('validation', 'accountId and turnstileToken are required', 400);
    }
    const ip = resolveClientIp(req) ?? undefined;
    // PoP (Phase 2): the client folds its session public key into the (sealed)
    // login body to bind the session to it.
    const popRaw = (body as Record<string, unknown>)[POP_PUBKEY_FIELD];
    const res = await ctx.runAction(internal.auth.accountLogin, {
      accountId: body.accountId,
      turnstileToken: body.turnstileToken,
      ip,
      popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
    });
    if (!res.ok) {
      if (res.reason === 'turnstile') {
        return errorJson('auth.turnstile_failed', 'Turnstile verification failed', 403);
      }
      return errorJson('auth.invalid_account_id', 'The submitted credential is not valid', 401);
    }
    const cookie = buildSetCookie(MEMBER_COOKIE, res.signedCookieValue, {
      maxAge: res.maxAgeSec,
      sameSite: 'Lax',
      secure: secureCookies(),
    });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
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
    const user = await ctx.runQuery(api.users.get, { id: member.userId });
    const tier = user ? await ctx.runQuery(api.tiers.get, { id: user.tierId }) : null;
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
    const member = await resolveMember(ctx, req);
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const view = await ctx.runAction(internal.account.getAccountView, { userId: member.userId });
    if (!view) return errorJson('not_found', 'user not found', 404);
    return json(view);
  }),
});

http.route({
  path: '/api/v1/account/regenerate',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req);
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const requestId = newRequestId();
    try {
      const result = await ctx.runAction(internal.account.regenerate, {
        userId: member.userId,
        requestId,
      });
      return json(result);
    } catch (err) {
      return issuanceErrorResponse(err, requestId);
    }
  }),
});

http.route({
  path: '/api/v1/account/switch-backend',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req);
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
    const body = await readJson<{ backend?: 'remnawave' | 'outline'; confirm?: boolean }>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return errorJson('validation', 'backend must be "remnawave" or "outline"', 400);
    }
    if (body.confirm !== true) return errorJson('validation', 'confirm:true required', 400);
    const requestId = newRequestId();
    let result;
    try {
      result = await ctx.runAction(internal.account.switchBackend, {
        userId: member.userId,
        target: body.backend,
        requestId,
      });
    } catch (err) {
      return issuanceErrorResponse(err, requestId);
    }
    if (!result.ok) return errorJson(result.code, result.message, result.status);
    const {
      ok: _ok,
      status: _status,
      code: _code,
      message: _message,
      ...payload
    } = result as typeof result & {
      status?: number;
      code?: string;
      message?: string;
    };
    return json(payload);
  }),
});

http.route({
  path: '/api/v1/account/account-id/rotate',
  method: 'POST',
  handler: sealed(async (ctx, req) => {
    const member = await resolveMember(ctx, req);
    if (!member) return errorJson('auth.unauthenticated', 'Authentication required', 401);
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
    const member = await resolveMember(ctx, req);
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

// --- admin passkey auth -----------------------------------------------------

http.route({
  path: '/api/admin/auth/status',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req);
    const status = await ctx.runQuery(api.admins.bootstrapStatus, {});
    return json({ ...status, signedIn: Boolean(admin?.adminUserId) });
  }),
});

http.route({
  path: '/api/admin/auth/register-bootstrap/options',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
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
  handler: httpAction(async (ctx, req) => {
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
  handler: httpAction(async (ctx, req) => {
    const body = await readJson<{ username?: string }>(req);
    if (!body.username) return errorJson('validation', 'username required', 400);
    try {
      const out = await ctx.runAction(internal.webauthn.authenticateOptions, {
        username: body.username,
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
  handler: httpAction(async (ctx, req) => {
    const body = await readJson<{ challengeId?: string; response?: unknown }>(req);
    if (!body.challengeId || !body.response) {
      return errorJson('validation', 'challengeId and response required', 400);
    }
    const popRaw = (body as Record<string, unknown>)[POP_PUBKEY_FIELD];
    try {
      const out = await ctx.runAction(internal.webauthn.authenticateVerify, {
        challengeId: body.challengeId,
        response: body.response,
        requestId: newRequestId(),
        popPublicKey: typeof popRaw === 'string' ? popRaw : undefined,
      });
      const cookie = buildSetCookie(ADMIN_COOKIE, out.signedCookieValue, {
        maxAge: out.maxAgeSec,
        sameSite: 'Strict',
        secure: secureCookies(),
      });
      return json({ ok: true, username: out.username }, 200, { 'set-cookie': cookie });
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

// --- billing webhook seam ---------------------------------------------------

http.route({
  path: '/api/webhooks/billing',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const rawBody = await req.text();
    try {
      const result = await ctx.runAction(internal.webhooks.ingest, {
        rawBody,
        signature: req.headers.get('x-signature') ?? undefined,
      });
      return json(result);
    } catch {
      // Generic: never echo the internal error (leaks paths) to an
      // unauthenticated endpoint. Detail is in the function logs.
      return errorJson('webhook.rejected', 'Webhook rejected (invalid signature or payload)', 400);
    }
  }),
});

// --- admin: tiers -----------------------------------------------------------

http.route({
  path: '/api/v1/admin/tiers',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.tiersList, {}));
  }),
});

http.route({
  path: '/api/v1/admin/tiers',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
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
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'tiers'>;
    try {
      return json(await ctx.runMutation(internal.adminApi.deleteTier, { id }));
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const u = new URL(req.url);
    const limitRaw = u.searchParams.get('limit');
    const limit = limitRaw ? Number(limitRaw) : undefined;
    try {
      return json(
        await ctx.runQuery(internal.adminApi.usersSearch, {
          q: u.searchParams.get('q') ?? undefined,
          status: (u.searchParams.get('status') as never) ?? undefined,
          tier: u.searchParams.get('tier') ?? undefined,
          cursor: u.searchParams.get('cursor') ?? undefined,
          limit: Number.isFinite(limit) ? limit : undefined,
        }),
      );
    } catch (err) {
      return adminError(err);
    }
  }),
});

// POST /api/v1/admin/users/{id}/{op}  (op ∈ disable | reset-traffic | resync)
http.route({
  pathPrefix: '/api/v1/admin/users/',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req);
    if (!admin) return ADMIN_UNAUTH();
    const { id, op } = userIdAndOp(req);
    if (op !== 'disable' && op !== 'reset-traffic' && op !== 'resync') {
      return errorJson('not_found', `Unknown user op "${op}"`, 404);
    }
    try {
      const result = await ctx.runAction(internal.adminApi.runUserOp, {
        userId: id as Id<'users'>,
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.tokensList, {}));
  }),
});

http.route({
  path: '/api/v1/admin/tokens',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req);
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const cursor = new URL(req.url).searchParams.get('cursor') ?? undefined;
    return json(await ctx.runQuery(internal.adminApi.auditList, { cursor }));
  }),
});

// --- admin: settings --------------------------------------------------------

http.route({
  path: '/api/v1/admin/settings',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const settings = await ctx.runQuery(api.appSettings.resolved, {});
    return json({ settings });
  }),
});

http.route({
  path: '/api/v1/admin/settings',
  method: 'PATCH',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req);
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    const validKeys = new Set(Object.keys(SETTINGS_DEFAULTS));
    for (const key of Object.keys(body)) {
      if (!validKeys.has(key)) {
        return errorJson('validation', `Unknown setting "${key}"`, 400);
      }
    }
    for (const [key, value] of Object.entries(body)) {
      await ctx.runMutation(api.appSettings.set, {
        key,
        value: JSON.stringify(value),
        updatedByAdminId: admin.adminUserId,
      });
    }
    const settings = await ctx.runQuery(api.appSettings.resolved, {});
    return json({ settings });
  }),
});

// --- admin: rate-limit policies (W2) ----------------------------------------

http.route({
  path: '/api/v1/admin/rate-limits',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    return json({ policies: await ctx.runQuery(internal.rateLimits.listPolicies, {}) });
  }),
});

http.route({
  path: '/api/v1/admin/rate-limits',
  method: 'PATCH',
  handler: httpAction(async (ctx, req) => {
    const admin = await resolveAdmin(ctx, req);
    if (!admin) return ADMIN_UNAUTH();
    const body = await readJson<{
      policyKey?: string;
      max?: number;
      windowMs?: number;
      enabled?: boolean;
    }>(req);
    if (
      typeof body.policyKey !== 'string' ||
      typeof body.max !== 'number' ||
      typeof body.windowMs !== 'number' ||
      typeof body.enabled !== 'boolean'
    ) {
      return errorJson('validation', 'policyKey, max, windowMs, enabled are required', 400);
    }
    try {
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

// --- admin: backend servers (instances) -------------------------------------

http.route({
  path: '/api/v1/admin/backend-servers',
  method: 'GET',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    return json(await ctx.runQuery(internal.adminApi.backendServersList, {}));
  }),
});

http.route({
  path: '/api/v1/admin/backend-servers',
  method: 'POST',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
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
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const body = await readJson<Record<string, unknown>>(req);
    if (body.backend !== 'remnawave' && body.backend !== 'outline') {
      return json({ ok: false, error: 'Pick a backend type first' });
    }
    const result = await ctx.runAction(internal.adminApi.testBackendConnection, body as never);
    return json(result);
  }),
});

http.route({
  pathPrefix: '/api/v1/admin/backend-servers/',
  method: 'PATCH',
  handler: httpAction(async (ctx, req) => {
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
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
    if (!(await resolveAdmin(ctx, req))) return ADMIN_UNAUTH();
    const id = lastPathSegment(req) as Id<'backendServers'>;
    try {
      return json(await ctx.runMutation(internal.adminApi.deleteBackendServer, { id }));
    } catch (err) {
      return adminError(err);
    }
  }),
});

export default http;
