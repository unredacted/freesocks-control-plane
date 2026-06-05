import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { eq } from 'drizzle-orm';
import { ForbiddenError } from '../../lib/errors';
import { parseMirrors } from '../../lib/mirrors';
import { resolveActiveSubscription } from '../../lib/current-subscription';
import { users } from '../../db/schema';
import type { AppEnv } from '../../env';
import { requireScopeIfToken } from '../../middleware/require-scope';
import { SubscriptionRequest, SubscriptionResponse } from '../../../shared/contracts/subscription';
import { ApiErrorResponse } from '../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

// Token-scope enforcement only. Anonymous (Turnstile) and cookie/JWT members
// are untouched; their fate is decided by the handlers below. Registered here,
// BEFORE any router.openapi(...) handler, per the Hono ordering rule — a
// `router.use` only gates handlers registered after it (cf. admin/tiers.ts).
router.use('/', async (c, next) => {
  if (c.req.method === 'POST') return requireScopeIfToken('subscription:write')(c, next);
  if (c.req.method === 'GET') return requireScopeIfToken('subscription:read')(c, next);
  return next();
});

const postSubscriptionRoute = createRoute({
  method: 'post',
  path: '/',
  tags: ['Subscription'],
  summary: 'Issue a subscription URL',
  description:
    'Anonymous callers must provide a Turnstile token. Authenticated members get a key matching their tier.',
  security: [{ authentikJwt: [] }, { apiToken: ['subscription:write'] }, {}],
  request: {
    body: {
      content: { 'application/json': { schema: SubscriptionRequest } },
      required: true,
    },
  },
  responses: {
    200: {
      description:
        'Subscription issued (or re-issued for the same IP within the rate-limit window)',
      content: { 'application/json': { schema: SubscriptionResponse } },
    },
    400: {
      description: 'Bad request',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
    403: {
      description: 'Turnstile failed',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
    429: {
      description: 'Rate-limited',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(postSubscriptionRoute, async (c) => {
  // Distinguish "no body" (legitimate for authed members) from "malformed
  // body" (a real client bug worth surfacing). Treat content-type and length
  // signals as the truth of intent — only fall back to {} when the caller
  // sent nothing at all. Malformed JSON gets a clear 400 instead of a silent
  // empty parse.
  const contentType = c.req.header('content-type') ?? '';
  const contentLength = c.req.header('content-length');
  const hasBody = contentLength !== '0' && contentType.toLowerCase().includes('json');
  let raw: unknown = {};
  if (hasBody) {
    try {
      raw = await c.req.json();
    } catch {
      return c.json(
        { error: { code: 'validation', message: 'Request body is not valid JSON' } },
        400,
      );
    }
  }
  const json = SubscriptionRequest.parse(raw);
  const services = c.var.services;

  if (c.var.member) {
    return await issueForMember(c);
  }

  if (!json.turnstileToken) {
    return c.json(
      { error: { code: 'validation', message: 'Turnstile token required for anonymous requests' } },
      400,
    );
  }

  // The free-tier rate limit keys off a trustworthy client IP (resolveClientIp
  // in middleware/services.ts). When the platform can't establish one (Workers
  // missing cf-connecting-ip; off-Workers without TRUSTED_PROXY + a normalizing
  // proxy), we MUST NOT issue — otherwise every unresolvable caller collapses
  // into one shared rate-limit bucket, itself a bypass vector. This is a
  // deployment/trust-config state, not a client error, so mirror the
  // backend.disabled 503 below. (On Workers, cf-connecting-ip is always set, so
  // this only fires on a misconfigured self-host / Fastly deploy.)
  if (!c.var.clientIp) {
    c.var.logger.warn('freetier_ip_unresolved', { requestId: c.var.requestId });
    return c.json(
      {
        error: {
          code: 'freetier.ip_unresolved',
          message: 'Unable to establish your network address. Try again later or contact support.',
        },
      },
      503,
    );
  }
  const ip = c.var.clientIp;
  const turnstile = await services.turnstile.verify(json.turnstileToken, ip);
  if (!turnstile.success) {
    throw new ForbiddenError('Turnstile verification failed', { errorCodes: turnstile.errorCodes });
  }

  // Resolve which backend to use. Three inputs feed the decision:
  //   1. The caller's optional `backend` preference from the request body.
  //   2. `subscription.user_choice_enabled` — admin setting that gates
  //      whether the caller's preference is honored at all.
  //   3. `subscription.default_backend` — fallback when (1) is missing or (2)
  //      is off, AND validation gate that an enabled backend exists.
  //
  // A requested backend that is itself disabled by `{remnawave,outline}.enabled`
  // is rejected with a 503 (not a 400) — it's an admin config state, not a
  // bad request.
  const settings = await services.appSettings.getAll();
  const requested = json.backend;
  let resolvedBackend: 'remnawave' | 'outline' = settings['subscription.default_backend'];
  if (requested && settings['subscription.user_choice_enabled']) {
    resolvedBackend = requested;
  }
  const backendEnabledKey = `${resolvedBackend}.enabled` as 'remnawave.enabled' | 'outline.enabled';
  if (!settings[backendEnabledKey]) {
    return c.json(
      {
        error: {
          code: 'backend.disabled',
          message: `Backend "${resolvedBackend}" is currently disabled. Try again later or contact support.`,
        },
      },
      503,
    );
  }

  const country = c.req.header('cf-ipcountry') ?? undefined;
  const ua = c.req.header('user-agent') ?? undefined;
  const result = await services.freeTier.issueOrReissue({
    ip,
    ipCountry: country,
    userAgent: ua,
    turnstileAction: turnstile.action,
    turnstileCdata: turnstile.cdata,
    requestId: c.var.requestId,
    backend: resolvedBackend,
  });

  const mirrors = result.subscription.mirrors.map((m) => ({
    provider: m.provider,
    publicUrl: m.publicUrl,
  }));
  return c.json(
    SubscriptionResponse.parse({
      subscriptionUrl: result.subscription.url,
      fallbackUrl: mirrors[0]?.publicUrl,
      mirrors,
      tier: {
        slug: result.user.tier.slug,
        name: result.user.tier.name,
        monthlyTrafficGb: result.user.tier.monthlyTrafficGb,
        deviceLimit: result.user.tier.deviceLimit,
      },
      backend: result.user.tier.backend,
      expiresAt: result.subscription.expireAt,
      trafficLimitBytes: result.subscription.trafficLimitBytes,
      trafficUsedBytes: 0,
      isReissued: result.reissued,
      banner: result.banner,
    }),
    200,
  );
});

const getSubscriptionRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Subscription'],
  summary: "Fetch the caller's existing subscription (if any)",
  security: [{ authentikJwt: [] }, { apiToken: ['subscription:read'] }, {}],
  responses: {
    200: {
      description: 'Subscription found',
      content: { 'application/json': { schema: SubscriptionResponse.partial() } },
    },
  },
});

router.openapi(getSubscriptionRoute, async (c) => {
  if (!c.var.member) {
    return c.json({ subscription: null } as never, 200);
  }
  const platform = c.var.platform;
  const userId = c.var.member.userId;
  const userRow = await platform.db.select().from(users).where(eq(users.id, userId)).limit(1).all();
  const user = userRow[0];
  if (!user) return c.json({ subscription: null } as never, 200);
  // Shared resolver: prefer users.currentSubscriptionId (so this matches
  // /api/v1/account) and never return a tombstoned row during the 24h
  // regenerate/switch-backend grace window.
  const sub = await resolveActiveSubscription(platform.db, user);
  if (!sub) return c.json({ subscription: null } as never, 200);
  return c.json(
    {
      subscription: {
        url: sub.subscriptionUrl,
        shortUuid: sub.backendShortId,
        mirrors: parseMirrors(sub.subscriptionMirrors, platform.logger, {
          subscriptionId: sub.id,
          userId,
        }),
      },
    } as never,
    200,
  );
});

async function issueForMember(c: Context<AppEnv>) {
  const services = c.var.services;
  const member = c.var.member!;
  const platform = c.var.platform;
  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  // Prefer users.currentSubscriptionId; only the live (non-tombstoned) row.
  const sub = user ? await resolveActiveSubscription(platform.db, user) : undefined;
  if (!sub) {
    return c.json(
      {
        error: {
          code: 'subscription.absent',
          message: 'No subscription on file. Use /api/v1/account/regenerate to create one.',
        },
      },
      409,
    );
  }
  const tier = user ? await services.tierPolicy.getById(user.tierId) : null;
  if (!tier) {
    return c.json({ error: { code: 'tier.missing', message: 'Tier not found' } }, 500);
  }
  const state = await services.backends.fromSubscription(sub).getUser(sub.backendUserId);
  const mirrorsRaw = parseMirrors(sub.subscriptionMirrors, platform.logger, {
    subscriptionId: sub.id,
    userId: member.userId,
  });
  return c.json(
    SubscriptionResponse.parse({
      subscriptionUrl: sub.subscriptionUrl,
      fallbackUrl: mirrorsRaw[0]?.publicUrl,
      mirrors: mirrorsRaw.map((m) => ({ provider: m.provider, publicUrl: m.publicUrl })),
      tier: {
        slug: tier.slug,
        name: tier.name,
        monthlyTrafficGb: tier.monthlyTrafficGb,
        deviceLimit: tier.deviceLimit,
      },
      backend: sub.backend,
      expiresAt: state.expireAt,
      trafficLimitBytes: state.trafficLimitBytes,
      trafficUsedBytes: state.usedTrafficBytes,
      isReissued: false,
    }),
    200,
  );
}

export default router;
