import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
import { and, eq } from 'drizzle-orm';
import { subscriptions, users } from '../../db/schema';
import type { AppEnv } from '../../env';
import { requireScope } from '../../middleware/require-scope';
import {
  AccountResponse,
  RegenerateRequest,
  SwitchBackendRequest,
  SwitchBackendResponse,
} from '../../../shared/contracts/account';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { randomHex } from '../../lib/crypto';
import { parseMirrors } from '../../lib/mirrors';
import { resolveActiveSubscription } from '../../lib/current-subscription';
import { z, ApiErrorResponse } from '../../openapi/registry';

const router = new OpenAPIHono<AppEnv>();

router.use('/*', requireScope('account:read'));

const getAccountRoute = createRoute({
  method: 'get',
  path: '/',
  tags: ['Account'],
  summary: 'Get the current member account',
  security: [{ authentikJwt: [] }, { apiToken: ['account:read'] }],
  responses: {
    200: {
      description: 'Account state including subscription and membership',
      content: { 'application/json': { schema: AccountResponse } },
    },
    401: {
      description: 'Unauthenticated',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.openapi(getAccountRoute, async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const member = c.var.member!;

  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  if (!user) throw new NotFoundError('user');
  const tier = await services.tierPolicy.getById(user.tierId);
  if (!tier) throw new NotFoundError('tier');

  // Shared resolver (also used by /api/v1/subscription so the two can't
  // diverge): prefer users.currentSubscriptionId, fall back to the newest
  // active row, and never return a tombstoned row during the 24h grace window.
  const sub = await resolveActiveSubscription(platform.db, user);

  let subscriptionPayload: ReturnType<typeof AccountResponse.parse>['subscription'] = null;
  if (sub) {
    const provider = services.backends.fromSubscription(sub);
    const state = await provider.getUser(sub.backendUserId);
    const mirrors = parseMirrors(sub.subscriptionMirrors, platform.logger, {
      subscriptionId: sub.id,
      userId: user.id,
    });
    subscriptionPayload = {
      url: sub.subscriptionUrl,
      shortUuid: sub.backendShortId,
      mirrors,
      expiresAt: state.expireAt,
      trafficLimitBytes: state.trafficLimitBytes,
      trafficUsedBytes: state.usedTrafficBytes,
      backend: sub.backend,
      devices: state.devices.map((d) => ({
        hwid: d.hwid,
        firstSeenAt: d.firstSeenAt ?? undefined,
        lastSeenAt: d.lastSeenAt ?? undefined,
      })),
    };
  }

  // CiviCRM live-membership lookup has been removed; the membership block is
  // populated from local entitlement state (membershipExpiresAt) and will be
  // fed by the billing portal via the entitlement seam (setMembership).
  const membershipBlock: ReturnType<typeof AccountResponse.parse>['user']['membership'] =
    user.membershipExpiresAt
      ? {
          expiresAt: new Date(user.membershipExpiresAt).toISOString(),
          isCurrent: user.status === 'active',
        }
      : null;

  return c.json(
    AccountResponse.parse({
      user: {
        id: user.id,
        email: user.email ?? undefined,
        status: user.status,
        tier: {
          slug: tier.slug,
          name: tier.name,
          monthlyTrafficGb: tier.monthlyTrafficGb,
          deviceLimit: tier.deviceLimit,
          backend: tier.backend,
        },
        membership: membershipBlock,
        createdAt: new Date(user.createdAt).toISOString(),
      },
      subscription: subscriptionPayload,
    }),
    200,
  );
});

const regenerateRoute = createRoute({
  method: 'post',
  path: '/regenerate',
  tags: ['Account'],
  summary: 'Regenerate the subscription URL',
  description:
    'Creates a fresh Remnawave user and tombstones the old subscription. Devices using the old URL will need to re-import.',
  security: [{ authentikJwt: [] }, { apiToken: ['account:write'] }],
  request: {
    body: {
      content: { 'application/json': { schema: RegenerateRequest } },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'New subscription created',
      content: {
        'application/json': {
          schema: z.object({ subscriptionUrl: z.string().url(), shortUuid: z.string() }),
        },
      },
    },
  },
});

router.use('/regenerate', requireScope('account:write'));

router.openapi(regenerateRoute, async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const member = c.var.member!;

  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  if (!user) throw new NotFoundError('user');
  const tier = await services.tierPolicy.getById(user.tierId);
  if (!tier) throw new NotFoundError('tier');

  // CRITICAL: look up the OLD subscription via `users.currentSubscriptionId`,
  // not `userId`. After a previous regenerate, the user has multiple rows
  // (an active one + tombstoned ones), and `where(userId=...).limit(1)`
  // is ordering-unstable — it can return the tombstoned row, which then
  // gets tombstoned a second time while the genuinely-active one is left
  // dangling forever.
  const oldSub = user.currentSubscriptionId
    ? await platform.db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.id, user.currentSubscriptionId))
        .limit(1)
        .all()
    : await platform.db
        .select()
        .from(subscriptions)
        .where(and(eq(subscriptions.userId, user.id), eq(subscriptions.state, 'active')))
        .limit(1)
        .all();

  const trafficLimit = tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;
  const newSub = await services.subscription.issueNew({
    userId: user.id,
    backend: tier.backend,
    spec: {
      username: `freesocks-${tier.slug}-${randomHex(8)}`,
      trafficLimitBytes: trafficLimit,
      trafficLimitStrategy: tier.trafficStrategy,
      expireAt: null,
      hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
      tag: tier.slug,
      remnawaveSquadUuid: tier.remnawaveSquadUuid ?? null,
    },
  });

  await platform.db
    .update(users)
    .set({ currentSubscriptionId: newSub.id, updatedAt: Date.now() })
    .where(eq(users.id, user.id));

  if (oldSub[0]) {
    // Regenerate keeps the user on the same backend (a backend switch goes
    // through /api/v1/account/switch-backend instead). The old subscription
    // is tombstoned with a 24h grace window so the user's existing devices
    // keep working while they re-import. The grace-sweep cron flips
    // tombstones to hard-deleted once their `deletedAt` passes.
    await services.subscription.tombstoneWithGrace(
      oldSub[0].backend,
      oldSub[0].backendUserId,
      24 * 60 * 60 * 1000,
    );
  }
  await services.audit.record({
    actorType: 'member',
    actorId: String(user.id),
    action: 'subscription.regenerate',
    targetType: 'subscription',
    targetId: String(newSub.id),
    requestId: c.var.requestId,
  });
  return c.json({ subscriptionUrl: newSub.subscriptionUrl, shortUuid: newSub.backendShortId }, 200);
});

const switchBackendRoute = createRoute({
  method: 'post',
  path: '/switch-backend',
  tags: ['Account'],
  summary: 'Switch the member to the peer tier on the other backend',
  description:
    'Switches free-tier users to the default-free tier on the target backend, issues a new subscription ' +
    "there, and tombstones the old subscription with a 24h grace window so the user's existing devices " +
    'keep working while they re-import. Paid cross-backend switching is unavailable until the billing ' +
    'portal defines cross-backend tier linkage. Returns 409 if no peer tier exists and 503 if the target ' +
    'backend is currently disabled in app settings.',
  security: [{ authentikJwt: [] }, { apiToken: ['account:write'] }],
  request: {
    body: {
      content: { 'application/json': { schema: SwitchBackendRequest } },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Switched',
      content: { 'application/json': { schema: SwitchBackendResponse } },
    },
    409: {
      description: 'No peer tier on the target backend',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
    503: {
      description: 'Target backend disabled by admin',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.use('/switch-backend', requireScope('account:write'));

router.openapi(switchBackendRoute, async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const member = c.var.member!;
  // `c.req.valid('json')` infers `never` for this route under the current
  // @hono/zod-openapi typings (the admin routes resolve it fine; the exact
  // cause here is unclear), so we read + re-validate the body explicitly. The
  // route's body schema is still enforced by the validator middleware upstream.
  const raw = await c.req.json();
  const { backend: target } = SwitchBackendRequest.parse(raw);

  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  if (!user) throw new NotFoundError('user');
  const currentTier = await services.tierPolicy.getById(user.tierId);
  if (!currentTier) throw new NotFoundError('tier');

  // Switching to the same backend is a no-op; reject early rather than
  // silently doing nothing — the SPA can guard but defense-in-depth.
  if (currentTier.backend === target) {
    throw new ValidationError('Already on the requested backend');
  }

  // Gate on the target backend being enabled. Without this an admin who
  // turned Outline off in settings could still get switched-to traffic.
  const settings = await services.appSettings.getAll();
  const enabledKey = `${target}.enabled` as 'remnawave.enabled' | 'outline.enabled';
  if (!settings[enabledKey]) {
    return c.json(
      {
        error: {
          code: 'backend.disabled',
          message: `Backend "${target}" is currently disabled. Try again later or contact support.`,
        },
      },
      503,
    );
  }

  // Resolve the peer tier on the target backend. Free-tier users switch via the
  // default-free tier on that backend. Paid cross-backend switching was driven
  // by CiviCRM membership-type linkage, which has been removed — until the
  // billing portal defines explicit cross-backend tier linkage, paid users
  // can't switch backends and fall through to the 409 below.
  let peerTier: typeof currentTier | null = null;
  if (currentTier.isDefaultFree) {
    try {
      peerTier = await services.tierPolicy.getDefaultFreeTier(target);
    } catch {
      peerTier = null;
    }
  }
  if (!peerTier) {
    return c.json(
      {
        error: {
          code: 'tier.no_peer',
          message: `No peer tier configured on backend "${target}" for this membership. Ask an admin to add one.`,
        },
      },
      409,
    );
  }

  // Fetch current subscription so we can tombstone it.
  // Same active-state fallback rule as GET /account: if the user lost
  // `currentSubscriptionId` somehow, we still only want the live row, not
  // a previously-tombstoned one.
  const oldSubRow = user.currentSubscriptionId
    ? await platform.db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.id, user.currentSubscriptionId))
        .limit(1)
        .all()
    : await platform.db
        .select()
        .from(subscriptions)
        .where(and(eq(subscriptions.userId, user.id), eq(subscriptions.state, 'active')))
        .limit(1)
        .all();
  const oldSub = oldSubRow[0];

  // Issue the new subscription on the target backend.
  const trafficLimit =
    peerTier.monthlyTrafficGb > 0 ? peerTier.monthlyTrafficGb * 1_000_000_000 : null;
  const newSub = await services.subscription.issueNew({
    userId: user.id,
    backend: peerTier.backend,
    spec: {
      username: `freesocks-${peerTier.slug}-${randomHex(8)}`,
      trafficLimitBytes: trafficLimit,
      trafficLimitStrategy: peerTier.trafficStrategy,
      expireAt: null,
      hwidDeviceLimit: peerTier.hwidEnabled ? peerTier.hwidLimit : null,
      tag: peerTier.slug,
      remnawaveSquadUuid: peerTier.remnawaveSquadUuid ?? null,
    },
  });

  // Flip the user to the peer tier and point them at the new subscription.
  await platform.db
    .update(users)
    .set({ tierId: peerTier.id, currentSubscriptionId: newSub.id, updatedAt: Date.now() })
    .where(eq(users.id, user.id));

  // Record the tier history so an admin can trace the switch later.
  // Free tier → paid tier transitions go through `applyTierChange`, so we
  // only need to record peer-to-peer same-membership switches.
  await services.audit.record({
    actorType: 'member',
    actorId: String(user.id),
    action: 'subscription.switch_backend',
    targetType: 'subscription',
    targetId: String(newSub.id),
    payload: {
      fromBackend: currentTier.backend,
      toBackend: peerTier.backend,
      fromTier: currentTier.slug,
      toTier: peerTier.slug,
    },
    requestId: c.var.requestId,
  });

  // Tombstone the old subscription with a 24h grace window. Cron sweep
  // hard-deletes after the window passes. `tombstoneWithGrace` returns null
  // when there's nothing meaningful to tombstone — the row was already
  // non-active and had no recorded deletedAt (rare; usually a quick
  // double-switch). Don't fabricate a fake timestamp in that case.
  let oldDeletedAt: number | null = null;
  if (oldSub) {
    const tombstone = await services.subscription.tombstoneWithGrace(
      oldSub.backend,
      oldSub.backendUserId,
      24 * 60 * 60 * 1000,
    );
    oldDeletedAt = tombstone?.deletedAt ?? null;
  }

  return c.json(
    {
      subscriptionUrl: newSub.subscriptionUrl,
      shortUuid: newSub.backendShortId,
      backend: newSub.backend,
      tier: {
        slug: peerTier.slug,
        name: peerTier.name,
        monthlyTrafficGb: peerTier.monthlyTrafficGb,
        deviceLimit: peerTier.deviceLimit,
      },
      oldSubscriptionDeletedAt: oldDeletedAt !== null ? new Date(oldDeletedAt).toISOString() : null,
    },
    200,
  );
});

const refreshMembershipRoute = createRoute({
  method: 'post',
  path: '/refresh-membership',
  tags: ['Account'],
  summary: "Re-read the member's current entitlement state",
  description:
    "Returns the member's current tier and membership expiry from local entitlement state. Rate-limited to once per 30 seconds per member.",
  security: [{ authentikJwt: [] }, { apiToken: ['account:read'] }],
  responses: {
    200: {
      description: 'Refreshed',
      content: {
        'application/json': {
          schema: z.object({
            tierSlug: z.string(),
            tierName: z.string(),
            membershipExpiresAt: z.string().datetime().nullable(),
            isCurrent: z.boolean(),
          }),
        },
      },
    },
    429: {
      description: 'Rate-limited',
      content: { 'application/json': { schema: ApiErrorResponse } },
    },
  },
});

router.use('/refresh-membership', requireScope('account:read'));

router.openapi(refreshMembershipRoute, async (c) => {
  const services = c.var.services;
  const platform = c.var.platform;
  const member = c.var.member!;

  // Rate-limit: 1 per 30s per member.
  const rlKey = `rl:refresh-membership:user:${member.userId}`;
  const rl = await services.rateLimit.checkAndIncrement(rlKey, 1, 30);
  if (!rl.allowed) {
    return c.json(
      {
        error: {
          code: 'rate_limit.exceeded',
          message: 'Refresh too soon. Try again in 30 seconds.',
          details: { retryAfterSeconds: rl.retryAfterSeconds },
        },
      },
      429,
    );
  }

  // CiviCRM live lookup removed — return the user's current local entitlement
  // state (tier + membership expiry). The billing portal will keep this fresh
  // via the entitlement seam (setMembership).
  const userRow = await platform.db
    .select()
    .from(users)
    .where(eq(users.id, member.userId))
    .limit(1)
    .all();
  const user = userRow[0];
  const tier = user
    ? ((await services.tierPolicy.getById(user.tierId)) ??
      (await services.tierPolicy.getDefaultFreeTier()))
    : await services.tierPolicy.getDefaultFreeTier();
  return c.json(
    {
      tierSlug: tier.slug,
      tierName: tier.name,
      membershipExpiresAt: user?.membershipExpiresAt
        ? new Date(user.membershipExpiresAt).toISOString()
        : null,
      isCurrent: (user?.status ?? 'active') === 'active',
    },
    200,
  );
});

export default router;
