/**
 * Member account operations (P7) — the multi-step flows behind GET /account,
 * regenerate, switch-backend, and refresh-membership. Ported from
 * routes/api/account.ts. The HTTP layer authenticates the member session and
 * passes the userId; these internalActions own the saga (backend issue + S3 via
 * lib/issuance, tombstone-with-grace, tier switch, audit). The live subscription
 * state is fetched best-effort so a backend outage degrades /account instead of
 * 500-ing it.
 *
 * The switch-backend peer resolution is the documented interim: free-tier users
 * switch via the default-free peer tier; paid users get 409 until the billing
 * portal defines cross-backend tier linkage (CiviCRM linkage is gone).
 */
import { internalAction } from './_generated/server';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { randomHex } from './lib/crypto';
import { issueNewSubscription } from './lib/issuance';

type Backend = 'remnawave' | 'outline';

interface AccountView {
  user: {
    id: Id<'users'>;
    email?: string;
    status: 'active' | 'grace' | 'disabled' | 'deleted';
    tier: {
      slug: string;
      name: string;
      monthlyTrafficGb: number;
      deviceLimit: number;
      backend: Backend;
    };
    membership: { expiresAt: string | null; isCurrent: boolean } | null;
    createdAt: string;
  };
  subscription: {
    url: string;
    shortUuid: string;
    mirrors: { provider: string; publicUrl: string }[];
    expiresAt: string | null;
    trafficLimitBytes: number | null;
    trafficUsedBytes: number;
    backend: Backend;
    devices: { hwid: string; firstSeenAt?: string; lastSeenAt?: string }[];
  } | null;
}

export const getAccountView = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<AccountView | null> => {
    const user = await ctx.runQuery(api.users.get, { id: userId });
    if (!user) return null;
    const tier = await ctx.runQuery(api.tiers.get, { id: user.tierId });
    if (!tier) return null;
    const sub = await ctx.runQuery(api.subscriptions.resolveCurrentOrActive, { userId });

    const trafficLimitFromTier =
      tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null;
    let subscription: AccountView['subscription'] = null;
    if (sub) {
      // Best-effort live state; degrade to local data if the backend is down.
      let live = {
        expireAt: null as string | null,
        trafficLimitBytes: trafficLimitFromTier,
        usedTrafficBytes: 0,
        devices: [] as { hwid: string; firstSeenAt?: string | null; lastSeenAt?: string | null }[],
      };
      try {
        const state = await ctx.runAction(internal.backends.getUser, {
          backend: sub.backend,
          backendUserId: sub.backendUserId,
        });
        live = {
          expireAt: state.expireAt,
          trafficLimitBytes: state.trafficLimitBytes,
          usedTrafficBytes: state.usedTrafficBytes,
          devices: state.devices,
        };
      } catch {
        /* backend unreachable — serve local data with zeroed live fields */
      }
      subscription = {
        url: sub.subscriptionUrl,
        shortUuid: sub.backendShortId,
        mirrors: sub.subscriptionMirrors.map((m) => ({
          provider: m.provider,
          publicUrl: m.publicUrl,
        })),
        expiresAt: live.expireAt,
        trafficLimitBytes: live.trafficLimitBytes,
        trafficUsedBytes: live.usedTrafficBytes,
        backend: sub.backend,
        devices: live.devices.map((d) => ({
          hwid: d.hwid,
          firstSeenAt: d.firstSeenAt ?? undefined,
          lastSeenAt: d.lastSeenAt ?? undefined,
        })),
      };
    }

    return {
      user: {
        id: user._id,
        email: user.email ?? undefined,
        status: user.status,
        tier: {
          slug: tier.slug,
          name: tier.name,
          monthlyTrafficGb: tier.monthlyTrafficGb,
          deviceLimit: tier.deviceLimit,
          backend: tier.backend,
        },
        membership: user.membershipExpiresAt
          ? {
              expiresAt: new Date(user.membershipExpiresAt).toISOString(),
              isCurrent: user.status === 'active',
            }
          : null,
        createdAt: new Date(user._creationTime).toISOString(),
      },
      subscription,
    };
  },
});

export const regenerate = internalAction({
  args: { userId: v.id('users'), requestId: v.optional(v.string()) },
  handler: async (
    ctx,
    { userId, requestId },
  ): Promise<{ subscriptionUrl: string; shortUuid: string }> => {
    const user = await ctx.runQuery(api.users.get, { id: userId });
    if (!user) throw new Error('user not found');
    const tier = await ctx.runQuery(api.tiers.get, { id: user.tierId });
    if (!tier) throw new Error('tier not found');

    // Capture the OLD subscription BEFORE issuing (issueNewSubscription repoints
    // currentSubscriptionId at the new row).
    const oldSub = await ctx.runQuery(api.subscriptions.resolveCurrentOrActive, { userId });

    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: tier.backend,
      spec: {
        username: `freesocks-${tier.slug}-${randomHex(8)}`,
        trafficLimitBytes: tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null,
        trafficLimitStrategy: tier.trafficStrategy,
        expireAt: null,
        hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
        tag: tier.slug,
        remnawaveSquadUuid: tier.remnawaveSquadUuid ?? null,
      },
    });

    if (oldSub) {
      await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: oldSub.backendUserId,
        graceMs: 24 * 60 * 60 * 1000,
      });
    }
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.regenerate',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      requestId,
    });
    return { subscriptionUrl: issued.subscriptionUrl, shortUuid: issued.backendShortId };
  },
});

type SwitchResult =
  | {
      ok: true;
      subscriptionUrl: string;
      shortUuid: string;
      backend: Backend;
      tier: { slug: string; name: string; monthlyTrafficGb: number; deviceLimit: number };
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

export const switchBackend = internalAction({
  args: {
    userId: v.id('users'),
    target: v.union(v.literal('remnawave'), v.literal('outline')),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, { userId, target, requestId }): Promise<SwitchResult> => {
    const user = await ctx.runQuery(api.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const currentTier = await ctx.runQuery(api.tiers.get, { id: user.tierId });
    if (!currentTier)
      return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };

    if (currentTier.backend === target) {
      return {
        ok: false,
        code: 'validation',
        message: 'Already on the requested backend',
        status: 400,
      };
    }
    const settings = await ctx.runQuery(api.appSettings.resolved, {});
    if (!settings[`${target}.enabled`]) {
      return {
        ok: false,
        code: 'backend.disabled',
        message: `Backend "${target}" is currently disabled. Try again later or contact support.`,
        status: 503,
      };
    }

    // Free-tier users switch via the default-free peer tier; paid cross-backend
    // switching awaits the billing portal's tier linkage (interim 409).
    const peerTier = currentTier.isDefaultFree
      ? await ctx.runQuery(api.tiers.getDefaultFree, { backend: target })
      : null;
    if (!peerTier) {
      return {
        ok: false,
        code: 'tier.no_peer',
        message: `No peer tier configured on backend "${target}" for this membership. Ask an admin to add one.`,
        status: 409,
      };
    }

    const oldSub = await ctx.runQuery(api.subscriptions.resolveCurrentOrActive, { userId });
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: peerTier.backend,
      spec: {
        username: `freesocks-${peerTier.slug}-${randomHex(8)}`,
        trafficLimitBytes:
          peerTier.monthlyTrafficGb > 0 ? peerTier.monthlyTrafficGb * 1_000_000_000 : null,
        trafficLimitStrategy: peerTier.trafficStrategy,
        expireAt: null,
        hwidDeviceLimit: peerTier.hwidEnabled ? peerTier.hwidLimit : null,
        tag: peerTier.slug,
        remnawaveSquadUuid: peerTier.remnawaveSquadUuid ?? null,
      },
    });
    await ctx.runMutation(internal.users.setTier, { userId, tierId: peerTier._id });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.switch_backend',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      payload: {
        fromBackend: currentTier.backend,
        toBackend: peerTier.backend,
        fromTier: currentTier.slug,
        toTier: peerTier.slug,
      },
      requestId,
    });

    let oldDeletedAt: number | null = null;
    if (oldSub) {
      const tomb = await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: oldSub.backendUserId,
        graceMs: 24 * 60 * 60 * 1000,
      });
      oldDeletedAt = tomb?.deletedAt ?? null;
    }
    return {
      ok: true,
      subscriptionUrl: issued.subscriptionUrl,
      shortUuid: issued.backendShortId,
      backend: issued.backend,
      tier: {
        slug: peerTier.slug,
        name: peerTier.name,
        monthlyTrafficGb: peerTier.monthlyTrafficGb,
        deviceLimit: peerTier.deviceLimit,
      },
      oldSubscriptionDeletedAt: oldDeletedAt !== null ? new Date(oldDeletedAt).toISOString() : null,
    };
  },
});

/** Local entitlement snapshot (CiviCRM live lookup removed). Read-only query. */
export const refreshMembership = internalAction({
  args: { userId: v.id('users') },
  handler: async (
    ctx,
    { userId },
  ): Promise<{
    tierSlug: string;
    tierName: string;
    membershipExpiresAt: string | null;
    isCurrent: boolean;
  }> => {
    const user = await ctx.runQuery(api.users.get, { id: userId });
    const tier = user ? await ctx.runQuery(api.tiers.get, { id: user.tierId }) : null;
    const effective = tier ?? (await ctx.runQuery(api.tiers.getDefaultFree, {}));
    if (!effective) throw new Error('no tier');
    return {
      tierSlug: effective.slug,
      tierName: effective.name,
      membershipExpiresAt: user?.membershipExpiresAt
        ? new Date(user.membershipExpiresAt).toISOString()
        : null,
      isCurrent: (user?.status ?? 'active') === 'active',
    };
  },
});
