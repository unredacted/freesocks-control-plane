/**
 * Member account operations (P7): the multi-step flows behind GET /account,
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
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { randomHex } from './lib/crypto';
import { issueNewSubscription } from './lib/issuance';
import { computeExpireAtIso, gbToBytes } from './lib/backends/types';

type Backend = 'remnawave' | 'outline';

// P1-3: a serializable per-user issuance lock. regenerate / switch-backend each
// mint a NEW backend key and tombstone the old one; two concurrent runs would
// mint two keys but tombstone only one, orphaning a live key forever. The lock
// makes only one issuance saga run per user at a time. A short TTL means a
// crashed saga self-heals (the next attempt re-acquires once it expires).
const ISSUE_LOCK_TTL_MS = 30_000;

export const acquireIssuanceLock = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ acquired: boolean }> => {
    const key = `issue-lock:${userId}`;
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) {
      const exp = Number(row.value);
      if (Number.isFinite(exp) && exp > now) return { acquired: false };
      await ctx.db.patch(row._id, { value: String(now + ISSUE_LOCK_TTL_MS), updatedAt: now });
      return { acquired: true };
    }
    await ctx.db.insert('appState', {
      key,
      value: String(now + ISSUE_LOCK_TTL_MS),
      updatedAt: now,
    });
    return { acquired: true };
  },
});

export const releaseIssuanceLock = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<null> => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', `issue-lock:${userId}`))
      .unique();
    if (row) await ctx.db.delete(row._id);
    return null;
  },
});

interface AccountView {
  user: {
    id: Id<'users'>;
    status: 'active' | 'grace' | 'disabled' | 'deleted';
    supportId: string | null;
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
    devices: {
      hwid: string;
      platform?: string;
      deviceModel?: string;
      firstSeenAt?: string;
      lastSeenAt?: string;
    }[];
  } | null;
}

export const getAccountView = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<AccountView | null> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return null;
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return null;
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });

    // W3: lazily backfill the support ID for pre-W3 accounts. Non-fatal — the
    // account view still renders if minting transiently fails.
    let supportId = user.supportId ?? null;
    if (!supportId) {
      try {
        supportId = (await ctx.runAction(internal.supportId.ensureForUser, { userId })).supportId;
      } catch {
        /* leave null; next view retries */
      }
    }

    const trafficLimitFromTier =
      tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null;
    let subscription: AccountView['subscription'] = null;
    if (sub) {
      // Best-effort live state; degrade to local data if the backend is down.
      let live = {
        expireAt: null as string | null,
        trafficLimitBytes: trafficLimitFromTier,
        usedTrafficBytes: 0,
        devices: [] as {
          hwid: string;
          platform?: string | null;
          deviceModel?: string | null;
          firstSeenAt?: string | null;
          lastSeenAt?: string | null;
        }[],
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
        /* backend unreachable: serve local data with zeroed live fields */
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
          platform: d.platform ?? undefined,
          deviceModel: d.deviceModel ?? undefined,
          firstSeenAt: d.firstSeenAt ?? undefined,
          lastSeenAt: d.lastSeenAt ?? undefined,
        })),
      };
    }

    return {
      user: {
        id: user._id,
        status: user.status,
        supportId,
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
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) throw new Error('user not found');
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) throw new Error('tier not found');

    // Capture the OLD subscription BEFORE issuing (issueNewSubscription repoints
    // currentSubscriptionId at the new row).
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const freeExpiryDays = Number(settings['freetier.expiryDays'] ?? 90);
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: tier.backend,
      spec: {
        username: `freesocks-${tier.slug}-${randomHex(8)}`,
        trafficLimitBytes: tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null,
        trafficLimitStrategy: tier.trafficStrategy,
        // Member term, else the free window — Remnawave requires a real date.
        expireAt: computeExpireAtIso(user.membershipExpiresAt, freeExpiryDays),
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
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const currentTier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
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
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    if (!settings[`${target}.enabled`]) {
      return {
        ok: false,
        code: 'backend.disabled',
        message: `Backend "${target}" is currently disabled. Try again later or contact support.`,
        status: 503,
      };
    }

    // Resolve the cross-backend peer (D-1): a free tier auto-peers via the
    // per-backend default-free row; a paid tier uses the admin-linked peerTierId
    // (either direction). No peer → an actionable 409 (an admin can now link one).
    const peerTier = await ctx.runQuery(internal.tiers.getPeerTier, {
      tierId: currentTier._id,
      targetBackend: target,
    });
    if (!peerTier) {
      return {
        ok: false,
        code: 'tier.no_peer',
        message: `No peer tier configured on backend "${target}" for this membership. Ask an admin to add one.`,
        status: 409,
      };
    }

    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: peerTier.backend,
      spec: {
        username: `freesocks-${peerTier.slug}-${randomHex(8)}`,
        trafficLimitBytes:
          peerTier.monthlyTrafficGb > 0 ? gbToBytes(peerTier.monthlyTrafficGb) : null,
        trafficLimitStrategy: peerTier.trafficStrategy,
        // Entitlement unchanged by a backend switch: keep the member's term / free window.
        expireAt: computeExpireAtIso(
          user.membershipExpiresAt,
          Number(settings['freetier.expiryDays'] ?? 90),
        ),
        hwidDeviceLimit: peerTier.hwidEnabled ? peerTier.hwidLimit : null,
        tag: peerTier.slug,
        remnawaveSquadUuid: peerTier.remnawaveSquadUuid ?? null,
      },
    });

    // P1-6: tombstone the OLD subscription BEFORE flipping the tier. issueNew
    // already repointed currentSubscriptionId at the new key, so the old key is
    // scheduled for teardown first; if a later step dies, the worst case is the
    // user on the old tier with the new key live and the old key tombstoned —
    // never two indefinitely-live keys.
    let oldDeletedAt: number | null = null;
    if (oldSub) {
      const tomb = await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: oldSub.backendUserId,
        graceMs: 24 * 60 * 60 * 1000,
      });
      oldDeletedAt = tomb?.deletedAt ?? null;
    }

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

type RevokeDeviceResult =
  | { ok: true }
  | { ok: false; code: string; message: string; status: number };

/**
 * Revoke one of the member's HWID devices, freeing a slot under the tier's
 * device cap without a full key regenerate. The hwid must belong to the
 * member's own current key (verified against the backend's live device list
 * before the delete — a member can never name someone else's device).
 */
export const revokeDevice = internalAction({
  args: { userId: v.id('users'), hwid: v.string(), requestId: v.optional(v.string()) },
  handler: async (ctx, { userId, hwid, requestId }): Promise<RevokeDeviceResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!sub) {
      return {
        ok: false,
        code: 'devices.no_subscription',
        message: 'No active subscription',
        status: 404,
      };
    }
    if (sub.backend !== 'remnawave') {
      return {
        ok: false,
        code: 'devices.unsupported',
        message: 'This backend does not support device management',
        status: 409,
      };
    }

    // Ownership check: the hwid must be on the member's own key right now.
    const state = await ctx.runAction(internal.backends.getUser, {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
    });
    if (!state.devices.some((d) => d.hwid === hwid)) {
      return {
        ok: false,
        code: 'devices.not_found',
        message: 'Device not found on this account',
        status: 404,
      };
    }

    await ctx.runAction(internal.backends.revokeDevice, {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      hwid,
    });
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.device_revoke',
      targetType: 'subscription',
      targetId: sub._id,
      // Never the full hwid (it's a device identifier): a short prefix traces it.
      payload: { hwidPrefix: hwid.slice(0, 8) },
      requestId,
    });
    return { ok: true };
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
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    const tier = user ? await ctx.runQuery(internal.tiers.get, { id: user.tierId }) : null;
    const effective = tier ?? (await ctx.runQuery(internal.tiers.getDefaultFree, {}));
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
