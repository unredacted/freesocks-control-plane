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
import { internalAction, internalMutation, type ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { randomHex } from './lib/crypto';
import { issueNewSubscription } from './lib/issuance';
import {
  computeExpireAtIso,
  gbToBytes,
  resolveHwidLimit,
  type UsageSeries,
} from './lib/backends/types';

type Backend = 'remnawave' | 'outline';

/**
 * WS1 bring-up safety net: when a Remnawave key is issued with a null placement
 * (only possible when NO mode has a pool bound anywhere on the deploy), the key
 * has no inbounds. We still issue it (keys must mint during bring-up) but never
 * SILENTLY — audit it so an admin sees they must bind a placement pool. A no-op
 * for Outline or when a placement resolved. `switchMode` can't reach this (it
 * rejects unbound targets first).
 */
async function auditIfPlacementless(
  ctx: ActionCtx,
  args: {
    backend: Backend;
    placement: string | null;
    userId: Id<'users'>;
    subscriptionId: Id<'subscriptions'>;
    requestedMode: string | null;
    requestId?: string;
  },
): Promise<void> {
  if (args.backend !== 'remnawave' || args.placement !== null) return;
  console.warn('[placement] issued a squad-less key: no Remnawave pool bound on this deploy');
  await ctx.runMutation(internal.audit.record, {
    actorType: 'member',
    actorId: args.userId,
    action: 'subscription.issued_without_placement',
    targetType: 'subscription',
    targetId: args.subscriptionId,
    payload: { requestedMode: args.requestedMode },
    requestId: args.requestId,
  });
}

// P1-3: a serializable per-user issuance lock. regenerate / switch-backend /
// switch-profile each mint a NEW backend key and tombstone the old one; two
// concurrent runs would mint two keys but tombstone only one, orphaning a live key
// forever. The lock makes only one issuance saga run per user at a time.
//
// Review #7: the TTL must exceed a worst-case saga — a switch chains several
// backend HTTP calls (8s timeout each, see remnawave.ts) plus S3 mirror work, so
// the old 30s could expire mid-saga and let a SECOND saga acquire (the exact
// double-issue this lock prevents). And release is owner-checked via a nonce, so
// even after such a takeover a stale saga's `finally` can't delete the NEW holder's
// lock (a blind delete previously could).
const ISSUE_LOCK_TTL_MS = 120_000;

/** Parse a lock row's value; tolerates the legacy plain-number (expiry-only) form. */
function parseLock(value: string): { exp: number; token: string | null } {
  try {
    const o = JSON.parse(value) as { exp?: number; token?: string };
    if (o && typeof o.exp === 'number') {
      return { exp: o.exp, token: typeof o.token === 'string' ? o.token : null };
    }
  } catch {
    /* legacy format: a bare expiry number */
  }
  const n = Number(value);
  return { exp: Number.isFinite(n) ? n : 0, token: null };
}

export const acquireIssuanceLock = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<{ acquired: boolean; token?: string }> => {
    const key = `issue-lock:${userId}`;
    const now = Date.now();
    const token = randomHex(16);
    const value = JSON.stringify({ exp: now + ISSUE_LOCK_TTL_MS, token });
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (row) {
      if (parseLock(row.value).exp > now) return { acquired: false }; // held + unexpired
      await ctx.db.patch(row._id, { value, updatedAt: now }); // take over an expired lock
      return { acquired: true, token };
    }
    await ctx.db.insert('appState', { key, value, updatedAt: now });
    return { acquired: true, token };
  },
});

export const releaseIssuanceLock = internalMutation({
  args: { userId: v.id('users'), token: v.optional(v.string()) },
  handler: async (ctx, { userId, token }): Promise<null> => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', `issue-lock:${userId}`))
      .unique();
    if (!row) return null;
    // Owner-checked: delete only when the caller's nonce matches the held one, so a
    // saga whose lock already expired + was re-acquired by another can't delete the
    // NEW holder's lock. A missing token on either side (legacy row / legacy caller)
    // falls back to an unconditional delete. (Review #7.)
    const held = parseLock(row.value).token;
    if (token && held && held !== token) return null;
    await ctx.db.delete(row._id);
    return null;
  },
});

interface AccountView {
  user: {
    id: Id<'users'>;
    status: 'active' | 'grace' | 'disabled' | 'deleted' | 'inactive';
    supportId: string | null;
    tier: {
      slug: string;
      name: string;
      monthlyTrafficGb: number;
      deviceLimit: number;
      backend: Backend;
      // True when this member's tier enforces a device limit AND enforcement is
      // globally enabled — the SPA gates app compatibility only when true.
      deviceLimited: boolean;
    };
    membership: { expiresAt: string | null; isCurrent: boolean } | null;
    connectionModeId: string;
    createdAt: string;
  };
  subscription: {
    url: string;
    // Opaque FCP-fronted-URL token; the SPA builds `<origin>/api/v1/sub/<subToken>`.
    subToken: string | null;
    shortUuid: string;
    mirrors: { provider: string; publicUrl: string }[];
    expiresAt: string | null;
    trafficLimitBytes: number | null;
    trafficUsedBytes: number;
    // Live key state from the backend (undefined/'unknown' when it's unreachable).
    // `status` explains a stopped VPN (limited = over quota, disabled = lapsed);
    // resetStrategy + lastResetAt drive the "resets in N days" hint.
    status?: 'active' | 'disabled' | 'limited' | 'expired' | 'unknown';
    resetStrategy?: 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH';
    lastResetAt?: string;
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
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const deviceLimited = !!settings['devices.enforcementEnabled'] && tier.hwidEnabled;

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

    // Member's chosen connection mode (or the catalog default) — surfaced so the
    // client renders the selected transport server-authoritatively.
    const connectionModeId =
      user.connectionModeId ?? (await ctx.runQuery(internal.connectionModes.defaultId, {}));
    const trafficLimitFromTier =
      tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null;
    let subscription: AccountView['subscription'] = null;
    if (sub) {
      // Best-effort live state; degrade to local data if the backend is down.
      let live = {
        expireAt: null as string | null,
        trafficLimitBytes: trafficLimitFromTier,
        usedTrafficBytes: 0,
        // Degrade default: backend unreachable ⇒ we don't know the key's status,
        // so 'unknown' (the member badge only fires for limited/disabled).
        status: 'unknown' as 'active' | 'disabled' | 'limited' | 'expired' | 'unknown',
        resetStrategy: undefined as 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH' | undefined,
        lastResetAt: undefined as string | undefined,
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
          status: state.status,
          resetStrategy: state.trafficLimitStrategy,
          lastResetAt: state.lastTrafficResetAt,
          devices: state.devices,
        };
      } catch {
        /* backend unreachable: serve local data with zeroed live fields */
      }
      subscription = {
        // The raw backend URL (fallback) + the opaque token; the SPA builds the
        // FCP-fronted URL from the token + its own origin, so there's no
        // deployment-origin env dependency and every UI surface fronts uniformly.
        url: sub.subscriptionUrl,
        subToken: sub.subToken ?? null,
        shortUuid: sub.backendShortId,
        // Don't advertise a mirror whose last refresh failed (Review #2): it's kept
        // in the DB so the cap holds + the next refresh retries it, but the member
        // shouldn't be handed a URL we couldn't refresh.
        mirrors: sub.subscriptionMirrors
          .filter((m) => m.status !== 'failed')
          .map((m) => ({ provider: m.provider, publicUrl: m.publicUrl })),
        expiresAt: live.expireAt,
        trafficLimitBytes: live.trafficLimitBytes,
        trafficUsedBytes: live.usedTrafficBytes,
        status: live.status,
        resetStrategy: live.resetStrategy,
        lastResetAt: live.lastResetAt,
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
          deviceLimited,
        },
        membership: user.membershipExpiresAt
          ? {
              expiresAt: new Date(user.membershipExpiresAt).toISOString(),
              isCurrent: user.status === 'active',
            }
          : null,
        connectionModeId,
        createdAt: new Date(user._creationTime).toISOString(),
      },
      subscription,
    };
  },
});

/**
 * Member usage trend (aggregate, read-live-and-never-stored). Resolves the
 * member's current subscription and asks the backend for the last `days` of
 * usage; null when there's no sub or the backend has no usage history (Outline).
 * Kept OUT of getAccountView so it doesn't add a second live backend call to the
 * main account load — the client fetches it lazily when the member opens the panel.
 */
export const getUsage = internalAction({
  args: { userId: v.id('users'), days: v.optional(v.number()) },
  handler: async (ctx, { userId, days }): Promise<{ usage: UsageSeries | null }> => {
    const sub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    if (!sub) return { usage: null };
    const usage = await ctx.runAction(internal.backends.getUserUsage, {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      days: days ?? 30,
    });
    return { usage };
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
    // Node placement from the member's chosen mode's pool (Remnawave only).
    const nodePlacement =
      tier.backend === 'remnawave'
        ? await ctx.runQuery(internal.remnawaveNodes.resolvePlacement, {
            modeId: user.connectionModeId ?? null,
          })
        : null;
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: tier.backend,
      spec: {
        username: `freesocks-${tier.slug}-${randomHex(8)}`,
        trafficLimitBytes: tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null,
        trafficLimitStrategy: tier.trafficStrategy,
        // Member term, else the free window — Remnawave requires a real date.
        expireAt: computeExpireAtIso(user.membershipExpiresAt, freeExpiryDays),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
        tag: tier.slug,
        placement: nodePlacement,
      },
    });

    if (oldSub) {
      await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: oldSub.backendUserId,
        graceMs: 24 * 60 * 60 * 1000,
      });
    }
    await auditIfPlacementless(ctx, {
      backend: tier.backend,
      placement: nodePlacement,
      userId,
      subscriptionId: issued.subscriptionId,
      requestedMode: user.connectionModeId ?? null,
      requestId,
    });
    // Free key (re)issued → refresh the idle window (and reactivate if the member
    // was inactive and regenerated from a still-valid session). (WS2.)
    if (tier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
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
    // Carry the member's chosen mode across the backend switch (Remnawave only).
    const nodePlacement =
      peerTier.backend === 'remnawave'
        ? await ctx.runQuery(internal.remnawaveNodes.resolvePlacement, {
            modeId: user.connectionModeId ?? null,
          })
        : null;
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
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], peerTier),
        tag: peerTier.slug,
        placement: nodePlacement,
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

    await auditIfPlacementless(ctx, {
      backend: peerTier.backend,
      placement: nodePlacement,
      userId,
      subscriptionId: issued.subscriptionId,
      requestedMode: user.connectionModeId ?? null,
      requestId,
    });
    if (peerTier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
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

type SwitchModeResult =
  | {
      ok: true;
      subscriptionUrl: string;
      shortUuid: string;
      mode: { id: string; label: string | null };
      oldSubscriptionDeletedAt: string | null;
    }
  | { ok: false; code: string; message: string; status: number };

/**
 * Switch the member's connection mode (transport) WITHIN the same backend.
 * Mirrors switchBackend's saga (issue new key → tombstone the old with 24h grace
 * → audit) but with no tier/backend change: it re-issues the key into the chosen
 * mode's least-loaded node and records the choice on the user. Degrades cleanly
 * when the mode has no placement pool bound yet (falls back to the tier squad).
 */
export const switchMode = internalAction({
  args: {
    userId: v.id('users'),
    target: v.string(),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, { userId, target, requestId }): Promise<SwitchModeResult> => {
    const user = await ctx.runQuery(internal.users.get, { id: userId });
    if (!user) return { ok: false, code: 'not_found', message: 'user not found', status: 404 };
    const tier = await ctx.runQuery(internal.tiers.get, { id: user.tierId });
    if (!tier) return { ok: false, code: 'not_found', message: 'tier not found', status: 404 };

    // No-op guard: choosing the mode you already have shouldn't churn a new key.
    if ((user.connectionModeId ?? null) === target) {
      return {
        ok: false,
        code: 'validation',
        message: 'Already on the requested mode',
        status: 400,
      };
    }

    // Validate the target against the live catalog (data-driven; not a union).
    const modes = await ctx.runQuery(internal.connectionModes.list, {});
    const chosen = modes.find((m) => m.id === target);
    if (!chosen) {
      return { ok: false, code: 'validation', message: 'Unknown connection mode', status: 400 };
    }
    // Refuse to switch to a mode with no placement pool bound (Remnawave only):
    // issuing into it would mint a squad-less "dead" key AND we'd have tombstoned
    // the working key to do it. The picker also disables unbound modes; this is
    // the server-authoritative guard. (WS1.)
    if (tier.backend === 'remnawave' && !chosen.bound) {
      return {
        ok: false,
        code: 'validation',
        message: 'This connection mode is not available yet.',
        status: 400,
      };
    }

    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const nodePlacement =
      tier.backend === 'remnawave'
        ? await ctx.runQuery(internal.remnawaveNodes.resolvePlacement, { modeId: target })
        : null;
    const oldSub = await ctx.runQuery(internal.subscriptions.resolveCurrentOrActive, { userId });
    const issued = await issueNewSubscription(ctx, {
      userId,
      backend: tier.backend,
      spec: {
        username: `freesocks-${tier.slug}-${randomHex(8)}`,
        trafficLimitBytes: tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null,
        trafficLimitStrategy: tier.trafficStrategy,
        expireAt: computeExpireAtIso(
          user.membershipExpiresAt,
          Number(settings['freetier.expiryDays'] ?? 90),
        ),
        hwidDeviceLimit: resolveHwidLimit(!!settings['devices.enforcementEnabled'], tier),
        tag: tier.slug,
        placement: nodePlacement,
      },
    });

    // Tombstone the OLD key before recording the choice (issueNew already
    // repointed currentSubscriptionId), same 24h grace as regenerate/switch.
    let oldDeletedAt: number | null = null;
    if (oldSub) {
      const tomb = await ctx.runMutation(internal.subscriptions.tombstoneWithGrace, {
        backendUserId: oldSub.backendUserId,
        graceMs: 24 * 60 * 60 * 1000,
      });
      oldDeletedAt = tomb?.deletedAt ?? null;
    }
    await ctx.runMutation(internal.users.setConnectionMode, { userId, modeId: target });
    if (tier.isDefaultFree) {
      await ctx.runMutation(internal.lifecycle.refreshFreeWindow, { userId });
    }
    await ctx.runMutation(internal.audit.record, {
      actorType: 'member',
      actorId: userId,
      action: 'subscription.switch_mode',
      targetType: 'subscription',
      targetId: issued.subscriptionId,
      // Never a placement/squad uuid — only which mode.
      payload: {
        fromMode: user.connectionModeId ?? null,
        toMode: target,
      },
      requestId,
    });
    return {
      ok: true,
      subscriptionUrl: issued.subscriptionUrl,
      shortUuid: issued.backendShortId,
      mode: { id: chosen.id, label: chosen.label },
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
