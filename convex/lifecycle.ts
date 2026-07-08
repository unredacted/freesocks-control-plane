/**
 * Membership lifecycle (P5d): the setMembership entitlement seam + the generic
 * active→grace→disabled sweep + free-tier cleanup. Ported from the surviving
 * half of services/membership-sync.ts and FreeTierService.cleanupExpired.
 *
 * Transitions are recorded to the audit log but trigger no user notifications:
 * accounts are anonymous, so the control plane has no contact channel by design.
 *
 * Handlers that reference same-file `internal.lifecycle.*` carry explicit return
 * types to break Convex's self-reference inference cycle.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import { heartbeatFromAction } from './cronHeartbeat';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { deleteSubscriptionEverywhere } from './lib/issuance';
import { computeExpireAtIso, gbToBytes, resolveHwidLimit } from './lib/backends/types';
import { SETTINGS_DEFAULTS } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { resolveProfileSquad } from './lib/connectionProfiles';
import { resolveDefaultFreeTier } from './tiers';

// --- entitlement seam ------------------------------------------------------

export interface SetMembershipArgs {
  userId: Id<'users'>;
  tierId: Id<'tiers'>;
  expiresAtMs: number | null;
  reason: string;
  triggeredBy?: string;
}

/**
 * The entitlement-seam core, reusable inside other mutations (e.g. W4 code
 * redemption grants membership atomically with consuming the code). Sets tier +
 * expiry; on a tier change records history + audit and schedules a durable
 * backend push. Idempotent on an unchanged tier (only patches expiry if it moved).
 */
export async function applyMembership(ctx: MutationCtx, a: SetMembershipArgs): Promise<void> {
  const user = await ctx.db.get(a.userId);
  if (!user) return;
  const toTier = await ctx.db.get(a.tierId);
  if (!toTier) throw new Error('tier not found');

  if (user.tierId === a.tierId) {
    const expiryMoved = a.expiresAtMs !== (user.membershipExpiresAt ?? null);
    const statusLifted = user.status === 'grace' || user.status === 'disabled';
    if (expiryMoved || statusLifted) {
      await ctx.db.patch(a.userId, {
        membershipExpiresAt: a.expiresAtMs ?? undefined,
        // A renewed/extended membership re-activates a lapsed (grace/disabled) user
        // and clears the lapse markers (mirrors the admin re-enable path).
        ...(statusLifted
          ? { status: 'active' as const, disabledReason: undefined, suspendedAt: undefined }
          : {}),
        updatedAt: Date.now(),
      });
      // Re-push so a same-tier renewal re-enables the backend key (the grace sweep
      // disabled it via setUserStatus(false)) and extends its expiry. Previously
      // this branch returned without a push, so the common monthly re-up left the
      // Remnawave key DISABLED. (Review #2.)
      await ctx.scheduler.runAfter(0, internal.lifecycle.pushTierToBackend, { userId: a.userId });
    }
    return;
  }

  await ctx.db.patch(a.userId, {
    tierId: a.tierId,
    membershipExpiresAt: a.expiresAtMs ?? undefined,
    ...(user.status === 'grace' || user.status === 'disabled'
      ? { status: 'active' as const, disabledReason: undefined, suspendedAt: undefined }
      : {}),
    updatedAt: Date.now(),
  });
  await ctx.db.insert('tierHistory', {
    userId: a.userId,
    fromTierId: user.tierId,
    toTierId: a.tierId,
    reason: a.reason,
    triggeredBy: a.triggeredBy ?? 'system',
  });
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'membership.tier_change',
    targetType: 'user',
    targetId: a.userId,
    payload: { fromTierId: user.tierId, toTierId: a.tierId, reason: a.reason },
  });
  // Durable, decoupled propagation of the new tier spec to the live backend.
  await ctx.scheduler.runAfter(0, internal.lifecycle.pushTierToBackend, { userId: a.userId });
}

/**
 * Set a user's tier + membership expiry from an external source of truth
 * (admin tier change today; the billing portal later). On a tier change it
 * records history + audit and schedules a durable backend push. Idempotent.
 */
export const setMembership = internalMutation({
  args: {
    userId: v.id('users'),
    tierId: v.id('tiers'),
    expiresAtMs: v.union(v.number(), v.null()),
    reason: v.string(),
    triggeredBy: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<null> => {
    await applyMembership(ctx, a);
    return null;
  },
});

/**
 * Auto-lift a returning lapsed member (status=disabled, reason 'membership_lapsed')
 * so they regain a working key + see an upgrade prompt instead of staying locked
 * out. Called from accountLogin (Review #1). No-op for admin-disabled / grace /
 * active users. A member on a PAID tier is moved to the default-free tier; one
 * already ON a free tier (odd lapsed-free state) is lifted in place — either way
 * the lapse is cleared and a backend re-enable is scheduled (never left disabled).
 */
export const downgradeLapsedToFree = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<null> => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    if (user.status !== 'disabled' || user.disabledReason !== 'membership_lapsed') return null;
    const currentTier = await ctx.db.get(user.tierId);

    // Already free but somehow lapsed: lift in place (same-tier, no expiry) rather
    // than no-op — else login admits them but they stay disabled locally + on the
    // backend forever. (Re-review follow-up.)
    if (currentTier?.isDefaultFree) {
      await applyMembership(ctx, {
        userId,
        tierId: user.tierId,
        expiresAtMs: null,
        reason: 'membership_lapsed_downgrade',
      });
      return null;
    }

    // Paid tier: resolve the default-free tier for the member's current key backend
    // so the re-push applies free limits to the existing subscription in place;
    // fall back to any active default-free tier if that backend has none.
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .order('desc')
      .first();
    const free =
      (sub ? await resolveDefaultFreeTier(ctx.db, sub.backend) : null) ??
      (await resolveDefaultFreeTier(ctx.db));
    if (!free) return null; // no free tier configured — leave as-is (login still works)

    // Tier change → applyMembership lifts disabled→active locally and schedules
    // pushTierToBackend, which (Review #2) re-enables the key at free-tier limits
    // in the member's profile squad.
    await applyMembership(ctx, {
      userId,
      tierId: free._id,
      expiresAtMs: null,
      reason: 'membership_lapsed_downgrade',
    });
    return null;
  },
});

/** The user's active subscription + their tier's backend spec (for push/disable). */
export const activeSubAndTier = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    const tier = await ctx.db.get(user.tierId);
    if (!tier) return null;
    const sub = await ctx.db
      .query('subscriptions')
      .withIndex('by_user_state', (q) => q.eq('userId', userId).eq('state', 'active'))
      .order('desc')
      .first();
    if (!sub) return null;
    // The placement this key was issued into, PRESERVED: a tier push must re-send
    // the key's own placement, never re-pick (that would thrash live keys across
    // nodes on every renewal) and never re-home to the tier squad (which would
    // discard the member's mode choice, or clear activeInternalSquads → "No hosts
    // found"). (Review #3 + node placement.) Rows with no persisted placement
    // fall back to a stable mode-first resolution.
    const placement =
      sub.backendPlacement ??
      sub.remnawaveSquadUuid ?? // legacy rows pre-migration (Phase 5 copies it over)
      (await resolveProfileSquad(ctx.db, user.connectionProfileId ?? null));
    // Read the device-limit master toggle (fail-safe to the compiled default) so
    // the tier push honors it exactly like the issuance path — flipping it off
    // clears hwidDeviceLimit on the next push.
    const enforcementRow = await ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', 'devices.enforcementEnabled'))
      .unique();
    let enforcementEnabled = SETTINGS_DEFAULTS['devices.enforcementEnabled'] as boolean;
    if (enforcementRow) {
      try {
        enforcementEnabled = JSON.parse(enforcementRow.value) === true;
      } catch {
        /* keep the default */
      }
    }
    return {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      // The user's local status, so the push can re-enable a key the grace sweep
      // disabled (updateUser never touches enable/disable state). (Review #2.)
      userStatus: user.status,
      trafficLimitBytes: tier.monthlyTrafficGb > 0 ? gbToBytes(tier.monthlyTrafficGb) : null,
      trafficLimitStrategy: tier.trafficStrategy,
      hwidDeviceLimit: resolveHwidLimit(enforcementEnabled, tier),
      placement: placement ?? tier.remnawaveSquadUuid ?? null,
      // Raw ms (this is a query — the ISO is computed in the action, which can
      // call Date.now()), so a renewal re-pushes the backend expiry.
      membershipExpiresAt: user.membershipExpiresAt ?? null,
    };
  },
});

// P2: retry the backend push with bounded exponential backoff. setMembership
// schedules this with attempt:0; a redeemed membership code (W4) drives it on
// day 1, so a transient backend blip must not silently leave the backend on the
// old tier. On the final failure we write an audit entry so the drift is
// observable (an admin can hit "resync"). Backoff: ~30s, 2m, 8m, 30m.
const PUSH_MAX_ATTEMPTS = 4;
const PUSH_BACKOFF_MS = [30_000, 120_000, 480_000, 1_800_000];

export const pushTierToBackend = internalAction({
  args: { userId: v.id('users'), attempt: v.optional(v.number()) },
  handler: async (ctx, { userId, attempt }): Promise<null> => {
    const n = attempt ?? 0;
    const st = await ctx.runQuery(internal.lifecycle.activeSubAndTier, { userId });
    if (!st) return null; // no active sub to push to (e.g. free user pre-issuance)
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const freeExpiryDays = Number(settings['freetier.expiryDays'] ?? 90);
    try {
      // Re-enable a key the grace sweep disabled: updateUser/remnawaveUpdateUser
      // never touches enable/disable state, so a renewal or lapsed→free downgrade
      // must flip the backend user active again. Idempotent (enabling an already-
      // enabled key is a no-op), so it's safe on every active push. (Review #2.)
      if (st.userStatus === 'active') {
        await ctx.runAction(internal.backends.setUserStatus, {
          backend: st.backend,
          backendUserId: st.backendUserId,
          active: true,
        });
      }
      await ctx.runAction(internal.backends.updateUser, {
        backend: st.backend,
        backendUserId: st.backendUserId,
        patch: {
          trafficLimitBytes: st.trafficLimitBytes,
          trafficLimitStrategy: st.trafficLimitStrategy,
          hwidDeviceLimit: st.hwidDeviceLimit,
          placement: st.placement,
          // Push the entitlement expiry too, so a renewal extends the backend key.
          expireAt: computeExpireAtIso(st.membershipExpiresAt, freeExpiryDays),
        },
      });
      // Push succeeded: clear any prior drift flag (no-op if it wasn't set).
      await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
    } catch (err) {
      if (n + 1 < PUSH_MAX_ATTEMPTS) {
        await ctx.scheduler.runAfter(
          PUSH_BACKOFF_MS[n] ?? 1_800_000,
          internal.lifecycle.pushTierToBackend,
          {
            userId,
            attempt: n + 1,
          },
        );
      } else {
        // Exhausted retries: record it so the drift is visible (admin can resync).
        await ctx.runMutation(internal.lifecycle.recordPushFailure, {
          userId,
          detail: err instanceof Error ? err.message.slice(0, 200) : 'unknown',
        });
      }
    }
    return null;
  },
});

/** Audit a tier-push that exhausted its retries (no secrets; backend errors are pre-scrubbed). */
export const recordPushFailure = internalMutation({
  args: { userId: v.id('users'), detail: v.string() },
  handler: async (ctx, { userId }) => {
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'membership.push_failed',
      targetType: 'user',
      targetId: userId,
    });
    // Flag the drift so an admin can see the backend never got this user's tier.
    await ctx.db.patch(userId, { backendPushFailedAt: Date.now() });
    return null;
  },
});

/**
 * Set or clear the user's backend push-drift flag (the admin "backend drift"
 * signal). `failed:true` stamps now; `failed:false` clears it, but only writes
 * when it was actually set — so a clear-on-every-successful-push is a no-op in the
 * common (no drift) case.
 */
export const setBackendDrift = internalMutation({
  args: { userId: v.id('users'), failed: v.boolean() },
  handler: async (ctx, { userId, failed }) => {
    const user = await ctx.db.get(userId);
    if (!user) return null;
    if (failed) {
      await ctx.db.patch(userId, { backendPushFailedAt: Date.now() });
    } else if (user.backendPushFailedAt != null) {
      await ctx.db.patch(userId, { backendPushFailedAt: undefined });
    }
    return null;
  },
});

// --- grace / disable sweep -------------------------------------------------

const SWEEP_PAGE = 500;
const SWEEP_MAX_PAGES = 200; // safety backstop: 200 * 500 = 100k rows/run, then log

/**
 * Active users whose membership has lapsed (expiry in the past), as an EXACT
 * index range — not a take-then-filter — so the page contains only due users
 * (most overdue first) and the sweep can drain it fully. Free users (no expiry)
 * are excluded by `gt(...,0)`. (P1-4: the old take(500)+post-filter silently
 * stopped processing anyone past row 500.)
 */
export const findGraceTransitions = internalQuery({
  args: { now: v.number(), limit: v.optional(v.number()) },
  handler: async (ctx, { now, limit }) => {
    const rows = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) =>
        q.eq('status', 'active').gt('membershipExpiresAt', 0).lt('membershipExpiresAt', now),
      )
      .take(limit ?? SWEEP_PAGE);
    return rows.map((u) => u._id);
  },
});

/**
 * A page of grace users with expiry > `afterExpiry` (keyset cursor), with the
 * due ones (past THEIR tier's grace window) flagged. Read-only: the caller
 * collects across pages, then applies, so disabling-while-paginating can't shift
 * the set. (P1-4.)
 */
export const findDisableTransitions = internalQuery({
  args: { now: v.number(), afterExpiry: v.number(), limit: v.optional(v.number()) },
  handler: async (ctx, { now, afterExpiry, limit }) => {
    const pageSize = limit ?? SWEEP_PAGE;
    const rows = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) =>
        q.eq('status', 'grace').gt('membershipExpiresAt', afterExpiry),
      )
      .take(pageSize);
    const due: Id<'users'>[] = [];
    let lastExpiry = afterExpiry;
    // Memoize the per-tier grace window across the page (tiers are ~a handful and
    // many users share one) so this is O(distinct tiers), not O(users). (Review P2.)
    const windowByTier = new Map<Id<'tiers'>, number>();
    for (const u of rows) {
      if (u.membershipExpiresAt == null) continue;
      lastExpiry = u.membershipExpiresAt;
      let windowMs = windowByTier.get(u.tierId);
      if (windowMs === undefined) {
        const tier = await ctx.db.get(u.tierId);
        windowMs = (tier?.expirationDaysAfterMembershipLapse ?? 7) * 86_400_000;
        windowByTier.set(u.tierId, windowMs);
      }
      if (u.membershipExpiresAt + windowMs < now) due.push(u._id);
    }
    return { due, lastExpiry, hasMore: rows.length === pageSize };
  },
});

export const applyGraceTransition = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    await ctx.db.patch(userId, { status: 'grace', updatedAt: Date.now() });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'membership.transition.grace',
      targetType: 'user',
      targetId: userId,
    });
    return null;
  },
});

export const applyDisableTransition = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    await ctx.db.patch(userId, {
      status: 'disabled',
      disabledReason: 'membership_lapsed',
      suspendedAt: Date.now(),
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'membership.transition.disabled',
      targetType: 'user',
      targetId: userId,
    });
    return null;
  },
});

/** Cron: active→grace for lapsed members, grace→disabled past the grace window. */
export const runGraceSweep = internalAction({
  args: {},
  handler: async (ctx): Promise<{ toGrace: number; toDisabled: number }> => {
    await heartbeatFromAction(ctx, 'grace-sweep');
    const now = Date.now();

    // active → grace: drain the exact-range page repeatedly. Each applied user
    // leaves the active index, so re-querying advances through the whole set.
    let toGrace = 0;
    for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
      const due = await ctx.runQuery(internal.lifecycle.findGraceTransitions, { now });
      if (due.length === 0) break;
      for (const userId of due) {
        await ctx.runMutation(internal.lifecycle.applyGraceTransition, { userId });
      }
      toGrace += due.length;
      if (due.length < SWEEP_PAGE) break;
      if (page === SWEEP_MAX_PAGES - 1) {
        console.warn('[grace-sweep] grace transitions hit the per-run cap; remainder next run');
      }
    }

    // grace → disabled: paginate the grace set read-only (keyset on expiry),
    // collecting due ids, then apply. Backend-disable FIRST so a backend failure
    // leaves the user in `grace` for the next sweep to retry (not silently
    // disabled-locally with the key still routing).
    const disableIds: Id<'users'>[] = [];
    let afterExpiry = 0;
    for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
      const res = await ctx.runQuery(internal.lifecycle.findDisableTransitions, {
        now,
        afterExpiry,
      });
      disableIds.push(...res.due);
      if (!res.hasMore || res.lastExpiry <= afterExpiry) break;
      afterExpiry = res.lastExpiry;
      if (page === SWEEP_MAX_PAGES - 1) {
        console.warn('[grace-sweep] disable scan hit the per-run cap; remainder next run');
      }
    }
    let toDisabled = 0;
    for (const userId of disableIds) {
      const st = await ctx.runQuery(internal.lifecycle.activeSubAndTier, { userId });
      if (st) {
        try {
          await ctx.runAction(internal.backends.setUserStatus, {
            backend: st.backend,
            backendUserId: st.backendUserId,
            active: false,
          });
        } catch {
          // Backend unreachable: leave the user in `grace` so the next sweep
          // retries; disabling locally now would strand a still-routing key. Flag
          // the drift so the still-routing key is observable meanwhile.
          await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: true });
          continue;
        }
      }
      await ctx.runMutation(internal.lifecycle.applyDisableTransition, { userId });
      await ctx.runMutation(internal.lifecycle.setBackendDrift, { userId, failed: false });
      toDisabled++;
    }
    return { toGrace, toDisabled };
  },
});

// --- tombstone sweep -------------------------------------------------------

/** Disabled subscriptions whose grace window (deletedAt) has elapsed. */
export const findTombstonedDue = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    // Exact index range on by_state = ['state','deletedAt'] (mirrors
    // findGraceTransitions / retention.sweepDeletedSubscriptions), not a
    // take(500)+JS-filter that could leave due rows beyond the 500-window
    // unprocessed for extra sweeps. gt(...,0) excludes rows with no deletedAt
    // (undefined sorts below numbers), preserving the old null-guard. (Review #6.)
    const due = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) =>
        q.eq('state', 'disabled').gt('deletedAt', 0).lt('deletedAt', now),
      )
      .take(limit);
    return due.map((s) => ({ backend: s.backend, backendUserId: s.backendUserId }));
  },
});

/** Cron: hard-delete subscriptions whose 24h regenerate/switch grace has passed. */
export const sweepTombstones = internalAction({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }): Promise<{ removed: number }> => {
    await heartbeatFromAction(ctx, 'tombstone-sweep');
    const due = await ctx.runQuery(internal.lifecycle.findTombstonedDue, {
      now: Date.now(),
      limit: limit ?? 100,
    });
    let removed = 0;
    for (const d of due) {
      try {
        await deleteSubscriptionEverywhere(ctx, {
          backend: d.backend,
          backendUserId: d.backendUserId,
        });
        removed++;
      } catch {
        /* best-effort; retried next sweep */
      }
    }
    return { removed };
  },
});

// --- free-tier cleanup -----------------------------------------------------

/** The default-free tier ids (the only tiers cleanup-expired-free touches). */
export const defaultFreeTierIds = internalQuery({
  args: {},
  handler: async (ctx): Promise<Id<'tiers'>[]> =>
    (await ctx.db.query('tiers').collect()).filter((t) => t.isDefaultFree).map((t) => t._id),
});

/**
 * One page of expired free users on a SINGLE tier, oldest first, with a
 * `_creationTime` keyset cursor (`afterCreation`, exclusive). Targets the tier
 * via `by_tier` so paid members never crowd the page, and the cursor pages past
 * already-deleted old users instead of re-scanning them each run. (P1-4.)
 */
export const findExpiredFree = internalQuery({
  args: {
    tierId: v.id('tiers'),
    cutoff: v.number(),
    limit: v.number(),
    afterCreation: v.number(),
  },
  handler: async (ctx, { tierId, cutoff, limit, afterCreation }) => {
    const rows = await ctx.db
      .query('users')
      .withIndex('by_tier', (q) => q.eq('tierId', tierId).gt('_creationTime', afterCreation))
      .order('asc')
      .take(limit);
    const expired: {
      userId: Id<'users'>;
      backend: 'remnawave' | 'outline';
      backendUserId: string;
    }[] = [];
    let cursor = afterCreation;
    let reachedCutoff = false;
    for (const u of rows) {
      cursor = u._creationTime;
      if (u._creationTime >= cutoff) {
        reachedCutoff = true; // asc order → nothing older remains on this tier
        break;
      }
      if (u.status !== 'active') continue;
      const sub = await ctx.db
        .query('subscriptions')
        .withIndex('by_user_state', (q) => q.eq('userId', u._id).eq('state', 'active'))
        .order('desc')
        .first();
      if (!sub) continue;
      expired.push({ userId: u._id, backend: sub.backend, backendUserId: sub.backendUserId });
    }
    // More to scan on this tier iff we filled the page and haven't hit the cutoff.
    const hasMore = !reachedCutoff && rows.length === limit;
    return { expired, nextCursor: hasMore ? cursor : null };
  },
});

export const markUserDeleted = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    await ctx.db.patch(userId, { status: 'deleted', updatedAt: Date.now() });
    return null;
  },
});

/** Cron: delete free-tier users past the expiry window (backend + S3 + local). */
export const cleanupExpiredFree = internalAction({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }): Promise<{ removed: number }> => {
    await heartbeatFromAction(ctx, 'cleanup-expired-free');
    // Admin-tunable (appSettings 'freetier.expiryDays', default 90); replaced the
    // FREE_TIER_EXPIRY_DAYS env var, and matches what issuance stamps on the key.
    const settings = await ctx.runQuery(internal.appSettings.resolved, {});
    const expiryDays = Number(settings['freetier.expiryDays'] ?? 90);
    const cutoff = Date.now() - expiryDays * 86_400_000;
    const pageSize = limit ?? 100;
    const tierIds = await ctx.runQuery(internal.lifecycle.defaultFreeTierIds, {});
    let removed = 0;
    for (const tierId of tierIds) {
      let afterCreation = 0;
      for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
        const { expired, nextCursor } = await ctx.runQuery(internal.lifecycle.findExpiredFree, {
          tierId,
          cutoff,
          limit: pageSize,
          afterCreation,
        });
        for (const e of expired) {
          try {
            await deleteSubscriptionEverywhere(ctx, {
              backend: e.backend,
              backendUserId: e.backendUserId,
            });
            await ctx.runMutation(internal.lifecycle.markUserDeleted, { userId: e.userId });
            removed++;
          } catch {
            /* best-effort; teardown failure leaves the row for the next sweep */
          }
        }
        if (nextCursor == null) break;
        afterCreation = nextCursor;
        if (page === SWEEP_MAX_PAGES - 1) {
          console.warn('[cleanup-free] hit the per-run page cap; remainder next run');
        }
      }
    }
    return { removed };
  },
});
