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
import type { MutationCtx, DatabaseReader } from './_generated/server';
import { internal } from './_generated/api';
import { runWithCronOutcome } from './cronHeartbeat';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { deleteSubscriptionEverywhere } from './lib/issuance';
import {
  computeExpireAtIso,
  resolveHwidLimit,
  resolveTrafficLimitBytes,
} from './lib/backends/types';
import { resolveCurrentBonusGb } from './lib/donationBonus';
import { SETTINGS_DEFAULTS } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { applyCountsDelta } from './lib/statusCounters';
import { resolvePlacementTarget } from './lib/remnawavePlacement';
import { resolveDefaultFreeTier } from './tiers';

// --- entitlement seam ------------------------------------------------------

export interface SetMembershipArgs {
  userId: Id<'users'>;
  tierId: Id<'tiers'>;
  expiresAtMs: number | null;
  reason: string;
  triggeredBy?: string;
  /**
   * Permit lifting an ADMIN disable ('admin_action'). Default false: a payment
   * or code redemption must never un-ban an account (a ban is only reversible
   * by an admin). Only the admin grant flow (adminApi.grantMembership) sets
   * this — an explicit admin decision to restore the account.
   */
  liftAdminBan?: boolean;
}

/**
 * The statuses a grant lifts back to active. An admin disable ('admin_action')
 * is NEVER lifted by a payment/grant — a ban is only reversible by an admin
 * (`liftAdminBan`); the grant still records the new tier/expiry (so a later
 * un-ban honors the purchase) but the account and its backend key stay disabled.
 */
function isLiftableStatus(
  user: { status: string; disabledReason?: string },
  liftAdminBan: boolean,
): boolean {
  if (user.status === 'grace' || user.status === 'inactive') return true;
  if (user.status !== 'disabled') return false;
  return user.disabledReason === 'membership_lapsed' || liftAdminBan;
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

  // Track the PAID-through date separately from the effective expiry: grants
  // that carry real value (billing, code redemption, admin grant — anything
  // that isn't a referral reward) advance `membershipPaidThroughAt`; referral
  // bonuses extend only `membershipExpiresAt`. The referral vest check reads
  // the paid-through date so a self-referral bonus can't satisfy its own
  // holding period (M4).
  const paidThrough =
    a.expiresAtMs != null && !a.reason.startsWith('referral.')
      ? Math.max(user.membershipPaidThroughAt ?? 0, a.expiresAtMs)
      : undefined;

  if (user.tierId === a.tierId) {
    const expiryMoved = a.expiresAtMs !== (user.membershipExpiresAt ?? null);
    const statusLifted = isLiftableStatus(user, a.liftAdminBan === true);
    if (expiryMoved || statusLifted) {
      await ctx.db.patch(a.userId, {
        membershipExpiresAt: a.expiresAtMs ?? undefined,
        ...(paidThrough !== undefined ? { membershipPaidThroughAt: paidThrough } : {}),
        // A renewed/extended membership re-activates a lapsed (grace/disabled)
        // user and clears the lapse markers (mirrors the admin re-enable path).
        // An idle-deactivated ('inactive') account is lifted too: a grant can
        // land via the generic webhook / an fsv1_ token with no login to run
        // refreshFreeWindow, and a paying member must never stay parked
        // inactive (the grace sweep only scans status='active').
        ...(statusLifted
          ? { status: 'active' as const, disabledReason: undefined, suspendedAt: undefined }
          : {}),
        updatedAt: Date.now(),
      });
      if (statusLifted)
        await applyCountsDelta(ctx, { statusFrom: user.status, statusTo: 'active' });
      // Re-push so a same-tier renewal re-enables the backend key (the grace sweep
      // disabled it via setUserStatus(false)) and extends its expiry. Previously
      // this branch returned without a push, so the common monthly re-up left the
      // Remnawave key DISABLED. (Review #2.) Skipped for an admin-disabled user:
      // the key must stay off until an admin lifts the ban.
      if (statusLifted || user.status === 'active') {
        await ctx.scheduler.runAfter(0, internal.lifecycle.pushTierToBackend, {
          userId: a.userId,
        });
      }
      // Referral hook (scheduled, async): a paid-tier grant may convert a
      // referral. No-op for free tiers, referral-reward grants, or when the
      // program is disabled.
      await ctx.scheduler.runAfter(0, internal.referrals.maybeConvert, {
        userId: a.userId,
        toTierId: a.tierId,
        reason: a.reason,
      });
    }
    return;
  }

  const tierChangeLifts = isLiftableStatus(user, a.liftAdminBan === true);
  await ctx.db.patch(a.userId, {
    tierId: a.tierId,
    membershipExpiresAt: a.expiresAtMs ?? undefined,
    ...(paidThrough !== undefined ? { membershipPaidThroughAt: paidThrough } : {}),
    ...(tierChangeLifts
      ? { status: 'active' as const, disabledReason: undefined, suspendedAt: undefined }
      : {}),
    updatedAt: Date.now(),
  });
  if (tierChangeLifts) {
    await applyCountsDelta(ctx, { statusFrom: user.status, statusTo: 'active' });
  }
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
  // Skipped for an admin-disabled user: their key stays off until an admin lifts
  // the ban (the grant is still recorded above, so the un-ban honors it).
  if (tierChangeLifts || user.status === 'active') {
    await ctx.scheduler.runAfter(0, internal.lifecycle.pushTierToBackend, { userId: a.userId });
  }
  // Referral hook (scheduled, async): a paid-tier grant may convert a referral.
  // No-op for free tiers, referral-reward grants, or when the program is off.
  await ctx.scheduler.runAfter(0, internal.referrals.maybeConvert, {
    userId: a.userId,
    toTierId: a.tierId,
    reason: a.reason,
  });
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
      // Start the free idle clock so a returning downgraded member isn't swept next run.
      await ctx.db.patch(userId, {
        freeKeyExpiresAt: await freeWindowExpiryMs(ctx.db),
        updatedAt: Date.now(),
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
    // pushTierToBackend, which (Review #2) re-enables the key at free-tier limits,
    // preserving the key's persisted placement.
    await applyMembership(ctx, {
      userId,
      tierId: free._id,
      expiresAtMs: null,
      reason: 'membership_lapsed_downgrade',
    });
    await ctx.db.patch(userId, {
      freeKeyExpiresAt: await freeWindowExpiryMs(ctx.db),
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * Placement for a legacy sub row with no persisted `backendPlacement` (see
 * activeSubAndTier): pinned to the row's recorded panel when it has one;
 * resolved normally when the deploy is single-panel (any pool squad is on the
 * only panel); undefined — the push OMITS placement, preserving the key's
 * current squad — when the panel can't be proven (multi-panel deploy).
 */
async function legacyPushPlacement(
  db: DatabaseReader,
  modeId: string | null,
  serverId: Id<'backendServers'> | undefined,
): Promise<string | undefined> {
  if (serverId) {
    return (
      (await resolvePlacementTarget(db, modeId, { onlyServerId: serverId as string })).placement ??
      undefined
    );
  }
  const instances = await db
    .query('backendServers')
    .withIndex('by_backend_active', (q) => q.eq('backend', 'remnawave').eq('isActive', true))
    .collect();
  if (instances.length > 1) return undefined;
  return (await resolvePlacementTarget(db, modeId, {})).placement ?? undefined;
}

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
    // nodes on every renewal, discarding the member's mode choice). (Review #3 +
    // node placement.) Legacy rows with no persisted placement resolve PINNED to
    // the key's own panel when one is recorded (onlyServerId); with no panel
    // recorded, they resolve normally only on a SINGLE-panel deploy (any pool
    // squad is on it), and the push OMITS placement (undefined — never null,
    // which would clear the squad panel-side) on multi-panel deploys where the
    // panel can't be proven.
    const placement =
      sub.backendPlacement ??
      (await legacyPushPlacement(ctx.db, user.connectionModeId ?? null, sub.backendServerId));
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
    // Fold the current shared donation bonus into the free-tier limit so an
    // event-driven tier push (login, renewal, downgrade) re-sends base+bonus for a
    // free key — keeping it consistent with the donation fleet apply.
    const bonusGb = await resolveCurrentBonusGb(ctx.db, Date.now());
    return {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      // The user's local status, so the push can re-enable a key the grace sweep
      // disabled (updateUser never touches enable/disable state). (Review #2.)
      userStatus: user.status,
      trafficLimitBytes: resolveTrafficLimitBytes(tier, bonusGb),
      trafficLimitStrategy: tier.trafficStrategy,
      hwidDeviceLimit: resolveHwidLimit(enforcementEnabled, tier),
      placement,
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
    const u = await ctx.db.get(userId);
    await ctx.db.patch(userId, { backendPushFailedAt: Date.now() });
    // Bump the drift tally only on the null→set transition (never double-count).
    if (u && u.backendPushFailedAt == null) await applyCountsDelta(ctx, { driftDelta: 1 });
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
      if (user.backendPushFailedAt == null) await applyCountsDelta(ctx, { driftDelta: 1 });
      await ctx.db.patch(userId, { backendPushFailedAt: Date.now() });
    } else if (user.backendPushFailedAt != null) {
      await ctx.db.patch(userId, { backendPushFailedAt: undefined });
      await applyCountsDelta(ctx, { driftDelta: -1 });
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
    const u = await ctx.db.get(userId);
    if (!u) return null;
    // Re-guard the read→apply race (M2): a renewal landing between the sweep's
    // page read and this apply must not be flipped back to grace — only a
    // STILL-active, STILL-lapsed user transitions.
    if (
      u.status !== 'active' ||
      u.membershipExpiresAt == null ||
      u.membershipExpiresAt >= Date.now()
    ) {
      return null;
    }
    await ctx.db.patch(userId, { status: 'grace', updatedAt: Date.now() });
    await applyCountsDelta(ctx, { statusFrom: u.status, statusTo: 'grace' });
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
    const u = await ctx.db.get(userId);
    if (!u) return null;
    // Re-guard the read→apply race (M2): the disable ids are collected read-only
    // across up to SWEEP_MAX_PAGES pages, so a renewal can land minutes before
    // the apply. Recompute due-ness against the tier's grace window — a renewed
    // member must never be disabled as 'membership_lapsed'.
    if (u.status !== 'grace' || u.membershipExpiresAt == null) return null;
    const tier = await ctx.db.get(u.tierId);
    const windowMs = (tier?.expirationDaysAfterMembershipLapse ?? 7) * 86_400_000;
    if (u.membershipExpiresAt + windowMs >= Date.now()) return null;
    await ctx.db.patch(userId, {
      status: 'disabled',
      disabledReason: 'membership_lapsed',
      suspendedAt: Date.now(),
      updatedAt: Date.now(),
    });
    await applyCountsDelta(ctx, { statusFrom: u.status, statusTo: 'disabled' });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'membership.transition.disabled',
      targetType: 'user',
      targetId: userId,
    });
    return null;
  },
});

/**
 * Single-user due-ness re-check for the disable loop (M2): the sweep collects
 * ids read-only across pages, so before the BACKEND disable (which can't be
 * transactionally paired with the local flip) we re-read the user and confirm
 * they're still grace + past their tier's window. A renewal that lands after
 * this check is still covered: the renewal's scheduled tier push re-enables
 * the key, and applyDisableTransition's own re-guard skips the local flip.
 */
export const isDisableDue = internalQuery({
  args: { userId: v.id('users'), now: v.number() },
  handler: async (ctx, { userId, now }) => {
    const u = await ctx.db.get(userId);
    if (!u || u.status !== 'grace' || u.membershipExpiresAt == null) return false;
    const tier = await ctx.db.get(u.tierId);
    const windowMs = (tier?.expirationDaysAfterMembershipLapse ?? 7) * 86_400_000;
    return u.membershipExpiresAt + windowMs < now;
  },
});

/** Cron: active→grace for lapsed members, grace→disabled past the grace window. */
export const runGraceSweep = internalAction({
  args: {},
  handler: async (ctx): Promise<{ toGrace: number; toDisabled: number }> =>
    runWithCronOutcome(ctx, 'grace-sweep', async () => {
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
        // Re-check due-ness right before acting (M2): the ids were collected
        // read-only across pages, so a renewal may have landed since — disabling
        // a paying member's key at the panel would be entitlement loss caused by
        // the control plane itself.
        if (!(await ctx.runQuery(internal.lifecycle.isDisableDue, { userId, now }))) continue;
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
    }),
});

// --- tombstone sweep -------------------------------------------------------

/**
 * A tombstone whose backend delete keeps failing (dead panel) used to occupy
 * the oldest-100 page forever, starving every NEWER tombstone (head-of-line
 * blocking). Failures now back off exponentially (10 min → 24 h cap) and the
 * due-row selection skips rows still inside their backoff; after
 * TOMBSTONE_MAX_ATTEMPTS the row is abandoned (marked deleted + audited) so a
 * permanently-dead backend can't wedge the sweep.
 */
const TOMBSTONE_RETRY_BASE_MS = 10 * 60_000;
const TOMBSTONE_RETRY_CAP_MS = 24 * 3_600_000;
const TOMBSTONE_MAX_ATTEMPTS = 14; // ~2 weeks at the capped backoff.

/** Disabled subscriptions whose grace window (deletedAt) has elapsed and whose
 *  retry backoff (if any) has too. */
export const findTombstonedDue = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    // by_state_tombstone_retry = ['state','tombstoneRetryAfter','deletedAt']:
    // undefined retryAfter sorts below numbers, so never-retried rows are
    // picked first and backoff-deferred rows (retryAfter >= now) fall outside
    // the range. The deletedAt range can't ride the same index, so it's the
    // JS filter below (deletedAt > 0 also excludes rows with no deletedAt).
    const rows = await ctx.db
      .query('subscriptions')
      .withIndex('by_state_tombstone_retry', (q) =>
        q.eq('state', 'disabled').lt('tombstoneRetryAfter', now),
      )
      .take(limit);
    return rows
      .filter((s) => s.deletedAt !== undefined && s.deletedAt > 0 && s.deletedAt < now)
      .map((s) => ({
        subscriptionId: s._id,
        backend: s.backend,
        backendUserId: s.backendUserId,
        attempts: s.tombstoneAttempts ?? 0,
      }));
  },
});

/** Stamp a failed tombstone delete with its next backoff (serializable read of
 *  the current attempt count). */
export const deferTombstone = internalMutation({
  args: { subscriptionId: v.id('subscriptions'), retryAfter: v.number() },
  handler: async (ctx, { subscriptionId, retryAfter }) => {
    const row = await ctx.db.get(subscriptionId);
    if (!row || row.state !== 'disabled') return null;
    await ctx.db.patch(subscriptionId, {
      tombstoneAttempts: (row.tombstoneAttempts ?? 0) + 1,
      tombstoneRetryAfter: retryAfter,
      updatedAt: Date.now(),
    });
    return null;
  },
});

/** Cron: hard-delete subscriptions whose 24h regenerate/switch grace has passed. */
export const sweepTombstones = internalAction({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }): Promise<{ removed: number }> =>
    runWithCronOutcome(ctx, 'tombstone-sweep', async () => {
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
          const attempts = d.attempts + 1;
          if (attempts >= TOMBSTONE_MAX_ATTEMPTS) {
            // Give up: the row leaves the disabled set so the sweep (and the
            // deleted-row retention sweep) move on; the backend key may still
            // exist — loud audit for the operator cleanup queue.
            try {
              await ctx.runMutation(internal.subscriptions.markSubscriptionDeleted, {
                subscriptionId: d.subscriptionId,
              });
              await ctx.runMutation(internal.audit.record, {
                actorType: 'system',
                action: 'subscription.tombstone_abandoned',
                targetType: 'subscription',
                targetId: d.subscriptionId,
                payload: { backend: d.backend, backendUserId: d.backendUserId, attempts },
              });
            } catch {
              /* the next sweep re-attempts the abandon path */
            }
          } else {
            const backoff = Math.min(
              TOMBSTONE_RETRY_BASE_MS * 2 ** d.attempts,
              TOMBSTONE_RETRY_CAP_MS,
            );
            await ctx.runMutation(internal.lifecycle.deferTombstone, {
              subscriptionId: d.subscriptionId,
              retryAfter: Date.now() + backoff,
            });
          }
        }
      }
      return { removed };
    }),
});

// --- free-tier cleanup -----------------------------------------------------

/** The default-free tier ids (the only tiers cleanup-expired-free touches). */
export const defaultFreeTierIds = internalQuery({
  args: {},
  handler: async (ctx): Promise<Id<'tiers'>[]> =>
    (await ctx.db.query('tiers').collect()).filter((t) => t.isDefaultFree).map((t) => t._id),
});

/** The free-tier window in days — `freetier.expiryDays` (default 90). Fail-safe. */
export async function freeWindowDays(db: DatabaseReader): Promise<number> {
  const row = await db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'freetier.expiryDays'))
    .unique();
  if (row) {
    try {
      const n = Number(JSON.parse(row.value));
      if (Number.isFinite(n) && n > 0) return n;
    } catch {
      /* keep the default */
    }
  }
  return 90;
}

/** The free-key window expiry (ms from now) — matching what issuance stamps on
 *  the backend key. */
export async function freeWindowExpiryMs(db: DatabaseReader): Promise<number> {
  return Date.now() + (await freeWindowDays(db)) * 86_400_000;
}

/**
 * One page of ACTIVE free users on a SINGLE tier whose free key has expired and
 * wasn't refreshed (`freeKeyExpiresAt < now`) — the deactivate-idle-free set.
 * Paginated over `by_tier_status_freekey` (compound `(_creationTime,_id)` cursor —
 * no same-ms skip), tier- + status-scoped so `inactive` rows are never re-scanned
 * (no accretion) and paid users never appear. Read-only; the action applies.
 * Legacy free users with an UNSET `freeKeyExpiresAt` (pre-WS2 accounts that never
 * returned) are INCLUDED — undefined sorts below numbers, and treating them as
 * due is how they get swept now that the one-time backfill migration is retired
 * (they reactivate on login, so this only reclaims their key).
 */
export const findIdleFree = internalQuery({
  args: {
    tierId: v.id('tiers'),
    now: v.number(),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, { tierId, now, cursor, numItems }) => {
    const res = await ctx.db
      .query('users')
      .withIndex('by_tier_status_freekey', (q) =>
        q.eq('tierId', tierId).eq('status', 'active').lt('freeKeyExpiresAt', now),
      )
      .paginate({ cursor, numItems });
    const idle: {
      userId: Id<'users'>;
      backend: 'remnawave' | 'outline' | null;
      backendUserId: string | null;
    }[] = [];
    for (const u of res.page) {
      const sub = await ctx.db
        .query('subscriptions')
        .withIndex('by_user_state', (q) => q.eq('userId', u._id).eq('state', 'active'))
        .order('desc')
        .first();
      idle.push({
        userId: u._id,
        backend: sub?.backend ?? null,
        backendUserId: sub?.backendUserId ?? null,
      });
    }
    return { idle, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

/** Point-in-time idle-due check (the deactivate sweep's pre-reclaim re-guard):
 *  true exactly when the user is active AND their free window has elapsed.
 *  A legacy `freeKeyExpiresAt: null` counts as DUE (pre-WS2 accounts that never
 *  returned; they reactivate on login — treating them as due is how they get
 *  swept at all, since the one-time backfill migration was retired). */
export const isIdleFreeDue = internalQuery({
  args: { userId: v.id('users'), now: v.number() },
  handler: async (ctx, { userId, now }) => {
    const u = await ctx.db.get(userId);
    return !!u && u.status === 'active' && (u.freeKeyExpiresAt ?? 0) < now;
  },
});

/** Deactivate one idle free user: RETAIN the row (status→inactive), keep the free
 *  tier, reclaim the key. Re-reads + guards the read-then-act race: a regenerate/
 *  reactivation between the sweep's read and now moves `freeKeyExpiresAt` to the
 *  future (or flips status), leaving the user active. */
export const markUserInactive = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const u = await ctx.db.get(userId);
    if (!u || u.status !== 'active') return null;
    // null = legacy, never returned (due); a future stamp = refreshed (spare).
    if (u.freeKeyExpiresAt != null && u.freeKeyExpiresAt >= Date.now()) return null;
    await ctx.db.patch(userId, {
      status: 'inactive',
      suspendedAt: Date.now(),
      updatedAt: Date.now(),
    });
    await applyCountsDelta(ctx, { statusFrom: 'active', statusTo: 'inactive' });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'membership.transition.inactive',
      targetType: 'user',
      targetId: userId,
    });
    return null;
  },
});

/** Re-stamp a free user's key window (the "still using the service" signal), and
 *  if they were `inactive`, REACTIVATE them (→active) so a returning member's next
 *  key issues normally. Called on login + on every free-tier (re)issue. */
export const refreshFreeWindow = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const u = await ctx.db.get(userId);
    if (!u) return null;
    const patch: {
      freeKeyExpiresAt: number;
      updatedAt: number;
      status?: 'active';
      suspendedAt?: undefined;
    } = { freeKeyExpiresAt: await freeWindowExpiryMs(ctx.db), updatedAt: Date.now() };
    const reactivating = u.status === 'inactive';
    if (reactivating) {
      patch.status = 'active';
      patch.suspendedAt = undefined;
    }
    await ctx.db.patch(userId, patch);
    if (reactivating) {
      await applyCountsDelta(ctx, { statusFrom: 'inactive', statusTo: 'active' });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'account.reactivate',
        targetType: 'user',
        targetId: userId,
      });
    }
    return null;
  },
});

/** Cron: deactivate + RETAIN idle free users (key reclaimed, row kept on the free
 *  tier, reactivatable on return). Never deletes — manual `purgeInactiveFree`
 *  removes long-inactive rows on operator demand. */
export const deactivateIdleFree = internalAction({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }): Promise<{ deactivated: number }> =>
    runWithCronOutcome(ctx, 'deactivate-idle-free', async () => {
      const now = Date.now();
      const pageSize = limit ?? 100;
      const tierIds = await ctx.runQuery(internal.lifecycle.defaultFreeTierIds, {});
      let deactivated = 0;
      for (const tierId of tierIds) {
        // Collect the due set read-only across pages (cursor stable — no mutation
        // between pages), then apply.
        const due: {
          userId: Id<'users'>;
          backend: 'remnawave' | 'outline' | null;
          backendUserId: string | null;
        }[] = [];
        let cursor: string | null = null;
        for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
          // Annotate to break the same-module self-referential inference.
          const res: {
            idle: {
              userId: Id<'users'>;
              backend: 'remnawave' | 'outline' | null;
              backendUserId: string | null;
            }[];
            isDone: boolean;
            continueCursor: string;
          } = await ctx.runQuery(internal.lifecycle.findIdleFree, {
            tierId,
            now,
            cursor,
            numItems: pageSize,
          });
          due.push(...res.idle);
          if (res.isDone) break;
          cursor = res.continueCursor;
          if (page === SWEEP_MAX_PAGES - 1) {
            console.warn('[deactivate-free] hit the per-run page cap; remainder next run');
          }
        }
        for (const e of due) {
          try {
            // Re-guard BEFORE reclaiming the key: a login/regenerate landing
            // since the read re-stamped freeKeyExpiresAt (or reactivated the
            // user) must spare them — deleting the key first and letting
            // markUserInactive's guard skip would leave an ACTIVE user whose
            // key was just deleted (no auto-reissue).
            const stillDue = await ctx.runQuery(internal.lifecycle.isIdleFreeDue, {
              userId: e.userId,
              now,
            });
            if (!stillDue) continue;
            if (e.backendUserId && e.backend) {
              await deleteSubscriptionEverywhere(ctx, {
                backend: e.backend,
                backendUserId: e.backendUserId,
              });
            }
            await ctx.runMutation(internal.lifecycle.markUserInactive, { userId: e.userId });
            deactivated++;
          } catch {
            /* best-effort; teardown failure leaves the user active for the next run */
          }
        }
      }
      return { deactivated };
    }),
});

/** One page of long-`inactive` free users past the purge threshold. Delete-and-
 *  re-query drain (deleting removes them from the range), so no cursor needed. */
export const findPurgeableInactive = internalQuery({
  args: { tierId: v.id('tiers'), cutoff: v.number(), numItems: v.number() },
  handler: async (ctx, { tierId, cutoff, numItems }) => {
    const rows = await ctx.db
      .query('users')
      .withIndex('by_tier_status_freekey', (q) =>
        q
          .eq('tierId', tierId)
          .eq('status', 'inactive')
          .gt('freeKeyExpiresAt', 0)
          .lt('freeKeyExpiresAt', cutoff),
      )
      .take(numItems);
    return rows.map((u) => ({ userId: u._id }));
  },
});

/** Hard-delete a long-inactive free user's row + every row that references it
 *  (Convex has no FK cascades): subscriptions, tier history, referrals on BOTH
 *  sides, billing orders, passkey credentials, sessions. Guarded to the
 *  `inactive` state so a user who returned between the query and now is
 *  spared. Only reached via the operator-run purge. */
export const deleteInactiveUser = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const u = await ctx.db.get(userId);
    if (!u || u.status !== 'inactive') return null;
    const deleteByUser = async (
      table:
        | 'subscriptions'
        | 'tierHistory'
        | 'billingOrders'
        | 'memberPasskeyCredentials'
        | 'sessions',
    ) => {
      const rows = await ctx.db
        .query(table)
        .withIndex('by_user', (q) => q.eq('userId', userId))
        .collect();
      for (const r of rows) await ctx.db.delete(r._id);
    };
    await deleteByUser('subscriptions');
    await deleteByUser('tierHistory');
    await deleteByUser('billingOrders');
    await deleteByUser('memberPasskeyCredentials');
    await deleteByUser('sessions');
    // Referrals reference the user on BOTH sides (referee + referrer).
    for (const index of ['by_referee', 'by_referrer'] as const) {
      const rows = await ctx.db
        .query('referrals')
        .withIndex(index, (q) =>
          q.eq(index === 'by_referee' ? 'refereeUserId' : 'referrerUserId', userId),
        )
        .collect();
      for (const r of rows) await ctx.db.delete(r._id);
    }
    await applyCountsDelta(ctx, {
      statusFrom: 'inactive',
      driftDelta: u.backendPushFailedAt != null ? -1 : 0,
    });
    await ctx.db.delete(userId);
    return null;
  },
});

/**
 * MANUAL, operator-run purge of long-inactive free users (NOT a cron):
 * `bunx convex run lifecycle:purgeInactiveFree '{"olderThanDays":180}'`. Their key
 * was already reclaimed at deactivation, so this is a pure local-row reclaim. Uses
 * `freeKeyExpiresAt` as the "idle since" marker; drains delete-and-re-query.
 */
export const purgeInactiveFree = internalAction({
  args: { olderThanDays: v.number(), limit: v.optional(v.number()) },
  handler: async (ctx, { olderThanDays, limit }): Promise<{ removed: number }> => {
    const pageSize = limit ?? 200;
    const cutoff = Date.now() - olderThanDays * 86_400_000;
    const tierIds = await ctx.runQuery(internal.lifecycle.defaultFreeTierIds, {});
    let removed = 0;
    for (const tierId of tierIds) {
      for (let page = 0; page < SWEEP_MAX_PAGES; page++) {
        const rows = await ctx.runQuery(internal.lifecycle.findPurgeableInactive, {
          tierId,
          cutoff,
          numItems: pageSize,
        });
        if (rows.length === 0) break;
        for (const e of rows) {
          await ctx.runMutation(internal.lifecycle.deleteInactiveUser, { userId: e.userId });
          removed++;
        }
      }
    }
    return { removed };
  },
});
