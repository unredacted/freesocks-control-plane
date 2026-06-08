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
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { deleteSubscriptionEverywhere } from './lib/issuance';

// --- entitlement seam ------------------------------------------------------

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
    const user = await ctx.db.get(a.userId);
    if (!user) return null;
    const toTier = await ctx.db.get(a.tierId);
    if (!toTier) throw new Error('tier not found');

    if (user.tierId === a.tierId) {
      if (a.expiresAtMs !== (user.membershipExpiresAt ?? null)) {
        await ctx.db.patch(a.userId, {
          membershipExpiresAt: a.expiresAtMs ?? undefined,
          updatedAt: Date.now(),
        });
      }
      return null;
    }

    await ctx.db.patch(a.userId, {
      tierId: a.tierId,
      membershipExpiresAt: a.expiresAtMs ?? undefined,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('tierHistory', {
      userId: a.userId,
      fromTierId: user.tierId,
      toTierId: a.tierId,
      reason: a.reason,
      triggeredBy: a.triggeredBy ?? 'system',
    });
    await ctx.db.insert('auditLog', {
      actorType: 'system',
      action: 'membership.tier_change',
      targetType: 'user',
      targetId: a.userId,
      payload: { fromTierId: user.tierId, toTierId: a.tierId, reason: a.reason },
    });
    // Durable, decoupled propagation of the new tier spec to the live backend.
    await ctx.scheduler.runAfter(0, internal.lifecycle.pushTierToBackend, { userId: a.userId });
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
    const subs = await ctx.db
      .query('subscriptions')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
    const sub = subs
      .filter((s) => s.state === 'active')
      .sort((x, y) => y._creationTime - x._creationTime)[0];
    if (!sub) return null;
    return {
      backend: sub.backend,
      backendUserId: sub.backendUserId,
      trafficLimitBytes: tier.monthlyTrafficGb > 0 ? tier.monthlyTrafficGb * 1_000_000_000 : null,
      trafficLimitStrategy: tier.trafficStrategy,
      hwidDeviceLimit: tier.hwidEnabled ? tier.hwidLimit : null,
      remnawaveSquadUuid: tier.remnawaveSquadUuid ?? null,
    };
  },
});

/** Push the user's current tier spec to their live backend subscription. */
export const pushTierToBackend = internalAction({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }): Promise<null> => {
    const st = await ctx.runQuery(internal.lifecycle.activeSubAndTier, { userId });
    if (!st) return null;
    try {
      await ctx.runAction(internal.backends.updateUser, {
        backend: st.backend,
        backendUserId: st.backendUserId,
        patch: {
          trafficLimitBytes: st.trafficLimitBytes,
          trafficLimitStrategy: st.trafficLimitStrategy,
          hwidDeviceLimit: st.hwidDeviceLimit,
          remnawaveSquadUuid: st.remnawaveSquadUuid,
        },
      });
    } catch {
      /* best-effort: local state is already consistent; retried on next edit */
    }
    return null;
  },
});

// --- grace / disable sweep -------------------------------------------------

/** Active users whose membership has lapsed (expiry in the past). */
export const findGraceTransitions = internalQuery({
  args: { now: v.number(), limit: v.optional(v.number()) },
  handler: async (ctx, { now, limit }) => {
    const rows = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) => q.eq('status', 'active').gt('membershipExpiresAt', 0))
      .take(limit ?? 500);
    return rows.filter((u) => u.membershipExpiresAt != null && u.membershipExpiresAt < now);
  },
});

/** Grace users past THEIR tier's grace window. */
export const findDisableTransitions = internalQuery({
  args: { now: v.number(), limit: v.optional(v.number()) },
  handler: async (ctx, { now, limit }) => {
    const graceUsers = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) => q.eq('status', 'grace').gt('membershipExpiresAt', 0))
      .take(limit ?? 500);
    const due = [];
    for (const u of graceUsers) {
      if (u.membershipExpiresAt == null) continue;
      const tier = await ctx.db.get(u.tierId);
      const windowMs = (tier?.expirationDaysAfterMembershipLapse ?? 7) * 86_400_000;
      if (u.membershipExpiresAt + windowMs < now) due.push(u);
    }
    return due;
  },
});

export const applyGraceTransition = internalMutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    await ctx.db.patch(userId, { status: 'grace', updatedAt: Date.now() });
    await ctx.db.insert('auditLog', {
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
    await ctx.db.insert('auditLog', {
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
    const now = Date.now();
    const toGrace = await ctx.runQuery(internal.lifecycle.findGraceTransitions, { now });
    for (const u of toGrace) {
      await ctx.runMutation(internal.lifecycle.applyGraceTransition, { userId: u._id });
    }
    const toDisable = await ctx.runQuery(internal.lifecycle.findDisableTransitions, { now });
    for (const u of toDisable) {
      await ctx.runMutation(internal.lifecycle.applyDisableTransition, { userId: u._id });
      // Disable the backend sub too, so the key actually stops routing.
      const st = await ctx.runQuery(internal.lifecycle.activeSubAndTier, { userId: u._id });
      if (st) {
        try {
          await ctx.runAction(internal.backends.updateUser, {
            backend: st.backend,
            backendUserId: st.backendUserId,
            patch: { status: 'disabled' },
          });
        } catch {
          /* best-effort */
        }
      }
    }
    return { toGrace: toGrace.length, toDisabled: toDisable.length };
  },
});

// --- tombstone sweep -------------------------------------------------------

/** Disabled subscriptions whose grace window (deletedAt) has elapsed. */
export const findTombstonedDue = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    const disabled = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'disabled'))
      .take(500);
    const due: { backend: 'remnawave' | 'outline'; backendUserId: string }[] = [];
    for (const s of disabled) {
      if (s.deletedAt != null && s.deletedAt < now) {
        due.push({ backend: s.backend, backendUserId: s.backendUserId });
        if (due.length >= limit) break;
      }
    }
    return due;
  },
});

/** Cron: hard-delete subscriptions whose 24h regenerate/switch grace has passed. */
export const sweepTombstones = internalAction({
  args: { limit: v.optional(v.number()) },
  handler: async (ctx, { limit }): Promise<{ removed: number }> => {
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

/** Active free-tier users created before the cutoff, with a live subscription. */
export const findExpiredFree = internalQuery({
  args: { cutoff: v.number(), limit: v.number() },
  handler: async (ctx, { cutoff, limit }) => {
    // Active users sort free-tier (no expiry) first under by_status_expires.
    const candidates = await ctx.db
      .query('users')
      .withIndex('by_status_expires', (q) => q.eq('status', 'active'))
      .take(500);
    const out: { userId: Id<'users'>; backend: 'remnawave' | 'outline'; backendUserId: string }[] =
      [];
    for (const u of candidates) {
      if (u._creationTime >= cutoff) continue;
      const tier = await ctx.db.get(u.tierId);
      if (!tier?.isDefaultFree) continue;
      const subs = await ctx.db
        .query('subscriptions')
        .withIndex('by_user', (q) => q.eq('userId', u._id))
        .collect();
      const sub = subs.find((s) => s.state === 'active');
      if (!sub) continue;
      out.push({ userId: u._id, backend: sub.backend, backendUserId: sub.backendUserId });
      if (out.length >= limit) break;
    }
    return out;
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
    const expiryDays = Number(process.env.FREE_TIER_EXPIRY_DAYS ?? '90');
    const cutoff = Date.now() - expiryDays * 86_400_000;
    const expired = await ctx.runQuery(internal.lifecycle.findExpiredFree, {
      cutoff,
      limit: limit ?? 100,
    });
    let removed = 0;
    for (const e of expired) {
      try {
        await deleteSubscriptionEverywhere(ctx, {
          backend: e.backend,
          backendUserId: e.backendUserId,
        });
        await ctx.runMutation(internal.lifecycle.markUserDeleted, { userId: e.userId });
        removed++;
      } catch {
        /* best-effort; sub-ops log their own failures */
      }
    }
    return { removed };
  },
});
