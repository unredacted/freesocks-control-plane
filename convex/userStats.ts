/**
 * Counter reconciles (M2 / WS3 + 2026-09-04). Both `appState` counters that feed
 * `adminApi.statusSummary` — `stats:userCounts` and `stats:sessionCounts` — are
 * rebuilt exactly by the begin → scan pages → finish protocol in
 * lib/statusCounters.ts (bounded per page so it never trips the per-execution
 * read limit; exact under concurrent writes via the pinned boundary + journal).
 * Run daily by cron + once post-deploy.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { runWithCronOutcome } from './cronHeartbeat';
import {
  SESSION_COUNTER,
  USER_COUNTER,
  beginCounterReconcile,
  finishCounterReconcile,
  patchCounterCounts,
  readSessionCounts,
  readUserCounts,
  scanCounterPage,
  sessionBucket,
  type SessionCounts,
  type UserCounts,
} from './lib/statusCounters';

const PAGE = 500;

// === Users ===================================================================

export const beginUserCountsReconcile = internalMutation({
  args: {},
  handler: async (ctx): Promise<number> => beginCounterReconcile(ctx, USER_COUNTER),
});

/** Scan one page of users (bounded read) into the open reconcile. `freeTierIds`
 *  = the default-free tier set; active users on one count toward `freeActive`. */
export const scanUserCountsPage = internalMutation({
  args: { freeTierIds: v.array(v.id('tiers')), pageSize: v.optional(v.number()) },
  handler: async (ctx, { freeTierIds, pageSize }) => {
    const freeIdSet = new Set<string>(freeTierIds);
    return scanCounterPage(
      ctx,
      USER_COUNTER,
      (u) => ({
        [u.status]: 1,
        ...(u.backendPushFailedAt != null ? { backendDrift: 1 } : {}),
        ...(u.status === 'active' && freeIdSet.has(u.tierId) ? { freeActive: 1 } : {}),
      }),
      pageSize ?? PAGE,
    );
  },
});

export const finishUserCountsReconcile = internalMutation({
  args: { token: v.number() },
  handler: async (ctx, { token }): Promise<boolean> =>
    finishCounterReconcile(ctx, USER_COUNTER, token),
});

/** The counter row as it currently stands. */
export const getUserCounts = internalQuery({
  args: {},
  handler: async (ctx): Promise<UserCounts> => readUserCounts(ctx.db),
});

/** One page of ACTIVE users on a free tier (index prefix scan) — the targeted
 *  freeActive recount, far cheaper than the full-table reconcile scan. */
export const countFreeActivePage = internalQuery({
  args: {
    tierId: v.id('tiers'),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, { tierId, cursor, numItems }) => {
    const res = await ctx.db
      .query('users')
      .withIndex('by_tier_status_freekey', (q) => q.eq('tierId', tierId).eq('status', 'active'))
      .paginate({ cursor, numItems });
    return { count: res.page.length, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

/** Overwrite ONLY the freeActive field of the live counter row (the other
 *  fields + any open reconcile's state are preserved). */
export const setFreeActive = internalMutation({
  args: { freeActive: v.number() },
  handler: async (ctx, { freeActive }) => {
    await patchCounterCounts(ctx, USER_COUNTER, { freeActive: Math.max(0, freeActive) });
    return null;
  },
});

/**
 * Refresh JUST the freeActive counter (the "free accounts reached" impact stat)
 * by an exact recount over the free tiers' (tierId, 'active') index prefix.
 * Scheduled from the donation grant so a donor sees a current figure right away
 * — freeActive is otherwise maintained only by the DAILY full reconcile (a
 * status transition can't bump it: it doesn't know tier membership), which
 * stays as the self-healing backstop. Deliberately not the full
 * reconcileUserCounts: this scan is bounded to free users and touches no other
 * counter field.
 */
export const refreshFreeActive = internalAction({
  args: {},
  handler: async (ctx): Promise<null> => {
    const freeTierIds: Id<'tiers'>[] = await ctx.runQuery(internal.tiers.defaultFreeTierIds, {});
    let freeActive = 0;
    for (const tierId of freeTierIds) {
      let cursor: string | null = null;
      for (let i = 0; i < 100_000; i++) {
        const res: { count: number; isDone: boolean; continueCursor: string } = await ctx.runQuery(
          internal.userStats.countFreeActivePage,
          { tierId, cursor, numItems: PAGE },
        );
        freeActive += res.count;
        if (res.isDone) break;
        cursor = res.continueCursor;
      }
    }
    await ctx.runMutation(internal.userStats.setFreeActive, { freeActive });
    return null;
  },
});

/** Recompute the user counter row from scratch (idempotent, self-healing). */
export const reconcileUserCounts = internalAction({
  args: {},
  handler: async (ctx): Promise<UserCounts> =>
    runWithCronOutcome(ctx, 'user-counts-reconcile', async () => {
      const freeTierIds: Id<'tiers'>[] = await ctx.runQuery(internal.tiers.defaultFreeTierIds, {});
      const token: number = await ctx.runMutation(internal.userStats.beginUserCountsReconcile, {});
      for (let i = 0; i < 100_000; i++) {
        const res: { done: boolean; rows: number } = await ctx.runMutation(
          internal.userStats.scanUserCountsPage,
          { freeTierIds },
        );
        if (res.done) break;
      }
      const applied: boolean = await ctx.runMutation(internal.userStats.finishUserCountsReconcile, {
        token,
      });
      if (!applied) console.warn('[user-counts-reconcile] superseded by a newer run; skipped');
      return await ctx.runQuery(internal.userStats.getUserCounts, {});
    }),
});

// === Sessions ================================================================
// Counts rows PRESENT (expired-but-unswept included) to match what the per-write
// bumps track; the daily session-sweep decrements as it deletes.

export const beginSessionCountsReconcile = internalMutation({
  args: {},
  handler: async (ctx): Promise<number> => beginCounterReconcile(ctx, SESSION_COUNTER),
});

export const scanSessionCountsPage = internalMutation({
  args: { pageSize: v.optional(v.number()) },
  handler: async (ctx, { pageSize }) =>
    scanCounterPage(ctx, SESSION_COUNTER, (row) => ({ [sessionBucket(row)]: 1 }), pageSize ?? PAGE),
});

export const finishSessionCountsReconcile = internalMutation({
  args: { token: v.number() },
  handler: async (ctx, { token }): Promise<boolean> =>
    finishCounterReconcile(ctx, SESSION_COUNTER, token),
});

export const getSessionCounts = internalQuery({
  args: {},
  handler: async (ctx) => readSessionCounts(ctx.db),
});

/** Recompute the session counter row from scratch (idempotent, self-healing).
 *  Daily cron + once post-deploy (the deploy entrypoint); the row is built from
 *  nothing on the first run after this shipped, and `statusSummary` reports the
 *  readiness flag as NOT ready until that first run completes. */
export const reconcileSessionCounts = internalAction({
  args: {},
  handler: async (ctx): Promise<SessionCounts> =>
    runWithCronOutcome(ctx, 'session-counts-reconcile', async () => {
      const token: number = await ctx.runMutation(
        internal.userStats.beginSessionCountsReconcile,
        {},
      );
      for (let i = 0; i < 100_000; i++) {
        const res: { done: boolean; rows: number } = await ctx.runMutation(
          internal.userStats.scanSessionCountsPage,
          {},
        );
        if (res.done) break;
      }
      const applied: boolean = await ctx.runMutation(
        internal.userStats.finishSessionCountsReconcile,
        { token },
      );
      if (!applied) console.warn('[session-counts-reconcile] superseded by a newer run; skipped');
      const st: { counts: SessionCounts; initialized: boolean } = await ctx.runQuery(
        internal.userStats.getSessionCounts,
        {},
      );
      return st.counts;
    }),
});
