/**
 * User-status counter reconcile (M2 / WS3). `reconcileUserCounts` recomputes the
 * `appState` counter row (statusCounters.ts) exactly by a paginated full scan —
 * bounded per page so it never trips the per-query read limit — and self-heals any
 * drift from a missed transition bump. Run daily by cron + once post-deploy.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { v } from 'convex/values';
import { heartbeatFromAction } from './cronHeartbeat';
import { writeUserCounts, type UserCounts } from './lib/statusCounters';

const COUNTS_VALIDATOR = v.object({
  active: v.number(),
  grace: v.number(),
  disabled: v.number(),
  deleted: v.number(),
  inactive: v.number(),
  backendDrift: v.number(),
});

/** Tally one page of users (bounded read) → partial counts + the paginate cursor. */
export const tallyUserCountsPage = internalQuery({
  args: { cursor: v.union(v.string(), v.null()), numItems: v.number() },
  handler: async (ctx, { cursor, numItems }) => {
    const res = await ctx.db.query('users').paginate({ cursor, numItems });
    const counts: UserCounts = {
      active: 0,
      grace: 0,
      disabled: 0,
      deleted: 0,
      inactive: 0,
      backendDrift: 0,
    };
    for (const u of res.page) {
      counts[u.status] += 1;
      if (u.backendPushFailedAt != null) counts.backendDrift += 1;
    }
    return { counts, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

export const setUserCounts = internalMutation({
  args: { counts: COUNTS_VALIDATOR },
  handler: async (ctx, { counts }) => {
    await writeUserCounts(ctx, counts);
    return null;
  },
});

/** Recompute the counter row from scratch (idempotent, self-healing). */
export const reconcileUserCounts = internalAction({
  args: {},
  handler: async (ctx): Promise<UserCounts> => {
    await heartbeatFromAction(ctx, 'user-counts-reconcile');
    const total: UserCounts = {
      active: 0,
      grace: 0,
      disabled: 0,
      deleted: 0,
      inactive: 0,
      backendDrift: 0,
    };
    let cursor: string | null = null;
    for (let i = 0; i < 100_000; i++) {
      // Annotated to break the same-module self-referential inference.
      const res: { counts: UserCounts; isDone: boolean; continueCursor: string } =
        await ctx.runQuery(internal.userStats.tallyUserCountsPage, { cursor, numItems: 500 });
      for (const k of Object.keys(total) as (keyof UserCounts)[]) total[k] += res.counts[k];
      if (res.isDone) break;
      cursor = res.continueCursor;
    }
    await ctx.runMutation(internal.userStats.setUserCounts, { counts: total });
    return total;
  },
});
