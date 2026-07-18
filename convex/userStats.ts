/**
 * User-status counter reconcile (M2 / WS3). `reconcileUserCounts` recomputes the
 * `appState` counter row (statusCounters.ts) exactly by a paginated full scan —
 * bounded per page so it never trips the per-query read limit — and self-heals any
 * drift from a missed transition bump. Run daily by cron + once post-deploy.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { runWithCronOutcome } from './cronHeartbeat';
import { readUserCounts, writeUserCounts, type UserCounts } from './lib/statusCounters';

const COUNTS_VALIDATOR = v.object({
  active: v.number(),
  grace: v.number(),
  disabled: v.number(),
  deleted: v.number(),
  inactive: v.number(),
  backendDrift: v.number(),
  freeActive: v.number(),
});

/** Tally one page of users (bounded read) → partial counts + the paginate cursor.
 *  `freeTierIds` = the default-free tier set; active users on one count toward
 *  `freeActive` (the "free users helped" impact stat). */
export const tallyUserCountsPage = internalQuery({
  args: {
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
    freeTierIds: v.array(v.id('tiers')),
  },
  handler: async (ctx, { cursor, numItems, freeTierIds }) => {
    const res = await ctx.db.query('users').paginate({ cursor, numItems });
    const freeIdSet = new Set<string>(freeTierIds);
    const counts: UserCounts = {
      active: 0,
      grace: 0,
      disabled: 0,
      deleted: 0,
      inactive: 0,
      backendDrift: 0,
      freeActive: 0,
    };
    for (const u of res.page) {
      counts[u.status] += 1;
      if (u.backendPushFailedAt != null) counts.backendDrift += 1;
      if (u.status === 'active' && freeIdSet.has(u.tierId)) counts.freeActive += 1;
    }
    return { counts, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

/** The counter row as it currently stands (the reconcile baseline). */
export const getUserCounts = internalQuery({
  args: {},
  handler: async (ctx): Promise<UserCounts> => readUserCounts(ctx.db),
});

/**
 * Apply the reconcile result as a DELTA against the live row, not an absolute
 * write: status transitions landing mid-scan bump the live counter via
 * applyCountsDelta, and an absolute overwrite would silently discard those
 * bumps (up to 24h of drift from the daily "self-heal" itself). next =
 * live + (scanned − baseline); when nothing changed mid-scan this equals the
 * exact scanned total, and the residual error is bounded to transitions that
 * raced the scan rather than compounding them. Clamped ≥ 0 (a transition can
 * legitimately race both the scan AND this write).
 */
export const applyReconcileDelta = internalMutation({
  args: { baseline: COUNTS_VALIDATOR, scanned: COUNTS_VALIDATOR },
  handler: async (ctx, { baseline, scanned }) => {
    const live = await readUserCounts(ctx.db);
    const next = { ...live };
    for (const k of Object.keys(scanned) as (keyof UserCounts)[]) {
      next[k] = Math.max(0, live[k] + (scanned[k] - baseline[k]));
    }
    await writeUserCounts(ctx, next);
    return null;
  },
});

/** Recompute the counter row from scratch (idempotent, self-healing). */
export const reconcileUserCounts = internalAction({
  args: {},
  handler: async (ctx): Promise<UserCounts> =>
    runWithCronOutcome(ctx, 'user-counts-reconcile', async () => {
      const freeTierIds: Id<'tiers'>[] = await ctx.runQuery(internal.tiers.defaultFreeTierIds, {});
      // Baseline BEFORE the scan: transitions after this point bump the live row
      // and are preserved by the delta write (see applyReconcileDelta).
      const baseline = await ctx.runQuery(internal.userStats.getUserCounts, {});
      const total: UserCounts = {
        active: 0,
        grace: 0,
        disabled: 0,
        deleted: 0,
        inactive: 0,
        backendDrift: 0,
        freeActive: 0,
      };
      let cursor: string | null = null;
      for (let i = 0; i < 100_000; i++) {
        // Annotated to break the same-module self-referential inference.
        const res: { counts: UserCounts; isDone: boolean; continueCursor: string } =
          await ctx.runQuery(internal.userStats.tallyUserCountsPage, {
            cursor,
            numItems: 500,
            freeTierIds,
          });
        for (const k of Object.keys(total) as (keyof UserCounts)[]) total[k] += res.counts[k];
        if (res.isDone) break;
        cursor = res.continueCursor;
      }
      await ctx.runMutation(internal.userStats.applyReconcileDelta, {
        baseline,
        scanned: total,
      });
      return total;
    }),
});
