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
import {
  beginSessionReconcile,
  finishSessionReconcile,
  readSessionCounts,
  readUserCounts,
  sessionBucket,
  writeUserCounts,
  type SessionCounts,
  type UserCounts,
} from './lib/statusCounters';

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

/** Overwrite ONLY the freeActive field of the live counter row (read-full/
 *  write-full, so concurrent status-transition bumps to other fields are kept). */
export const setFreeActive = internalMutation({
  args: { freeActive: v.number() },
  handler: async (ctx, { freeActive }) => {
    const live = await readUserCounts(ctx.db);
    await writeUserCounts(ctx, { ...live, freeActive: Math.max(0, freeActive) });
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
 * reconcileUserCounts: this scan is bounded to free users, touches no other
 * counter field, and two concurrent runs converge on the same exact value
 * (the full reconcile's delta-write can transiently corrupt under a race).
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
          { tierId, cursor, numItems: 500 },
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

// === Session counter reconcile (2026-09-04) ==================================
// Exact under concurrency (see the statusCounters.ts header): `begin` pins the
// scan boundary (newest visible _creationTime) and opens a delta journal; the
// scan pages over the FIXED set of rows at or before that boundary; `finish`
// writes scanned + journal. Counts rows PRESENT (expired-but-unswept included)
// to match what the per-write bumps track; the daily session-sweep decrements
// as it deletes.

const SESSION_COUNTS_VALIDATOR = v.object({
  bound: v.number(),
  unboundMember: v.number(),
  unboundAdmin: v.number(),
});

export const beginSessionCountsReconcile = internalMutation({
  args: {},
  handler: async (ctx): Promise<number> => beginSessionReconcile(ctx),
});

/** Tally one page of the sessions created at or before the pinned boundary. */
export const tallySessionCountsPage = internalQuery({
  args: { startTs: v.number(), cursor: v.union(v.string(), v.null()), numItems: v.number() },
  handler: async (ctx, { startTs, cursor, numItems }) => {
    const res = await ctx.db
      .query('sessions')
      .withIndex('by_creation_time', (q) => q.lte('_creationTime', startTs))
      .paginate({ cursor, numItems });
    const counts: SessionCounts = { bound: 0, unboundMember: 0, unboundAdmin: 0 };
    for (const row of res.page) counts[sessionBucket(row)] += 1;
    return { counts, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

export const finishSessionCountsReconcile = internalMutation({
  args: { startTs: v.number(), scanned: SESSION_COUNTS_VALIDATOR },
  handler: async (ctx, { startTs, scanned }): Promise<boolean> =>
    finishSessionReconcile(ctx, startTs, scanned),
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
      const startTs: number = await ctx.runMutation(
        internal.userStats.beginSessionCountsReconcile,
        {},
      );
      const total: SessionCounts = { bound: 0, unboundMember: 0, unboundAdmin: 0 };
      let cursor: string | null = null;
      for (let i = 0; i < 100_000; i++) {
        const res: { counts: SessionCounts; isDone: boolean; continueCursor: string } =
          await ctx.runQuery(internal.userStats.tallySessionCountsPage, {
            startTs,
            cursor,
            numItems: 500,
          });
        for (const k of Object.keys(total) as (keyof SessionCounts)[]) total[k] += res.counts[k];
        if (res.isDone) break;
        cursor = res.continueCursor;
      }
      const applied: boolean = await ctx.runMutation(
        internal.userStats.finishSessionCountsReconcile,
        { startTs, scanned: total },
      );
      if (!applied) console.warn('[session-counts-reconcile] superseded by a newer run; skipped');
      return total;
    }),
});
