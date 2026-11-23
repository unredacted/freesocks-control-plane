/**
 * The fronted route's per-UA body cache (lib/subscriptionBodies.ts; the
 * route reads it through convex/deliveryContext.ts): the one-shot move of the
 * old `subscriptions.subCache` blobs into the table, and its rollback.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import {
  BODIES_PAUSED_KEY,
  SUB_CACHE_MAX,
  bodiesPaused,
  storeBodies,
} from './lib/subscriptionBodies';
import { readStateJson, writeStateJson } from './lib/appStateJson';

/** Set once every row's old blob has been moved; the move is then a no-op. */
export const LEGACY_MOVED_KEY = 'migration:subscriptionBodies';
// A row with an old blob can hold four full bodies, and the page reads and
// writes them: the same bound the other full scans of `subscriptions` keep
// under the 8 MiB per-execution read limit.
const MIGRATE_PAGE = 32;

/**
 * Move every row's old `subCache` blob into `subscriptionBodies` and clear it,
 * page by page in their own transactions (scheduled by seedCutover, so a page
 * that fails never fails the deploy; re-run with `{}` to resume from the
 * start). A deleted key's blob is dropped, not moved. The route keeps reading
 * a blob that is not moved yet, and a body written for the key moves it too,
 * so nothing is fetched again because of the move.
 */
export const migrateLegacy = internalMutation({
  args: { cursor: v.optional(v.union(v.string(), v.null())) },
  handler: async (ctx, { cursor }) => {
    if (!cursor && (await readStateJson(ctx.db, LEGACY_MOVED_KEY))) return { moved: 0 };
    // A rollback is draining the table: move nothing (the chain ends here).
    if (await bodiesPaused(ctx.db)) return { moved: 0 };
    const page = await ctx.db
      .query('subscriptions')
      .paginate({ cursor: cursor ?? null, numItems: MIGRATE_PAGE });
    let moved = 0;
    for (const sub of page.page) {
      if (sub.subCache === undefined) continue;
      if (sub.state === 'deleted') await ctx.db.patch(sub._id, { subCache: undefined });
      else await storeBodies(ctx, sub);
      moved++;
    }
    if (!page.isDone)
      await ctx.scheduler.runAfter(0, internal.subscriptionBodies.migrateLegacy, {
        cursor: page.continueCursor,
      });
    else await writeStateJson(ctx.db, LEGACY_MOVED_KEY, { at: Date.now() });
    return { moved };
  },
});

/**
 * Before deploying a build older than the table: pause body writes, then drop
 * every cached body and forget that the move ran, page by page (the pages
 * after the first are scheduled), so the older schema meets an empty table and
 * the move runs again when this build returns. While paused, the route writes
 * no body (a key keeps whatever old blob it has), so none can come back behind
 * the drain. Wait for `rollbackStatus` to answer `{ paused: true, empty: true }`
 * before deploying the older build. Members lose nothing but the cache (their
 * apps' next polls fetch afresh).
 */
export const clearForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    await writeStateJson(ctx.db, BODIES_PAUSED_KEY, true);
    const flag = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', LEGACY_MOVED_KEY))
      .unique();
    if (flag) await ctx.db.delete(flag._id);
    const rows = await ctx.db.query('subscriptionBodies').take(MIGRATE_PAGE * SUB_CACHE_MAX);
    for (const row of rows) await ctx.db.delete(row._id);
    if (rows.length === MIGRATE_PAGE * SUB_CACHE_MAX)
      await ctx.scheduler.runAfter(0, internal.subscriptionBodies.clearForRollback, {});
    return { deleted: rows.length };
  },
});

/** Whether a rollback may deploy: body writes paused and the table empty. */
export const rollbackStatus = internalQuery({
  args: {},
  handler: async (ctx) => ({
    paused: await bodiesPaused(ctx.db),
    empty: (await ctx.db.query('subscriptionBodies').first()) === null,
  }),
});

/**
 * Lift a rollback's pause: bodies are written again. Every deploy of this build
 * runs it (`seed:seedCutover`, before the move), so going forward again after a
 * rollback resumes the cache.
 */
export const resume = internalMutation({
  args: {},
  handler: async (ctx) => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', BODIES_PAUSED_KEY))
      .unique();
    if (row) await ctx.db.delete(row._id);
    return { resumed: !!row };
  },
});
