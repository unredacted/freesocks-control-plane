/**
 * The fronted route's per-UA body cache (lib/subscriptionBodies.ts): the read
 * the route makes, and the one-shot move of the old `subscriptions.subCache`
 * blobs into the table.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { SUB_CACHE_MAX, entriesForUa, storeBodies } from './lib/subscriptionBodies';
import { readStateJson, writeStateJson } from './lib/appStateJson';

/**
 * The serialized entries that may answer this key for this UA (zero or one):
 * one indexed read, so a body written for another UA never invalidates it.
 */
export const forUa = internalQuery({
  args: { subscriptionId: v.id('subscriptions'), ua: v.string() },
  handler: (ctx, { subscriptionId, ua }) => entriesForUa(ctx.db, subscriptionId, ua),
});

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
 * Before deploying a build older than the table: drop every cached body and
 * forget that the move ran, page by page, so the older schema meets an empty
 * table and the move runs again when this build returns. Members lose nothing
 * but the cache (their apps' next polls fetch afresh).
 */
export const clearForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
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
