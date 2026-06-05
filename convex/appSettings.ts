import { query } from './_generated/server';
import { v } from 'convex/values';

/** All settings rows (the SPA + services read these; Convex caches reactively). */
export const getAll = query({
  args: {},
  handler: (ctx) => ctx.db.query('appSettings').collect(),
});

/** Single setting by key (unique-index lookup). */
export const get = query({
  args: { key: v.string() },
  handler: (ctx, { key }) =>
    ctx.db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique(),
});
