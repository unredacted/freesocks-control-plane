// Pass 2: all internal — tier rows leak backend infra detail (remnawaveSquadUuid);
// the safe public projection is publicConfig.get, the admin one adminApi.tiersList.
import { internalQuery } from './_generated/server';
import { v } from 'convex/values';

/** All tiers (admin list + the cache-free replacement for TierPolicyService.listAll). */
export const list = internalQuery({
  args: {},
  handler: (ctx) => ctx.db.query('tiers').collect(),
});

export const listActive = internalQuery({
  args: {},
  handler: (ctx) =>
    ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect(),
});

export const get = internalQuery({
  args: { id: v.id('tiers') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/** Unique-index lookup by slug (also the read-check used when enforcing slug uniqueness). */
export const getBySlug = internalQuery({
  args: { slug: v.string() },
  handler: (ctx, { slug }) =>
    ctx.db
      .query('tiers')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique(),
});

/**
 * The active default-free tier, optionally constrained to a backend so a free
 * user requesting an Outline key gets the Outline-backed default-free tier.
 */
export const getDefaultFree = internalQuery({
  args: { backend: v.optional(v.union(v.literal('remnawave'), v.literal('outline'))) },
  handler: async (ctx, { backend }) => {
    const active = await ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    return (
      active
        .slice()
        .sort((a, b) => a.priority - b.priority)
        .find((t) => t.isDefaultFree && (backend === undefined || t.backend === backend)) ?? null
    );
  },
});
