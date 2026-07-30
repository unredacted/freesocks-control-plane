// Pass 2: all internal — tier rows carry admin-only fields (peerTierId, backend);
// the safe public projection is publicConfig.get, the admin one adminApi.tiersList.
import { internalQuery } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import { v } from 'convex/values';
import { backendIdValidator, type BackendId } from './lib/backendIds';

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
 * Plain resolver for the active default-free tier, optionally constrained to a
 * backend. Shared by the getDefaultFree query and lifecycle.downgradeLapsedToFree
 * (a mutation — which can't call a query, so it needs the DatabaseReader form).
 */
export async function resolveDefaultFreeTier(db: DatabaseReader, backend?: BackendId) {
  const active = await db
    .query('tiers')
    .withIndex('by_active', (q) => q.eq('isActive', true))
    .collect();
  return (
    active
      .slice()
      .sort((a, b) => a.priority - b.priority)
      .find((t) => t.isDefaultFree && (backend === undefined || t.backend === backend)) ?? null
  );
}

/**
 * The active default-free tier, optionally constrained to a backend so a free
 * user requesting an Outline key gets the Outline-backed default-free tier.
 */
export const getDefaultFree = internalQuery({
  args: { backend: v.optional(backendIdValidator) },
  handler: (ctx, { backend }) => resolveDefaultFreeTier(ctx.db, backend),
});

/** Ids of every default-free tier (any backend, active or not) — the tier-membership
 *  set the user-counts reconcile tallies `freeActive` against. */
export const defaultFreeTierIds = internalQuery({
  args: {},
  handler: async (ctx) => {
    const tiers = await ctx.db.query('tiers').collect();
    return tiers.filter((t) => t.isDefaultFree).map((t) => t._id);
  },
});

/**
 * Resolve a tier's cross-backend peer for a backend switch (D-1). Returns the
 * equivalent ACTIVE tier on `targetBackend`, or null if none is linked:
 *   - FREE tier (isDefaultFree): the per-backend default-free row is its peer, so
 *     a free user always switches cleanly (preserves the prior behavior).
 *   - PAID tier: the active tier on the target backend sharing this tier's
 *     `peerGroup` (lowest priority wins if several) — symmetric and N-ary, so
 *     three backends need one shared string, not a web of pairwise links.
 *     Falls back to the DEPRECATED pairwise `peerTierId` (either direction)
 *     until the seed has grouped every legacy pair.
 * The caller (account.switchBackend) has already ensured targetBackend differs
 * from the current one.
 */
export const getPeerTier = internalQuery({
  args: {
    tierId: v.id('tiers'),
    targetBackend: backendIdValidator,
  },
  handler: async (ctx, { tierId, targetBackend }) => {
    const tier = await ctx.db.get(tierId);
    if (!tier) return null;
    const active = await ctx.db
      .query('tiers')
      .withIndex('by_active', (q) => q.eq('isActive', true))
      .collect();
    if (tier.isDefaultFree) {
      return (
        active
          .slice()
          .sort((a, b) => a.priority - b.priority)
          .find((t) => t.isDefaultFree && t.backend === targetBackend) ?? null
      );
    }
    // Peer group: the symmetric N-ary link.
    if (tier.peerGroup) {
      const grouped = active
        .filter((t) => t.backend === targetBackend && t.peerGroup === tier.peerGroup)
        .sort((a, b) => a.priority - b.priority);
      if (grouped[0]) return grouped[0];
    }
    // DEPRECATED pairwise fallback (either direction) until the seed groups it.
    if (tier.peerTierId) {
      const peer = await ctx.db.get(tier.peerTierId);
      if (peer && peer.isActive && peer.backend === targetBackend) return peer;
    }
    return active.find((t) => t.backend === targetBackend && t.peerTierId === tierId) ?? null;
  },
});
