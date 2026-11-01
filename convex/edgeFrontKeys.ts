/**
 * How many of a bound node's keys still hold its operator fronts (docs/edges.md
 * "Direct-Host hides and the restore workflow"). Members' renders leave a front
 * out from the moment the node's binding is claimed, but an app that has not
 * fetched its subscription since still has the body from before and connects
 * through the front. Attention `front_host_unused` and the node page say how
 * many, so a front is not deleted while apps still use it.
 *
 * `subscriptions` scales with traffic, so the count is never made inside the
 * attention query: the reconcile's Host look schedules `refresh` for a bound
 * node with fronts at most hourly (`frontKeysDue`), which pages the node's
 * active keys (`by_backend_server_pinned`, FRONT_KEYS_PAGE a page, one query
 * each) and stores the result on the relay (`relays.frontKeys`). Counts only,
 * never a key, a member or an address.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { deliveryBindingFor } from './relays';
import { FRONT_KEYS_PAGE, keyIsStale } from './lib/edges/frontKeys';

interface Target {
  backendServerId: Id<'backendServers'>;
  nodeName: string;
  since: number;
}

/**
 * What to count for an origin: its node's keys, judged against the claim of
 * the binding that names it. Null when there is nothing to count: no fronts,
 * no binding of this origin, or a binding of the whole server (a front is a
 * backend Host, which only a node has).
 */
export const target = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<Target | null> => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.backendServerId || !relay.nodeName || !relay.operatorFronts) return null;
    const binding = await deliveryBindingFor(ctx.db, relay.backendServerId, relay.nodeName);
    if (!binding || binding.relaySlug !== relay.slug || !binding.nodeName) return null;
    return {
      backendServerId: relay.backendServerId,
      nodeName: binding.nodeName,
      since: binding.updatedAt,
    };
  },
});

/** One page of the node's active keys: how many, and how many have not fetched since `since`. */
export const countPage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    since: v.number(),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, { backendServerId, nodeName, since, cursor, numItems }) => {
    const res = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q.eq('backendServerId', backendServerId).eq('pinnedNode', nodeName).eq('state', 'active'),
      )
      .paginate({ cursor, numItems });
    return {
      total: res.page.length,
      stale: res.page.filter((s) => keyIsStale(s.lastDeliveredAt, since)).length,
      isDone: res.isDone,
      continueCursor: res.continueCursor,
    };
  },
});

/**
 * Store a count, or clear it (`counted: null`). A count made against a claim
 * that moved meanwhile, or for an origin whose fronts are gone, is dropped.
 */
export const record = internalMutation({
  args: {
    relayId: v.id('relays'),
    counted: v.union(
      v.object({ since: v.number(), stale: v.number(), total: v.number() }),
      v.null(),
    ),
  },
  handler: async (ctx, { relayId, counted }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    if (!counted || !relay.operatorFronts || !relay.backendServerId) {
      if (relay.frontKeys) await ctx.db.patch(relayId, { frontKeys: undefined });
      return null;
    }
    const binding = await deliveryBindingFor(ctx.db, relay.backendServerId, relay.nodeName);
    if (!binding || binding.relaySlug !== relay.slug || binding.updatedAt !== counted.since)
      return null;
    await ctx.db.patch(relayId, { frontKeys: { at: Date.now(), ...counted } });
    return null;
  },
});

/** Count one origin's keys again (scheduled by the reconcile's Host look). */
export const refresh = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<{ stale: number; total: number } | null> => {
    const t = await ctx.runQuery(internal.edgeFrontKeys.target, { relayId });
    if (!t) {
      await ctx.runMutation(internal.edgeFrontKeys.record, { relayId, counted: null });
      return null;
    }
    let cursor: string | null = null;
    let stale = 0;
    let total = 0;
    for (;;) {
      const page: { total: number; stale: number; isDone: boolean; continueCursor: string } =
        await ctx.runQuery(internal.edgeFrontKeys.countPage, {
          ...t,
          cursor,
          numItems: FRONT_KEYS_PAGE,
        });
      stale += page.stale;
      total += page.total;
      if (page.isDone) break;
      cursor = page.continueCursor;
    }
    await ctx.runMutation(internal.edgeFrontKeys.record, {
      relayId,
      counted: { since: t.since, stale, total },
    });
    return { stale, total };
  },
});
