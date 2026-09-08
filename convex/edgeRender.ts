/**
 * Relay rendering, DB half: resolve what a subscription's pinned node publishes
 * (edges, slots, profiles, the client-family rule) so the fronted /sub route,
 * the mirror refresh and the admin preview can apply the pure renderer.
 *
 * Rendering is ACTIVE for a (panel, node) pair when the global render switch is
 * on, an enabled origin exists for the node and it has at least one published
 * edge with an eligible slot/profile. `epochFor` returns the cache token the
 * /sub route stores on each cache entry: the origin's publication epoch while
 * active, null otherwise — so a cache hit is only served when nothing about the
 * published pool or the switch changed since the entry was written.
 */
import { v } from 'convex/values';
import { internalQuery } from './_generated/server';
import type { QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import {
  resolveEdgeConfig,
  RENDER_CLIENT_FAMILIES,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { effectiveRule, renderEntries } from './lib/edges/render';
import { assignEndpoints } from './lib/edges/assignment';
import type { PublishedEdge } from './lib/edges/assignment';
import { protocolUsesSni } from './lib/edges/protocols';
import type { EdgeRenderContext } from './lib/edges/renderPipeline';

const familyValidator = v.union(
  ...(RENDER_CLIENT_FAMILIES.map((f) => v.literal(f)) as [
    ReturnType<typeof v.literal>,
    ...ReturnType<typeof v.literal>[],
  ]),
);

async function relayFor(
  ctx: QueryCtx,
  backendServerId: Id<'backendServers'>,
  nodeHostname: string,
): Promise<Doc<'relays'> | null> {
  const rows = await ctx.db
    .query('relays')
    .withIndex('by_node_hostname', (q) => q.eq('nodeHostname', nodeHostname))
    .collect();
  return rows.find((r) => r.backendServerId === backendServerId) ?? null;
}

async function renderEnabled(ctx: QueryCtx): Promise<boolean> {
  const row = await ctx.db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'edge.render.enabled'))
    .unique();
  if (!row) return false;
  try {
    return JSON.parse(row.value) === true;
  } catch {
    return false;
  }
}

/**
 * Published edges in pool order. By default only edges with an eligible slot +
 * profile (and an address) are returned. With `includeIneligible` every
 * published, active edge is returned and the ineligible ones (slot retired or
 * undeployed, profile disabled, no address) carry `eligible:false`: they keep
 * their pool index in the assignment modulus, so one edge losing eligibility
 * moves only its own subscribers (`lib/edges/assignment.ts`).
 */
export async function publishedEdgesOf(
  ctx: QueryCtx | { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
  opts: { includeIneligible?: boolean } = {},
): Promise<{ published: PublishedEdge[]; templateRemarks: string[] }> {
  const slots = await ctx.db
    .query('relaySlots')
    .withIndex('by_relay', (q) => q.eq('relayId', origin._id))
    .collect();
  const templateRemarks = slots.map((s) => s.templateHostRemark);
  const published: PublishedEdge[] = [];
  for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
    const edgeId = origin.publishedEdgeIds[i];
    if (!edgeId) continue;
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.publication !== 'published' || edge.status !== 'active') continue;
    const slot = slots.find((s) => s._id === edge.slotId);
    const profile = slot ? await ctx.db.get(slot.profileId) : null;
    const eligible =
      (!!edge.addresses.v4 || !!edge.addresses.v6) &&
      !!slot &&
      !slot.retired &&
      slot.deployed &&
      !!profile &&
      profile.enabled;
    if (!eligible && !opts.includeIneligible) continue;
    const protocol = profile?.protocol ?? 'plain';
    published.push({
      edgeId: edge._id,
      poolIndex: edge.poolIndex ?? i,
      provider: edge.provider ?? 'adopted',
      slotId: slot?._id ?? (edge.slotId as string),
      slotRemark: slot?.templateHostRemark ?? '',
      protocol,
      edgePort: edge.listeners[0]?.edgePort ?? 443,
      addresses: { v4: edge.addresses.v4, v6: edge.addresses.v6 },
      serverNames:
        profile && protocolUsesSni(protocol)
          ? profile.serverNames.map((s) => ({
              sni: s.sni,
              status: s.status,
              retiredAt: s.retiredAt,
              drainUntil: s.drainUntil,
            }))
          : [],
      ...(eligible ? {} : { eligible: false }),
    });
  }
  return { published, templateRemarks };
}

/**
 * Cache token for a (panel, node): the publication epoch while rendering is
 * active for it, else null. Cheap: a few point reads, no config resolve.
 */
export const epochFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeHostname: v.string() },
  handler: async (ctx, { backendServerId, nodeHostname }): Promise<number | null> => {
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, backendServerId, nodeHostname);
    if (!origin || !origin.enabled) return null;
    // The epoch stands even for an empty pool: the body is then rendered with
    // the template entries dropped, and that render must be cached/invalidated
    // like any other.
    return origin.publicationEpoch;
  },
});

export interface SubscriptionRenderContext extends EdgeRenderContext {
  relayId: Id<'relays'>;
  renderKey: string | null;
}

/**
 * Everything the renderer needs for one subscription + client family, or null
 * when rendering is inactive for its node (the body then passes through).
 * `nodeHostname` overrides the stored pin (the /sub route knows the node it
 * just pinned before the row is updated).
 */
export const contextForSubscription = internalQuery({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: familyValidator,
    nodeHostname: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<SubscriptionRenderContext | null> => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || !sub.backendServerId) return null;
    const node = a.nodeHostname ?? sub.pinnedNode;
    if (!node) return null;
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, sub.backendServerId, node);
    if (!origin || !origin.enabled) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    if (!cfg.render.enabled) return null;
    // An empty eligible pool (every edge unpublished, draining, or behind a
    // disabled profile) still renders: the template entries carry the former
    // index-0 address and must be dropped, not distributed. Ineligible edges
    // are handed in flagged so the assignment modulus stays stable.
    const { published, templateRemarks } = await publishedEdgesOf(ctx, origin, {
      includeIneligible: true,
    });
    const family = a.family as RenderClientFamily;
    return {
      relayId: origin._id,
      epoch: origin.publicationEpoch,
      templateRemarks,
      published,
      rule: effectiveRule(cfg.render, cfg.render.clients[family]),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      renderKey: sub.renderKey ?? null,
    };
  },
});

/** Admin preview / endpoint view: the published pool of one origin as the renderer sees it. */
export const contextForRelay = internalQuery({
  args: { relayId: v.id('relays'), family: familyValidator },
  handler: async (ctx, a): Promise<EdgeRenderContext | null> => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published, templateRemarks } = await publishedEdgesOf(ctx, origin, {
      includeIneligible: true,
    });
    const family = a.family as RenderClientFamily;
    return {
      epoch: origin.publicationEpoch,
      templateRemarks,
      published,
      rule: effectiveRule(cfg.render, cfg.render.clients[family]),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
    };
  },
});

/**
 * The member-facing nudge (account node status): whether this key has fetched
 * content since its origin last rotated, and the LABELS of the connections its
 * current subscription carries (roles + address family only, never addresses).
 */
export const memberView = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (
    ctx,
    { subscriptionId },
  ): Promise<{
    refreshSuggested: boolean;
    connections: Array<{ label: string; role: 'primary' | 'backup'; family: 'v4' | 'v6' }>;
  } | null> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub || !sub.backendServerId || !sub.pinnedNode) return null;
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, sub.backendServerId, sub.pinnedNode);
    if (!origin || !origin.enabled) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
    if (published.length === 0) return null;
    // The nudge compares the epoch this key's content was last RENDERED against
    // with the origin's current one: publish/unpublish/standby swaps bump the
    // epoch without stamping `lastRotatedAt`, so a timestamp comparison misses
    // them. The legacy timestamp check stays as a fallback for rows that were
    // delivered before the epoch stamp existed.
    const refreshSuggested =
      (sub.lastRenderedEpoch !== undefined && sub.lastRenderedEpoch < origin.publicationEpoch) ||
      (sub.lastRenderedEpoch === undefined &&
        origin.lastRotatedAt !== undefined &&
        (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt);
    let connections: Array<{ label: string; role: 'primary' | 'backup'; family: 'v4' | 'v6' }> = [];
    if (sub.renderKey) {
      const rule = effectiveRule(cfg.render, cfg.render.clients.other);
      const assigned = assignEndpoints(sub.renderKey, published, {
        now: Date.now(),
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        includeBackup: rule.includeBackup,
        canEmitV6: rule.ipv6Mode === 'both',
      });
      connections = renderEntries(assigned, rule, false).map((e) => ({
        label: e.label,
        role: e.role,
        family: e.family,
      }));
    }
    return { refreshSuggested, connections };
  },
});
